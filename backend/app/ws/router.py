"""The WebSocket endpoint.

Handshake uses a single-use ticket rather than a token in the query string. Query
strings land in proxy logs, browser history and Referer headers; an access token there
is a credential written to disk in three places. The client calls POST /ws/ticket with
its normal Authorization header, gets a 30-second single-use value, and connects with
that. Redeeming it atomically (GETDEL) means a captured ticket is already spent.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.api.deps import Principal, current_principal
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core import ratelimit
from app.core.redis import (
    conversation_channel, get_redis, presence_key, typing_key, ws_ticket_key,
)
from app.core.security import random_token
from app.db.models import User
from app.db.session import SessionLocal
from app.services.authz import Permission, resolve_access
from app.services.sessions import is_session_revoked
from app.ws.manager import MAX_PAYLOAD_BYTES, Connection, manager

router = APIRouter(tags=["realtime"])
log = get_logger("ws")
settings = get_settings()

HEARTBEAT_SECONDS = 25
IDLE_TIMEOUT_SECONDS = 90
PRESENCE_TTL_SECONDS = 45
TYPING_TTL_SECONDS = 6


@router.post("/ws/ticket")
async def issue_ticket(principal: Principal = Depends(current_principal)):
    ticket = random_token(24)
    await get_redis().setex(
        ws_ticket_key(ticket), settings.ws_ticket_ttl_seconds,
        json.dumps({"user_id": str(principal.user.id),
                    "session_id": principal.session_id,
                    "device_id": principal.device_id}),
    )
    return {"ticket": ticket, "expires_in": settings.ws_ticket_ttl_seconds}


async def _redeem(ticket: str) -> dict | None:
    # GETDEL is atomic: two clients racing the same ticket, only one wins.
    raw = await get_redis().getdel(ws_ticket_key(ticket))
    return json.loads(raw) if raw else None


@router.websocket("/ws")
async def websocket_endpoint(socket: WebSocket, ticket: str = ""):
    claims = await _redeem(ticket) if ticket else None
    if not claims:
        await socket.close(code=4401)
        return

    # The session may have been revoked between issuing the ticket and connecting.
    if await is_session_revoked(claims["session_id"]):
        await socket.close(code=4401)
        return

    await socket.accept()
    connection = Connection(socket=socket, user_id=claims["user_id"],
                            session_id=claims["session_id"],
                            device_id=claims["device_id"])

    if not await manager.register(connection):
        await socket.send_text(json.dumps({"type": "error", "code": "too_many_connections"}))
        await socket.close(code=4429)
        return

    redis = get_redis()
    await redis.setex(presence_key(connection.user_id), PRESENCE_TTL_SECONDS, "online")

    heartbeat = asyncio.create_task(_heartbeat(connection))

    try:
        while True:
            try:
                raw = await asyncio.wait_for(socket.receive_text(),
                                             timeout=IDLE_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                # A socket that has not spoken in 90s is holding a slot for nothing.
                await socket.close(code=4408)
                break

            if len(raw) > MAX_PAYLOAD_BYTES:
                await connection.send({"type": "error", "code": "payload_too_large"})
                await socket.close(code=4413)
                break

            decision = await ratelimit.check("ws:event:connection", connection.connection_id)
            if not decision.allowed:
                await connection.send({"type": "error", "code": "rate_limited"})
                continue

            try:
                event = json.loads(raw)
                if not isinstance(event, dict):
                    raise ValueError
            except ValueError:
                await connection.send({"type": "error", "code": "malformed"})
                continue

            await _handle_event(connection, event)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.error("ws_error", error=type(exc).__name__)
    finally:
        heartbeat.cancel()
        await manager.unregister(connection)
        await redis.delete(presence_key(connection.user_id))


async def _heartbeat(connection: Connection) -> None:
    """Keeps presence alive and gives proxies traffic to see. Presence is a Redis key
    with a TTL, so a replica that dies stops refreshing and the user goes offline on
    its own — no cleanup job and no stale 'online' ghosts."""
    while True:
        await asyncio.sleep(HEARTBEAT_SECONDS)
        await get_redis().setex(presence_key(connection.user_id),
                                PRESENCE_TTL_SECONDS, "online")
        await connection.send({"type": "ping", "at": int(time.time())})


async def _handle_event(connection: Connection, event: dict) -> None:
    kind = event.get("type")

    if kind == "pong":
        return

    if kind == "subscribe":
        await _handle_subscribe(connection, event)
        return

    if kind == "unsubscribe":
        channel = conversation_channel(str(event.get("conversation_id", "")))
        await manager.unsubscribe(connection, channel)
        return

    if kind in {"typing.start", "typing.stop"}:
        await _handle_typing(connection, event, started=kind == "typing.start")
        return

    await connection.send({"type": "error", "code": "unknown_event"})


async def _handle_subscribe(connection: Connection, event: dict) -> None:
    """Membership is verified here, every time. The client naming a conversation id is a
    request, not an authorization — this is the WebSocket half of the IDOR defence."""
    conversation_id = str(event.get("conversation_id", ""))
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        await connection.send({"type": "error", "code": "invalid_conversation"})
        return

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.id == connection.user_id))
        if user is None:
            await connection.send({"type": "error", "code": "unauthorized"})
            return
        try:
            access = await resolve_access(db, user, conversation_id)
        except Exception:
            # Same answer for "not a member" and "does not exist".
            await connection.send({"type": "error", "code": "not_found"})
            return
        if not access.can(Permission.READ_MESSAGES):
            await connection.send({"type": "error", "code": "not_found"})
            return

    await manager.subscribe(connection, conversation_channel(conversation_id))
    await connection.send({"type": "subscribed", "conversation_id": conversation_id})


async def _handle_typing(connection: Connection, event: dict, *, started: bool) -> None:
    """Typing state is ephemeral by construction: a Redis key with a six-second TTL,
    never written to PostgreSQL. Storing every keystroke event would be a write
    amplification disaster and a needless record of user behaviour."""
    conversation_id = str(event.get("conversation_id", ""))
    channel = conversation_channel(conversation_id)

    # No database round trip: the connection must already hold an authorized
    # subscription to this channel, which was checked at subscribe time.
    if channel not in connection.subscriptions:
        return

    redis = get_redis()
    key = typing_key(conversation_id, connection.user_id)
    if started:
        await redis.setex(key, TYPING_TTL_SECONDS, "1")
    else:
        await redis.delete(key)

    from app.ws.manager import publish_to_conversation
    await publish_to_conversation(
        conversation_id,
        {"type": "typing", "conversation_id": conversation_id,
         "user_id": connection.user_id, "active": started},
        origin_connection=connection.connection_id,
    )
