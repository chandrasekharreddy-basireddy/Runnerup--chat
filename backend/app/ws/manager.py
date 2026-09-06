"""WebSocket connection registry and Redis fan-out.

The API runs as several replicas, so a message written by the replica holding the
sender's socket must reach a recipient held by a different replica. Every replica
subscribes to the Redis channels its own connections care about and forwards what
arrives. Redis carries the event; PostgreSQL remains the record.

Subscription is authorized once at subscribe time and re-checked on membership changes.
A connection cannot subscribe to a conversation id it names — it subscribes to what the
authorization layer confirms it belongs to.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import WebSocket

from app.core.logging import get_logger
from app.core.redis import conversation_channel, get_redis, user_channel

log = get_logger("ws")

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_CONNECTIONS_PER_USER = 10


@dataclass
class Connection:
    socket: WebSocket
    user_id: str
    session_id: str
    device_id: str
    connection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    subscriptions: set[str] = field(default_factory=set)

    async def send(self, payload: dict) -> None:
        try:
            await self.socket.send_text(json.dumps(payload, separators=(",", ":")))
        except Exception:
            # A dead socket is normal; the reader task will clean up.
            pass


class ConnectionManager:
    def __init__(self) -> None:
        self._by_user: dict[str, set[Connection]] = defaultdict(set)
        self._by_channel: dict[str, set[Connection]] = defaultdict(set)
        self._pubsub_task: asyncio.Task | None = None
        self._pubsub = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        redis = get_redis()
        self._pubsub = redis.pubsub(ignore_subscribe_messages=True)
        # Placeholder subscription keeps the pubsub object alive with zero channels.
        await self._pubsub.subscribe("__keepalive__")
        self._pubsub_task = asyncio.create_task(self._relay())

    async def stop(self) -> None:
        if self._pubsub_task:
            self._pubsub_task.cancel()
        if self._pubsub:
            await self._pubsub.aclose()

    async def _relay(self) -> None:
        """One task per replica pumping Redis messages out to local sockets."""
        assert self._pubsub is not None
        while True:
            try:
                message = await self._pubsub.get_message(timeout=1.0)
                if not message or message.get("type") != "message":
                    continue
                channel = message["channel"]
                try:
                    payload = json.loads(message["data"])
                except (TypeError, ValueError):
                    continue
                for connection in list(self._by_channel.get(channel, ())):
                    # Skip the originating connection: its optimistic UI already shows
                    # this message, and echoing it back causes a visible flicker.
                    if payload.get("_origin") == connection.connection_id:
                        continue
                    await connection.send({k: v for k, v in payload.items()
                                           if not k.startswith("_")})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("pubsub_relay_error", error=type(exc).__name__)
                await asyncio.sleep(0.5)

    async def register(self, connection: Connection) -> bool:
        async with self._lock:
            if len(self._by_user[connection.user_id]) >= MAX_CONNECTIONS_PER_USER:
                # Connection flooding is a cheap denial-of-service; cap it per account.
                return False
            self._by_user[connection.user_id].add(connection)
        await self.subscribe(connection, user_channel(connection.user_id))
        return True

    async def unregister(self, connection: Connection) -> None:
        async with self._lock:
            self._by_user[connection.user_id].discard(connection)
            if not self._by_user[connection.user_id]:
                del self._by_user[connection.user_id]
            for channel in list(connection.subscriptions):
                self._by_channel[channel].discard(connection)
                if not self._by_channel[channel]:
                    del self._by_channel[channel]
                    if self._pubsub:
                        await self._pubsub.unsubscribe(channel)
            connection.subscriptions.clear()

    async def subscribe(self, connection: Connection, channel: str) -> None:
        """Callers must have already authorized this. The manager does no permission
        work — keeping that in one place (services/authz.py) is what makes it auditable."""
        first_local_subscriber = channel not in self._by_channel
        self._by_channel[channel].add(connection)
        connection.subscriptions.add(channel)
        if first_local_subscriber and self._pubsub:
            await self._pubsub.subscribe(channel)

    async def unsubscribe(self, connection: Connection, channel: str) -> None:
        self._by_channel.get(channel, set()).discard(connection)
        connection.subscriptions.discard(channel)
        if not self._by_channel.get(channel) and self._pubsub:
            self._by_channel.pop(channel, None)
            await self._pubsub.unsubscribe(channel)

    async def drop_user_connections(self, user_id: str, reason: str) -> None:
        """Called when a session is revoked. An open socket authenticated an hour ago
        must not outlive the session that authorized it."""
        for connection in list(self._by_user.get(user_id, ())):
            await connection.send({"type": "session.revoked", "reason": reason})
            await connection.socket.close(code=4001)


manager = ConnectionManager()


async def publish_to_conversation(conversation_id: str, event: dict,
                                  origin_connection: str | None = None) -> None:
    payload = dict(event)
    if origin_connection:
        payload["_origin"] = origin_connection
    await get_redis().publish(conversation_channel(conversation_id),
                              json.dumps(payload, separators=(",", ":")))


async def publish_to_user(user_id: str, event: dict) -> None:
    await get_redis().publish(user_channel(user_id),
                              json.dumps(event, separators=(",", ":")))
