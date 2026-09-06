"""Redis client, pub/sub channel naming, and the ephemeral key conventions.

Redis holds presence, typing state, rate-limit counters, WebSocket tickets and the
pub/sub bus. It is never the source of truth for a message: everything here is
reconstructible from PostgreSQL, so losing Redis costs availability, not data.
"""
from __future__ import annotations

import redis.asyncio as aioredis

from app.core.config import get_settings

_pool: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(
            get_settings().redis_url,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=20,
            socket_keepalive=True,
            max_connections=64,
        )
    return _pool


async def close_redis() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None


# ----------------------------------------------------------------- key naming
def conversation_channel(conversation_id: str) -> str:
    """Fan-out channel. Every API replica subscribes on behalf of its connected
    clients, so a message published by replica A reaches a client held by replica B."""
    return f"conv:{conversation_id}"


def user_channel(user_id: str) -> str:
    """Cross-device delivery: read receipts, membership changes, session revocation."""
    return f"user:{user_id}"


def presence_key(user_id: str) -> str:
    return f"presence:{user_id}"


def typing_key(conversation_id: str, user_id: str) -> str:
    return f"typing:{conversation_id}:{user_id}"


def ws_ticket_key(ticket: str) -> str:
    return f"wsticket:{ticket}"


def connection_count_key(user_id: str) -> str:
    return f"wsconn:{user_id}"


def revoked_session_key(session_id: str) -> str:
    """Session revocation must take effect before the access token expires. Revoked
    session ids sit here for exactly the access-token lifetime, and the auth dependency
    checks this set on every request — a 10-minute window is too long to leave open."""
    return f"revoked:{session_id}"
