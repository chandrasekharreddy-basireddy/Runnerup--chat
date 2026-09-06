"""Session lifecycle: creation, rotation, reuse detection, revocation.

The refresh token is an opaque 256-bit random value, not a JWT. That choice is load
bearing: a self-contained token cannot be revoked before it expires, and instant
revocation is the entire point of a session table.

Reuse detection works on token families. Every rotation descends from one login and
shares a family_id. A valid refresh token is single-use — presenting one that has
already been rotated means either the client replayed it or someone stole it, and the
server cannot tell which. Both cases are handled the same way: kill the whole family and
force reauthentication. Losing a session to a false positive is a minor annoyance;
leaving a stolen token live is an account takeover.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import get_redis, revoked_session_key, user_channel
from app.core.security import mint_access_token, random_token, sha256
from app.db.models import User, UserDevice, UserSession
from app.services.audit import record_audit, record_security

log = get_logger("sessions")
settings = get_settings()


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    session_id: uuid.UUID
    device_id: uuid.UUID
    expires_in: int
    user_id: uuid.UUID
    display_name: str


class RefreshRejected(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


async def create_session(
    db: AsyncSession, *, user: User, platform: str, device_label: str,
    ip: str | None, existing_device_id: uuid.UUID | None = None,
) -> IssuedTokens:
    device = None
    if existing_device_id:
        device = await db.scalar(select(UserDevice).where(
            UserDevice.id == existing_device_id,
            UserDevice.user_id == user.id,          # scoped: a device id from another
            UserDevice.revoked_at.is_(None),        # user must never bind here
        ))
    if device is None:
        device = UserDevice(
            user_id=user.id, platform=platform, display_label=device_label,
            ip_first_seen=ip, ip_last_seen=ip,
        )
        db.add(device)
        await db.flush()

    refresh = random_token(32)
    session = UserSession(
        user_id=user.id,
        device_id=device.id,
        family_id=uuid.uuid4(),                     # new login, new family
        refresh_hash=sha256(refresh),
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.refresh_token_ttl_seconds),
    )
    db.add(session)
    await db.flush()

    access = mint_access_token(
        user_id=str(user.id), session_id=str(session.id),
        device_id=str(device.id), system_role=user.system_role,
    )
    await record_audit(db, action="session.created", actor_id=user.id,
                       actor_role=user.system_role, target_type="session",
                       target_id=str(session.id), ip=ip,
                       metadata={"platform": platform})
    await db.commit()

    # Tell the user's other devices a new session appeared. Unexpected-login visibility
    # is one of the few practical defences against SIM swap.
    await get_redis().publish(user_channel(str(user.id)),
                              f'{{"type":"session.created","device_id":"{device.id}"}}')

    return IssuedTokens(access, refresh, session.id, device.id,
                        settings.access_token_ttl_seconds, user.id, user.display_name)


async def rotate_session(
    db: AsyncSession, *, presented_refresh: str, ip: str | None
) -> IssuedTokens:
    """Exchange a refresh token for a new pair. Single use, always rotates."""
    digest = sha256(presented_refresh)
    session = await db.scalar(
        select(UserSession).where(UserSession.refresh_hash == digest).with_for_update()
    )
    if session is None:
        # Unknown token: could be garbage, could be a family already burned. Nothing to
        # revoke, so just refuse.
        raise RefreshRejected("unknown_token")

    now = datetime.now(UTC)

    if session.rotated_at is not None:
        # --- reuse detected -------------------------------------------------------
        # This exact token was already exchanged. Burn the entire family.
        await revoke_family(db, session.family_id, reason="refresh_reuse_detected")
        await record_security(
            db, event="refresh_reuse_detected", severity="CRITICAL",
            user_id=session.user_id, session_id=session.id,
            device_id=session.device_id, ip=ip,
            detail={"family_id": str(session.family_id)},
        )
        await db.commit()
        raise RefreshRejected("reuse_detected")

    if session.revoked_at is not None:
        raise RefreshRejected("revoked")
    if session.expires_at <= now:
        raise RefreshRejected("expired")

    user = await db.scalar(select(User).where(User.id == session.user_id))
    if user is None or not user.is_usable:
        raise RefreshRejected("account_unavailable")

    # Mark the presented token spent, then mint its successor in the same family.
    session.rotated_at = now
    session.last_used_at = now

    new_refresh = random_token(32)
    successor = UserSession(
        user_id=session.user_id,
        device_id=session.device_id,
        family_id=session.family_id,
        refresh_hash=sha256(new_refresh),
        previous_id=session.id,
        expires_at=session.expires_at,   # rotation extends nothing; the family still ages out
    )
    db.add(successor)
    await db.flush()

    await db.execute(update(UserDevice)
                     .where(UserDevice.id == session.device_id)
                     .values(last_active_at=now, ip_last_seen=ip))

    access = mint_access_token(
        user_id=str(user.id), session_id=str(successor.id),
        device_id=str(session.device_id), system_role=user.system_role,
    )
    await db.commit()

    # The old session id may still be inside an unexpired access token.
    await mark_revoked_in_cache(str(session.id))

    return IssuedTokens(access, new_refresh, successor.id, session.device_id,
                        settings.access_token_ttl_seconds, user.id, user.display_name)


async def revoke_family(db: AsyncSession, family_id: uuid.UUID, *, reason: str) -> None:
    rows = await db.execute(
        update(UserSession)
        .where(UserSession.family_id == family_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC), revoked_reason=reason)
        .returning(UserSession.id)
    )
    for (session_id,) in rows:
        await mark_revoked_in_cache(str(session_id))


async def revoke_session(db: AsyncSession, *, session_id: uuid.UUID,
                         user_id: uuid.UUID, reason: str) -> bool:
    """Scoped by user_id so a session id belonging to someone else is a no-op rather
    than a cross-account logout primitive."""
    session = await db.scalar(select(UserSession).where(
        UserSession.id == session_id, UserSession.user_id == user_id))
    if session is None:
        return False
    await revoke_family(db, session.family_id, reason=reason)
    await db.commit()
    return True


async def revoke_all_for_user(db: AsyncSession, *, user_id: uuid.UUID,
                              reason: str, except_session: uuid.UUID | None = None) -> int:
    query = (update(UserSession)
             .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
             .values(revoked_at=datetime.now(UTC), revoked_reason=reason)
             .returning(UserSession.id))
    if except_session:
        query = query.where(UserSession.id != except_session)
    rows = list(await db.execute(query))
    for (session_id,) in rows:
        await mark_revoked_in_cache(str(session_id))
    await db.commit()
    return len(rows)


async def mark_revoked_in_cache(session_id: str) -> None:
    """An access token stays cryptographically valid until it expires. Without this,
    revocation would take up to the full access-token lifetime to bite — far too long
    for 'log out my stolen laptop'. Every authenticated request checks this key.

    TTL is the access-token lifetime plus a margin: after that no token bearing this
    session id can still verify, so the entry is dead weight.
    """
    await get_redis().setex(
        revoked_session_key(session_id), settings.access_token_ttl_seconds + 60, "1"
    )


async def is_session_revoked(session_id: str) -> bool:
    return await get_redis().exists(revoked_session_key(session_id)) == 1
