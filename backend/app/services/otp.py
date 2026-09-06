"""Phone OTP issuance and verification.

The threat this file exists to defeat is an attacker who can send unlimited requests to
both endpoints. Every decision below follows from that:

* Requesting a code returns the same response whether or not an account exists. There is
  no "number not registered" branch anywhere, because that branch is a free subscriber
  enumeration oracle.
* The code is never stored. `code_hash = HMAC(pepper, challenge_id || code)` binds it to
  one challenge, so a code observed for challenge A cannot be replayed against a
  concurrent challenge B for the same number.
* Verification compares digests in constant time and always burns an attempt, including
  when the challenge has already expired. Returning early on expiry leaks, through
  timing, which challenges are live.
* Issuing a new code invalidates every outstanding one for that number. Otherwise an
  attacker who triggers ten resends gets ten simultaneously valid codes and ten times
  the guessing surface.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core import ratelimit
from app.core.security import (
    constant_time_equal, hash_otp, numeric_otp, phone_fingerprint, sha256,
)
from app.db.models import OtpChallenge
from app.services.audit import record_security
from app.services.sms import send_sms

log = get_logger("otp")
settings = get_settings()


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    expires_at: datetime


async def issue_challenge(
    db: AsyncSession, *, phone_e164: str, ip: str | None, user_agent: str | None
) -> Challenge:
    """Always succeeds from the caller's point of view unless rate limited. Never
    reveals account existence."""
    fingerprint = phone_fingerprint(phone_e164)
    identity = fingerprint.hex()

    # Two independent budgets. A composite key would let an attacker rotate IPs to
    # reset the per-number budget, which is the whole point of having a per-number one.
    await ratelimit.enforce("otp:request:phone", identity)
    if ip:
        await ratelimit.enforce("otp:request:ip", ip)

    # Supersede outstanding challenges so only one code is ever live per number.
    await db.execute(
        update(OtpChallenge)
        .where(OtpChallenge.phone_hash == fingerprint,
               OtpChallenge.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )

    challenge_id = uuid.uuid4()
    code = numeric_otp(6)
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.otp_ttl_seconds)

    db.add(OtpChallenge(
        id=challenge_id,
        phone_hash=fingerprint,
        code_hash=hash_otp(str(challenge_id), code),
        max_attempts=settings.otp_max_attempts,
        request_ip=ip,
        user_agent_hash=sha256(user_agent) if user_agent else None,
        expires_at=expires_at,
    ))
    await db.commit()

    # The only place the plaintext code exists is this call. It is never logged and
    # never returned through the API, in any environment.
    await send_sms(phone_e164, code)

    log.info("otp_issued", challenge_id=str(challenge_id))
    return Challenge(str(challenge_id), expires_at)


class OtpResult:
    OK = "ok"
    INVALID = "invalid"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


async def verify_challenge(
    db: AsyncSession, *, challenge_id: str, code: str, phone_e164: str, ip: str | None
) -> tuple[str, bool]:
    """Returns (result, consumed). The caller maps every failure mode onto one identical
    client-facing error — the distinction here is for the security log, not the user."""
    fingerprint = phone_fingerprint(phone_e164)
    await ratelimit.enforce("otp:verify:phone", fingerprint.hex())
    if ip:
        await ratelimit.enforce("otp:verify:ip", ip)

    try:
        cid = uuid.UUID(challenge_id)
    except ValueError:
        return OtpResult.INVALID, False

    challenge = await db.scalar(
        select(OtpChallenge)
        .where(OtpChallenge.id == cid, OtpChallenge.phone_hash == fingerprint)
        .with_for_update()
    )
    if challenge is None:
        return OtpResult.INVALID, False

    now = datetime.now(UTC)

    # Burn an attempt before any other check. Cheap early exits are a timing oracle for
    # which challenges are still live.
    challenge.attempts += 1
    supplied = hash_otp(str(challenge.id), code)
    matches = constant_time_equal(challenge.code_hash, supplied)

    if challenge.consumed_at is not None:
        await db.commit()
        await record_security(db, event="otp_replay_attempt", user_id=None, ip=ip,
                              detail={"challenge_id": challenge_id})
        return OtpResult.INVALID, False

    if challenge.expires_at <= now:
        await db.commit()
        return OtpResult.EXPIRED, False

    if challenge.attempts > challenge.max_attempts:
        challenge.consumed_at = now   # burn it; further guessing is pointless
        await db.commit()
        await record_security(db, event="otp_attempts_exhausted", ip=ip,
                              detail={"challenge_id": challenge_id})
        return OtpResult.EXHAUSTED, False

    if not matches:
        await db.commit()
        await record_security(db, event="otp_invalid", severity="INFO", ip=ip,
                              detail={"attempt": challenge.attempts})
        return OtpResult.INVALID, False

    # Single use: consumed in the same transaction that validated it, so two concurrent
    # requests carrying the same code cannot both win. The row lock above serializes them.
    challenge.consumed_at = now
    await db.commit()
    return OtpResult.OK, True
