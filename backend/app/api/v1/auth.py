"""Authentication routes.

The uniform-response rule runs through everything here: request-otp gives the same shape
and the same latency profile for a brand-new number as for an existing account, and
verify-otp collapses invalid, expired and exhausted into one client-facing error. The
distinctions live in the security log where they belong.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, client_ip, current_principal, require_csrf
from app.core.config import get_settings
from app.core.errors import NotAuthenticated, ValidationFailed
from app.core.logging import get_logger
from app.core import ratelimit
from app.core.security import (
    InvalidPhoneNumber, normalize_phone, phone_display_parts, phone_fingerprint,
)
from app.db.models import User, UserDevice, UserSession
from app.db.session import get_db
from app.schemas.auth import (
    DeviceOut, OtpRequestIn, OtpRequestOut, OtpVerifyIn, SessionOut,
)
from app.services import otp as otp_service
from app.services import sessions as session_service
from app.services.audit import record_audit, record_security

router = APIRouter(prefix="/auth", tags=["auth"])
log = get_logger("auth")
settings = get_settings()

REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"


def _device_label(user_agent: str | None) -> str:
    """A coarse, server-derived label. The raw user agent is never stored or echoed —
    it is a fingerprinting surface and it is attacker-controlled text that would end up
    rendered in the device list."""
    ua = (user_agent or "").lower()
    browser = next((b for b in ("firefox", "edg", "chrome", "safari") if b in ua), None)
    system = next((s for s in ("windows", "android", "iphone", "ipad", "mac", "linux") if s in ua), None)
    names = {"edg": "Edge", "chrome": "Chrome", "safari": "Safari", "firefox": "Firefox"}
    systems = {"windows": "Windows", "android": "Android", "iphone": "iPhone",
               "ipad": "iPad", "mac": "macOS", "linux": "Linux"}
    if browser and system:
        return f"{names[browser]} on {systems[system]}"
    return systems.get(system or "", "Unknown device")


def _set_auth_cookies(response: Response, refresh_token: str) -> str:
    """The refresh token lives in an HttpOnly cookie scoped to the refresh path only, so
    XSS cannot read it and it is not attached to any other request. The CSRF token is
    readable by script on purpose — that is what makes double-submit work."""
    csrf = secrets.token_urlsafe(24)
    response.set_cookie(
        REFRESH_COOKIE, refresh_token,
        httponly=True, secure=settings.cookie_secure, samesite="strict",
        path="/api/v1/auth", max_age=settings.refresh_token_ttl_seconds,
    )
    response.set_cookie(
        CSRF_COOKIE, csrf,
        httponly=False, secure=settings.cookie_secure, samesite="strict",
        path="/", max_age=settings.refresh_token_ttl_seconds,
    )
    return csrf


@router.post("/otp/request", response_model=OtpRequestOut)
async def request_otp(payload: OtpRequestIn, request: Request,
                      db: AsyncSession = Depends(get_db)):
    try:
        phone = normalize_phone(payload.phone, payload.region)
    except InvalidPhoneNumber:
        raise ValidationFailed("invalid_phone")

    challenge = await otp_service.issue_challenge(
        db, phone_e164=phone, ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    # Same response for a known and an unknown number. No account lookup happens above,
    # so not even the timing differs.
    return OtpRequestOut(challenge_id=challenge.challenge_id,
                         expires_in=settings.otp_ttl_seconds)


@router.post("/otp/verify", response_model=SessionOut)
async def verify_otp(payload: OtpVerifyIn, request: Request, response: Response,
                     db: AsyncSession = Depends(get_db)):
    try:
        phone = normalize_phone(payload.phone, payload.region)
    except InvalidPhoneNumber:
        raise ValidationFailed("invalid_phone")

    result, consumed = await otp_service.verify_challenge(
        db, challenge_id=payload.challenge_id, code=payload.code,
        phone_e164=phone, ip=client_ip(request),
    )
    if not consumed:
        # One error for every failure mode. Telling the caller "expired" versus
        # "incorrect" hands them a free signal about which codes were ever real.
        raise NotAuthenticated("verification_failed")

    fingerprint = phone_fingerprint(phone)
    user = await db.scalar(select(User).where(User.phone_hash == fingerprint))
    is_new = user is None

    if is_new:
        country, last4 = phone_display_parts(phone)
        user = User(
            phone_hash=fingerprint, phone_last4=last4, phone_country=country,
            display_name=f"User {last4}",
        )
        db.add(user)
        await db.flush()
        await record_audit(db, action="user.registered", actor_id=user.id,
                           target_type="user", target_id=str(user.id),
                           ip=client_ip(request))
    elif not user.is_usable:
        await record_security(db, event="login_blocked_account_state",
                              user_id=user.id, ip=client_ip(request),
                              detail={"state": user.account_state})
        await db.commit()
        raise NotAuthenticated("verification_failed")

    tokens = await session_service.create_session(
        db, user=user, platform=payload.platform,
        device_label=_device_label(request.headers.get("user-agent")),
        ip=client_ip(request),
    )
    _set_auth_cookies(response, tokens.refresh_token)

    # The access token is returned in the body and held in memory by the client only.
    # It is never written to localStorage, where any XSS would harvest it.
    return SessionOut(
        access_token=tokens.access_token, expires_in=tokens.expires_in,
        user_id=str(user.id), display_name=user.display_name, is_new_account=is_new,
    )


@router.post("/refresh", response_model=SessionOut, dependencies=[Depends(require_csrf)])
async def refresh(request: Request, response: Response,
                  db: AsyncSession = Depends(get_db)):
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        raise NotAuthenticated()

    ip = client_ip(request)
    await ratelimit.enforce("auth:refresh:ip", ip or "unknown")

    try:
        tokens = await session_service.rotate_session(db, presented_refresh=presented, ip=ip)
    except session_service.RefreshRejected as exc:
        # On reuse detection the family is already dead. Clear the cookie so the client
        # stops replaying a token that will never work again.
        response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
        log.info("refresh_rejected", reason=exc.reason)
        raise NotAuthenticated("reauthentication_required")

    _set_auth_cookies(response, tokens.refresh_token)
    return SessionOut(
        access_token=tokens.access_token, expires_in=tokens.expires_in,
        user_id=str(tokens.user_id), display_name=tokens.display_name,
        is_new_account=False,
    )


@router.post("/logout")
async def logout(request: Request, response: Response,
                 principal: Principal = Depends(current_principal),
                 db: AsyncSession = Depends(get_db)):
    import uuid as _uuid
    await session_service.revoke_session(
        db, session_id=_uuid.UUID(principal.session_id),
        user_id=principal.user.id, reason="user_logout")
    await record_audit(db, action="session.logout", actor_id=principal.user.id,
                       target_type="session", target_id=principal.session_id,
                       ip=client_ip(request))
    await db.commit()
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    return {"status": "ok"}


@router.post("/logout-all")
async def logout_all(request: Request, response: Response,
                     principal: Principal = Depends(current_principal),
                     db: AsyncSession = Depends(get_db)):
    count = await session_service.revoke_all_for_user(
        db, user_id=principal.user.id, reason="user_logout_all")
    await record_audit(db, action="session.logout_all", actor_id=principal.user.id,
                       target_type="user", target_id=str(principal.user.id),
                       ip=client_ip(request), metadata={"revoked": count})
    await db.commit()
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    return {"status": "ok", "revoked": count}


@router.get("/devices", response_model=list[DeviceOut])
async def list_devices(principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(
        select(UserDevice)
        .where(UserDevice.user_id == principal.user.id, UserDevice.revoked_at.is_(None))
        .order_by(UserDevice.last_active_at.desc())
    )
    # IP addresses are held for security review but not surfaced here; a device list is
    # a common shoulder-surfing target and the location adds nothing the owner needs.
    return [
        DeviceOut(id=str(d.id), platform=d.platform, label=d.display_label,
                  created_at=d.created_at.isoformat(),
                  last_active_at=d.last_active_at.isoformat(),
                  is_current=str(d.id) == principal.device_id)
        for d in rows
    ]


@router.delete("/devices/{device_id}")
async def revoke_device(device_id: str, request: Request,
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    import uuid as _uuid
    try:
        target = _uuid.UUID(device_id)
    except ValueError:
        raise ValidationFailed("invalid_device_id")

    # Scoped to the caller's own devices. An id belonging to someone else finds nothing.
    device = await db.scalar(select(UserDevice).where(
        UserDevice.id == target, UserDevice.user_id == principal.user.id))
    if device is None:
        return {"status": "ok"}     # no existence signal

    device.revoked_at = datetime.now(UTC)
    revoked = await db.scalars(select(UserSession).where(
        UserSession.device_id == device.id, UserSession.revoked_at.is_(None)))
    for session in revoked:
        await session_service.revoke_family(db, session.family_id, reason="device_revoked")

    await record_audit(db, action="device.revoked", actor_id=principal.user.id,
                       target_type="device", target_id=device_id, ip=client_ip(request))
    await db.commit()
    return {"status": "ok"}
