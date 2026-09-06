"""Request dependencies: authentication, client IP, CSRF.

`current_user` deliberately does four things on every request rather than trusting the
token alone — signature check, cache check for revocation, database read of the user,
and an account-state check. A JWT proves only that we minted it; it does not prove the
session still exists or the account is still in good standing.
"""
from __future__ import annotations

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AccountUnavailable, NotAuthenticated, PermissionDenied
from app.core.logging import user_id_ctx
from app.core.security import InvalidToken, decode_access_token
from app.db.models import User
from app.db.session import get_db
from app.services.sessions import is_session_revoked

settings = get_settings()


def client_ip(request: Request) -> str | None:
    """Trust X-Forwarded-For only behind our own proxy, and take the left-most entry the
    proxy appended. Blindly trusting the header lets a caller forge any IP and defeat
    every IP-scoped rate limit."""
    if settings.is_production:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


class Principal:
    def __init__(self, user: User, session_id: str, device_id: str):
        self.user = user
        self.session_id = session_id
        self.device_id = device_id


async def current_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise NotAuthenticated()
    token = authorization.split(" ", 1)[1].strip()

    try:
        claims = decode_access_token(token)
    except InvalidToken:
        raise NotAuthenticated()

    session_id = claims.get("sid", "")
    if await is_session_revoked(session_id):
        # Revoked mid-token-lifetime. Without this check a logout would not take effect
        # for up to ten minutes.
        raise NotAuthenticated()

    user = await db.scalar(select(User).where(User.id == claims["sub"]))
    if user is None or user.deleted_at is not None:
        raise NotAuthenticated()
    if user.account_state in {"SUSPENDED", "DELETED"}:
        raise AccountUnavailable()

    user_id_ctx.set(str(user.id))
    request.state.principal = Principal(user, session_id, claims.get("did", ""))
    return request.state.principal


async def current_user(p: Principal = Depends(current_principal)) -> User:
    return p.user


async def require_csrf(request: Request) -> None:
    """Double-submit plus origin check, for the cookie-authenticated refresh endpoint.

    Bearer-token endpoints need neither, since a browser will not attach an
    Authorization header cross-site on its own. The refresh cookie is the one piece of
    ambient authority in the system, so it gets both defences.
    """
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not any(origin.startswith(o) for o in settings.allowed_origins):
        raise PermissionDenied("bad_origin")

    header_token = request.headers.get("x-csrf-token")
    cookie_token = request.cookies.get("csrf_token")
    if not header_token or not cookie_token or header_token != cookie_token:
        raise PermissionDenied("csrf_failed")
