"""Primitives: token minting, hashing, constant-time comparison, phone handling.

Design notes that matter:

* Refresh tokens are opaque 256-bit random values, not JWTs. They must be revocable
  instantly, and a self-contained token cannot be. Only their SHA-256 digest is stored.
* Phone numbers are keyed by HMAC, not by a plain hash. An unkeyed hash of an E.164
  number is trivially reversible — the search space is a few billion — so the pepper is
  what actually protects the number.
* OTP codes are compared in constant time on their digest, never on the plaintext.
"""
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import phonenumbers
from jose import JWTError, jwt

from app.core.config import get_settings

ALGORITHM = "HS256"


# ----------------------------------------------------------------- random values
def random_token(nbytes: int = 32) -> str:
    """URL-safe high-entropy token. Used for refresh tokens, invite links, WS tickets.
    Never use a counter or a uuid4 string where this function belongs."""
    return secrets.token_urlsafe(nbytes)


def numeric_otp(digits: int = 6) -> str:
    """Uniform over the full range, including leading zeros. `secrets.randbelow` avoids
    the modulo bias that `random.randint`-style code introduces."""
    return f"{secrets.randbelow(10 ** digits):0{digits}d}"


# ------------------------------------------------------------------- hashing
def sha256(value: str | bytes) -> bytes:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).digest()


def hmac_digest(value: str, *, pepper: str | None = None) -> bytes:
    key = (pepper or get_settings().otp_pepper).encode()
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def hash_otp(challenge_id: str, code: str) -> bytes:
    """Binding the code to its challenge id means a code captured for one challenge
    cannot be replayed against a different concurrent challenge for the same number."""
    return hmac_digest(f"{challenge_id}:{code}")


# ------------------------------------------------------------------ phone numbers
class InvalidPhoneNumber(ValueError):
    pass


def normalize_phone(raw: str, default_region: str | None = None) -> str:
    """Canonical E.164. Normalizing before hashing is what stops '+91 98765 43210' and
    '+919876543210' from becoming two accounts."""
    try:
        parsed = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as exc:
        raise InvalidPhoneNumber(str(exc)) from exc
    if not phonenumbers.is_valid_number(parsed):
        raise InvalidPhoneNumber("not a valid number")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def phone_fingerprint(e164: str) -> bytes:
    return hmac_digest(f"phone:{e164}")


def phone_display_parts(e164: str) -> tuple[str, str]:
    parsed = phonenumbers.parse(e164, None)
    return str(parsed.country_code), e164[-4:]


# --------------------------------------------------------------- access tokens
def mint_access_token(*, user_id: str, session_id: str, device_id: str,
                      system_role: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "sid": session_id,
        "did": device_id,
        "role": system_role,      # a hint for UI affordances only
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        "iss": "chat-api",
        "typ": "access",
    }
    return jwt.encode(payload, settings.jwt_signing_key, algorithm=ALGORITHM)


class InvalidToken(Exception):
    pass


def decode_access_token(token: str) -> dict[str, Any]:
    """Returns claims if the signature and expiry hold.

    The `role` claim is deliberately *not* trusted for authorization anywhere. Every
    permission decision re-reads the role from the database, because a token minted
    before a demotion would otherwise keep working until it expired.
    """
    try:
        claims = jwt.decode(token, get_settings().jwt_signing_key,
                            algorithms=[ALGORITHM], issuer="chat-api")
    except JWTError as exc:
        raise InvalidToken(str(exc)) from exc
    if claims.get("typ") != "access":
        raise InvalidToken("wrong token type")
    return claims
