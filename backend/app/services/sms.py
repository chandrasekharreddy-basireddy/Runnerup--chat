"""SMS delivery.

The console provider exists so development never needs a real SMS account. It prints to
stdout, which is acceptable only because it refuses to run when ENVIRONMENT=production —
a console OTP provider in production would put live codes into the log pipeline.
"""
from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("sms")


async def send_sms(phone_e164: str, code: str) -> None:
    settings = get_settings()

    if settings.sms_provider == "console":
        if settings.is_production:
            raise RuntimeError("console SMS provider must never run in production")
        print(f"[dev-sms] {phone_e164} -> {code}", flush=True)
        return

    # Real provider. Note the code is passed in the request body and never logged;
    # only the delivery outcome is recorded.
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://api.twilio.com/2010-04-01/Messages.json",
                auth=(settings.sms_sender_id, settings.sms_api_key),
                data={"To": phone_e164, "From": settings.sms_sender_id,
                      "Body": f"{code} is your verification code."},
            )
        log.info("sms_dispatched", status=response.status_code)
    except httpx.HTTPError as exc:
        # Deliberately not re-raised with detail: a provider failure must not tell the
        # caller anything about the number's validity.
        log.error("sms_failed", error=type(exc).__name__)
        raise RuntimeError("sms_dispatch_failed") from exc
