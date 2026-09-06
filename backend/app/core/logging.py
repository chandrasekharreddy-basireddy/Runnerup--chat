"""Structured JSON logging with a request-scoped correlation id.

The redaction processor is the important part: it is a hard backstop against a future
`log.info("otp", code=...)` shipping a credential to a log aggregator. Keys on the
denylist are dropped, not masked, so nothing partial survives either.
"""
import logging
import sys
from contextvars import ContextVar

import structlog

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")
user_id_ctx: ContextVar[str | None] = ContextVar("user_id", default=None)

# Never emitted, at any level, in any environment.
_FORBIDDEN_KEYS = {
    "otp", "otp_code", "code", "access_token", "refresh_token", "token",
    "authorization", "cookie", "set-cookie", "password", "secret", "api_key",
    "s3_secret_key", "invite_token", "phone", "phone_e164", "mfa_secret",
    "push_endpoint", "body", "message_body",
}


def _redact(_logger, _method, event_dict: dict) -> dict:
    for key in list(event_dict):
        if key.lower() in _FORBIDDEN_KEYS:
            event_dict[key] = "[redacted]"
    return event_dict


def _add_context(_logger, _method, event_dict: dict) -> dict:
    event_dict["request_id"] = request_id_ctx.get()
    uid = user_id_ctx.get()
    if uid:
        event_dict["user_id"] = uid
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout,
                        level=getattr(logging, level.upper(), logging.INFO))
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _add_context,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "app"):
    return structlog.get_logger(name)
