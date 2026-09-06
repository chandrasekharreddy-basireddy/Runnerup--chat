"""Audit and security event writers.

Kept separate from application logging on purpose. Structured logs go to a log
aggregator with a retention window; these two tables are durable evidence that survives
log rotation, and the `chat_app` role holds INSERT but not UPDATE or DELETE on them.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, request_id_ctx
from app.db.models import AuditLog, SecurityEvent

log = get_logger("audit")


async def record_audit(
    db: AsyncSession, *, action: str, actor_id: uuid.UUID | None = None,
    actor_role: str | None = None, target_type: str | None = None,
    target_id: str | None = None, ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    await db.execute(insert(AuditLog).values(
        actor_id=actor_id, actor_role=actor_role, action=action,
        target_type=target_type, target_id=target_id,
        request_id=request_id_ctx.get(), ip=ip, metadata=metadata or {},
    ))
    log.info("audit", action=action, target_type=target_type, target_id=target_id)


async def record_security(
    db: AsyncSession, *, event: str, severity: str = "WARNING",
    user_id: uuid.UUID | None = None, session_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None, ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    await db.execute(insert(SecurityEvent).values(
        event=event, severity=severity, user_id=user_id, session_id=session_id,
        device_id=device_id, ip=ip, request_id=request_id_ctx.get(),
        detail=detail or {},
    ))
    log.warning("security_event", event=event, severity=severity)
