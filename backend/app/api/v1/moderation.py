"""Reporting and moderation.

Reports are private to their reporter and to staff. A user must never be able to read
another user's reports, or discover that they have been reported — both would make
reporting unsafe for the person doing it.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal
from app.core.errors import NotVisible, PermissionDenied, ValidationFailed
from app.core import ratelimit
from app.db.models import (
    BlockedUser, ConversationMember, Message, Report, User,
)
from app.db.session import get_db
from app.services.audit import record_audit
from app.services.authz import Permission, require_system_permission

router = APIRouter(tags=["moderation"])

REASONS = {"SPAM", "HARASSMENT", "SCAM", "ABUSE", "ILLEGAL_CONTENT", "IMPERSONATION", "OTHER"}


class ReportIn(BaseModel):
    subject_type: str = Field(pattern="^(USER|MESSAGE|CONVERSATION)$")
    subject_id: str
    reason: str
    detail: str | None = Field(default=None, max_length=2000)


class BlockIn(BaseModel):
    user_id: str


class ResolveIn(BaseModel):
    state: str = Field(pattern="^(TRIAGED|ACTIONED|DISMISSED)$")
    resolution: str | None = Field(default=None, max_length=1000)


@router.post("/reports")
async def create_report(payload: ReportIn,
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    if payload.reason not in REASONS:
        raise ValidationFailed("invalid_reason")
    # Report flooding is itself an abuse vector — used to bury a moderation queue or to
    # harass through repeated notifications.
    await ratelimit.enforce("report:create:user", str(principal.user.id))

    try:
        subject = uuid.UUID(payload.subject_id)
    except ValueError:
        raise ValidationFailed("invalid_subject")

    report = Report(reporter_id=principal.user.id, subject_type=payload.subject_type,
                    reason=payload.reason, detail=payload.detail)

    if payload.subject_type == "MESSAGE":
        # You can only report a message you could legitimately see. Otherwise the
        # report endpoint becomes an oracle for whether an arbitrary message id exists.
        from app.services.authz import resolve_message_access
        message, _ = await resolve_message_access(db, principal.user, subject)
        report.subject_message_id = message.id
        report.subject_conversation_id = message.conversation_id
    elif payload.subject_type == "CONVERSATION":
        from app.services.authz import resolve_access
        access = await resolve_access(db, principal.user, subject)
        report.subject_conversation_id = access.conversation.id
    else:
        target = await db.scalar(select(User).where(User.id == subject))
        if target is None or target.id == principal.user.id:
            raise NotVisible()
        report.subject_user_id = target.id

    db.add(report)
    try:
        # Flush before anything else touches the session. A partial unique index allows
        # one open report per reporter per subject, and the violation surfaces here —
        # not at commit — because the audit write below would flush it for us anyway.
        await db.flush()
    except IntegrityError:
        # A repeat is not an error the user needs to hear about. Answering identically
        # avoids confirming that an earlier report exists, and a double-tap is far more
        # common than an attack.
        await db.rollback()
        return {"status": "received"}

    await record_audit(db, action="report.created", actor_id=principal.user.id,
                       target_type=payload.subject_type, target_id=str(subject))
    await db.commit()

    # No id is returned that could be probed, and the reported party is never notified.
    return {"status": "received"}


@router.post("/blocks")
async def block_user(payload: BlockIn,
                     principal: Principal = Depends(current_principal),
                     db: AsyncSession = Depends(get_db)):
    try:
        target = uuid.UUID(payload.user_id)
    except ValueError:
        raise ValidationFailed("invalid_user")
    if target == principal.user.id:
        raise ValidationFailed("cannot_block_self")

    existing = await db.scalar(select(BlockedUser).where(
        BlockedUser.blocker_id == principal.user.id, BlockedUser.blocked_id == target))
    if existing is None:
        db.add(BlockedUser(blocker_id=principal.user.id, blocked_id=target))
        await db.commit()
    # Idempotent and silent. The blocked user is never told.
    return {"status": "ok"}


@router.delete("/blocks/{user_id}")
async def unblock_user(user_id: str,
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    try:
        target = uuid.UUID(user_id)
    except ValueError:
        raise ValidationFailed("invalid_user")
    existing = await db.scalar(select(BlockedUser).where(
        BlockedUser.blocker_id == principal.user.id, BlockedUser.blocked_id == target))
    if existing is not None:
        await db.delete(existing)
        await db.commit()
    return {"status": "ok"}


@router.get("/blocks")
async def list_blocks(principal: Principal = Depends(current_principal),
                      db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(BlockedUser.blocked_id).where(
        BlockedUser.blocker_id == principal.user.id))
    return {"blocked": [str(r) for r in rows]}


# ------------------------------------------------------------------ staff only
@router.get("/admin/reports")
async def review_queue(state: str = Query(default="OPEN"),
                       limit: int = Query(default=50, ge=1, le=200),
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    await require_system_permission(principal.user, Permission.VIEW_REPORTS)

    rows = await db.scalars(
        select(Report).where(Report.state == state)
        .order_by(Report.created_at.asc()).limit(limit))
    # Message bodies are not included. Reviewing content is a separate, separately
    # audited action rather than something that happens by loading a list.
    return {"reports": [
        {"id": str(r.id), "subject_type": r.subject_type, "reason": r.reason,
         "detail": r.detail, "state": r.state,
         "created_at": r.created_at.isoformat()}
        for r in rows
    ]}


@router.post("/admin/reports/{report_id}")
async def resolve_report(report_id: str, payload: ResolveIn,
                         principal: Principal = Depends(current_principal),
                         db: AsyncSession = Depends(get_db)):
    await require_system_permission(principal.user, Permission.MODERATE_CONTENT)

    try:
        target = uuid.UUID(report_id)
    except ValueError:
        raise ValidationFailed("invalid_report")

    report = await db.scalar(select(Report).where(Report.id == target))
    if report is None:
        raise NotVisible()

    report.state = payload.state
    report.handled_by = principal.user.id
    report.resolution = payload.resolution
    report.handled_at = datetime.now(UTC)

    await record_audit(db, action="report.resolved", actor_id=principal.user.id,
                       actor_role=principal.user.system_role,
                       target_type="report", target_id=report_id,
                       metadata={"state": payload.state})
    await db.commit()
    return {"status": "ok"}


class SuspendIn(BaseModel):
    user_id: str
    reason: str = Field(min_length=3, max_length=500)
    days: int | None = Field(default=None, ge=1, le=3650)


@router.post("/admin/users/suspend")
async def suspend_user(payload: SuspendIn,
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    await require_system_permission(principal.user, Permission.MANAGE_USERS)

    try:
        target_id = uuid.UUID(payload.user_id)
    except ValueError:
        raise ValidationFailed("invalid_user")

    target = await db.scalar(select(User).where(User.id == target_id))
    if target is None:
        raise NotVisible()
    # A moderator cannot act on a peer or a superior. Without this, one compromised
    # admin account can disable every other admin and take the platform.
    rank = {"USER": 0, "MODERATOR": 1, "ADMIN": 2, "SUPER_ADMIN": 3}
    if rank[target.system_role] >= rank[principal.user.system_role]:
        raise PermissionDenied("cannot_action_peer_or_superior")

    target.account_state = "SUSPENDED"
    await record_audit(db, action="user.suspended", actor_id=principal.user.id,
                       actor_role=principal.user.system_role, target_type="user",
                       target_id=payload.user_id,
                       metadata={"reason": payload.reason, "days": payload.days})
    await db.commit()

    # Revoke every session so the suspension takes effect immediately rather than when
    # the current access token happens to expire.
    from app.services.sessions import revoke_all_for_user
    await revoke_all_for_user(db, user_id=target_id, reason="account_suspended")
    return {"status": "ok"}
