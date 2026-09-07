"""Attachment routes: grant an upload, then validate it before it can be sent."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal
from app.core.errors import NotVisible, ValidationFailed
from app.core import ratelimit
from app.db.models import Attachment
from app.db.session import get_db
from app.services import storage
from app.services.authz import Permission, resolve_access

router = APIRouter(tags=["attachments"])


class UploadRequest(BaseModel):
    conversation_id: str
    filename: str = Field(min_length=1, max_length=255)
    mime: str = Field(min_length=3, max_length=100)
    size: int = Field(gt=0)


@router.post("/uploads")
async def request_upload(payload: UploadRequest,
                         principal: Principal = Depends(current_principal),
                         db: AsyncSession = Depends(get_db)):
    """Authorization happens before a URL is minted. A presigned URL is a capability —
    handing one out to a non-member would let them write into our bucket."""
    try:
        conversation_id = uuid.UUID(payload.conversation_id)
    except ValueError:
        raise ValidationFailed("invalid_conversation")

    access = await resolve_access(db, principal.user, conversation_id)
    access.require(Permission.SEND_MESSAGE)
    await ratelimit.enforce("upload:init:user", str(principal.user.id))

    grant = await storage.create_upload_grant(
        owner_id=principal.user.id,
        declared_name=payload.filename,
        declared_mime=payload.mime,
        declared_size=payload.size,
    )

    db.add(Attachment(
        id=uuid.UUID(grant.attachment_id),
        owner_id=principal.user.id,
        conversation_id=conversation_id,
        storage_key=grant.storage_key,
        display_name=storage.sanitize_filename(payload.filename),
        byte_size=payload.size,          # provisional; replaced by the observed size
        detected_mime="application/octet-stream",
        declared_mime=payload.mime,
        state="PENDING",
    ))
    await db.commit()

    return {
        "attachment_id": grant.attachment_id,
        "upload_url": grant.upload_url,
        "expires_in": grant.expires_in,
        # The storage key is deliberately not returned. The client never needs it, and
        # exposing the layout invites probing.
    }


@router.post("/uploads/{attachment_id}/finalize")
async def finalize_upload(attachment_id: str,
                          principal: Principal = Depends(current_principal),
                          db: AsyncSession = Depends(get_db)):
    """Read the object back and decide what it really is.

    A file that fails this check is deleted from storage and marked REJECTED, so a
    rejected upload cannot sit in the bucket waiting to be referenced by some other
    path later.
    """
    try:
        target = uuid.UUID(attachment_id)
    except ValueError:
        raise ValidationFailed("invalid_attachment")

    attachment = await db.scalar(select(Attachment).where(
        Attachment.id == target,
        Attachment.owner_id == principal.user.id,   # only your own upload
    ))
    if attachment is None:
        raise NotVisible()
    if attachment.state == "READY":
        return {"state": "READY", "attachment_id": attachment_id}

    probe = await storage.probe_object(attachment.storage_key)

    if probe.detected_mime is None:
        attachment.state = "REJECTED"
        attachment.scan_verdict = "unrecognized_content"
        await db.commit()
        await storage.delete_object(attachment.storage_key)
        raise ValidationFailed("file_type_not_allowed")

    # The declared type is compared against the observed one but never overrides it.
    # A mismatch is worth recording: it is a strong signal of a deliberate attempt.
    if attachment.declared_mime != probe.detected_mime:
        attachment.scan_verdict = f"declared_{attachment.declared_mime}_actual_{probe.detected_mime}"

    attachment.byte_size = probe.byte_size
    attachment.detected_mime = probe.detected_mime
    attachment.state = "READY"
    attachment.finalized_at = datetime.now(UTC)
    await db.commit()

    return {"state": "READY", "attachment_id": attachment_id,
            "mime": probe.detected_mime, "size": probe.byte_size}


@router.get("/attachments/{attachment_id}/url")
async def download_url(attachment_id: str,
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    """Membership is re-checked on every download. A link shared outside the
    conversation is useless: the URL expires in minutes and the endpoint that mints it
    requires an authorized session."""
    try:
        target = uuid.UUID(attachment_id)
    except ValueError:
        raise ValidationFailed("invalid_attachment")

    attachment = await db.scalar(select(Attachment).where(Attachment.id == target))
    if attachment is None or attachment.state != "READY":
        raise NotVisible()

    if attachment.conversation_id is None:
        if attachment.owner_id != principal.user.id:
            raise NotVisible()
    else:
        access = await resolve_access(db, principal.user, attachment.conversation_id)
        access.require(Permission.READ_MESSAGES)

    url = await storage.signed_download_url(attachment.storage_key,
                                            display_name=attachment.display_name)
    return {"url": url, "expires_in": 300, "name": attachment.display_name,
            "mime": attachment.detected_mime, "size": attachment.byte_size}
