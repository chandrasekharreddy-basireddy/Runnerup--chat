"""Conversation and message routes.

Every path parameter naming a resource goes through `resolve_access` before anything
else happens. There is no route below that fetches a row by id and returns it.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Principal, current_principal
from app.core.errors import ValidationFailed
from app.db.session import get_db
from app.services import conversations as conv_service
from app.services import messages as message_service
from app.services.authz import resolve_access, resolve_message_access

router = APIRouter(tags=["conversations"])


class CreateDirectIn(BaseModel):
    user_id: str


class CreateGroupIn(BaseModel):
    title: str = Field(min_length=1, max_length=128)
    kind: str = Field(default="GROUP", pattern="^(GROUP|CHANNEL)$")
    visibility: str = Field(default="PRIVATE", pattern="^(PRIVATE|PUBLIC)$")
    slug: str | None = Field(default=None, max_length=32)
    member_ids: list[str] = Field(default_factory=list, max_length=200)


class SendMessageIn(BaseModel):
    client_msg_id: str
    body: str | None = Field(default=None, max_length=8192)
    kind: str = Field(default="TEXT", pattern="^(TEXT|IMAGE|VIDEO|AUDIO|VOICE|FILE)$")
    reply_to_id: str | None = None
    attachment_ids: list[str] = Field(default_factory=list, max_length=10)


class EditMessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=8192)


class ReadIn(BaseModel):
    up_to_seq: int = Field(ge=0)


class InviteIn(BaseModel):
    max_uses: int | None = Field(default=None, ge=1, le=10000)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=2592000)
    requires_approval: bool = False


def _uuid(value: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise ValidationFailed(f"invalid_{field}")


@router.get("/conversations")
async def list_conversations(principal: Principal = Depends(current_principal),
                             db: AsyncSession = Depends(get_db)):
    return await conv_service.list_for_user(db, user=principal.user)


@router.post("/conversations/direct")
async def create_direct(payload: CreateDirectIn,
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    conversation = await conv_service.get_or_create_direct(
        db, user=principal.user, other_id=_uuid(payload.user_id, "user_id"))
    return {"id": str(conversation.id), "kind": conversation.kind}


@router.post("/conversations")
async def create_conversation(payload: CreateGroupIn,
                              principal: Principal = Depends(current_principal),
                              db: AsyncSession = Depends(get_db)):
    conversation = await conv_service.create_group(
        db, user=principal.user, title=payload.title, kind=payload.kind,
        visibility=payload.visibility, slug=payload.slug,
        member_ids=[_uuid(m, "member") for m in payload.member_ids],
    )
    return {"id": str(conversation.id), "kind": conversation.kind,
            "title": conversation.title}


@router.get("/conversations/{conversation_id}/messages")
async def list_messages(conversation_id: str,
                        before: int | None = Query(default=None, ge=0),
                        after: int | None = Query(default=None, ge=0),
                        limit: int = Query(default=50, ge=1, le=100),
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    access = await resolve_access(db, principal.user, _uuid(conversation_id, "conversation"))
    return {"messages": await message_service.list_messages(
        db, access=access, before_seq=before, after_seq=after, limit=limit)}


@router.post("/conversations/{conversation_id}/messages")
async def send_message(conversation_id: str, payload: SendMessageIn,
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    access = await resolve_access(db, principal.user, _uuid(conversation_id, "conversation"))
    result = await message_service.send_message(
        db, access=access, client_msg_id=payload.client_msg_id, body=payload.body,
        kind=payload.kind, reply_to_id=payload.reply_to_id,
        attachment_ids=payload.attachment_ids,
    )
    # 200 rather than 201 when idempotency returned the original: a retry is not a
    # new creation, and the client needs to be able to tell.
    return {"message": message_service._serialize(result.message, []),
            "created": result.created}


@router.patch("/messages/{message_id}")
async def edit_message(message_id: str, payload: EditMessageIn,
                       principal: Principal = Depends(current_principal),
                       db: AsyncSession = Depends(get_db)):
    message, access = await resolve_message_access(
        db, principal.user, _uuid(message_id, "message"))
    updated = await message_service.edit_message(db, access=access, message=message,
                                                 body=payload.body)
    return {"message": message_service._serialize(updated, [])}


@router.delete("/messages/{message_id}")
async def delete_message(message_id: str,
                         principal: Principal = Depends(current_principal),
                         db: AsyncSession = Depends(get_db)):
    message, access = await resolve_message_access(
        db, principal.user, _uuid(message_id, "message"))
    await message_service.delete_message(db, access=access, message=message)
    return {"status": "ok"}


@router.post("/messages/{message_id}/reactions/{emoji}")
async def toggle_reaction(message_id: str, emoji: str,
                          principal: Principal = Depends(current_principal),
                          db: AsyncSession = Depends(get_db)):
    message, access = await resolve_message_access(
        db, principal.user, _uuid(message_id, "message"))
    added = await message_service.toggle_reaction(db, access=access, message=message,
                                                  emoji=emoji)
    return {"added": added}


@router.post("/conversations/{conversation_id}/read")
async def mark_read(conversation_id: str, payload: ReadIn,
                    principal: Principal = Depends(current_principal),
                    db: AsyncSession = Depends(get_db)):
    access = await resolve_access(db, principal.user, _uuid(conversation_id, "conversation"))
    await message_service.mark_read(db, access=access, up_to_seq=payload.up_to_seq)
    return {"status": "ok"}


@router.get("/search")
async def search(q: str = Query(min_length=2, max_length=128),
                 conversation_id: str | None = None,
                 principal: Principal = Depends(current_principal),
                 db: AsyncSession = Depends(get_db)):
    return {"results": await message_service.search_messages(
        db, user=principal.user, query_text=q, conversation_id=conversation_id)}


@router.get("/sync")
async def sync(after: int = Query(default=0, ge=0),
               principal: Principal = Depends(current_principal),
               db: AsyncSession = Depends(get_db)):
    events, cursor = await message_service.sync_events(
        db, user=principal.user, after_id=after)
    return {"events": events, "cursor": cursor}


@router.post("/conversations/{conversation_id}/invites")
async def create_invite(conversation_id: str, payload: InviteIn,
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    access = await resolve_access(db, principal.user, _uuid(conversation_id, "conversation"))
    token = await conv_service.create_invite(
        db, access=access, max_uses=payload.max_uses,
        expires_in_seconds=payload.expires_in_seconds,
        requires_approval=payload.requires_approval,
    )
    # Shown once. There is no endpoint that can retrieve it again.
    return {"token": token}


@router.post("/invites/{token}/redeem")
async def redeem_invite(token: str,
                        principal: Principal = Depends(current_principal),
                        db: AsyncSession = Depends(get_db)):
    conversation = await conv_service.redeem_invite(db, user=principal.user, token=token)
    return {"conversation_id": str(conversation.id), "title": conversation.title}
