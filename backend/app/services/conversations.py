"""Conversation creation, membership and invite links."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotVisible, PermissionDenied, ValidationFailed
from app.core import ratelimit
from app.core.security import random_token, sha256
from app.db.models import (
    Conversation, ConversationMember, DirectConversationKey, InviteLink, User,
)
from app.services.audit import record_audit
from app.services.authz import Access, Permission, assert_can_direct_message, resolve_access


async def get_or_create_direct(db: AsyncSession, *, user: User,
                               other_id: uuid.UUID) -> Conversation:
    """Direct chats are keyed by the ordered participant pair, so two people opening a
    chat with each other simultaneously converge on one conversation instead of two."""
    if other_id == user.id:
        raise ValidationFailed("cannot_message_self")

    other = await db.scalar(select(User).where(User.id == other_id))
    if other is None or not other.is_usable:
        raise NotVisible()

    # Blocking is enforced before the conversation exists, not after.
    await assert_can_direct_message(db, user, other_id)

    lo, hi = sorted([user.id, other_id], key=str)
    existing = await db.scalar(
        select(Conversation)
        .join(DirectConversationKey,
              DirectConversationKey.conversation_id == Conversation.id)
        .where(DirectConversationKey.user_lo == lo, DirectConversationKey.user_hi == hi)
    )
    if existing is not None:
        return existing

    conversation = Conversation(kind="DIRECT", visibility="PRIVATE",
                                created_by=user.id, member_limit=2)
    db.add(conversation)
    await db.flush()

    db.add(DirectConversationKey(conversation_id=conversation.id, user_lo=lo, user_hi=hi))
    for member_id in (user.id, other_id):
        db.add(ConversationMember(conversation_id=conversation.id,
                                  user_id=member_id, role="MEMBER"))
    try:
        await db.commit()
    except IntegrityError:
        # Lost the race; the unique pair constraint held. Take the winner's row.
        await db.rollback()
        return await db.scalar(
            select(Conversation)
            .join(DirectConversationKey,
                  DirectConversationKey.conversation_id == Conversation.id)
            .where(DirectConversationKey.user_lo == lo,
                   DirectConversationKey.user_hi == hi)
        )
    return conversation


async def create_group(db: AsyncSession, *, user: User, title: str, kind: str = "GROUP",
                       visibility: str = "PRIVATE", slug: str | None = None,
                       member_ids: list[uuid.UUID] | None = None) -> Conversation:
    await ratelimit.enforce("conversation:create:user", str(user.id))

    if not title.strip() or len(title) > 128:
        raise ValidationFailed("invalid_title")
    if visibility == "PUBLIC" and not slug:
        raise ValidationFailed("public_requires_slug")

    conversation = Conversation(
        kind=kind, visibility=visibility, title=title.strip(), slug=slug,
        created_by=user.id,
        # Channels default to broadcast: only elevated roles may post.
        send_policy="ADMIN" if kind == "CHANNEL" else "MEMBER",
    )
    db.add(conversation)
    await db.flush()

    db.add(ConversationMember(conversation_id=conversation.id, user_id=user.id,
                              role="OWNER"))

    # Adding people to a group without consent is a spam vector, so only users who have
    # not blocked the creator can be seeded in.
    for member_id in (member_ids or [])[:200]:
        if member_id == user.id:
            continue
        try:
            await assert_can_direct_message(db, user, member_id)
        except NotVisible:
            continue
        db.add(ConversationMember(
            conversation_id=conversation.id, user_id=member_id,
            role="SUBSCRIBER" if kind == "CHANNEL" else "MEMBER",
            invited_by=user.id))

    await record_audit(db, action="conversation.created", actor_id=user.id,
                       actor_role=user.system_role, target_type="conversation",
                       target_id=str(conversation.id),
                       metadata={"kind": kind, "visibility": visibility})
    await db.commit()
    return conversation


async def list_for_user(db: AsyncSession, *, user: User, limit: int = 100) -> list[dict]:
    rows = await db.execute(
        select(Conversation, ConversationMember)
        .join(ConversationMember,
              ConversationMember.conversation_id == Conversation.id)
        .where(ConversationMember.user_id == user.id,
               ConversationMember.left_at.is_(None),
               ConversationMember.state != "BANNED",
               Conversation.deleted_at.is_(None))
        .order_by(Conversation.updated_at.desc())
        .limit(limit)
    )
    return [
        {"id": str(c.id), "kind": c.kind, "visibility": c.visibility,
         "title": c.title, "slug": c.slug, "last_seq": c.last_seq,
         "unread": max(0, c.last_seq - m.last_read_seq),
         "role": m.role, "muted": m.notify_policy == "MUTED"}
        for c, m in rows
    ]


async def add_member(db: AsyncSession, *, access: Access, new_member_id: uuid.UUID,
                     role: str = "MEMBER") -> None:
    access.require(Permission.ADD_MEMBER)
    if role in {"OWNER"}:
        raise PermissionDenied("cannot_grant_owner")

    count = await db.scalar(select(func.count()).select_from(ConversationMember).where(
        ConversationMember.conversation_id == access.conversation.id,
        ConversationMember.left_at.is_(None)))
    if count >= access.conversation.member_limit:
        raise ValidationFailed("member_limit_reached")

    existing = await db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == access.conversation.id,
        ConversationMember.user_id == new_member_id))

    if existing is not None:
        if existing.state == "BANNED":
            # Re-adding a banned user would silently undo a moderation decision.
            raise PermissionDenied("user_is_banned")
        existing.left_at = None
        existing.state = "ACTIVE"
    else:
        db.add(ConversationMember(conversation_id=access.conversation.id,
                                  user_id=new_member_id, role=role,
                                  invited_by=access.user.id))

    await record_audit(db, action="conversation.member_added", actor_id=access.user.id,
                       target_type="conversation", target_id=str(access.conversation.id),
                       metadata={"member": str(new_member_id), "role": role})
    await db.commit()


async def change_role(db: AsyncSession, *, access: Access, member_id: uuid.UUID,
                      new_role: str) -> None:
    """Privilege escalation guard: you can never grant a role at or above your own.
    Without this an ADMIN could promote themselves or a confederate to OWNER."""
    access.require(Permission.MANAGE_ROLES)
    from app.services.authz import _ROLE_RANK

    actor_rank = _ROLE_RANK.get(access.role or "", 0)
    target_rank = _ROLE_RANK.get(new_role, 99)
    if target_rank >= actor_rank:
        raise PermissionDenied("cannot_grant_equal_or_higher_role")

    membership = await db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == access.conversation.id,
        ConversationMember.user_id == member_id))
    if membership is None:
        raise NotVisible()
    if _ROLE_RANK.get(membership.role, 0) >= actor_rank:
        raise PermissionDenied("cannot_modify_peer_or_superior")

    membership.role = new_role
    await record_audit(db, action="conversation.role_changed", actor_id=access.user.id,
                       target_type="conversation", target_id=str(access.conversation.id),
                       metadata={"member": str(member_id), "role": new_role})
    await db.commit()


async def create_invite(db: AsyncSession, *, access: Access, max_uses: int | None,
                        expires_in_seconds: int | None,
                        requires_approval: bool = False) -> str:
    """Returns the plaintext token exactly once. Only its digest is stored, so a database
    read yields no usable invite links."""
    access.require(Permission.MANAGE_INVITES)
    await ratelimit.enforce("invite:create:user", str(access.user.id))

    token = random_token(24)          # ~192 bits: not enumerable, unlike /invite/123
    expires_at = None
    if expires_in_seconds:
        expires_at = datetime.now(UTC).timestamp() + expires_in_seconds
        expires_at = datetime.fromtimestamp(expires_at, UTC)

    db.add(InviteLink(conversation_id=access.conversation.id, token_hash=sha256(token),
                      created_by=access.user.id, max_uses=max_uses,
                      requires_approval=requires_approval, expires_at=expires_at))
    await record_audit(db, action="invite.created", actor_id=access.user.id,
                       target_type="conversation",
                       target_id=str(access.conversation.id),
                       metadata={"max_uses": max_uses})
    await db.commit()
    return token


async def redeem_invite(db: AsyncSession, *, user: User, token: str) -> Conversation:
    invite = await db.scalar(
        select(InviteLink).where(InviteLink.token_hash == sha256(token)).with_for_update()
    )
    now = datetime.now(UTC)
    # One error for every failure: an invalid token and an exhausted one are
    # indistinguishable, so a guesser learns nothing from the difference.
    if (invite is None or invite.revoked_at is not None
            or (invite.expires_at and invite.expires_at <= now)
            or (invite.max_uses is not None and invite.use_count >= invite.max_uses)):
        raise NotVisible()

    membership = await db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == invite.conversation_id,
        ConversationMember.user_id == user.id))
    if membership is not None and membership.state == "BANNED":
        raise NotVisible()

    conversation = await db.scalar(select(Conversation).where(
        Conversation.id == invite.conversation_id, Conversation.deleted_at.is_(None)))
    if conversation is None:
        raise NotVisible()

    if membership is None:
        db.add(ConversationMember(
            conversation_id=conversation.id, user_id=user.id,
            role="SUBSCRIBER" if conversation.kind == "CHANNEL" else "MEMBER"))
    else:
        membership.left_at = None
        membership.state = "ACTIVE"

    invite.use_count += 1
    await record_audit(db, action="invite.redeemed", actor_id=user.id,
                       target_type="conversation", target_id=str(conversation.id))
    await db.commit()
    return conversation
