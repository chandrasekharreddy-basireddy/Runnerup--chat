"""Message persistence and fan-out.

The send path is the hottest and most security-sensitive route in the system, so the
ordering of its steps is deliberate:

    authorize -> validate -> rate limit -> idempotency -> transaction -> publish

Publishing happens strictly after commit. Publishing first would let a recipient see a
message that a rolled-back transaction never actually stored — a phantom the sender
could never retrieve on reconnect.

Sequence numbers come from `next_conversation_seq()`, which allocates under a row lock.
That makes ordering total and independent of client clocks, which are wrong, adversarial
or both.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotVisible, PermissionDenied, ValidationFailed
from app.core.logging import get_logger
from app.core import ratelimit
from app.db.models import (
    Attachment, ConversationEvent, ConversationMember, Message,
    MessageEdit, MessageMention, MessageReaction, User,
)
from app.services.authz import (
    Access, Permission, can_delete_message, can_modify_message,
)
from app.ws.manager import publish_to_conversation

log = get_logger("messages")

MAX_BODY_CHARS = 8192
MAX_ATTACHMENTS = 10
EDIT_WINDOW_SECONDS = 48 * 3600

# Mentions are parsed server-side from the body. Accepting a client-supplied mention list
# would let a sender notify people who were never actually mentioned — a spam vector that
# bypasses the notification preferences of everyone in the conversation.
_MENTION_PATTERN = re.compile(r"@([a-z0-9_]{3,32})", re.IGNORECASE)


@dataclass
class SendResult:
    message: Message
    created: bool          # False when idempotency returned the original


def _validate_body(body: str | None, kind: str, attachment_ids: list[str]) -> str | None:
    if kind == "TEXT":
        if not body or not body.strip():
            raise ValidationFailed("empty_message")
    if body is not None:
        if len(body) > MAX_BODY_CHARS:
            raise ValidationFailed("message_too_long")
        # Strip control characters except tab and newline. They serve no purpose in a
        # message and are a classic vector for spoofing rendered output — a right-to-left
        # override can make a link's visible text disagree with its target.
        body = "".join(c for c in body if c in "\t\n" or ord(c) >= 32)
        body = body.replace("\u202e", "").replace("\u202d", "")
    if len(attachment_ids) > MAX_ATTACHMENTS:
        raise ValidationFailed("too_many_attachments")
    return body


async def _resolve_mentions(db: AsyncSession, conversation_id: uuid.UUID,
                            body: str | None) -> list[uuid.UUID]:
    """Only members can be mentioned. Mentioning a non-member would leak the existence
    of a private conversation to someone outside it via their notification feed."""
    if not body:
        return []
    handles = {m.group(1).lower() for m in _MENTION_PATTERN.finditer(body)}
    if not handles:
        return []
    rows = await db.execute(
        select(User.id).join(
            ConversationMember, ConversationMember.user_id == User.id
        ).where(
            func.lower(User.username).in_(handles),
            ConversationMember.conversation_id == conversation_id,
            ConversationMember.left_at.is_(None),
            ConversationMember.state != "BANNED",
        )
    )
    return [row[0] for row in rows]


async def send_message(
    db: AsyncSession, *, access: Access, client_msg_id: str, body: str | None,
    kind: str = "TEXT", reply_to_id: str | None = None,
    attachment_ids: list[str] | None = None, origin_connection: str | None = None,
) -> SendResult:
    access.require(Permission.SEND_MESSAGE)
    attachment_ids = attachment_ids or []
    body = _validate_body(body, kind, attachment_ids)

    try:
        idempotency_key = uuid.UUID(client_msg_id)
    except (ValueError, AttributeError):
        raise ValidationFailed("invalid_client_msg_id")

    user, conversation = access.user, access.conversation

    # Idempotency check before the rate limiter, so a client retrying after a timeout is
    # not punished for a message the server already accepted.
    existing = await db.scalar(select(Message).where(
        Message.conversation_id == conversation.id,
        Message.sender_id == user.id,
        Message.client_msg_id == idempotency_key,
    ))
    if existing is not None:
        return SendResult(existing, created=False)

    await ratelimit.enforce("message:send:user", str(user.id))
    await ratelimit.enforce("message:send:conv", str(conversation.id))

    if reply_to_id:
        # Scoped to this conversation. A reply target from elsewhere is rejected here and
        # again by a database trigger.
        parent = await db.scalar(select(Message).where(
            Message.id == reply_to_id,
            Message.conversation_id == conversation.id,
            Message.deleted_at.is_(None),
        ))
        if parent is None:
            raise ValidationFailed("invalid_reply_target")

    attachments: list[Attachment] = []
    if attachment_ids:
        rows = await db.scalars(select(Attachment).where(
            Attachment.id.in_(attachment_ids),
            Attachment.owner_id == user.id,        # only your own uploads
            Attachment.message_id.is_(None),       # not already attached elsewhere
            Attachment.state == "READY",           # scanned and validated
        ))
        attachments = list(rows)
        if len(attachments) != len(set(attachment_ids)):
            raise ValidationFailed("invalid_attachments")

    seq = await db.scalar(text("SELECT next_conversation_seq(:cid)"),
                          {"cid": str(conversation.id)})

    message = Message(
        conversation_id=conversation.id, seq=seq, sender_id=user.id, kind=kind,
        body=body, client_msg_id=idempotency_key,
        reply_to_id=uuid.UUID(reply_to_id) if reply_to_id else None,
        created_at=datetime.now(UTC),          # server clock, always
    )
    db.add(message)

    try:
        await db.flush()
    except IntegrityError:
        # Two concurrent retries of the same client_msg_id: the unique constraint caught
        # the loser. Return the winner rather than surfacing an error.
        await db.rollback()
        existing = await db.scalar(select(Message).where(
            Message.conversation_id == conversation.id,
            Message.sender_id == user.id,
            Message.client_msg_id == idempotency_key,
        ))
        if existing is not None:
            return SendResult(existing, created=False)
        raise

    for attachment in attachments:
        attachment.message_id = message.id
        attachment.conversation_id = conversation.id

    for mentioned_id in await _resolve_mentions(db, conversation.id, body):
        db.add(MessageMention(message_id=message.id, user_id=mentioned_id))

    payload = _serialize(message, attachments)
    db.add(ConversationEvent(
        conversation_id=conversation.id, seq=seq, type="message.created",
        payload=payload, actor_id=user.id,
    ))

    await db.commit()

    # Only now, after durability is guaranteed.
    await publish_to_conversation(
        str(conversation.id),
        {"type": "message.created", "conversation_id": str(conversation.id),
         "message": payload},
        origin_connection=origin_connection,
    )
    return SendResult(message, created=True)


async def edit_message(db: AsyncSession, *, access: Access, message: Message,
                       body: str) -> Message:
    if not can_modify_message(access, message):
        raise PermissionDenied()

    age = (datetime.now(UTC) - message.created_at).total_seconds()
    if age > EDIT_WINDOW_SECONDS:
        # An unbounded edit window lets someone rewrite history long after others have
        # acted on what was said.
        raise PermissionDenied("edit_window_expired")

    await ratelimit.enforce("message:edit:user", str(access.user.id))
    body = _validate_body(body, message.kind, [])

    # Prior versions are retained: an edit trail is what makes moderation of an edited
    # message possible at all.
    db.add(MessageEdit(message_id=message.id, previous_body=message.body,
                       edited_by=access.user.id))
    message.body = body
    message.edited_at = datetime.now(UTC)
    message.edit_count += 1

    seq = await db.scalar(text("SELECT next_conversation_seq(:cid)"),
                          {"cid": str(message.conversation_id)})
    payload = _serialize(message, [])
    db.add(ConversationEvent(conversation_id=message.conversation_id, seq=seq,
                             type="message.edited", payload=payload,
                             actor_id=access.user.id))
    await db.commit()

    await publish_to_conversation(str(message.conversation_id), {
        "type": "message.edited", "conversation_id": str(message.conversation_id),
        "message": payload})
    return message


async def delete_message(db: AsyncSession, *, access: Access, message: Message) -> None:
    if not can_delete_message(access, message):
        raise PermissionDenied()

    # Soft delete. A hard delete would tear a hole in the sequence and break the sync
    # cursor for every client that had not yet caught up.
    message.deleted_at = datetime.now(UTC)
    message.deleted_by = access.user.id
    message.body = None                       # content genuinely goes

    seq = await db.scalar(text("SELECT next_conversation_seq(:cid)"),
                          {"cid": str(message.conversation_id)})
    payload = {"id": str(message.id), "deleted": True,
               "by_moderator": message.sender_id != access.user.id}
    db.add(ConversationEvent(conversation_id=message.conversation_id, seq=seq,
                             type="message.deleted", payload=payload,
                             actor_id=access.user.id))
    await db.commit()

    await publish_to_conversation(str(message.conversation_id), {
        "type": "message.deleted", "conversation_id": str(message.conversation_id),
        **payload})


async def list_messages(db: AsyncSession, *, access: Access, before_seq: int | None,
                        after_seq: int | None, limit: int) -> list[dict]:
    """Cursor pagination on `seq`. Offset pagination would drift as messages arrive and
    would let a caller walk an entire conversation with `offset=0&limit=1000000`."""
    access.require(Permission.READ_MESSAGES)
    limit = max(1, min(limit, 100))

    query = select(Message).where(Message.conversation_id == access.conversation.id)
    if before_seq is not None:
        query = query.where(Message.seq < before_seq).order_by(Message.seq.desc())
    elif after_seq is not None:
        query = query.where(Message.seq > after_seq).order_by(Message.seq.asc())
    else:
        query = query.order_by(Message.seq.desc())

    rows = list(await db.scalars(query.limit(limit)))
    return [_serialize(m, []) for m in rows]


async def search_messages(db: AsyncSession, *, user: User, query_text: str,
                          conversation_id: str | None, limit: int = 30) -> list[dict]:
    """Search is constrained to conversations the caller is currently a member of.

    The membership join is part of the query, not a filter applied to its results. That
    distinction matters: a post-filter still executes the search across everything and
    leaks timing and resource signals about conversations the caller cannot see.
    """
    await ratelimit.enforce("search:user", str(user.id))
    if len(query_text.strip()) < 2:
        raise ValidationFailed("query_too_short")

    member_conversations = select(ConversationMember.conversation_id).where(
        ConversationMember.user_id == user.id,
        ConversationMember.left_at.is_(None),
        ConversationMember.state != "BANNED",
    )
    if conversation_id:
        member_conversations = member_conversations.where(
            ConversationMember.conversation_id == conversation_id)

    statement = (
        select(Message)
        .where(
            Message.conversation_id.in_(member_conversations),
            Message.deleted_at.is_(None),
            Message.search_tsv.op("@@")(func.plainto_tsquery("simple", query_text)),
        )
        .order_by(Message.seq.desc())
        .limit(min(limit, 50))
    )
    return [_serialize(m, []) for m in await db.scalars(statement)]


async def mark_read(db: AsyncSession, *, access: Access, up_to_seq: int) -> None:
    """Read state is a high-water mark per member, not a row per message. Writing one
    receipt per message in a busy group is a write amplification trap."""
    membership = access.membership
    if membership is None:
        raise NotVisible()
    if up_to_seq <= membership.last_read_seq:
        return

    membership.last_read_seq = min(up_to_seq, access.conversation.last_seq)
    await db.commit()

    await publish_to_conversation(str(access.conversation.id), {
        "type": "receipt.read", "conversation_id": str(access.conversation.id),
        "user_id": str(access.user.id), "up_to_seq": membership.last_read_seq})


async def toggle_reaction(db: AsyncSession, *, access: Access, message: Message,
                          emoji: str) -> bool:
    access.require(Permission.SEND_MESSAGE)
    if len(emoji) > 16:
        raise ValidationFailed("invalid_emoji")

    existing = await db.scalar(select(MessageReaction).where(
        MessageReaction.message_id == message.id,
        MessageReaction.user_id == access.user.id,
        MessageReaction.emoji == emoji,
    ))
    if existing is not None:
        await db.delete(existing)
        added = False
    else:
        db.add(MessageReaction(message_id=message.id, user_id=access.user.id, emoji=emoji))
        added = True
    await db.commit()

    await publish_to_conversation(str(message.conversation_id), {
        "type": "reaction.changed", "conversation_id": str(message.conversation_id),
        "message_id": str(message.id), "user_id": str(access.user.id),
        "emoji": emoji, "added": added})
    return added


async def sync_events(db: AsyncSession, *, user: User, after_id: int,
                      limit: int = 200) -> tuple[list[dict], int]:
    """Replay everything the caller missed, scoped to current membership.

    The `created_at` guard is not cosmetic. BIGSERIAL assigns ids before commit, so a
    slow writer can commit id 100 after id 101 is already visible. A client that read up
    to 101 would skip 100 permanently. Holding back events younger than one second — far
    longer than the 8s statement timeout allows a write to stay open — closes that race.
    """
    member_conversations = select(ConversationMember.conversation_id).where(
        ConversationMember.user_id == user.id,
        ConversationMember.left_at.is_(None),
        ConversationMember.state != "BANNED",
    )
    rows = list(await db.execute(
        select(ConversationEvent)
        .where(
            ConversationEvent.id > after_id,
            ConversationEvent.conversation_id.in_(member_conversations),
            ConversationEvent.created_at < func.now() - text("interval '1 second'"),
        )
        .order_by(ConversationEvent.id.asc())
        .limit(limit)
    ))
    events = [r[0] for r in rows]
    cursor = events[-1].id if events else after_id
    return ([{"event_id": e.id, "type": e.type,
              "conversation_id": str(e.conversation_id), "payload": e.payload}
             for e in events], cursor)


def _serialize(message: Message, attachments: list[Attachment]) -> dict:
    return {
        "id": str(message.id),
        "seq": message.seq,
        "conversation_id": str(message.conversation_id),
        "sender_id": str(message.sender_id) if message.sender_id else None,
        "kind": message.kind,
        # Raw text. Escaping is the renderer's job — escaping here would double-encode
        # for any non-HTML client and hide the real content from moderation review.
        "body": message.body,
        "client_msg_id": str(message.client_msg_id),
        "reply_to_id": str(message.reply_to_id) if message.reply_to_id else None,
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "deleted": message.deleted_at is not None,
        "created_at": message.created_at.isoformat(),
        "attachments": [
            {"id": str(a.id), "name": a.display_name, "size": a.byte_size,
             "mime": a.detected_mime, "width": a.width, "height": a.height,
             "duration_ms": a.duration_ms}
            for a in attachments
        ],
    }
