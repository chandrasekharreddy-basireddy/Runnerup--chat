"""SQLAlchemy mappings over the schema in migrations/0001_init.sql.

The SQL file is authoritative — constraints, triggers and the sequence function live
there, not here. These classes are a typed access layer, deliberately thin. Anything
security-relevant is enforced by the database as well as by the application, so a bug in
one layer is not sufficient on its own.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Index,
    Integer, LargeBinary, SmallInteger, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())


TS = DateTime(timezone=True)

SystemRole = Enum("USER", "MODERATOR", "ADMIN", "SUPER_ADMIN", name="system_role", create_type=False)
AccountState = Enum("ACTIVE", "RESTRICTED", "SUSPENDED", "DELETED", name="account_state", create_type=False)
ConversationKind = Enum("DIRECT", "GROUP", "CHANNEL", name="conversation_kind", create_type=False)
Visibility = Enum("PRIVATE", "PUBLIC", name="conversation_visibility", create_type=False)
MemberRole = Enum("OWNER", "ADMIN", "MODERATOR", "MEMBER", "SUBSCRIBER", name="member_role", create_type=False)
MemberState = Enum("ACTIVE", "MUTED", "RESTRICTED", "BANNED", "LEFT", name="member_state", create_type=False)
MessageKind = Enum("TEXT", "IMAGE", "VIDEO", "AUDIO", "VOICE", "FILE", "SYSTEM", name="message_kind", create_type=False)
ReceiptKind = Enum("DELIVERED", "READ", name="receipt_kind", create_type=False)
AttachmentState = Enum("PENDING", "SCANNING", "READY", "REJECTED", name="attachment_state", create_type=False)
ReportReason = Enum("SPAM", "HARASSMENT", "SCAM", "ABUSE", "ILLEGAL_CONTENT", "IMPERSONATION", "OTHER", name="report_reason", create_type=False)
ReportState = Enum("OPEN", "TRIAGED", "ACTIONED", "DISMISSED", name="report_state", create_type=False)
PreviewPolicy = Enum("SHOW_PREVIEW", "HIDE_PREVIEW", "MENTIONS_ONLY", "MUTED", name="preview_policy", create_type=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = _uuid_pk()
    # The plaintext number is never persisted. Lookup is by keyed digest only.
    phone_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    phone_last4: Mapped[str] = mapped_column(Text, nullable=False)
    phone_country: Mapped[str] = mapped_column(Text, nullable=False)
    username: Mapped[str | None] = mapped_column(Text, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    avatar_key: Mapped[str | None] = mapped_column(Text)
    bio: Mapped[str | None] = mapped_column(Text)
    system_role: Mapped[str] = mapped_column(SystemRole, nullable=False, default="USER")
    account_state: Mapped[str] = mapped_column(AccountState, nullable=False, default="ACTIVE")
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(TS)
    presence_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_scope: Mapped[str] = mapped_column(Text, default="CONTACTS")
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    deleted_at: Mapped[dt.datetime | None] = mapped_column(TS)

    @property
    def is_usable(self) -> bool:
        return self.account_state == "ACTIVE" and self.deleted_at is None


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[uuid.UUID] = _uuid_pk()
    phone_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    code_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    max_attempts: Mapped[int] = mapped_column(SmallInteger, default=5)
    request_ip: Mapped[str | None] = mapped_column(INET)
    user_agent_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    consumed_at: Mapped[dt.datetime | None] = mapped_column(TS)
    expires_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class UserDevice(Base):
    __tablename__ = "user_devices"
    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    platform: Mapped[str] = mapped_column(Text, nullable=False)
    display_label: Mapped[str] = mapped_column(Text, nullable=False)
    ip_first_seen: Mapped[str | None] = mapped_column(INET)
    ip_last_seen: Mapped[str | None] = mapped_column(INET)
    push_token_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    last_active_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TS)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_devices.id", ondelete="CASCADE"))
    # All rotations of one login share a family. Reuse anywhere kills the family.
    family_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    refresh_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    previous_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("user_sessions.id", ondelete="SET NULL"))
    rotated_at: Mapped[dt.datetime | None] = mapped_column(TS)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TS)
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    last_used_at: Mapped[dt.datetime | None] = mapped_column(TS)


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[uuid.UUID] = _uuid_pk()
    kind: Mapped[str] = mapped_column(ConversationKind, nullable=False)
    visibility: Mapped[str] = mapped_column(Visibility, nullable=False, default="PRIVATE")
    slug: Mapped[str | None] = mapped_column(Text, unique=True)
    title: Mapped[str | None] = mapped_column(Text)
    topic: Mapped[str | None] = mapped_column(Text)
    avatar_key: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    last_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    send_policy: Mapped[str] = mapped_column(MemberRole, default="MEMBER")
    invite_policy: Mapped[str] = mapped_column(MemberRole, default="ADMIN")
    pin_policy: Mapped[str] = mapped_column(MemberRole, default="ADMIN")
    edit_info_policy: Mapped[str] = mapped_column(MemberRole, default="ADMIN")
    member_limit: Mapped[int] = mapped_column(Integer, default=512)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    deleted_at: Mapped[dt.datetime | None] = mapped_column(TS)


class DirectConversationKey(Base):
    __tablename__ = "direct_conversation_keys"
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True)
    user_lo: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    user_hi: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))


class ConversationMember(Base):
    __tablename__ = "conversation_members"
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(MemberRole, default="MEMBER")
    state: Mapped[str] = mapped_column(MemberState, default="ACTIVE")
    muted_until: Mapped[dt.datetime | None] = mapped_column(TS)
    restricted_until: Mapped[dt.datetime | None] = mapped_column(TS)
    last_read_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    notify_policy: Mapped[str] = mapped_column(PreviewPolicy, default="SHOW_PREVIEW")
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    joined_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    left_at: Mapped[dt.datetime | None] = mapped_column(TS)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[uuid.UUID] = _uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sender_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(MessageKind, default="TEXT")
    body: Mapped[str | None] = mapped_column(Text)
    client_msg_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    reply_to_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="SET NULL"))
    thread_root_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="SET NULL"))
    forwarded_from: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="SET NULL"))
    edited_at: Mapped[dt.datetime | None] = mapped_column(TS)
    edit_count: Mapped[int] = mapped_column(SmallInteger, default=0)
    deleted_at: Mapped[dt.datetime | None] = mapped_column(TS)
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("conversation_id", "seq"),
        UniqueConstraint("conversation_id", "sender_id", "client_msg_id"),
    )


class MessageReceipt(Base):
    __tablename__ = "message_receipts"
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(ReceiptKind, primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class MessageReaction(Base):
    __tablename__ = "message_reactions"
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    emoji: Mapped[str] = mapped_column(Text, primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class MessageMention(Base):
    __tablename__ = "message_mentions"
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class MessageEdit(Base):
    __tablename__ = "message_edits"
    id: Mapped[uuid.UUID] = _uuid_pk()
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    previous_body: Mapped[str | None] = mapped_column(Text)
    edited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    edited_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class PinnedMessage(Base):
    __tablename__ = "pinned_messages"
    conversation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True)
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    pinned_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    pinned_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[uuid.UUID] = _uuid_pk()
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    message_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    storage_key: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detected_mime: Mapped[str] = mapped_column(Text, nullable=False)
    declared_mime: Mapped[str | None] = mapped_column(Text)
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    checksum_sha256: Mapped[bytes | None] = mapped_column(LargeBinary)
    state: Mapped[str] = mapped_column(AttachmentState, default="PENDING")
    scan_verdict: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    finalized_at: Mapped[dt.datetime | None] = mapped_column(TS)


class InviteLink(Base):
    __tablename__ = "invite_links"
    id: Mapped[uuid.UUID] = _uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    max_uses: Mapped[int | None] = mapped_column(Integer)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(TS)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TS)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class BlockedUser(Base):
    __tablename__ = "blocked_users"
    blocker_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    blocked_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[uuid.UUID] = _uuid_pk()
    reporter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    subject_type: Mapped[str] = mapped_column(Text, nullable=False)
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    subject_message_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    subject_conversation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(ReportReason, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(ReportState, default="OPEN")
    handled_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    handled_at: Mapped[dt.datetime | None] = mapped_column(TS)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    message_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    read_at: Mapped[dt.datetime | None] = mapped_column(TS)
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class ConversationEvent(Base):
    __tablename__ = "conversation_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    conversation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_role: Mapped[str | None] = mapped_column(SystemRole)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(INET)
    audit_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(TS, server_default=func.now())
    event: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, default="WARNING")
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    session_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    device_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
