"""The authorization layer. Every read and write in the system passes through here.

Two invariants hold everywhere below:

1. Nothing is trusted from the client except opaque identifiers. Roles, membership and
   permissions are always re-read from the database on the request that uses them. A
   role baked into a JWT at login would keep working after a demotion; that gap is
   exactly what an attacker waits for.

2. A caller who is not permitted to *see* a resource gets `NotVisible` (404), not
   `PermissionDenied` (403). Distinguishing the two turns any endpoint into an oracle
   for which conversation ids exist.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AccountUnavailable, NotVisible, PermissionDenied
from app.db.models import (
    BlockedUser, Conversation, ConversationMember, DirectConversationKey, Message, User,
)


class Permission(StrEnum):
    SEND_MESSAGE = "SEND_MESSAGE"
    READ_MESSAGES = "READ_MESSAGES"
    EDIT_OWN_MESSAGE = "EDIT_OWN_MESSAGE"
    DELETE_OWN_MESSAGE = "DELETE_OWN_MESSAGE"
    DELETE_ANY_MESSAGE = "DELETE_ANY_MESSAGE"
    PIN_MESSAGE = "PIN_MESSAGE"
    ADD_MEMBER = "ADD_MEMBER"
    REMOVE_MEMBER = "REMOVE_MEMBER"
    BAN_MEMBER = "BAN_MEMBER"
    MANAGE_CONVERSATION = "MANAGE_CONVERSATION"
    MANAGE_INVITES = "MANAGE_INVITES"
    MANAGE_ROLES = "MANAGE_ROLES"
    TRANSFER_OWNERSHIP = "TRANSFER_OWNERSHIP"
    VIEW_REPORTS = "VIEW_REPORTS"
    MODERATE_CONTENT = "MODERATE_CONTENT"
    MANAGE_USERS = "MANAGE_USERS"
    MANAGE_SYSTEM = "MANAGE_SYSTEM"


# Ordered weakest to strongest. Used to compare a member's role against a
# conversation's configurable policy thresholds (send_policy, pin_policy, ...).
_ROLE_RANK = {"SUBSCRIBER": 0, "MEMBER": 1, "MODERATOR": 2, "ADMIN": 3, "OWNER": 4}

_ROLE_GRANTS: dict[str, set[Permission]] = {
    "SUBSCRIBER": {Permission.READ_MESSAGES},
    "MEMBER": {
        Permission.READ_MESSAGES, Permission.SEND_MESSAGE,
        Permission.EDIT_OWN_MESSAGE, Permission.DELETE_OWN_MESSAGE,
    },
    "MODERATOR": {
        Permission.READ_MESSAGES, Permission.SEND_MESSAGE,
        Permission.EDIT_OWN_MESSAGE, Permission.DELETE_OWN_MESSAGE,
        Permission.DELETE_ANY_MESSAGE, Permission.PIN_MESSAGE,
    },
    "ADMIN": {
        Permission.READ_MESSAGES, Permission.SEND_MESSAGE,
        Permission.EDIT_OWN_MESSAGE, Permission.DELETE_OWN_MESSAGE,
        Permission.DELETE_ANY_MESSAGE, Permission.PIN_MESSAGE,
        Permission.ADD_MEMBER, Permission.REMOVE_MEMBER, Permission.BAN_MEMBER,
        Permission.MANAGE_CONVERSATION, Permission.MANAGE_INVITES,
    },
    "OWNER": set(Permission) - {
        Permission.VIEW_REPORTS, Permission.MODERATE_CONTENT,
        Permission.MANAGE_USERS, Permission.MANAGE_SYSTEM,
    },
}

# System roles grant platform-wide capability. Note they do NOT grant SEND_MESSAGE or
# READ_MESSAGES: a global admin does not silently gain the ability to read every private
# conversation. Reading private content for moderation goes through an explicit,
# separately audited path (see services/moderation.py), never through this function.
_SYSTEM_GRANTS: dict[str, set[Permission]] = {
    "USER": set(),
    "MODERATOR": {Permission.VIEW_REPORTS, Permission.MODERATE_CONTENT},
    "ADMIN": {Permission.VIEW_REPORTS, Permission.MODERATE_CONTENT, Permission.MANAGE_USERS},
    "SUPER_ADMIN": {Permission.VIEW_REPORTS, Permission.MODERATE_CONTENT,
                    Permission.MANAGE_USERS, Permission.MANAGE_SYSTEM},
}

_POLICY_FOR_PERMISSION = {
    Permission.SEND_MESSAGE: "send_policy",
    Permission.PIN_MESSAGE: "pin_policy",
    Permission.ADD_MEMBER: "invite_policy",
    Permission.MANAGE_INVITES: "invite_policy",
    Permission.MANAGE_CONVERSATION: "edit_info_policy",
}


@dataclass(frozen=True)
class Access:
    """The resolved answer to 'what may this user do in this conversation, right now'."""
    user: User
    conversation: Conversation
    membership: ConversationMember | None
    permissions: frozenset[Permission]

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.can(permission):
            raise PermissionDenied()

    @property
    def role(self) -> str | None:
        return self.membership.role if self.membership else None


async def resolve_access(
    db: AsyncSession, user: User, conversation_id: uuid.UUID | str
) -> Access:
    """Load the conversation and compute the caller's effective permission set.

    Raises NotVisible if the conversation does not exist, is deleted, or the caller is
    not entitled to know about it. From outside, those three cases are identical.
    """
    if not user.is_usable:
        raise AccountUnavailable()

    conversation = await db.scalar(
        select(Conversation).where(
            Conversation.id == conversation_id, Conversation.deleted_at.is_(None)
        )
    )
    if conversation is None:
        raise NotVisible()

    membership = await db.scalar(
        select(ConversationMember).where(
            ConversationMember.conversation_id == conversation.id,
            ConversationMember.user_id == user.id,
        )
    )

    now = datetime.now(UTC)
    granted: set[Permission] = set()

    if membership is not None and membership.left_at is None:
        if membership.state == "BANNED":
            # A banned member must not learn the conversation still exists.
            raise NotVisible()
        granted |= _ROLE_GRANTS.get(membership.role, set())

        # Temporary restrictions strip write capability without removing membership.
        muted = membership.muted_until and membership.muted_until > now
        restricted = membership.restricted_until and membership.restricted_until > now
        if membership.state in {"MUTED", "RESTRICTED"} or muted or restricted:
            granted -= {Permission.SEND_MESSAGE, Permission.EDIT_OWN_MESSAGE,
                        Permission.PIN_MESSAGE, Permission.ADD_MEMBER}

        # Per-conversation policy thresholds narrow what the role would otherwise allow.
        rank = _ROLE_RANK.get(membership.role, 0)
        for permission, policy_field in _POLICY_FOR_PERMISSION.items():
            required = _ROLE_RANK.get(getattr(conversation, policy_field), 4)
            if rank < required:
                granted.discard(permission)

    elif conversation.visibility == "PUBLIC":
        # Non-members may read a public channel and nothing else.
        granted.add(Permission.READ_MESSAGES)
    else:
        raise NotVisible()

    if conversation.is_archived:
        granted -= {Permission.SEND_MESSAGE, Permission.EDIT_OWN_MESSAGE}

    # Blocking has to be enforced here, not only when a chat is created. Checking it
    # only at creation left an existing conversation fully usable after a block, which
    # is precisely the harassment path blocking exists to close. Reads are left intact
    # so neither party loses their history; writes are what stop.
    if conversation.kind == "DIRECT" and granted & {Permission.SEND_MESSAGE}:
        counterpart = await _direct_counterpart(db, conversation.id, user.id)
        if counterpart is not None:
            blocked_them, blocked_by_them = await blocking_state(db, user.id, counterpart)
            if blocked_them or blocked_by_them:
                granted -= {
                    Permission.SEND_MESSAGE, Permission.EDIT_OWN_MESSAGE,
                    Permission.PIN_MESSAGE,
                }

    granted |= _SYSTEM_GRANTS.get(user.system_role, set())
    return Access(user, conversation, membership, frozenset(granted))


async def _direct_counterpart(
    db: AsyncSession, conversation_id: uuid.UUID, user_id: uuid.UUID
) -> uuid.UUID | None:
    """The other participant in a direct chat, via the ordered-pair key."""
    row = await db.execute(
        select(DirectConversationKey.user_lo, DirectConversationKey.user_hi)
        .where(DirectConversationKey.conversation_id == conversation_id)
    )
    pair = row.first()
    if pair is None:
        return None
    lo, hi = pair
    return hi if lo == user_id else lo


async def require_permission(
    db: AsyncSession, user: User, conversation_id: uuid.UUID | str, permission: Permission
) -> Access:
    access = await resolve_access(db, user, conversation_id)
    access.require(permission)
    return access


async def resolve_message_access(
    db: AsyncSession, user: User, message_id: uuid.UUID | str
) -> tuple[Message, Access]:
    """Never fetch a message by id alone. The conversation it belongs to decides
    whether the caller may see it — this is the fix for the IDOR class of bug."""
    message = await db.scalar(select(Message).where(Message.id == message_id))
    if message is None:
        raise NotVisible()
    access = await resolve_access(db, user, message.conversation_id)
    access.require(Permission.READ_MESSAGES)
    return message, access


def can_modify_message(access: Access, message: Message) -> bool:
    if message.deleted_at is not None:
        return False
    if message.sender_id == access.user.id:
        return access.can(Permission.EDIT_OWN_MESSAGE)
    return False


def can_delete_message(access: Access, message: Message) -> bool:
    if message.sender_id == access.user.id and access.can(Permission.DELETE_OWN_MESSAGE):
        return True
    return access.can(Permission.DELETE_ANY_MESSAGE)


# ------------------------------------------------------------------- blocking
async def blocking_state(
    db: AsyncSession, a: uuid.UUID, b: uuid.UUID
) -> tuple[bool, bool]:
    """Returns (a_blocked_b, b_blocked_a). Both directions matter: the blocker must not
    receive from the blocked user, and the blocked user must not be able to reach the
    blocker by initiating a new chat."""
    rows = await db.execute(
        select(BlockedUser.blocker_id, BlockedUser.blocked_id).where(
            ((BlockedUser.blocker_id == a) & (BlockedUser.blocked_id == b))
            | ((BlockedUser.blocker_id == b) & (BlockedUser.blocked_id == a))
        )
    )
    a_blocked_b = b_blocked_a = False
    for blocker, blocked in rows:
        if blocker == a and blocked == b:
            a_blocked_b = True
        if blocker == b and blocked == a:
            b_blocked_a = True
    return a_blocked_b, b_blocked_a


async def assert_can_direct_message(db: AsyncSession, sender: User, recipient_id: uuid.UUID) -> None:
    """Blocking is enforced on the write path, not just hidden in the reader's UI.
    A blocked sender's message must never reach persistence, or it would sync to the
    blocker's other devices."""
    blocked_them, blocked_by_them = await blocking_state(db, sender.id, recipient_id)
    if blocked_them or blocked_by_them:
        # Identical error either way: the sender learns nothing about being blocked.
        raise NotVisible()


async def require_system_permission(user: User, permission: Permission) -> None:
    if permission not in _SYSTEM_GRANTS.get(user.system_role, set()):
        raise PermissionDenied()
