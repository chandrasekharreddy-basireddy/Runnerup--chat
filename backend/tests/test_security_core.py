"""Tests for the properties that would be silent, expensive failures.

These are not coverage-chasing tests. Each one pins a specific claim the README makes,
so if a refactor breaks the claim the build fails rather than the property quietly
disappearing.
"""
import uuid

import pytest

from app.core.security import (
    constant_time_equal, hash_otp, normalize_phone, numeric_otp, phone_fingerprint,
    random_token,
)
from app.services.authz import (
    Access, Permission, _ROLE_GRANTS, _SYSTEM_GRANTS, can_delete_message,
)


class FakeUser:
    def __init__(self, uid=None, role="USER"):
        self.id = uid or uuid.uuid4()
        self.system_role = role
        self.account_state = "ACTIVE"
        self.deleted_at = None

    @property
    def is_usable(self):
        return True


class FakeMessage:
    def __init__(self, sender_id, deleted=False):
        self.sender_id = sender_id
        self.deleted_at = "x" if deleted else None


def _access(user, permissions):
    return Access(user=user, conversation=object(), membership=None,
                  permissions=frozenset(permissions))


# ------------------------------------------------------------------ OTP hygiene
def test_otp_is_six_digits_and_zero_padded():
    for _ in range(500):
        code = numeric_otp(6)
        assert len(code) == 6 and code.isdigit()


def test_otp_uses_full_range_including_leading_zeros():
    # A generator using randint(100000, 999999) can never emit these. That silently
    # removes 10% of the keyspace and makes brute force meaningfully cheaper.
    codes = {numeric_otp(6) for _ in range(20000)}
    assert any(c.startswith("0") for c in codes)


def test_otp_hash_is_bound_to_its_challenge():
    code = "123456"
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    # Same code, different challenge, different digest: no cross-challenge replay.
    assert hash_otp(a, code) != hash_otp(b, code)


def test_otp_comparison_is_constant_time_helper():
    digest = hash_otp(str(uuid.uuid4()), "000000")
    assert constant_time_equal(digest, digest)
    assert not constant_time_equal(digest, hash_otp(str(uuid.uuid4()), "000000"))


# ------------------------------------------------------------------ phone handling
def test_phone_normalization_collapses_formatting():
    variants = ["+91 98765 43210", "+91-98765-43210", "+919876543210"]
    normalized = {normalize_phone(v) for v in variants}
    assert len(normalized) == 1, "formatting differences must not create separate accounts"


def test_phone_fingerprint_is_keyed_not_plain():
    e164 = "+919876543210"
    import hashlib
    assert phone_fingerprint(e164) != hashlib.sha256(e164.encode()).digest()


# ------------------------------------------------------------------ token entropy
def test_tokens_have_real_entropy():
    tokens = {random_token(32) for _ in range(5000)}
    assert len(tokens) == 5000
    assert all(len(t) >= 40 for t in tokens)


# ------------------------------------------------------------------ authorization
def test_system_admin_cannot_read_private_conversations():
    # A platform admin gets moderation powers, not a master key to every private chat.
    for role, grants in _SYSTEM_GRANTS.items():
        assert Permission.READ_MESSAGES not in grants
        assert Permission.SEND_MESSAGE not in grants


def test_subscriber_cannot_post_to_a_channel():
    assert Permission.SEND_MESSAGE not in _ROLE_GRANTS["SUBSCRIBER"]
    assert Permission.READ_MESSAGES in _ROLE_GRANTS["SUBSCRIBER"]


def test_member_cannot_delete_other_peoples_messages():
    user = FakeUser()
    access = _access(user, _ROLE_GRANTS["MEMBER"])
    assert not can_delete_message(access, FakeMessage(sender_id=uuid.uuid4()))
    assert can_delete_message(access, FakeMessage(sender_id=user.id))


def test_moderator_can_delete_any_message_in_conversation():
    user = FakeUser()
    access = _access(user, _ROLE_GRANTS["MODERATOR"])
    assert can_delete_message(access, FakeMessage(sender_id=uuid.uuid4()))


def test_owner_does_not_inherit_platform_powers():
    owner = _ROLE_GRANTS["OWNER"]
    assert Permission.MANAGE_USERS not in owner
    assert Permission.MANAGE_SYSTEM not in owner
    assert Permission.VIEW_REPORTS not in owner
