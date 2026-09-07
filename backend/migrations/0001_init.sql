-- =============================================================================
-- 0001_init.sql — durable schema. PostgreSQL 15+.
-- Run as the project owner. 0002_roles.sql then drops privileges for the app role.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid, digest
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- filename / display-name fuzzy lookup
-- Lets a GIN index mix a scalar column with a tsvector. Without it the composite
-- (conversation_id, search_tsv) index below cannot be built, and search would have to
-- scan the tsvector index globally and filter afterwards — which is exactly the
-- unauthorized-reach problem the composite index exists to prevent.
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- ---------------------------------------------------------------- enumerations
CREATE TYPE system_role      AS ENUM ('USER','MODERATOR','ADMIN','SUPER_ADMIN');
CREATE TYPE account_state    AS ENUM ('ACTIVE','RESTRICTED','SUSPENDED','DELETED');
CREATE TYPE conversation_kind AS ENUM ('DIRECT','GROUP','CHANNEL');
CREATE TYPE conversation_visibility AS ENUM ('PRIVATE','PUBLIC');
CREATE TYPE member_role      AS ENUM ('OWNER','ADMIN','MODERATOR','MEMBER','SUBSCRIBER');
CREATE TYPE member_state     AS ENUM ('ACTIVE','MUTED','RESTRICTED','BANNED','LEFT');
CREATE TYPE message_kind     AS ENUM ('TEXT','IMAGE','VIDEO','AUDIO','VOICE','FILE','SYSTEM');
CREATE TYPE receipt_kind     AS ENUM ('DELIVERED','READ');
CREATE TYPE attachment_state AS ENUM ('PENDING','SCANNING','READY','REJECTED');
CREATE TYPE report_reason    AS ENUM ('SPAM','HARASSMENT','SCAM','ABUSE','ILLEGAL_CONTENT','IMPERSONATION','OTHER');
CREATE TYPE report_state     AS ENUM ('OPEN','TRIAGED','ACTIONED','DISMISSED');
CREATE TYPE preview_policy   AS ENUM ('SHOW_PREVIEW','HIDE_PREVIEW','MENTIONS_ONLY','MUTED');

-- ---------------------------------------------------------------------- users
-- phone_e164 is stored only as an HMAC digest for lookup plus a redacted display
-- form. The plaintext number is never at rest, so a database read alone does not
-- yield a subscriber list.
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash       BYTEA NOT NULL UNIQUE,        -- HMAC-SHA256(pepper, E.164)
    phone_last4      TEXT  NOT NULL CHECK (phone_last4 ~ '^[0-9]{2,4}$'),
    phone_country    TEXT  NOT NULL CHECK (char_length(phone_country) BETWEEN 1 AND 4),
    username         CITEXT UNIQUE CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    display_name     TEXT  NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    avatar_key       TEXT,
    bio              TEXT CHECK (char_length(bio) <= 280),
    system_role      system_role   NOT NULL DEFAULT 'USER',
    account_state    account_state NOT NULL DEFAULT 'ACTIVE',
    mfa_secret_enc   BYTEA,                        -- required for ADMIN/SUPER_ADMIN
    last_seen_at     TIMESTAMPTZ,
    presence_visible BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_scope  TEXT NOT NULL DEFAULT 'CONTACTS'
                     CHECK (last_seen_scope IN ('EVERYONE','CONTACTS','NOBODY')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX users_display_name_trgm ON users USING gin (display_name gin_trgm_ops);
-- Elevated accounts must carry a second factor. Enforced in the database so a bug in
-- the role-change endpoint cannot produce a passwordless super admin.
ALTER TABLE users ADD CONSTRAINT users_admin_requires_mfa
    CHECK (system_role IN ('USER','MODERATOR') OR mfa_secret_enc IS NOT NULL);

-- ------------------------------------------------------------------ auth / OTP
-- The code itself is never stored: code_hash = HMAC-SHA256(pepper, challenge_id||code).
CREATE TABLE otp_challenges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash    BYTEA NOT NULL,
    code_hash     BYTEA NOT NULL,
    attempts      SMALLINT NOT NULL DEFAULT 0,
    max_attempts  SMALLINT NOT NULL DEFAULT 5,
    request_ip    INET,
    user_agent_hash BYTEA,
    consumed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX otp_lookup ON otp_challenges (phone_hash, created_at DESC);
CREATE INDEX otp_expiry ON otp_challenges (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE user_devices (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform       TEXT NOT NULL CHECK (platform IN ('WEB','IOS','ANDROID','DESKTOP','UNKNOWN')),
    display_label  TEXT NOT NULL,                 -- "Chrome on Windows", derived server-side
    ip_first_seen  INET,
    ip_last_seen   INET,
    push_token_enc BYTEA,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX devices_by_user ON user_devices (user_id) WHERE revoked_at IS NULL;

-- Refresh tokens are opaque 256-bit values; only their SHA-256 digest is stored.
-- A family is one login. Presenting an already-rotated token kills the whole family.
CREATE TABLE user_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    family_id       UUID NOT NULL,
    refresh_hash    BYTEA NOT NULL UNIQUE,
    previous_id     UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    rotated_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX sessions_family ON user_sessions (family_id);
CREATE INDEX sessions_active ON user_sessions (user_id) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------- conversations
CREATE TABLE conversations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          conversation_kind NOT NULL,
    visibility    conversation_visibility NOT NULL DEFAULT 'PRIVATE',
    slug          CITEXT UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{2,31}$'),
    title         TEXT CHECK (char_length(title) BETWEEN 1 AND 128),
    topic         TEXT CHECK (char_length(topic) <= 512),
    avatar_key    TEXT,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Per-conversation monotonic counter. Allocated inside the send transaction, so
    -- ordering never depends on a client clock and never has gaps.
    last_seq      BIGINT NOT NULL DEFAULT 0,
    -- Who may do what. Read by the authorization layer, never by the client.
    send_policy      member_role NOT NULL DEFAULT 'MEMBER',
    invite_policy    member_role NOT NULL DEFAULT 'ADMIN',
    pin_policy       member_role NOT NULL DEFAULT 'ADMIN',
    edit_info_policy member_role NOT NULL DEFAULT 'ADMIN',
    member_limit  INTEGER NOT NULL DEFAULT 512 CHECK (member_limit BETWEEN 2 AND 200000),
    is_archived   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,
    CONSTRAINT direct_chats_are_private
        CHECK (kind <> 'DIRECT' OR (visibility = 'PRIVATE' AND slug IS NULL)),
    CONSTRAINT public_needs_slug
        CHECK (visibility <> 'PUBLIC' OR slug IS NOT NULL)
);
CREATE INDEX conversations_public ON conversations (kind, visibility)
    WHERE visibility = 'PUBLIC' AND deleted_at IS NULL;

-- Direct chats are keyed by the ordered participant pair so a second one can never be
-- created by racing requests.
CREATE TABLE direct_conversation_keys (
    conversation_id UUID PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    user_lo         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_hi         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ordered_pair CHECK (user_lo < user_hi),
    UNIQUE (user_lo, user_hi)
);

CREATE TABLE conversation_members (
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            member_role  NOT NULL DEFAULT 'MEMBER',
    state           member_state NOT NULL DEFAULT 'ACTIVE',
    muted_until     TIMESTAMPTZ,
    restricted_until TIMESTAMPTZ,
    last_read_seq   BIGINT NOT NULL DEFAULT 0,
    notify_policy   preview_policy NOT NULL DEFAULT 'SHOW_PREVIEW',
    invited_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at         TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX members_by_user ON conversation_members (user_id)
    WHERE state <> 'BANNED' AND left_at IS NULL;
-- Exactly one owner per group/channel.
CREATE UNIQUE INDEX one_owner_per_conversation ON conversation_members (conversation_id)
    WHERE role = 'OWNER' AND left_at IS NULL;

-- -------------------------------------------------------------------- messages
CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    seq             BIGINT NOT NULL,               -- server-allocated, authoritative order
    sender_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    kind            message_kind NOT NULL DEFAULT 'TEXT',
    body            TEXT CHECK (char_length(body) <= 8192),
    -- Idempotency key from the client. Unique per sender per conversation, so a retry
    -- of the same send returns the original row instead of duplicating it.
    client_msg_id   UUID NOT NULL,
    reply_to_id     UUID REFERENCES messages(id) ON DELETE SET NULL,
    thread_root_id  UUID REFERENCES messages(id) ON DELETE SET NULL,
    forwarded_from  UUID REFERENCES messages(id) ON DELETE SET NULL,
    edited_at       TIMESTAMPTZ,
    edit_count      SMALLINT NOT NULL DEFAULT 0,
    deleted_at      TIMESTAMPTZ,
    deleted_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Server clock only. Client timestamps are accepted for display hints and stored
    -- nowhere that affects ordering.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_tsv      TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', coalesce(body,''))) STORED,
    UNIQUE (conversation_id, seq),
    UNIQUE (conversation_id, sender_id, client_msg_id)
);
-- Primary read path: newest-first cursor pagination within a conversation.
CREATE INDEX messages_cursor ON messages (conversation_id, seq DESC);
CREATE INDEX messages_thread ON messages (thread_root_id, seq) WHERE thread_root_id IS NOT NULL;
-- Search is always scoped to a conversation the caller belongs to; the conversation_id
-- leads the index so an unauthorized search cannot even reach other rows.
CREATE INDEX messages_search ON messages USING gin (conversation_id, search_tsv);

CREATE TABLE message_edits (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id  UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    previous_body TEXT,
    edited_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    edited_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX edits_by_message ON message_edits (message_id, edited_at DESC);

CREATE TABLE message_receipts (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       receipt_kind NOT NULL,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, kind)
);
CREATE INDEX receipts_by_user ON message_receipts (user_id, at DESC);

CREATE TABLE message_reactions (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      TEXT NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 16),
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji)
);

CREATE TABLE message_mentions (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, user_id)
);
CREATE INDEX mentions_by_user ON message_mentions (user_id);

CREATE TABLE pinned_messages (
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id      UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    pinned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, message_id)
);

-- ----------------------------------------------------------------- attachments
-- storage_key is server-generated and random. The user-supplied filename is kept only
-- as a sanitized display string and is never used to build a path.
CREATE TABLE attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    message_id      UUID REFERENCES messages(id) ON DELETE CASCADE,
    storage_key     TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    byte_size       BIGINT NOT NULL CHECK (byte_size > 0),
    -- Determined server-side from the object's magic bytes, not from Content-Type.
    detected_mime   TEXT NOT NULL,
    declared_mime   TEXT,
    width           INTEGER,
    height          INTEGER,
    duration_ms     INTEGER,
    checksum_sha256 BYTEA,
    state           attachment_state NOT NULL DEFAULT 'PENDING',
    scan_verdict    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at    TIMESTAMPTZ
);
CREATE INDEX attachments_by_message ON attachments (message_id);
CREATE INDEX attachments_orphans ON attachments (created_at) WHERE message_id IS NULL;

-- --------------------------------------------------------------- invite links
-- token_hash only: possession of the database does not yield usable invite links.
CREATE TABLE invite_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    token_hash      BYTEA NOT NULL UNIQUE,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    max_uses        INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       INTEGER NOT NULL DEFAULT 0,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uses_within_limit CHECK (max_uses IS NULL OR use_count <= max_uses)
);
CREATE INDEX invites_by_conversation ON invite_links (conversation_id) WHERE revoked_at IS NULL;

CREATE TABLE join_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invite_id       UUID REFERENCES invite_links(id) ON DELETE SET NULL,
    state           TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (state IN ('PENDING','APPROVED','REJECTED')),
    decided_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ,
    UNIQUE (conversation_id, user_id)
);

-- ------------------------------------------------------ blocking / reporting
CREATE TABLE blocked_users (
    blocker_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT no_self_block CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocks_reverse ON blocked_users (blocked_id);

CREATE TABLE reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_type   TEXT NOT NULL CHECK (subject_type IN ('USER','MESSAGE','CONVERSATION')),
    subject_user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    subject_message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    subject_conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    reason         report_reason NOT NULL,
    detail         TEXT CHECK (char_length(detail) <= 2000),
    state          report_state NOT NULL DEFAULT 'OPEN',
    handled_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    handled_at     TIMESTAMPTZ,
    CONSTRAINT subject_matches_type CHECK (
        (subject_type = 'USER'         AND subject_user_id IS NOT NULL) OR
        (subject_type = 'MESSAGE'      AND subject_message_id IS NOT NULL) OR
        (subject_type = 'CONVERSATION' AND subject_conversation_id IS NOT NULL))
);
CREATE INDEX reports_queue ON reports (state, created_at);
CREATE INDEX reports_by_reporter ON reports (reporter_id);
-- One open report per reporter per subject: stops report-flooding as an abuse vector.
CREATE UNIQUE INDEX one_open_report_per_user_subject ON reports
    (reporter_id, subject_type, coalesce(subject_user_id, subject_message_id, subject_conversation_id))
    WHERE state = 'OPEN';

CREATE TABLE moderation_actions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    action       TEXT NOT NULL,
    target_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    target_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    target_conversation_id UUID REFERENCES conversations(id) ON DELETE SET NULL,
    report_id    UUID REFERENCES reports(id) ON DELETE SET NULL,
    reason       TEXT NOT NULL,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------- notifications
CREATE TABLE notifications (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    message_id   UUID REFERENCES messages(id) ON DELETE CASCADE,
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    read_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX notifications_inbox ON notifications (user_id, created_at DESC) WHERE read_at IS NULL;

CREATE TABLE notification_preferences (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    policy          preview_policy NOT NULL DEFAULT 'SHOW_PREVIEW',
    quiet_from      TIME,
    quiet_to        TIME,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX notif_pref_key ON notification_preferences
    (user_id, coalesce(conversation_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE push_subscriptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    transport   TEXT NOT NULL CHECK (transport IN ('WEBPUSH','FCM','APNS')),
    endpoint_enc BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    UNIQUE (device_id, transport)
);

-- ------------------------------------------------------- sync event log
-- Append-only. Clients reconnect with a cursor and replay everything they missed,
-- filtered to conversations they are currently a member of.
--
-- Note on the cursor: BIGSERIAL values are assigned before commit, so a slow writer can
-- commit id 100 after id 101 is already visible. Readers therefore never take events
-- newer than `now() - sync_lag`, which is longer than the statement timeout. Without
-- that guard a reconnecting client can silently skip an event forever.
CREATE TABLE conversation_events (
    id              BIGSERIAL PRIMARY KEY,
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    seq             BIGINT NOT NULL,
    type            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, seq, type)
);
CREATE INDEX events_sync ON conversation_events (conversation_id, id);
CREATE INDEX events_by_id ON conversation_events (id);

-- ---------------------------------------------------------------- audit trail
-- Append-only for the application role: 0002 grants INSERT and SELECT but not UPDATE
-- or DELETE, so a compromised API cannot erase its own tracks.
CREATE TABLE audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_role  system_role,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    request_id  TEXT,
    ip          INET,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_by_actor ON audit_logs (actor_id, at DESC);
CREATE INDEX audit_by_action ON audit_logs (action, at DESC);

CREATE TABLE security_events (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    event       TEXT NOT NULL,           -- otp_failed, refresh_reuse_detected, ...
    severity    TEXT NOT NULL DEFAULT 'WARNING'
                CHECK (severity IN ('INFO','WARNING','CRITICAL')),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id  UUID,
    device_id   UUID,
    ip          INET,
    request_id  TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX security_recent ON security_events (at DESC);
CREATE INDEX security_by_user ON security_events (user_id, at DESC);

-- ------------------------------------------------------------------- triggers
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;

CREATE TRIGGER users_touch BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER conversations_touch BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- Allocates the next authoritative sequence number for a conversation and returns it.
-- The row lock serializes concurrent senders, which is what makes ordering total.
CREATE OR REPLACE FUNCTION next_conversation_seq(p_conversation UUID) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE v BIGINT;
BEGIN
    UPDATE conversations SET last_seq = last_seq + 1
     WHERE id = p_conversation AND deleted_at IS NULL
     RETURNING last_seq INTO v;
    IF v IS NULL THEN
        RAISE EXCEPTION 'conversation_not_found' USING ERRCODE = 'no_data_found';
    END IF;
    RETURN v;
END $$;

-- A message may only reply to a message in the same conversation. Enforced here so no
-- API route can leak a foreign conversation's message id through a reply chain.
CREATE OR REPLACE FUNCTION check_reply_scope() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE parent_conv UUID;
BEGIN
    IF NEW.reply_to_id IS NOT NULL THEN
        SELECT conversation_id INTO parent_conv FROM messages WHERE id = NEW.reply_to_id;
        IF parent_conv IS DISTINCT FROM NEW.conversation_id THEN
            RAISE EXCEPTION 'reply_target_outside_conversation';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER messages_reply_scope BEFORE INSERT OR UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION check_reply_scope();
