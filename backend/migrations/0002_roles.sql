-- =============================================================================
-- 0002_roles.sql — least-privilege database role + RLS lockdown.
-- Run as project owner AFTER 0001_init.sql. Substitute the password from the
-- secret store; never commit a real one.
-- =============================================================================

-- The API connects as this role. It is not the owner, has no DDL rights, and cannot
-- create roles or read other schemas.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chat_app') THEN
        CREATE ROLE chat_app LOGIN PASSWORD 'REPLACE_ME_FROM_SECRET_STORE'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
            CONNECTION LIMIT 60;
    END IF;
END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO chat_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO chat_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO chat_app;
GRANT EXECUTE ON FUNCTION next_conversation_seq(UUID) TO chat_app;

-- Audit and security logs are append-only from the application's point of view.
-- A compromised API can write history but cannot rewrite or delete it.
REVOKE UPDATE, DELETE ON audit_logs, security_events, message_edits FROM chat_app;

-- Nothing new should be reachable by default if a later migration forgets to grant.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;

-- ---------------------------------------------------------------------- RLS
-- Defense in depth for the Supabase deployment. The browser never talks to Postgres —
-- there is no supabase-js in the frontend and no anon key is ever shipped — but if a
-- key did leak, PostgREST would find every table readable by nobody.
DO $$
DECLARE t TEXT;
BEGIN
    FOR t IN
        SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;

-- Deliberately zero policies for anon/authenticated. RLS with no policy denies all.
-- chat_app is exempted by BYPASSRLS-free design: instead of bypassing, we grant it an
-- explicit permissive policy, so the deny-by-default posture stays visible in the
-- catalog rather than hidden in a role attribute.
DO $$
DECLARE t TEXT;
BEGIN
    FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    LOOP
        EXECUTE format(
            'CREATE POLICY app_role_full_access ON public.%I FOR ALL TO chat_app '
            'USING (true) WITH CHECK (true)', t);
    END LOOP;
END $$;

-- Supabase-specific: make sure the auto-created API roles hold nothing.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated';
        EXECUTE 'REVOKE ALL ON SCHEMA public FROM anon, authenticated';
    END IF;
END $$;

-- ------------------------------------------------------------- housekeeping
-- Expired OTP challenges hold a phone hash; drop them promptly.
CREATE OR REPLACE FUNCTION purge_expired_otp() RETURNS void
LANGUAGE sql AS $$
    DELETE FROM otp_challenges WHERE expires_at < now() - interval '1 hour';
$$;
GRANT EXECUTE ON FUNCTION purge_expired_otp() TO chat_app;
