-- =============================================================================
-- 0003_isolated_schema.sql — co-tenancy variant.
--
-- Use this ONLY when the chat platform has to share a Supabase project with another
-- application, because the free-tier project limit is exhausted. It installs every
-- object into a dedicated `chat` schema instead of `public`, so the two applications
-- never see each other's tables and a bad migration on one cannot touch the other.
--
-- This is weaker than a separate project. Sharing a database means sharing connection
-- limits, CPU, disk, backups and the blast radius of a restore. Prefer a project of its
-- own the moment one is available.
--
-- Usage:
--     psql "$SUPABASE_URI" -f 0003_isolated_schema.sql
--     psql "$SUPABASE_URI" -c "SET search_path = chat, public;" -f 0001_init.sql
--     psql "$SUPABASE_URI" -f 0002_roles.sql     -- adjust GRANTs to the chat schema
--
-- Then set the application's connection to pin the schema, so no query can silently
-- resolve to a table belonging to the other tenant:
--     DATABASE_URL=...?options=-csearch_path%3Dchat
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS chat;

-- Extensions stay in public: they are shared machinery, and installing a second copy
-- into `chat` would conflict with the co-tenant's.
CREATE EXTENSION IF NOT EXISTS pgcrypto   SCHEMA public;
CREATE EXTENSION IF NOT EXISTS citext     SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pg_trgm    SCHEMA public;
CREATE EXTENSION IF NOT EXISTS btree_gin  SCHEMA public;

-- The application role may use `chat` and nothing else. Without this revoke it would
-- inherit whatever the co-tenant's schema grants to PUBLIC.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chat_app') THEN
        CREATE ROLE chat_app LOGIN PASSWORD 'REPLACE_ME_FROM_SECRET_STORE'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 40;
    END IF;
END $$;

REVOKE ALL ON SCHEMA public FROM chat_app;
GRANT USAGE ON SCHEMA public TO chat_app;   -- extensions only, no table rights
GRANT USAGE ON SCHEMA chat   TO chat_app;

-- Pin the search path on the role itself, belt and braces alongside the connection
-- option, so an unqualified table name can never resolve into the co-tenant's schema.
ALTER ROLE chat_app SET search_path = chat, public;
