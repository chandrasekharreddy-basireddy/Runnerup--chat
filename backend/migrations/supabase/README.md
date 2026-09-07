# Supabase co-tenant install (applied)

The chat platform lives in the `runnerup_chat` schema of the `survivalschool-prod`
project, because the organisation's two free-project slots were already in use and
restoring the paused `Quiz-web` project counts toward the same limit.

## Why a schema and not `public`

The host application has 61 tables in `public`, including `users`, `audit_logs`,
`notifications`, `notification_preferences`, `push_subscriptions`, `sessions`,
`chat_rooms`, `chat_messages` and `message_reads`. Installing this platform into
`public` would have collided on at least six of those names.

## Applied migrations

| Migration | What it does |
|---|---|
| `runnerup_chat_01_schema_and_enums` | schema, 12 enums, core tables |
| `runnerup_chat_02_remaining_tables` | attachments, invites, blocks, reports, notifications, event log, audit |
| `runnerup_chat_03a_extensions` | `pg_trgm` and `btree_gin` into the shared `extensions` schema |
| `runnerup_chat_03_indexes_and_triggers` | 66 indexes, sequence allocator, reply-scope trigger |
| `runnerup_chat_04_role_and_rls` | `runnerup_chat_app` role, grants, RLS on all 25 tables |

## Isolation, as verified after applying

    chat tables                     25
    chat tables with RLS forced     25
    chat indexes                    66
    host tables (unchanged)         61
    host tables with RLS            60   (as before; untouched)
    grants to the role outside its own schema   0
    can read public.users           false
    can read public.chat_messages   false
    can read public.refresh_tokens  false
    can append to chat audit_logs   true
    can delete from chat audit_logs false

The role does hold `USAGE` on `public`, inherited from the `PUBLIC` pseudo-role, which
cannot be revoked without affecting the host application. It is harmless on its own:
schema usage grants no table rights, and every table-level check above returns false.

**Deliberate difference from the standalone `0002_roles.sql`:** that file revokes on
`public` and enables RLS on every table it finds. Running it here would have altered all
61 host tables. Every statement in `04` names `runnerup_chat` explicitly.

## Remaining step: set the login password

The role was created `NOLOGIN` with no password, so no credential passed through a
migration, this repository, or any chat transcript. Set one yourself in the Supabase SQL
editor, then use it in `DATABASE_URL`:

    ALTER ROLE runnerup_chat_app LOGIN PASSWORD 'a-long-random-password-you-generate';

Then, pinning the schema on the connection so no query can resolve into `public`:

    DATABASE_URL=postgresql://runnerup_chat_app:<password>@<session-pooler-host>:5432/postgres?options=-csearch_path%3Drunnerup_chat

Use the **session pooler** URI, not transaction pooling: transaction mode breaks
`LISTEN`, prepared statements and advisory locks, all of which this backend relies on.

## Move out when you can

Sharing a database means sharing connection limits, CPU, disk, backups and the blast
radius of any restore. Give this platform its own project as soon as a slot frees up.
