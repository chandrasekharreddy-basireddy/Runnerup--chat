# Managed deployment topology

                       browser
                          |  https + wss
              +-----------+------------+
              |                        |
        Vercel (Next.js)         Render (FastAPI)
        static + SSR only        WebSockets + REST + worker
        no DB access             |         |
                                 |         +--> Render Key Value (Redis)
                                 |               pub/sub, presence, rate limits, jobs
                                 +--> Supabase Postgres  (durable source of truth)
                                 +--> Supabase Storage   (private S3-compatible bucket)

## Why this split

The API cannot live on Vercel. WebSocket connections are long-lived and stateful;
Vercel's serverless functions are neither. Render runs the API as an always-on container
with two or more replicas, and every replica fans out through Redis pub/sub, so any
replica can deliver an event to any connected client.

Supabase is used **only** as managed Postgres and object storage. It is not used as an
auth provider and never as a client-side data source:

- The frontend does not ship `supabase-js`, an anon key, or a project URL. There is no
  path from the browser to the database. All reads and writes go through the FastAPI
  authorization layer, which is the requirement in section 44 of the spec.
- Row Level Security is enabled on every table anyway, as defense in depth, with no
  policies granting the `anon` or `authenticated` roles anything. If a key ever leaks,
  it reaches nothing.
- The API connects as a dedicated least-privilege role (`chat_app`), not `postgres`.
  It gets DML on application tables and nothing else: no DDL, no superuser, no access
  to `auth.*` or `storage.*` internals. See `backend/migrations/0002_roles.sql`.

## Accounts found on your connectors

| Platform | Target | Note |
|---|---|---|
| Supabase | org `edfhzqfaqmfcltkgrtci` | new project costs $0/month; nearest region `ap-south-1` |
| Render | `Chandra Sekhar's workspace` (`tea-d9vibne1egvs73ea2jkg`) | needs a paid instance type; free instances sleep and kill WebSockets |
| Vercel | team `Matrix Igniters`, Hobby plan | Hobby forbids commercial use — fine for building, needs Pro before launch |

Existing Supabase projects (`survivalschool-prod`, `rockstar-organics`, `Quiz-web`) are
unrelated to this system and are left untouched. Chat gets its own project so a
compromise or a bad migration cannot reach the others.

## Order of operations

1. Push this repo to GitHub. Render and Vercel both deploy from a Git remote.
2. Create the Supabase project, run `0001_init.sql` then `0002_roles.sql`, create the
   private `chat-media` bucket, mint S3 access keys.
3. Deploy `render.yaml` as a blueprint. Set `DATABASE_URL` to the Supabase **session
   pooler** URI with `sslmode=require` (transaction pooling breaks `LISTEN`, prepared
   statements and advisory locks).
4. Create the Vercel project from the same repo with root directory `frontend`, set
   `NEXT_PUBLIC_API_BASE` and `NEXT_PUBLIC_WS_URL` to the Render hostname.
5. Set `ALLOWED_ORIGINS` on Render to the exact Vercel production origin, then redeploy.

## Secrets

Nothing above is committed. Render generates `JWT_SIGNING_KEY`, `OTP_PEPPER` and
`COOKIE_SIGNING_KEY` at blueprint apply time; database, storage and SMS credentials are
entered once in the Render dashboard and never leave it. `.env.example` holds
placeholders only.

## Cost reality check

Free tiers do not work for this system. Render free web services sleep after inactivity
and terminate WebSocket connections; Supabase free projects pause after a week idle.
Expect roughly $7/month per Render service plus Key Value, and Supabase Pro at $25/month
once you are past prototyping.
