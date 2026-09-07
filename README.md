# Signal-Lite — secure real-time messaging platform

A production-shaped, security-first chat platform: phone/OTP authentication, rotating
refresh tokens, server-authoritative authorization, WebSocket fan-out over Redis,
PostgreSQL as the durable source of truth, private object storage.

**No AI components anywhere in the UI or the product surface.** No smart replies, no
summaries, no assistants, no embeddings, no model calls. See `docs/no-ai-policy.md`
and `scripts/no-ai-check.sh` (wired into CI) for the enforced guardrail.

## What is implemented in this drop

Backend (FastAPI, async SQLAlchemy 2.0):

- Phone normalization + OTP login: HMAC-hashed codes, single use, short TTL, attempt
  ceilings, per-phone / per-IP / global sliding-window limits, constant-time compare,
  identical responses whether or not the account exists.
- Sessions: 10-minute access JWTs, opaque 256-bit refresh tokens stored as SHA-256
  digests, rotation on every use, token-family reuse detection that revokes the whole
  family and writes a security event.
- Refresh token lives in an HttpOnly/Secure/SameSite=Strict cookie scoped to the
  refresh path; access token never touches localStorage. Double-submit CSRF token plus
  Origin checking on the cookie-authenticated endpoints.
- Devices: one row per login, listing + individual revoke + revoke-all.
- Authorization service: every conversation, message, attachment and admin resource is
  resolved through a membership/role check against server-side state. No route trusts a
  client-supplied user id, role, or conversation id.
- RBAC: system roles (USER/MODERATOR/ADMIN/SUPER_ADMIN) and per-conversation roles
  (OWNER/ADMIN/MODERATOR/MEMBER/SUBSCRIBER) resolved to an explicit permission set.
- Messages: server-assigned per-conversation sequence numbers, server timestamps,
  idempotency on `client_msg_id`, cursor pagination, edit/delete/reply/react/pin,
  receipts, full-text search that is filtered by membership before it touches the index.
- WebSocket: single-use Redis ticket handshake (no token in the query string),
  per-connection subscription authorization, payload size cap, per-connection rate
  limit, heartbeats, idle timeout, Redis pub/sub fan-out, `sync_after` cursor replay.
- Uploads: presigned PUT to private object storage under a random key, server-side
  finalize step that verifies real size and magic bytes, sanitized display filenames,
  short-lived signed download URLs.
- Structured JSON logging with request ids, audit log, security event log.
- Redis sliding-window rate limiter (Lua, atomic) applied per IP / phone / user / device.

Frontend (Next.js App Router, TypeScript, Tailwind):

- OTP login flow, in-memory access token with silent refresh, device manager,
  conversation list, virtualized message list, optimistic send with SENDING → SENT →
  DELIVERED → READ and an explicit FAILED + retry state, typing indicators, presence,
  reconnect with exponential backoff and jitter, plain-text rendering only (no
  `dangerouslySetInnerHTML` anywhere).

Infrastructure: Docker Compose (Postgres, Redis, MinIO, API, worker, web, nginx TLS
termination), least-privilege database role, `.env.example` with placeholders only.

## What is deliberately not finished

This is a large system; `docs/roadmap.md` lists the remaining phases in build order
(push notifications, moderation dashboard, channel discovery, malware scanning hookup,
E2EE key transport). Everything listed there is scaffolded with real interfaces, not
stubbed with fake behavior — nothing in this codebase claims a security property it
does not have. In particular: **traffic is TLS-encrypted, it is not end-to-end
encrypted.** See `docs/security.md`.

## Run it

    ./scripts/bootstrap.sh

That generates a `.env` with cryptographically random secrets, renders the role
migration with the real database password, and brings the stack up. It is idempotent —
an existing `.env` is left alone so re-running never rotates keys out from under a
running database.

  - Web: http://localhost:3000
  - API: http://localhost/api/v1/health
  - MinIO console: http://localhost:9001

To sign in, enter any phone number and read the six-digit code from the API log:

    docker compose logs -f api | grep dev-sms

The console SMS provider refuses to start when `ENVIRONMENT=production`, so it cannot
put a live code into a real log pipeline.

Postgres, Redis and MinIO publish no host ports — they are reachable only from inside
the compose network. Scale the API with `docker compose up --scale api=3`; it is
stateless and all fan-out goes through Redis pub/sub.

**Real SMS delivery is not configured.** Until `SMS_PROVIDER=twilio` and credentials are
set, this cannot serve real users — anyone who can read the logs can sign in as anyone.
