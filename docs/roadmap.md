# Roadmap

Done and verified: schema, least-privilege role and RLS, OTP auth, session rotation with
reuse detection, device management, the authorization core, conversations, groups,
channels, invites, messages with idempotency and cursor pagination, edit and delete,
reactions, read receipts, membership-scoped search, the sync cursor, WebSocket ticket
handshake with Redis fan-out, typing and presence, audit and security logging.

Remaining, in build order:

1. **Frontend** — Next.js login, conversation list, virtualized message view, optimistic
   send with retry, reconnect with exponential backoff and jitter.
2. **Attachments** — presigned PUT, server-side magic-byte validation, malware scan hook,
   short-lived signed download URLs. Interfaces exist in `services/storage.py`.
3. **Notifications** — Web Push and FCM/APNS, honouring the per-conversation preview
   policy so a private message does not leak its body to a lock screen.
4. **Moderation dashboard** — report queue, restriction and suspension actions. The
   explicitly-audited read path for private content belongs here and nowhere else.
5. **Blocking enforcement in group contexts** — currently enforced on direct messages
   and group seeding; group-level suppression needs finishing.
6. **E2EE** — the schema keeps message bodies in one column precisely so this can become
   a ciphertext blob later. Requires an audited library and a real key-management design.
