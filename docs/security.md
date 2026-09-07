# Security notes

## Verified behaviour

Every item below was exercised against a live PostgreSQL 16 and Redis 7, not asserted
in a comment.

Database-enforced (rejected by constraint or trigger, independent of application code):

- a SUPER_ADMIN row without a second factor
- a second OWNER in one conversation
- a duplicate `client_msg_id` from the same sender in the same conversation
- a reply whose target lives in a different conversation
- a self-block
- a duplicate direct-chat pair in either participant order
- a public conversation with no slug

Role-enforced (`chat_app` connecting as the least-privilege role):

- `DELETE FROM audit_logs` — permission denied
- `UPDATE audit_logs` — permission denied
- `CREATE TABLE` — permission denied on schema public
- RLS enabled and forced on all 25 tables

API-enforced, over HTTP:

- the OTP appears in neither the response body nor any structured log line
- a wrong code returns 401; a correct code creates the account and session
- the same code replayed returns 401 — challenges are single-use
- the fourth OTP request for one number in the window returns 429
- an outsider reading, posting to, or deleting from a private conversation gets 404 in
  every case — never 403, which would confirm the conversation exists
- search returns 1 hit for a member and 0 for an outsider on the same term
- a plain MEMBER creating an invite gets 403; the OWNER gets a 32-character token
- a single-use invite redeemed twice returns 404 on the second attempt, identical to the
  response for a forged token
- the same `client_msg_id` sent twice yields one message and `created=false` on the retry
- sync withholds events younger than the hold-back window, then replays exactly 3, and
  returns 0 when called again from the resulting cursor
- a deleted message reports `deleted=true` with the body scrubbed to null

## Not implemented

Transport is TLS. This is **not** end-to-end encrypted, and nothing in the product
claims otherwise. Attachments, push notifications and the moderation dashboard are
scaffolded but not finished; see docs/roadmap.md.
