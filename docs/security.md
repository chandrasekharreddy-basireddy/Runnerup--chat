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

## Attachments, blocking and moderation — verified

Upload requests rejected before any bytes move:

- `payload.exe` declared as `image/png` — blocked extension
- `shell.sh` declared as `image/jpeg` — blocked extension
- `evil.svg` declared as `image/webp` — SVG is on the blocked list because it carries
  script and renders as a document
- `doc.pdf` declared as `application/x-sh` — MIME not on the allow-list
- a 900 MB `huge.png` — over the size ceiling
- a legitimate `photo.jpg` is accepted

Filename sanitization, applied to the display name only (the storage key is random and
never derived from user input):

    '../../etc/passwd'  ->  '_._etc_passwd'
    'a/b\c.png'         ->  'a_b_c.png'
    '....//evil.png'    ->  '__evil.png'
    'photo\x00.png'     ->  'photo.png'

Validation is two-stage on purpose. The declared type gates the presigned URL; the
observed magic bytes decide what the file actually is, after upload, before it can be
attached to a message. A mismatch between the two is recorded — it is a strong signal of
a deliberate attempt rather than a mislabelled file.

Blocking and reporting:

- after Bob blocks Alice, Alice opening a new direct chat with Bob returns 404
- self-block returns 422
- reporting a message the caller cannot see returns 404, so the endpoint is not an
  oracle for which message ids exist
- three identical reports of the same user return 200 each and store exactly one row —
  a repeat neither errors nor confirms that an earlier report exists
- `/admin/reports` and `/admin/users/suspend` return 403 for an ordinary user
- suspension revokes every session immediately rather than waiting for token expiry
- a moderator cannot suspend a peer or a superior, so one compromised admin account
  cannot disable the others

## Blocking bypass — found and fixed

**The bug.** Blocking was enforced only when a direct conversation was created. Once a
conversation existed, a block did nothing: the blocked user could keep sending into it,
and the messages appeared in the blocker's client. Reproduced end to end — Bob blocked
Alice, Alice posted "HARASSMENT AFTER BLOCK" with HTTP 200, and Bob's message list
returned it.

That is the exact failure blocking exists to prevent. Checking a condition only at
creation time is a recurring shape of authorization bug: the check passes once and the
resource then outlives it.

**The fix.** Block state is now resolved inside `resolve_access`, the single chokepoint
every read and write already passes through, rather than at the one call site that
happened to think of it. For a direct conversation the counterpart is resolved through
the ordered-pair key and `SEND_MESSAGE`, `EDIT_OWN_MESSAGE` and `PIN_MESSAGE` are
withdrawn if either party has blocked the other.

**Verified after the fix:**

- blocked sender into an existing chat: 403
- the blocker sending to the blocked user: 403 as well, since a block is not a one-way
  mute that leaves the blocker able to keep talking
- both parties can still read their existing history — a block removes the ability to
  write, not the record of what was said
- after unblocking, sending succeeds again
- a 1:1 block does **not** silence either party in groups they both belong to
