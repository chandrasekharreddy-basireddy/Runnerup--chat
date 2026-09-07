# Going live: what is left, and what it costs

The code is done and verified. What remains is provisioning, and every step below needs
either your approval in the Claude app or a credential I should not be handling.

## 1. Supabase (database) — $0/month

I attempted this and the call returned "No approval received": creating a project is a
write action that needs your tap. Once approved:

- org `edfhzqfaqmfcltkgrtci`, region `ap-south-1`, cost confirmed at $0/month
- apply `backend/migrations/0001_init.sql`, then `0002_roles.sql` with the placeholder
  replaced by a real password
- create a **private** bucket named `chat-media`
- copy the **session pooler** URI (not transaction pooling — it breaks `LISTEN`,
  prepared statements and advisory locks, all of which this backend uses)

## 2. Render (API + worker + Redis)

`render.yaml` is a complete blueprint. The plan choice is a real decision:

- **Free**: $0, but instances sleep after ~15 minutes idle and terminate WebSocket
  connections. Fine for a demo, useless for a chat product.
- **Starter**: roughly $7/month per service plus Key Value. Required for anything real.

I did not provision this, because picking the paid tier spends your money and picking
the free tier ships something that appears broken the moment it idles. Tell me which.

## 3. Vercel — already live

https://runnerup-chat-matrix-igniters.vercel.app

After Render exists, set these and redeploy:

    NEXT_PUBLIC_API_BASE=https://<render-host>/api/v1
    NEXT_PUBLIC_API_ORIGIN=https://<render-host>
    NEXT_PUBLIC_WS_URL=wss://<render-host>/ws
    NEXT_PUBLIC_WS_ORIGIN=wss://<render-host>

Then set `ALLOWED_ORIGINS` on Render to the exact Vercel origin. CORS uses an exact
match, never a wildcard, so a trailing slash or a missing subdomain will fail closed.

## 4. SMS — the actual blocker for real users

There is no OTP delivery without a provider. `SMS_PROVIDER=console` prints codes to the
log and refuses to run in production, which is deliberate. A Twilio account with a
messaging-capable number and `SMS_API_KEY` set is the minimum for a real login.

Until then the deployment is a demo, and it should not be described as anything else.

## 5. Housekeeping

- The GitHub token pasted in chat should be revoked.
- The repo is public; consider making it private.
- CI is parked at `ci/github-actions-ci.yml` — move it to `.github/workflows/` from a
  local clone or the web editor (the push token lacked `workflow` scope).
