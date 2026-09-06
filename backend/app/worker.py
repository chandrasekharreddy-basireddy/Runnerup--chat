"""Background worker: housekeeping that must not run inside a request.

Kept intentionally small. Every job here is idempotent and safe to run twice, because a
worker that crashes mid-job will be restarted and will redo whatever it was doing.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core.logging import configure_logging, get_logger
from app.core.config import get_settings
from app.db.session import SessionLocal

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger("worker")


async def purge_expired_otp() -> None:
    """Expired challenges still carry a phone fingerprint. Drop them on a schedule so
    the retention window for that data is an hour, not forever."""
    async with SessionLocal() as db:
        await db.execute(text("SELECT purge_expired_otp()"))
        await db.commit()


async def purge_orphan_attachments() -> None:
    """An upload authorized but never attached to a message is dead weight in the
    bucket and a small privacy liability. Anything unattached after 24h goes."""
    async with SessionLocal() as db:
        result = await db.execute(text(
            "DELETE FROM attachments WHERE message_id IS NULL "
            "AND created_at < now() - interval '24 hours' RETURNING storage_key"))
        keys = [row[0] for row in result]
        await db.commit()
    if keys:
        log.info("orphan_attachments_purged", count=len(keys))
        # Object deletion is handled by services/storage.py in the next phase.


async def main() -> None:
    log.info("worker_started")
    while True:
        try:
            await purge_expired_otp()
            await purge_orphan_attachments()
        except Exception as exc:
            log.error("worker_cycle_failed", error=type(exc).__name__)
        await asyncio.sleep(300)


if __name__ == "__main__":
    asyncio.run(main())
