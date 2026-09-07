"""Object storage: presigned uploads, independent validation, signed downloads.

The upload flow never lets the client's claims about a file matter:

    authorize -> presign PUT to a random key -> client uploads directly to storage
              -> server re-reads the object -> validates size and magic bytes
              -> marks READY -> only then can it be attached to a message

Bytes go client-to-storage directly, so a 50 MB upload never occupies an API worker.
But the *decision* about what the file is happens server-side, after the upload, by
reading the actual leading bytes. Filename, extension and Content-Type are all
attacker-controlled and are treated as display metadata only.

The storage key is server-generated and random. A user-supplied name is never used to
build a path, which is what makes `../../etc/passwd` a non-event here.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

import aioboto3
from botocore.config import Config

from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.core.logging import get_logger

log = get_logger("storage")
settings = get_settings()

# Allow-list, not a deny-list. A deny-list of dangerous types is a losing game: every
# new container format is a bypass until someone remembers to add it.
ALLOWED_MIME: dict[str, tuple[bytes, ...]] = {
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": (b"RIFF",),
    "video/mp4": (b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x1cftyp", b"\x00\x00\x00 ftyp"),
    "audio/mpeg": (b"ID3", b"\xff\xfb"),
    "audio/ogg": (b"OggS",),
    "audio/webm": (b"\x1a\x45\xdf\xa3"),
    "application/pdf": (b"%PDF-",),
}

# Never accepted, whatever the magic bytes say. Belt and braces against an allow-list
# entry that turns out to be a polyglot container.
BLOCKED_EXTENSIONS = {
    "exe", "dll", "so", "dylib", "bat", "cmd", "com", "scr", "msi", "app",
    "sh", "bash", "zsh", "ps1", "psm1", "vbs", "js", "jar", "class", "py",
    "rb", "pl", "php", "asp", "aspx", "jsp", "cgi", "html", "htm", "svg",
}

MAGIC_PREFIX_BYTES = 32


@dataclass(frozen=True)
class UploadGrant:
    attachment_id: str
    storage_key: str
    upload_url: str
    expires_in: int


def sanitize_filename(raw: str) -> str:
    """Produce a safe *display* name. This value never touches the filesystem or the
    storage key — it exists so the recipient sees something meaningful."""
    name = raw.strip().replace("\x00", "")
    name = re.sub(r"[\\/]", "_", name)          # no path separators
    name = re.sub(r"\.{2,}", ".", name)         # no traversal sequences
    name = re.sub(r"[^\w\s.\-()\[\]]", "", name, flags=re.UNICODE)
    name = name.strip(". ") or "file"
    return name[:200]


def extension_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _session():
    return aioboto3.Session()


def _client_kwargs() -> dict:
    return {
        "endpoint_url": settings.s3_endpoint,
        "aws_access_key_id": settings.s3_access_key,
        "aws_secret_access_key": settings.s3_secret_key,
        "region_name": settings.s3_region,
        "config": Config(signature_version="s3v4", retries={"max_attempts": 3}),
    }


async def create_upload_grant(*, owner_id: uuid.UUID, declared_name: str,
                              declared_mime: str, declared_size: int) -> UploadGrant:
    if declared_size <= 0 or declared_size > settings.max_upload_bytes:
        raise ValidationFailed("file_too_large")
    if extension_of(declared_name) in BLOCKED_EXTENSIONS:
        raise ValidationFailed("file_type_not_allowed")
    if declared_mime not in ALLOWED_MIME:
        raise ValidationFailed("file_type_not_allowed")

    attachment_id = uuid.uuid4()
    # Random, opaque, and namespaced by owner for lifecycle rules. Contains nothing the
    # user supplied.
    storage_key = f"u/{owner_id}/{attachment_id}/{uuid.uuid4().hex}"

    async with _session().client("s3", **_client_kwargs()) as s3:
        upload_url = await s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": settings.s3_bucket,
                "Key": storage_key,
                # Binding the length stops a client from presenting a 1 KB declaration
                # and then streaming a gigabyte.
                "ContentLength": declared_size,
            },
            ExpiresIn=settings.upload_url_ttl_seconds,
        )

    return UploadGrant(str(attachment_id), storage_key, upload_url,
                       settings.upload_url_ttl_seconds)


@dataclass(frozen=True)
class Probe:
    byte_size: int
    detected_mime: str | None


async def probe_object(storage_key: str) -> Probe:
    """Re-read the uploaded object and decide what it actually is.

    This is the step that makes the whole flow trustworthy. Everything before it was
    the client's assertion; this is the server's observation.
    """
    async with _session().client("s3", **_client_kwargs()) as s3:
        head = await s3.head_object(Bucket=settings.s3_bucket, Key=storage_key)
        size = head["ContentLength"]

        if size > settings.max_upload_bytes:
            raise ValidationFailed("file_too_large")

        # Range request: never pull a whole file into the API to identify it.
        body = await s3.get_object(
            Bucket=settings.s3_bucket, Key=storage_key,
            Range=f"bytes=0-{MAGIC_PREFIX_BYTES - 1}",
        )
        prefix = await body["Body"].read()

    detected = None
    for mime, signatures in ALLOWED_MIME.items():
        if any(prefix.startswith(sig) for sig in signatures):
            detected = mime
            break

    return Probe(byte_size=size, detected_mime=detected)


async def delete_object(storage_key: str) -> None:
    async with _session().client("s3", **_client_kwargs()) as s3:
        await s3.delete_object(Bucket=settings.s3_bucket, Key=storage_key)


async def signed_download_url(storage_key: str, *, display_name: str) -> str:
    """Short-lived and generated per request, after the caller's membership has been
    checked. The bucket itself is private; there is no public object URL to leak.

    Content-Disposition is forced to attachment: it stops the browser rendering a file
    inline in the storage origin, which would turn any uploaded document into a
    same-origin script execution opportunity on that domain.
    """
    async with _session().client("s3", **_client_kwargs()) as s3:
        return await s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": settings.s3_bucket,
                "Key": storage_key,
                "ResponseContentDisposition":
                    f'attachment; filename="{sanitize_filename(display_name)}"',
                "ResponseContentType": "application/octet-stream",
            },
            ExpiresIn=settings.download_url_ttl_seconds,
        )
