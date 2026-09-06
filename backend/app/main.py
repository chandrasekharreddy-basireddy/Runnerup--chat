"""Application entrypoint.

Security headers are set here as well as at the edge proxy. Duplication is deliberate:
in the managed deployment the API sits behind Render's router rather than our nginx, and
a header that only exists in a config file we are not running is not a header.
"""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import auth
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger, request_id_ctx
from app.core.redis import close_redis, get_redis
from app.ws import router as ws_router
from app.ws.manager import manager

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger("http")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await get_redis().ping()
    await manager.start()
    log.info("startup", environment=settings.environment)
    yield
    await manager.stop()
    await close_redis()


app = FastAPI(
    title="Chat API",
    version="0.1.0",
    lifespan=lifespan,
    # Schema browsers are disabled in production: a public endpoint inventory is free
    # reconnaissance and there is no reason to hand it out.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,   # exact origins, never "*"
    allow_credentials=True,                   # required for the refresh cookie
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    max_age=600,
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    request_id_ctx.set(request_id)
    started = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        log.exception("unhandled_error", path=request.url.path, method=request.method)
        # Never leak a stack trace or an internal message to the client.
        return JSONResponse(status_code=500, content={"detail": "internal_error"},
                            headers={"X-Request-ID": request_id})

    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    log.info("request", method=request.method, path=request.url.path,
             status=response.status_code, duration_ms=duration_ms)
    return response


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}


app.include_router(auth.router, prefix="/api/v1")
app.include_router(ws_router.router)
