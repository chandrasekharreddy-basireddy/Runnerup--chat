"""Distributed sliding-window rate limiting.

Implemented as a Lua script so the read-decide-write cycle is atomic across replicas.
A naive INCR + EXPIRE pair loses its expiry under a crash and can be raced into
allowing double the intended budget.

A fixed window is not good enough for OTP: an attacker aligned to the window boundary
gets 2x the budget in a moment. This is a true sliding window over a sorted set.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from app.core.redis import get_redis

# KEYS[1] = bucket   ARGV = now_ms, window_ms, limit, member
_SLIDING_WINDOW = """
local bucket = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', bucket, '-inf', now - window)
local used = redis.call('ZCARD', bucket)
if used >= limit then
  local oldest = redis.call('ZRANGE', bucket, 0, 0, 'WITHSCORES')
  local retry = window - (now - tonumber(oldest[2]))
  return {0, used, retry}
end
redis.call('ZADD', bucket, now, member)
redis.call('PEXPIRE', bucket, window)
return {1, used + 1, 0}
"""


@dataclass(frozen=True)
class Limit:
    limit: int
    window_seconds: int


@dataclass(frozen=True)
class Decision:
    allowed: bool
    used: int
    retry_after_seconds: int


# Named budgets. Tuned so a real person never notices and a script always does.
LIMITS: dict[str, Limit] = {
    "otp:request:phone":  Limit(3, 900),      # 3 codes per number per 15 min
    "otp:request:ip":     Limit(10, 900),     # blunts bulk enumeration from one host
    "otp:verify:phone":   Limit(10, 900),
    "otp:verify:ip":      Limit(30, 900),
    "auth:refresh:ip":    Limit(120, 3600),
    "message:send:user":  Limit(30, 10),      # burst-friendly, flood-hostile
    "message:send:conv":  Limit(120, 10),
    "message:edit:user":  Limit(20, 60),
    "search:user":        Limit(20, 60),
    "upload:init:user":   Limit(20, 300),
    "conversation:create:user": Limit(10, 3600),
    "invite:create:user": Limit(20, 3600),
    "report:create:user": Limit(10, 3600),
    "ws:event:connection": Limit(60, 10),
    "ws:connect:user":    Limit(20, 60),
}


async def check(name: str, identity: str, *, cost: int = 1) -> Decision:
    """`identity` is whatever the budget is scoped to — an IP, a phone hash, a user id.
    Scoping by more than one dimension means calling this more than once; that is
    intentional, since a single composite key lets an attacker vary one dimension to
    reset the other."""
    spec = LIMITS[name]
    redis = get_redis()
    now_ms = int(time.time() * 1000)
    bucket = f"rl:{name}:{identity}"

    for i in range(cost):
        allowed, used, retry_ms = await redis.eval(
            _SLIDING_WINDOW, 1, bucket,
            now_ms, spec.window_seconds * 1000, spec.limit, f"{now_ms}-{i}",
        )
        if not allowed:
            return Decision(False, int(used), max(1, int(retry_ms) // 1000))
    return Decision(True, int(used), 0)


async def enforce(name: str, identity: str) -> None:
    from app.core.errors import RateLimited
    decision = await check(name, identity)
    if not decision.allowed:
        raise RateLimited(decision.retry_after_seconds)
