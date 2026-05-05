import time
from collections import defaultdict, deque

import redis.asyncio as aioredis

from app.config import settings
from app.services.observability import log_json


class LocalSlidingWindow:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int) -> bool:
        now = time.time()
        window = self._events[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True


class RateLimiter:
    def __init__(self) -> None:
        self.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        self.local_fallback = LocalSlidingWindow()

    async def check(self, tenant_id: str, limit: int) -> tuple[bool, str]:
        minute_bucket = int(time.time() // 60)
        key = f"rl:{tenant_id}:{minute_bucket}"
        try:
            current = await self.redis.incr(key)
            if current == 1:
                await self.redis.expire(key, 90)
            return current <= limit, "redis"
        except Exception as exc:
            allowed = self.local_fallback.allow(tenant_id, limit)
            log_json("rate_limit_fallback", tenant_id=tenant_id, error=str(exc))
            return allowed, "local_fallback"

    async def readiness(self) -> bool:
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False


rate_limiter = RateLimiter()
