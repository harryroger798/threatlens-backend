import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.core.config import settings

_buckets: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request, principal: str, limit_per_minute: int | None = None) -> None:
    """Sliding-window rate limiter keyed per user/API principal."""
    limit = limit_per_minute or settings.RATE_LIMIT_PER_MINUTE
    key = f"{request.client.host if request.client else 'local'}:{principal}"
    now = time.monotonic()
    window = _buckets[key]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail={"error_code": "rate_limited", "message": "Rate limit exceeded"})
    window.append(now)
