"""
Redis connection — Group 16 (caching, temporary state, alert queues,
background jobs, rate limiting, real-time dashboard events).
"""

import redis

from app.core.config import settings

_pool = redis.ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True,
)


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_pool)


# --- Convenience helpers used by services/alerting.py and the ingestion worker ---

ALERT_QUEUE_KEY = "honeyshield:alert_queue"
INGESTION_CHECKPOINT_PREFIX = "honeyshield:ingestion_checkpoint:"
RATE_LIMIT_PREFIX = "honeyshield:rate_limit:"


def push_alert(alert_payload: str):
    get_redis().lpush(ALERT_QUEUE_KEY, alert_payload)


def pop_alert(timeout_seconds: int = 5):
    result = get_redis().brpop(ALERT_QUEUE_KEY, timeout=timeout_seconds)
    return result[1] if result else None


def get_ingestion_checkpoint(source: str) -> str | None:
    return get_redis().get(f"{INGESTION_CHECKPOINT_PREFIX}{source}")


def set_ingestion_checkpoint(source: str, value: str):
    get_redis().set(f"{INGESTION_CHECKPOINT_PREFIX}{source}", value)


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Simple fixed-window rate limiter. Returns True if the request is
    allowed, False if the caller has exceeded max_requests in the window."""
    r = get_redis()
    full_key = f"{RATE_LIMIT_PREFIX}{key}"
    count = r.incr(full_key)
    if count == 1:
        r.expire(full_key, window_seconds)
    return count <= max_requests


