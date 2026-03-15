"""
Session manager with Redis backend. Multi-tenant: all data scoped by tenant_id.
Falls back to in-memory dict on Redis failure. Session schema: session_id, score,
turns (max 10), triggered_rules, created_at, last_seen.
"""

import json
import logging
import re
import time
from typing import Any

import config

logger = logging.getLogger(__name__)

EVENTS_MAX = 1000
KEY_PREFIX = "pw:tenant:"
SESSION_SUFFIX = ":session:"
EVENTS_SUFFIX = ":events"
TURNS_MAX = 10

# Tenant ID: alphanumeric, hyphen, underscore only (safe for Redis keys)
TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def _tenant_key(tenant_id: str) -> str:
    """Return normalized tenant key segment; fallback to default if invalid."""
    if not tenant_id or not TENANT_ID_PATTERN.match(tenant_id):
        return config.settings.DEFAULT_TENANT_ID
    return tenant_id


class SessionManager:
    """
    Async session storage per tenant. Redis keys: pw:tenant:{tenant_id}:session:{id},
    pw:tenant:{tenant_id}:events. On Redis failure, use in-memory fallback per tenant.
    """

    def __init__(self) -> None:
        # _memory[tenant_id][session_id] = session dict
        self._memory: dict[str, dict[str, dict]] = {}
        # _events_memory[tenant_id] = list of event dicts
        self._events_memory: dict[str, list[dict]] = {}
        self._redis = None
        self._use_redis = True

    async def _get_redis(self):
        """Lazy Redis connection. On failure set _use_redis = False."""
        if not self._use_redis:
            return None
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                config.settings.REDIS_URL,
                decode_responses=True,
            )
            await self._redis.ping()
            return self._redis
        except Exception as e:
            logger.warning("Redis connection failed, using in-memory fallback: %s", e)
            self._use_redis = False
            self._redis = None
            return None

    def _session_key(self, tenant_id: str, session_id: str) -> str:
        return KEY_PREFIX + _tenant_key(tenant_id) + SESSION_SUFFIX + session_id

    def _events_key(self, tenant_id: str) -> str:
        return KEY_PREFIX + _tenant_key(tenant_id) + EVENTS_SUFFIX

    async def get_session(self, tenant_id: str, session_id: str) -> dict:
        """Load session by tenant and session id. Returns empty session dict if not found."""
        tid = _tenant_key(tenant_id)
        default = {
            "session_id": session_id,
            "score": 0.0,
            "turns": [],
            "triggered_rules": [],
            "created_at": time.time(),
            "last_seen": time.time(),
        }
        r = await self._get_redis()
        if r is None:
            tenant_sessions = self._memory.setdefault(tid, {})
            return tenant_sessions.get(session_id, default)

        try:
            data = await r.get(self._session_key(tenant_id, session_id))
            if data is None:
                return default
            out = json.loads(data)
            out.setdefault("session_id", session_id)
            out.setdefault("score", 0.0)
            out.setdefault("turns", [])
            out.setdefault("triggered_rules", [])
            out.setdefault("created_at", time.time())
            out.setdefault("last_seen", time.time())
            return out
        except Exception as e:
            logger.warning("Redis get_session failed: %s", e)
            tenant_sessions = self._memory.setdefault(tid, {})
            return tenant_sessions.get(session_id, default)

    async def save_session(self, tenant_id: str, session_id: str, data: dict) -> None:
        """Save session with SETEX using SESSION_TTL; scoped to tenant."""
        tid = _tenant_key(tenant_id)
        data["last_seen"] = time.time()
        data["session_id"] = session_id
        turns = data.get("turns", [])
        if len(turns) > TURNS_MAX:
            data["turns"] = turns[-TURNS_MAX:]
        r = await self._get_redis()
        if r is None:
            self._memory.setdefault(tid, {})[session_id] = data
            return
        try:
            payload = json.dumps(data)
            await r.setex(
                self._session_key(tenant_id, session_id),
                config.settings.SESSION_TTL,
                payload,
            )
        except Exception as e:
            logger.warning("Redis save_session failed: %s", e)
            self._memory.setdefault(tid, {})[session_id] = data

    async def log_event(self, tenant_id: str, event: dict) -> None:
        """LPUSH to tenant events list and LTRIM to EVENTS_MAX."""
        tid = _tenant_key(tenant_id)
        r = await self._get_redis()
        if r is None:
            events = self._events_memory.setdefault(tid, [])
            events.insert(0, event)
            if len(events) > EVENTS_MAX:
                self._events_memory[tid] = events[:EVENTS_MAX]
            return
        try:
            key = self._events_key(tenant_id)
            await r.lpush(key, json.dumps(event))
            await r.ltrim(key, 0, EVENTS_MAX - 1)
        except Exception as e:
            logger.warning("Redis log_event failed: %s", e)
            events = self._events_memory.setdefault(tid, [])
            events.insert(0, event)
            if len(events) > EVENTS_MAX:
                self._events_memory[tid] = events[:EVENTS_MAX]

    async def get_events(self, tenant_id: str, limit: int = 100) -> list[dict]:
        """Return last `limit` events for the tenant."""
        tid = _tenant_key(tenant_id)
        r = await self._get_redis()
        if r is None:
            events = self._events_memory.get(tid, [])
            return events[:limit]
        try:
            raw = await r.lrange(self._events_key(tenant_id), 0, limit - 1)
            out = []
            for item in raw:
                try:
                    out.append(json.loads(item))
                except json.JSONDecodeError:
                    continue
            return out
        except Exception as e:
            logger.warning("Redis get_events failed: %s", e)
            events = self._events_memory.get(tid, [])
            return events[:limit]

    async def get_stats(self, tenant_id: str) -> dict:
        """Aggregate stats from tenant events: blocked/clean counts, rule frequency."""
        events = await self.get_events(tenant_id, limit=EVENTS_MAX)
        blocked = sum(1 for e in events if e.get("blocked") is True)
        clean = sum(1 for e in events if e.get("blocked") is False)
        rule_freq: dict[str, int] = {}
        for e in events:
            for r in e.get("rules", []) or []:
                rule_freq[r] = rule_freq.get(r, 0) + 1
        return {
            "tenant_id": _tenant_key(tenant_id),
            "total_events": len(events),
            "blocked": blocked,
            "clean": clean,
            "rule_frequency": rule_freq,
        }

    async def reset(self, tenant_id: str) -> None:
        """Delete all keys for the given tenant (sessions + events)."""
        tid = _tenant_key(tenant_id)
        if tid in self._memory:
            del self._memory[tid]
        if tid in self._events_memory:
            del self._events_memory[tid]
        r = await self._get_redis()
        if r is None:
            return
        try:
            pattern = KEY_PREFIX + tid + "*"
            keys = await r.keys(pattern)
            if keys:
                await r.delete(*keys)
        except Exception as e:
            logger.warning("Redis reset failed: %s", e)

    async def reset_all(self) -> None:
        """Delete all pw:tenant:* keys (all tenants). Use with care."""
        self._memory.clear()
        self._events_memory.clear()
        r = await self._get_redis()
        if r is None:
            return
        try:
            keys = await r.keys(KEY_PREFIX + "*")
            if keys:
                await r.delete(*keys)
        except Exception as e:
            logger.warning("Redis reset_all failed: %s", e)
