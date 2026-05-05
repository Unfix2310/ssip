import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from psycopg import AsyncConnection

from app.config import settings
from app.models import GovernanceReport, RuleAction
from app.services.observability import log_json


@dataclass
class AuditEvent:
    event_id: str
    ts: datetime
    tenant_id: str
    blocked: bool
    reason: str | None
    redacted_prompt: str
    actions: list[dict[str, Any]]
    request_id: str
    auth_subject: str
    policy_version: str


class AuditLogger:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=settings.audit_queue_maxsize)
        self._worker_task: asyncio.Task[None] | None = None
        self._running = False
        self._last_hash = "GENESIS"
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        await self._init_schema()
        await self._load_chain_head()
        self._running = True
        self._worker_task = asyncio.create_task(self._worker(), name="audit-worker")

    async def stop(self) -> None:
        self._running = False
        if self._worker_task is None:
            return
        try:
            await asyncio.wait_for(self._worker_task, timeout=5.0)
        except asyncio.TimeoutError:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def _init_schema(self) -> None:
        async with await AsyncConnection.connect(settings.postgres_dsn) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id BIGSERIAL PRIMARY KEY,
                        event_id UUID NOT NULL UNIQUE,
                        ts TIMESTAMPTZ NOT NULL,
                        tenant_id TEXT NOT NULL,
                        blocked BOOLEAN NOT NULL,
                        reason TEXT,
                        redacted_prompt TEXT NOT NULL,
                        actions JSONB NOT NULL,
                        request_id TEXT NOT NULL,
                        auth_subject TEXT NOT NULL,
                        policy_version TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL
                    );
                    """
                )
                await cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts
                    ON audit_logs (tenant_id, ts DESC);
                    """
                )
                await conn.commit()

    async def _load_chain_head(self) -> None:
        async with await AsyncConnection.connect(settings.postgres_dsn) as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT event_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
                row = await cur.fetchone()
                if row:
                    self._last_hash = str(row[0])

    async def log(
        self,
        tenant_id: str,
        blocked: bool,
        reason: str | None,
        redacted_prompt: str,
        actions: list[RuleAction],
        request_id: str,
        auth_subject: str,
        policy_version: str,
    ) -> None:
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            tenant_id=tenant_id,
            blocked=blocked,
            reason=reason,
            redacted_prompt=redacted_prompt,
            actions=[a.model_dump() for a in actions],
            request_id=request_id,
            auth_subject=auth_subject,
            policy_version=policy_version,
        )
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Deterministic hot-path should not block on audit saturation.
            log_json("audit_queue_full_drop", tenant_id=tenant_id, request_id=request_id)

    async def _worker(self) -> None:
        while True:
            try:
                first = await asyncio.wait_for(self.queue.get(), timeout=settings.audit_flush_seconds)
            except asyncio.TimeoutError:
                if not self._running and self.queue.empty():
                    break
                continue

            batch = [first]
            while len(batch) < settings.audit_batch_size and not self.queue.empty():
                batch.append(self.queue.get_nowait())

            try:
                await self._write_batch(batch)
            except Exception as exc:
                log_json("audit_batch_write_error", error=str(exc), batch_size=len(batch))
                for event in batch:
                    try:
                        self.queue.put_nowait(event)
                    except asyncio.QueueFull:
                        log_json("audit_queue_full_drop", tenant_id=event.tenant_id, request_id=event.request_id)
                        break
                await asyncio.sleep(0.2)

    def _hash_event(self, prev_hash: str, event: AuditEvent) -> str:
        canonical = json.dumps(
            {
                "event_id": event.event_id,
                "ts": event.ts.isoformat(),
                "tenant_id": event.tenant_id,
                "blocked": event.blocked,
                "reason": event.reason,
                "redacted_prompt": event.redacted_prompt,
                "actions": event.actions,
                "request_id": event.request_id,
                "auth_subject": event.auth_subject,
                "policy_version": event.policy_version,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()

    async def _write_batch(self, batch: list[AuditEvent]) -> None:
        async with self._lock:
            rows: list[tuple[Any, ...]] = []
            prev_hash = self._last_hash
            for event in batch:
                event_hash = self._hash_event(prev_hash, event)
                rows.append(
                    (
                        event.event_id,
                        event.ts,
                        event.tenant_id,
                        event.blocked,
                        event.reason,
                        event.redacted_prompt,
                        json.dumps(event.actions),
                        event.request_id,
                        event.auth_subject,
                        event.policy_version,
                        prev_hash,
                        event_hash,
                    )
                )
                prev_hash = event_hash

            async with await AsyncConnection.connect(settings.postgres_dsn) as conn:
                async with conn.cursor() as cur:
                    await cur.executemany(
                        """
                        INSERT INTO audit_logs (
                            event_id, ts, tenant_id, blocked, reason, redacted_prompt,
                            actions, request_id, auth_subject, policy_version, prev_hash, event_hash
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
                        """,
                        rows,
                    )
                    await conn.commit()
            self._last_hash = prev_hash

    async def readiness(self) -> bool:
        try:
            async with await AsyncConnection.connect(settings.postgres_dsn) as conn:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT 1")
                    await cur.fetchone()
            return True
        except Exception:
            return False

    async def report(self, tenant_id: str, from_ts: datetime, to_ts: datetime) -> GovernanceReport:
        async with await AsyncConnection.connect(settings.postgres_dsn) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT COUNT(*)::BIGINT, COALESCE(SUM(CASE WHEN blocked THEN 1 ELSE 0 END), 0)::BIGINT
                    FROM audit_logs
                    WHERE tenant_id = %s AND ts >= %s AND ts <= %s
                    """,
                    (tenant_id, from_ts, to_ts),
                )
                totals_row = await cur.fetchone()
                total_requests = int(totals_row[0]) if totals_row else 0
                blocked_requests = int(totals_row[1]) if totals_row else 0

                await cur.execute(
                    """
                    SELECT reason, COUNT(*)::BIGINT
                    FROM audit_logs
                    WHERE tenant_id = %s AND blocked = TRUE AND ts >= %s AND ts <= %s
                    GROUP BY reason
                    ORDER BY COUNT(*) DESC
                    LIMIT 5
                    """,
                    (tenant_id, from_ts, to_ts),
                )
                reasons_rows = await cur.fetchall()

        top_reasons = [{"reason": row[0] or "unknown", "count": int(row[1])} for row in reasons_rows]
        return GovernanceReport(
            tenant_id=tenant_id,
            from_ts=from_ts.isoformat(),
            to_ts=to_ts.isoformat(),
            total_requests=total_requests,
            blocked_requests=blocked_requests,
            top_block_reasons=top_reasons,
        )


audit_logger = AuditLogger()
