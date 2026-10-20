from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from vigil.core.models import AgentResult, AlertEnvelope, CaseReport, EvidenceRecord


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VigilStore:
    """Small SQLite repository. Each operation owns its connection for worker safety."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
                INSERT OR IGNORE INTO schema_version(version) VALUES (1);
                CREATE TABLE IF NOT EXISTS cases(
                    case_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, status TEXT NOT NULL,
                    alert_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ix_cases_alert ON cases(alert_id);
                CREATE TABLE IF NOT EXISTS agent_runs(
                    run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
                    agent_id TEXT NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL,
                    model_id TEXT NOT NULL, result_json TEXT NOT NULL, started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_runs_case_agent ON agent_runs(case_id, agent_id);
                CREATE TABLE IF NOT EXISTS evidence(
                    evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
                    native_event_id TEXT NOT NULL, source_type TEXT NOT NULL, record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_evidence_case ON evidence(case_id);
                CREATE TABLE IF NOT EXISTS tool_calls(
                    call_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
                    agent_id TEXT NOT NULL, tool_name TEXT NOT NULL, status TEXT NOT NULL,
                    call_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memories(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL, kind TEXT NOT NULL, content_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_memory_namespace ON memories(case_id, agent_id);
                CREATE TABLE IF NOT EXISTS model_assignments(
                    agent_id TEXT PRIMARY KEY, provider TEXT NOT NULL, model_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delegations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
                    source_agent TEXT NOT NULL, target_agent TEXT NOT NULL,
                    purpose TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports(
                    case_id TEXT PRIMARY KEY REFERENCES cases(case_id), report_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs(
                    job_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
                    status TEXT NOT NULL, payload_json TEXT NOT NULL,
                    idempotency_key TEXT UNIQUE, attempts INTEGER NOT NULL DEFAULT 0,
                    error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status, created_at);
                """
            )

    def create_case(self, alert: AlertEnvelope, *, reuse_alert: bool = False) -> str:
        with self.connect() as conn:
            if reuse_alert:
                row = conn.execute("SELECT case_id FROM cases WHERE alert_id=?", (alert.alert_id,)).fetchone()
                if row:
                    return str(row["case_id"])
            case_id = f"case-{uuid4().hex[:12]}"
            now = _now()
            conn.execute(
                "INSERT INTO cases VALUES(?,?,?,?,?,?)",
                (case_id, alert.alert_id, "queued", alert.model_dump_json(), now, now),
            )
            return case_id

    def ensure_case(self, case_id: str, alert: AlertEnvelope) -> None:
        with self.connect() as conn:
            if not conn.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
                now = _now()
                conn.execute("INSERT INTO cases VALUES(?,?,?,?,?,?)", (case_id, alert.alert_id, "queued", alert.model_dump_json(), now, now))

    def set_case_status(self, case_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE cases SET status=?, updated_at=? WHERE case_id=?", (status, _now(), case_id))

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            return dict(row) if row else None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT case_id,alert_id,status,created_at,updated_at FROM cases ORDER BY created_at DESC LIMIT ?", (min(limit, 200),))]

    def save_evidence(self, records: list[EvidenceRecord]) -> None:
        with self.connect() as conn:
            for item in records:
                conn.execute(
                    "INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?)",
                    (item.evidence_id, item.case_id, item.native_event_id, item.source_type, item.model_dump_json()),
                )

    def evidence_for_case(self, case_id: str) -> list[EvidenceRecord]:
        with self.connect() as conn:
            rows = conn.execute("SELECT record_json FROM evidence WHERE case_id=?", (case_id,)).fetchall()
            return [EvidenceRecord.model_validate_json(r[0]) for r in rows]

    def save_result(self, result: AgentResult) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_runs VALUES(?,?,?,?,?,?,?,?,?)",
                (result.run_id, result.case_id, result.agent_id, result.run_status.value, result.model_provider,
                 result.model_id, result.model_dump_json(), result.started_at.isoformat(), result.completed_at.isoformat()),
            )
            for call in result.tool_calls:
                conn.execute(
                    "INSERT OR REPLACE INTO tool_calls VALUES(?,?,?,?,?,?)",
                    (call.call_id, result.run_id, result.agent_id, call.tool_name, call.status, call.model_dump_json()),
                )
            conn.execute("UPDATE cases SET status=?, updated_at=? WHERE case_id=?", (result.run_status.value, _now(), result.case_id))

    def results_for_case(self, case_id: str) -> list[AgentResult]:
        with self.connect() as conn:
            rows = conn.execute("SELECT result_json FROM agent_runs WHERE case_id=? ORDER BY started_at", (case_id,)).fetchall()
            return [AgentResult.model_validate_json(r[0]) for r in rows]

    def append_memory(self, case_id: str, agent_id: str, kind: str, content: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO memories(case_id,agent_id,kind,content_json,created_at) VALUES(?,?,?,?,?)", (case_id, agent_id, kind, json.dumps(content), _now()))

    def load_memory(self, case_id: str, agent_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT kind,content_json,created_at FROM memories WHERE case_id=? AND agent_id=? ORDER BY id DESC LIMIT ?", (case_id, agent_id, min(limit, 100))).fetchall()
            return [{"kind": r[0], "content": json.loads(r[1]), "created_at": r[2]} for r in rows]

    def set_assignment(self, agent_id: str, provider: str, model_id: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO model_assignments VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET provider=excluded.provider,model_id=excluded.model_id,updated_at=excluded.updated_at", (agent_id, provider, model_id, _now()))

    def get_assignment(self, agent_id: str) -> tuple[str, str]:
        with self.connect() as conn:
            row = conn.execute("SELECT provider,model_id FROM model_assignments WHERE agent_id=?", (agent_id,)).fetchone()
            return (str(row[0]), str(row[1])) if row else ("offline", "deterministic-readonly-v1")

    def all_assignments(self) -> dict[str, tuple[str, str]]:
        with self.connect() as conn:
            return {str(r[0]): (str(r[1]), str(r[2])) for r in conn.execute("SELECT agent_id,provider,model_id FROM model_assignments")}

    def record_delegation(self, case_id: str, source: str, target: str, purpose: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO delegations(case_id,source_agent,target_agent,purpose,status,created_at) VALUES(?,?,?,?,?,?)", (case_id, source, target, purpose, status, _now()))

    def save_report(self, report: CaseReport) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO reports VALUES(?,?,?) ON CONFLICT(case_id) DO UPDATE SET report_json=excluded.report_json,updated_at=excluded.updated_at", (report.case_id, report.model_dump_json(), _now()))

    def get_report(self, case_id: str) -> CaseReport | None:
        with self.connect() as conn:
            row = conn.execute("SELECT report_json FROM reports WHERE case_id=?", (case_id,)).fetchone()
            return CaseReport.model_validate_json(row[0]) if row else None

    def enqueue_job(self, case_id: str, payload: dict[str, Any], idempotency_key: str | None) -> tuple[str, bool]:
        with self.connect() as conn:
            if idempotency_key:
                row = conn.execute("SELECT job_id FROM jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if row:
                    return str(row[0]), False
            job_id = f"job-{uuid4().hex[:12]}"
            now = _now()
            conn.execute("INSERT INTO jobs VALUES(?,?,?,?,?,0,NULL,?,?)", (job_id, case_id, "queued", json.dumps(payload), idempotency_key, now, now))
            return job_id, True

    def get_job_by_idempotency(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            return dict(row) if row else None

    def claim_job(self) -> dict[str, Any] | None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM jobs WHERE status IN ('queued','running') ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, created_at LIMIT 1").fetchone()
            if not row:
                return None
            conn.execute("UPDATE jobs SET status='running',attempts=attempts+1,updated_at=? WHERE job_id=?", (_now(), row["job_id"]))
            result = dict(row)
            result["status"] = "running"
            return result

    def update_job(self, job_id: str, status: str, error: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET status=?,error=?,updated_at=? WHERE job_id=?", (status, error, _now(), job_id))

    def get_job_for_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE case_id=? ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
            return dict(row) if row else None

