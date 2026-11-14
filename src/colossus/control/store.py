"""Transactional controller state, idempotent operations and budget reservations."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from colossus.contracts.core import DomainError, canonical_json, content_hash, new_id, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, project_id TEXT, revision INTEGER NOT NULL,
 data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS records_kind_project ON records(kind,project_id,created_at);
CREATE TABLE IF NOT EXISTS operations(
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
 data TEXT NOT NULL, UNIQUE(actor,key)
);
CREATE TABLE IF NOT EXISTS audit_events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, project_id TEXT,
 kind TEXT NOT NULL, actor TEXT NOT NULL, data TEXT NOT NULL,
 previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks(
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
 state TEXT NOT NULL, lease_owner TEXT, lease_expires REAL, attempt INTEGER NOT NULL DEFAULT 0,
 deadline REAL NOT NULL, created_at REAL NOT NULL, result TEXT
);
CREATE INDEX IF NOT EXISTS tasks_queue ON tasks(state,created_at);
CREATE TABLE IF NOT EXISTS budget_reservations(
 call_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, reserved INTEGER NOT NULL CHECK(reserved>=0),
 actual INTEGER CHECK(actual>=0), status TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(
            path, isolation_level=None, check_same_thread=False, timeout=10
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=10000")
        self.connection.executescript(SCHEMA)
        self.connection.execute("INSERT OR IGNORE INTO schema_migrations VALUES (1,?)", (utcnow(),))
        self.lock = threading.RLock()

    def close(self):
        self.connection.close()

    @contextmanager
    def transaction(self):
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
                self.connection.execute("COMMIT")
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise

    def _event(self, db, kind: str, data: dict, project_id: str | None, actor: str):
        previous = db.execute(
            "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        now = utcnow()
        event = dict(
            created_at=now,
            project_id=project_id,
            kind=kind,
            actor=actor,
            data=data,
            previous_hash=previous_hash,
        )
        db.execute(
            "INSERT INTO audit_events(created_at,project_id,kind,actor,data,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
            (
                now,
                project_id,
                kind,
                actor,
                canonical_json(data).decode(),
                previous_hash,
                content_hash(event),
            ),
        )

    def event(
        self, kind: str, data: dict, project_id: str | None = None, actor: str = "controller"
    ):
        with self.transaction() as db:
            self._event(db, kind, data, project_id, actor)

    def audit(self, project_id: str | None = None) -> list[dict]:
        with self.lock:
            if project_id:
                rows = self.connection.execute(
                    "SELECT * FROM audit_events WHERE project_id=? ORDER BY seq", (project_id,)
                ).fetchall()
            else:
                rows = self.connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
            return [dict(row) | {"data": json.loads(row["data"])} for row in rows]

    def verify_audit(self) -> bool:
        previous_hash = "0" * 64
        for event in self.audit():
            fields = {
                k: event[k]
                for k in ("created_at", "project_id", "kind", "actor", "data", "previous_hash")
            }
            if (
                event["previous_hash"] != previous_hash
                or content_hash(fields) != event["event_hash"]
            ):
                return False
            previous_hash = event["event_hash"]
        return True

    def _put(
        self,
        db,
        kind: str,
        record_id: str,
        data: dict,
        project_id: str | None,
        expected_revision: int | None = None,
    ):
        old = db.execute(
            "SELECT revision,kind,project_id FROM records WHERE id=?", (record_id,)
        ).fetchone()
        if old and (old["kind"] != kind or old["project_id"] != project_id):
            raise DomainError("record_scope_mismatch", "Record identity cannot change scope")
        revision = old["revision"] if old else 0
        if expected_revision is not None and revision != expected_revision:
            raise DomainError("stale_revision", "Resource changed; refresh before retrying")
        now = utcnow()
        revision += 1
        data = data | {"revision": revision}
        db.execute(
            """INSERT INTO records VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,data=excluded.data,updated_at=excluded.updated_at""",
            (record_id, kind, project_id, revision, canonical_json(data).decode(), now, now),
        )
        self._event(
            db,
            f"{kind}.updated",
            {"id": record_id, "revision": revision, "data_hash": content_hash(data)},
            project_id,
            "controller",
        )
        return data

    def put(
        self,
        kind: str,
        record_id: str,
        data: dict,
        project_id: str | None = None,
        expected_revision: int | None = None,
    ) -> dict:
        with self.transaction() as db:
            return self._put(db, kind, record_id, data, project_id, expected_revision)

    def get(self, kind: str, record_id: str, project_id: str | None = None) -> dict:
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM records WHERE kind=? AND id=?", (kind, record_id)
            ).fetchone()
        if row is None or (project_id is not None and row["project_id"] != project_id):
            raise DomainError("not_found", "Resource not found", 404)
        return json.loads(row["data"])

    def list(
        self, kind: str, project_id: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise DomainError("invalid_pagination", "Invalid pagination", 422)
        sql = "SELECT data FROM records WHERE kind=?"
        args: list[Any] = [kind]
        if project_id is not None:
            sql += " AND project_id=?"
            args.append(project_id)
        sql += " ORDER BY created_at DESC,id LIMIT ? OFFSET ?"
        with self.lock:
            rows = self.connection.execute(sql, (*args, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def mutate(self, actor: str, key: str, kind: str, request: dict, action) -> dict:
        """Commit the side-effect intent and its operation receipt together."""
        if not key or len(key) > 200:
            raise DomainError("invalid_idempotency_key", "Provide an idempotency key", 422)
        request_hash = content_hash({"kind": kind, "request": request})
        with self.transaction() as db:
            old = db.execute(
                "SELECT * FROM operations WHERE actor=? AND key=?", (actor, key)
            ).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise DomainError(
                        "idempotency_conflict", "Key was already used for a different request"
                    )
                return json.loads(old["data"])
            operation_id = new_id()
            resources = action(db, operation_id)
            now = utcnow()
            receipt = dict(
                operation_id=operation_id,
                idempotency_key=key,
                request_hash=request_hash,
                kind=kind,
                resource_ids=resources,
                status="accepted",
                reason_code=None,
                created_at=now,
                updated_at=now,
                result_ref=None,
            )
            db.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?)",
                (operation_id, actor, key, request_hash, canonical_json(receipt).decode()),
            )
            self._event(
                db,
                "operation.accepted",
                {"operation_id": operation_id, "kind": kind, "request_hash": request_hash},
                resources.get("project_id"),
                actor,
            )
            return receipt

    def operation(self, operation_id: str) -> dict:
        with self.lock:
            row = self.connection.execute(
                "SELECT data FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
        if not row:
            raise DomainError("not_found", "Operation not found", 404)
        return json.loads(row[0])

    def finish_operation(self, operation_id: str, status: str, reason: str | None = None):
        if status not in ("running", "succeeded", "failed"):
            raise ValueError("Invalid operation status")
        with self.transaction() as db:
            row = db.execute("SELECT data FROM operations WHERE id=?", (operation_id,)).fetchone()
            if not row:
                raise DomainError("not_found", "Operation not found", 404)
            result = json.loads(row[0]) | {
                "status": status,
                "reason_code": reason,
                "updated_at": utcnow(),
            }
            db.execute(
                "UPDATE operations SET data=? WHERE id=?",
                (canonical_json(result).decode(), operation_id),
            )
            self._event(
                db,
                "operation." + status,
                {"operation_id": operation_id, "reason": reason},
                result["resource_ids"].get("project_id"),
                "controller",
            )

    def enqueue(self, db, project_id: str, kind: str, payload: dict, deadline: float) -> str:
        task_id = new_id()
        db.execute(
            "INSERT INTO tasks(id,project_id,kind,payload,state,deadline,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                task_id,
                project_id,
                kind,
                canonical_json(payload).decode(),
                "queued",
                deadline,
                time.time(),
            ),
        )
        return task_id

    def claim(self, owner: str, lease_seconds: int = 60) -> dict | None:
        now = time.time()
        with self.transaction() as db:
            db.execute(
                "UPDATE tasks SET state='expired' WHERE state='queued' AND deadline<=?", (now,)
            )
            task = db.execute(
                """SELECT tasks.* FROM tasks LEFT JOIN records ON records.id=tasks.project_id
                   WHERE tasks.state='queued' AND (tasks.kind='rollback'
                   OR COALESCE(json_extract(records.data,'$.admission_state'),'active')='active')
                   ORDER BY tasks.created_at LIMIT 1"""
            ).fetchone()
            if task is None:
                return None
            db.execute(
                "UPDATE tasks SET state='running',lease_owner=?,lease_expires=?,attempt=attempt+1 WHERE id=?",
                (owner, min(now + lease_seconds, task["deadline"]), task["id"]),
            )
            self._event(
                db,
                "task.claimed",
                {"task_id": task["id"], "attempt": task["attempt"] + 1},
                task["project_id"],
                owner,
            )
            return dict(task) | {
                "payload": json.loads(task["payload"]),
                "lease_owner": owner,
                "attempt": task["attempt"] + 1,
            }

    def heartbeat(self, task_id: str, owner: str, attempt: int, lease_seconds: int = 60) -> bool:
        now = time.time()
        with self.transaction() as db:
            cursor = db.execute(
                """UPDATE tasks SET lease_expires=MIN(?,deadline)
                WHERE id=? AND lease_owner=? AND attempt=? AND state='running' AND lease_expires>? AND deadline>?""",
                (now + lease_seconds, task_id, owner, attempt, now, now),
            )
            return cursor.rowcount == 1

    def complete_task(self, task_id: str, owner: str, attempt: int, result: dict, success: bool):
        now = time.time()
        with self.transaction() as db:
            cursor = db.execute(
                """UPDATE tasks SET state=?,result=?,lease_expires=NULL
                WHERE id=? AND lease_owner=? AND attempt=? AND state='running' AND lease_expires>? AND deadline>?""",
                (
                    "succeeded" if success else "failed",
                    canonical_json(result).decode(),
                    task_id,
                    owner,
                    attempt,
                    now,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                raise DomainError("stale_task", "Result belongs to an expired or superseded task")
            self._event(
                db,
                "task.completed",
                {"task_id": task_id, "success": success, "result_hash": content_hash(result)},
                None,
                owner,
            )

    def reserve(
        self,
        call_id: str,
        case_id: str,
        amount: int,
        global_cap: int,
        case_cap: int,
        max_calls: int = 20,
    ):
        if type(amount) is not int or amount < 0:
            raise ValueError("Reservation must be nonnegative integer micro-USD")
        with self.transaction() as db:
            old = db.execute(
                "SELECT * FROM budget_reservations WHERE call_id=?", (call_id,)
            ).fetchone()
            if old:
                if old["case_id"] != case_id or old["reserved"] != amount:
                    raise DomainError("reservation_conflict", "Call reservation differs")
                return
            global_used = db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual,reserved)),0) FROM budget_reservations"
            ).fetchone()[0]
            case_used, calls = db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual,reserved)),0),COUNT(*) FROM budget_reservations WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if (
                global_used + amount > global_cap
                or case_used + amount > case_cap
                or calls >= max_calls
            ):
                raise DomainError("budget_stop", "Model budget or request cap reached")
            db.execute(
                "INSERT INTO budget_reservations VALUES(?,?,?,?,?,?)",
                (call_id, case_id, amount, None, "reserved", utcnow()),
            )
            self._event(
                db,
                "budget.reserved",
                {"call_id": call_id, "case_id": case_id, "micro_usd": amount},
                None,
                "controller",
            )

    def reconcile(self, call_id: str, actual: int | None):
        if actual is not None and (type(actual) is not int or actual < 0):
            raise ValueError("Actual cost must be nonnegative micro-USD or unknown")
        with self.transaction() as db:
            old = db.execute(
                "SELECT * FROM budget_reservations WHERE call_id=?", (call_id,)
            ).fetchone()
            if old is None:
                raise DomainError("not_found", "Reservation not found", 404)
            if old["actual"] is not None:
                if old["actual"] != actual:
                    raise DomainError("cost_conflict", "Reconciled charge cannot change silently")
                return
            db.execute(
                "UPDATE budget_reservations SET actual=?,status=? WHERE call_id=?",
                (actual, "settled" if actual is not None else "uncertain", call_id),
            )
            self._event(
                db,
                "budget.reconciled",
                {"call_id": call_id, "actual_micro_usd": actual},
                None,
                "controller",
            )

    def budget(self, case_id: str | None = None) -> dict:
        query = "SELECT COALESCE(SUM(COALESCE(actual,reserved)),0),COALESCE(SUM(actual),0),COUNT(*) FROM budget_reservations"
        args = ()
        if case_id:
            query += " WHERE case_id=?"
            args = (case_id,)
        with self.lock:
            total, actual, calls = self.connection.execute(query, args).fetchone()
        return {
            "committed_micro_usd": total,
            "settled_micro_usd": actual,
            "calls": calls,
            "uncertain_micro_usd": total - actual,
        }
