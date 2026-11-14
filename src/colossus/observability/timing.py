"""Read-only stage timing summary over the controller Store.

Sources, all read only:

* ``Store.audit()`` for ``task.claimed`` (start, per attempt) and ``task.completed`` (end).
* the ``tasks`` table for queue time, kind and payload. ``Store`` has no public task
  reader, so the table is read through a separate ``mode=ro`` SQLite connection opened on
  the same file. The Store's own connection is never used for queries here.

These are wall-clock timestamps written by the controller (``tasks.created_at`` is
``time.time()``, audit ``created_at`` is UTC ISO-8601). They are labelled
``clock="wall"``; monotonic durations exist only for spans produced by ``tracing``.
A missing timestamp yields ``None``, never zero.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from statistics import median
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from colossus.control.store import Store

COLD_WARM_KEYS = ("cache_state", "warm_state")


def iso_seconds(value: str | None) -> float | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _cold_warm(payload: dict, result: dict | None) -> str:
    """'cold' | 'warm' | 'unknown'. Only an explicit marker counts; nothing is inferred."""
    for source in (result or {}, payload):
        for key in COLD_WARM_KEYS:
            if source.get(key) in ("cold", "warm"):
                return source[key]
        if isinstance(source.get("warm"), bool):
            return "warm" if source["warm"] else "cold"
    return "unknown"


def _read_tasks(store: Store, project_id: str | None) -> list[dict]:
    with store.lock:
        databases = store.connection.execute("PRAGMA database_list").fetchall()
    path = next((row[2] for row in databases if row[1] == "main"), "")
    if not path:
        raise RuntimeError("Stage timing requires a file-backed Store")
    reader = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    reader.row_factory = sqlite3.Row
    try:
        sql = "SELECT id,project_id,kind,payload,state,attempt,created_at,result FROM tasks"
        args: tuple = ()
        if project_id is not None:
            sql += " WHERE project_id=?"
            args = (project_id,)
        rows = reader.execute(sql + " ORDER BY created_at,id", args).fetchall()
    finally:
        reader.close()
    return [dict(row) for row in rows]


def _delta(start: float | None, end: float | None) -> float | None:
    if start is None or end is None:
        return None
    return round(end - start, 6)


def stage_timings(store: Store, project_id: str | None = None) -> dict[str, Any]:
    tasks = _read_tasks(store, project_id)
    claims: dict[str, list[dict]] = {}
    completions: dict[str, dict] = {}
    for event in store.audit():
        data = event["data"]
        if event["kind"] == "task.claimed":
            claims.setdefault(data["task_id"], []).append(event)
        elif event["kind"] == "task.completed":
            completions[data["task_id"]] = event

    rows = []
    for task in tasks:
        payload = json.loads(task["payload"]) if task["payload"] else {}
        result = json.loads(task["result"]) if task["result"] else None
        queued = float(task["created_at"]) if task["created_at"] is not None else None
        attempts = []
        for claim in claims.get(task["id"], []):
            attempts.append(
                {"attempt": claim["data"].get("attempt"), "started_at": claim["created_at"]}
            )
        first_start = iso_seconds(attempts[0]["started_at"]) if attempts else None
        last_start = iso_seconds(attempts[-1]["started_at"]) if attempts else None
        done = completions.get(task["id"])
        end = iso_seconds(done["created_at"]) if done else None
        rows.append(
            {
                "task_id": task["id"],
                "project_id": task["project_id"],
                "stage": task["kind"],
                "state": task["state"],
                "attempts": task["attempt"],
                "claims": attempts,
                "queued_at_unix": queued,
                "started_at": attempts[0]["started_at"] if attempts else None,
                "ended_at": done["created_at"] if done else None,
                "success": done["data"].get("success") if done else None,
                "queue_wait_seconds": _delta(queued, first_start),
                "run_seconds": _delta(last_start, end),
                "total_seconds": _delta(queued, end),
                "cold_warm": _cold_warm(payload, result),
                "clock": "wall",
            }
        )

    stages: dict[str, dict] = {}
    for row in rows:
        stage = stages.setdefault(
            row["stage"],
            {
                "count": 0,
                "completed": 0,
                "retried": 0,
                "cold": 0,
                "warm": 0,
                "unknown": 0,
                "_queue": [],
                "_run": [],
            },
        )
        stage["count"] += 1
        stage["completed"] += row["ended_at"] is not None
        stage["retried"] += (row["attempts"] or 0) > 1
        stage[row["cold_warm"]] += 1
        if row["queue_wait_seconds"] is not None:
            stage["_queue"].append(row["queue_wait_seconds"])
        if row["run_seconds"] is not None:
            stage["_run"].append(row["run_seconds"])
    for stage in stages.values():
        for name in ("queue", "run"):
            values = stage.pop("_" + name)
            stage[f"{name}_seconds_median"] = round(median(values), 6) if values else None
            stage[f"{name}_seconds_max"] = max(values) if values else None
            stage[f"{name}_samples"] = len(values)
    return {"clock": "wall", "tasks": rows, "stages": dict(sorted(stages.items()))}
