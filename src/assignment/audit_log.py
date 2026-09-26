"""
Assignment 11 — Audit Log starter.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        key = request_id or user_id
        import time
        self._open[key] = {
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
            "start_time": time.time(),
            "start_iso": utc_now_iso()
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        key = request_id or user_id
        import time
        now = time.time()
        
        log_entry = {
            "user_id": user_id,
            "request_id": request_id,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "end_iso": utc_now_iso()
        }
        
        if key in self._open:
            data = self._open.pop(key)
            log_entry["input"] = data["input"]
            log_entry["start_iso"] = data["start_iso"]
            log_entry["latency_sec"] = round(now - data["start_time"], 3)
            
        self.logs.append(log_entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = filepath or default_audit_log_path()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
