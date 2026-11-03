"""Bảng việc của API: mỗi yêu cầu dài nhận một mã việc ngay, chạy nền, trạng thái ghi trong SQLite.

- Một luồng làm việc, chạy **lần lượt** từng việc: hệ thống chạy trên một máy, và hai việc cùng nạp log lớn vào DuckDB một
  lúc từng làm hết bộ nhớ.
- Trạng thái: ``queued`` → ``running`` → ``done`` | ``failed``. Máy chủ tắt giữa chừng thì lần khởi động sau đổi mọi việc
  ``queued``/``running`` thành ``interrupted``: không chạy lại ngầm, không mất dấu.
- Việc lỗi ghi loại lỗi và thông điệp, không ghi traceback (có thể chứa đường dẫn máy).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, params TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, result TEXT, error TEXT)"""
STATUSES = ("queued", "running", "done", "failed", "interrupted")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JobStore:
    def __init__(self, path: Path, *, inline: bool = False):
        """``inline=True`` chạy việc ngay trong lời gọi ``submit`` (chỉ dùng cho test)."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as c:
            c.execute(SCHEMA)
            c.execute("UPDATE jobs SET status = 'interrupted', finished_at = ?, error = ? "
                      "WHERE status IN ('queued', 'running')", (_now(), "Máy chủ dừng trước khi việc xong"))
        self.inline = inline
        self._pool = None if inline else ThreadPoolExecutor(max_workers=1, thread_name_prefix="cti-job")

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _update(self, job_id: str, **fields) -> None:
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._lock, self._connect() as c:
            c.execute(f"UPDATE jobs SET {cols} WHERE id = ?", (*fields.values(), job_id))

    def submit(self, kind: str, params: dict, fn: Callable[[], dict]) -> str:
        job_id = uuid.uuid4().hex
        with self._lock, self._connect() as c:
            c.execute("INSERT INTO jobs (id, kind, params, status, created_at) VALUES (?, ?, ?, 'queued', ?)",
                      (job_id, kind, json.dumps(params, ensure_ascii=False), _now()))
        if self.inline:
            self._run(job_id, fn)
        else:
            self._pool.submit(self._run, job_id, fn)
        return job_id

    def _run(self, job_id: str, fn: Callable[[], dict]) -> None:
        self._update(job_id, status="running", started_at=_now())
        try:
            result = fn()
        except Exception as e:  # noqa: BLE001 — mọi lỗi của việc đều ghi lại, không làm chết luồng làm việc
            self._update(job_id, status="failed", finished_at=_now(), error=f"{type(e).__name__}: {e}"[:2000])
            return
        self._update(job_id, status="done", finished_at=_now(),
                     result=json.dumps(result, ensure_ascii=False, default=str))

    def get(self, job_id: str) -> dict | None:
        with self._connect() as c:
            row = c.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row(row) if row else None

    def list(self, limit: int = 20) -> list[dict]:
        with self._connect() as c:
            rows = c.execute("SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r, with_result=False) for r in rows]

    @staticmethod
    def _row(row: sqlite3.Row, with_result: bool = True) -> dict:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        d["result"] = json.loads(d["result"]) if with_result and d["result"] else None
        return d

    def shutdown(self, wait: bool = True) -> None:
        if self._pool:
            self._pool.shutdown(wait=wait)
