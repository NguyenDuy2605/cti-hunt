"""Kết nối truy vấn. Dùng DuckDB in-memory + view trên Parquet thay vì file .duckdb, để notebook và
CLI mở cùng lúc không bị khóa file (hay gặp trên Windows).

Quy ước khi viết truy vấn tay:
- Luôn lọc kèm channel: `ev_channel = '...' AND ev_eid = ...` (v3 §3.4: System cũng có EID 1).
- Kết nối đặt default_collation='nocase', nên '=' và IN không phân biệt hoa thường (giống ngữ nghĩa
  Sigma). LIKE thì KHÔNG theo collation: viết `lower(Image) LIKE '%\\x.exe'` hoặc dùng ILIKE.
  Trong chuỗi SQL của DuckDB, dấu \\ là ký tự thường, không cần escape.
- Trường gốc đều là VARCHAR; so số thì dùng cột ev_eid, ev_rec hoặc TRY_CAST.
"""
from __future__ import annotations

from pathlib import Path

import duckdb


def connect(work_dir: Path) -> duckdb.DuckDBPyConnection:
    parquet = work_dir / "events.parquet"
    if not parquet.exists():
        raise FileNotFoundError(f"Chưa có {parquet}. Chạy `python -m cti_hunt ingest` trước.")
    con = duckdb.connect()
    con.execute("SET enable_progress_bar=false")
    con.execute("SET default_collation='nocase'")
    con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet('{parquet.as_posix()}')")
    from ..filter_approval import register_events
    register_events(con, parquet)
    return con
