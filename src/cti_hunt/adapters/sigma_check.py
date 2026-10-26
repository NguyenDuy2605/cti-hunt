"""Chạy hàng loạt rule Sigma (vd toàn bộ SigmaHQ rules/windows) qua adapter DuckDB, phân loại kết quả.

Mục đích: tìm lỗi của adapter trước khi mô hình ở khâu ⑤ gặp chúng (lỗi `|re` 21/9 chỉ lộ ra khi thử modifier
thật). Một rule rơi vào đúng một nhóm:

    ok                   biên dịch và chạy được trên ít nhất một nguồn log
    loi_sigma            pySigma từ chối rule (lỗi của rule, không phải của adapter)
    ngoai_danh_muc       logsource không có trong configs/logsource_catalog.yaml (khoảng trống phạm vi, có chủ ý)
    thieu_truong         có logsource nhưng mọi nguồn bị bỏ vì thiếu trường
    loi_backend          pySigma/adapter không dịch được sang SQL  -> xem lý do, có thể là lỗ hổng adapter
    loi_sql              dịch được nhưng DuckDB từ chối khi chạy   -> lỗi adapter, phải sửa

Hai chế độ:
- Có kết nối dữ liệu thật: kiểm tên cột thật, chạy EXPLAIN trên `events`. Cho biết rule SigmaHQ nào chạy được trên
  dataset APT29 (dùng làm rule chuẩn cho execution accuracy, v3 §6.2).
- Không có dữ liệu: bảng tổng hợp tự thêm cột khi truy vấn cần, chạy thật một dòng — chỉ kiểm cú pháp SQL.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import duckdb
from sigma.collection import SigmaCollection

from . import duckdb_sigma as adapter

_MISSING_COL = re.compile(r'Referenced column "([^"]+)" not found')
_NUMERIC_CMP = re.compile(r"\b[A-Za-z_][\w.]*\s*(?:<=|>=|<|>)\s*-?\d+(?:\.\d+)?\b")


def _synthetic_con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute("SET default_collation='nocase'")
    con.execute("CREATE TABLE events (ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, "
                "ev_ts TIMESTAMP)")
    con.execute("INSERT INTO events VALUES ('H', 'c', 1, 1, TIMESTAMP '2020-05-02 08:00:00')")
    return con


def _run(con, sql: str, grow: bool) -> str | None:
    """Chạy truy vấn; chế độ tổng hợp thì thêm cột VARCHAR còn thiếu rồi chạy lại. Trả None nếu chạy được."""
    for _ in range(60):
        try:
            con.execute(sql).fetchall()
            return None
        except duckdb.Error as e:
            msg = str(e).splitlines()[0]
            m = _MISSING_COL.search(str(e))
            if grow and m:
                con.execute(f'ALTER TABLE events ADD COLUMN "{m.group(1)}" VARCHAR')
                continue
            return msg
    return "quá nhiều cột thiếu"


def check_rule(text: str, catalog: dict, con, columns: set[str] | None, grow: bool) -> dict:
    out = {"nhom": "", "ly_do": "", "nguon_ok": [], "ghi_chu": [], "so_sanh_so": False}
    try:
        coll = SigmaCollection.from_yaml(text, collect_errors=True)
        errs = [str(e) for e in [*coll.errors, *(x for r in coll.rules for x in r.errors)]]
    except Exception as e:                                        # noqa: BLE001
        errs = [f"{type(e).__name__}: {e}"]
    if errs:
        return {**out, "nhom": "loi_sigma", "ly_do": errs[0]}
    try:
        hunts, skipped = adapter.compile_text(text, catalog, columns)
    except Exception as e:                                        # noqa: BLE001
        return {**out, "nhom": "loi_backend", "ly_do": f"{type(e).__name__}: {str(e).splitlines()[0]}"}
    if not hunts:
        if skipped and all("logsource" in s.ly_do for s in skipped):
            return {**out, "nhom": "ngoai_danh_muc", "ly_do": skipped[0].source}
        return {**out, "nhom": "thieu_truong", "ly_do": "; ".join(f"{s.source}: {s.ly_do}" for s in skipped)}
    sql_errors = []
    for h in hunts:
        wheres = [h.candidates] + [f["where"] for f in h.filters]
        if any(_NUMERIC_CMP.search(w) for w in wheres):
            out["so_sanh_so"] = True
        base = "SELECT count(*) FROM events WHERE ev_eid = ANY([1]) AND "
        prefix = "EXPLAIN " if not grow else ""
        for w in wheres:
            err = _run(con, f"{prefix}{base}({w})", grow)
            if err:
                sql_errors.append(f"{h.source}: {err}")
                break
        else:
            out["nguon_ok"].append(h.source)
        if h.ghi_chu:
            out["ghi_chu"].append(h.ghi_chu)
    if not out["nguon_ok"]:
        return {**out, "nhom": "loi_sql", "ly_do": sql_errors[0]}
    return {**out, "nhom": "ok"}


def check_dir(rules_dir: Path, catalog: dict, con=None, columns: set[str] | None = None) -> dict:
    grow = con is None
    con = con or _synthetic_con()
    per_rule = {}
    for f in sorted(rules_dir.rglob("*.yml")):
        per_rule[f.relative_to(rules_dir).as_posix()] = check_rule(f.read_text(encoding="utf-8"), catalog, con,
                                                                  columns, grow)
    return summarize(per_rule)


def _reason_key(nhom: str, ly_do: str) -> str:
    """Gộp lý do gần giống nhau để đếm: bỏ tên trường, số, chuỗi trong nháy."""
    s = re.sub(r"'[^']*'|\"[^\"]*\"|\[[^\]]*\]", "…", ly_do)
    return re.sub(r"\d+", "N", s)[:140]


def summarize(per_rule: dict) -> dict:
    groups = Counter(r["nhom"] for r in per_rule.values())
    reasons: dict[str, Counter] = defaultdict(Counter)
    examples: dict[tuple, str] = {}
    for name, r in per_rule.items():
        if r["nhom"] in ("loi_backend", "loi_sql", "loi_sigma", "thieu_truong", "ngoai_danh_muc"):
            k = _reason_key(r["nhom"], r["ly_do"])
            reasons[r["nhom"]][k] += 1
            examples.setdefault((r["nhom"], k), name)
    notes = Counter(n for r in per_rule.values() for n in r["ghi_chu"] if n)
    return {
        "tong": len(per_rule), "nhom": dict(groups),
        "ly_do": {g: [{"ly_do": k, "so_rule": n, "vi_du": examples[(g, k)]} for k, n in c.most_common()]
                  for g, c in reasons.items()},
        "ghi_chu_tach_dieu_kien": dict(notes.most_common(10)),
        "rule_ok": sorted(n for n, r in per_rule.items() if r["nhom"] == "ok"),
        "rule_so_sanh_so": sorted(n for n, r in per_rule.items() if r["so_sanh_so"]),
        "chi_tiet": per_rule,
    }
