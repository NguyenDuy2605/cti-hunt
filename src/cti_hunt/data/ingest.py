"""Nạp dataset OTRF (JSON lines) thành một bảng Parquet.

Giữ nguyên MỌI trường gốc (kiểu VARCHAR, đúng tên gốc như Image, ParentImage, ScriptBlockText) để
truy vấn viết tay và sau này rule Sigma dùng được tên trường thật. Thêm các cột dẫn xuất tiền tố `ev_`:

    ev_host     tên máy ngắn, viết hoa (UTICA.dmevals.local -> UTICA)
    ev_channel  channel hạ chữ thường (v3 §3.4: Security và security là cùng một log)
    ev_eid      EventID dạng INTEGER
    ev_rec      RecordNumber dạng BIGINT (chỉ duy nhất trong từng cặp máy + channel)
    ev_ts       thời điểm UTC thống nhất (v3 §3.4): UtcTime với Sysmon, EventTime + 4h với nguồn khác
    ev_ts_src   trường đã dùng cho ev_ts

Lưu ý DuckDB không phân biệt hoa thường ở tên cột, nên:
- cột dẫn xuất dùng tiền tố `ev_` để không đụng trường gốc (vd trường gốc `host`, `Channel`);
- trường gốc trùng tên khi bỏ hoa thường (IpAddress/Ipaddress, ...GUID/...Guid) thì bản sau đổi
  thành `<tên>__2`, ghi vào ingest_manifest.json.

Mỗi dòng JSON chỉ parse một lần (json_extract_string với danh sách đường dẫn) và ghi dạng dòng chảy,
nên chạy được trên máy 4 GB RAM với 2 luồng.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import duckdb

MAX_OBJECT_SIZE = 64 * 1024 * 1024


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _json_path(key: str) -> str:
    return _sql_str('$."' + key.replace("\\", "\\\\").replace('"', '\\"') + '"')


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _source(src: Path) -> str:
    return (f"read_json_objects({_sql_str(src.as_posix())}, format='newline_delimited', "
            f"maximum_object_size={MAX_OBJECT_SIZE})")


def column_names(keys: list[str]) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Gán tên cột cho từng khóa JSON; xử lý trùng tên không phân biệt hoa thường."""
    seen: dict[str, int] = {}
    cols, renamed = [], {}
    for k in sorted(keys):
        low = k.lower()
        n = seen.get(low, 0) + 1
        seen[low] = n
        name = k if n == 1 else f"{k}__{n}"
        if low.startswith("ev_"):
            name = f"src_{name}"
        if name != k:
            renamed[k] = name
        cols.append((k, name))
    return cols, renamed


def derived_columns_sql(name_of: dict[str, str], sysmon_channel: str, time_cfg: dict) -> str:
    def col(key: str) -> str:
        return _ident(name_of[key]) if key in name_of else "NULL::VARCHAR"

    sf, of, off = time_cfg["sysmon_field"], time_cfg["other_field"], int(time_cfg["other_offset_hours"])
    ch = f"lower({col('Channel')})"
    utc, other = col(sf), col(of)
    is_sysmon_utc = f"({ch} = {_sql_str(sysmon_channel)} AND {utc} IS NOT NULL)"
    return f"""
      upper(split_part({col('Hostname')}, '.', 1)) AS ev_host,
      {ch} AS ev_channel,
      TRY_CAST({col('EventID')} AS INTEGER) AS ev_eid,
      TRY_CAST({col('RecordNumber')} AS BIGINT) AS ev_rec,
      CASE WHEN {is_sysmon_utc} THEN TRY_STRPTIME({utc}, '%Y-%m-%d %H:%M:%S.%g')
           ELSE TRY_STRPTIME({other}, '%Y-%m-%d %H:%M:%S') + INTERVAL {off} HOUR END AS ev_ts,
      CASE WHEN {is_sysmon_utc} THEN {_sql_str(sf)} ELSE {_sql_str(f'{of}+{off}h')} END AS ev_ts_src"""


def ingest(src: Path, out_dir: Path, *, sysmon_channel: str, time_cfg: dict,
           event_key: list[str], expected_rows: int | None = None, threads: int = 2) -> dict:
    if not src.exists():
        raise FileNotFoundError(f"Không thấy {src}")
    out_dir.mkdir(parents=True, exist_ok=True)
    parquet = out_dir / "events.parquet"
    con = duckdb.connect()
    con.execute("SET enable_progress_bar=false")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET threads={int(threads)}")
    con.execute(f"SET temp_directory={_sql_str((out_dir / '.duckdb_tmp').as_posix())}")

    keys = [r[0] for r in con.execute(
        f"SELECT DISTINCT unnest(json_keys(json)) FROM {_source(src)}").fetchall()]
    cols, renamed = column_names(keys)
    paths = "[" + ", ".join(_json_path(k) for k, _ in cols) + "]"
    fields = ",\n        ".join(f"v[{i}] AS {_ident(n)}" for i, (_, n) in enumerate(cols, start=1))
    inner = f"SELECT {fields} FROM (SELECT json_extract_string(json, {paths}) AS v FROM {_source(src)})"
    derived = derived_columns_sql(dict(cols), sysmon_channel, time_cfg)
    con.execute(f"""COPY (SELECT *, {derived} FROM ({inner}))
                    TO {_sql_str(parquet.as_posix())} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 50000)""")

    ev = f"read_parquet({_sql_str(parquet.as_posix())})"
    n_rows = con.execute(f"SELECT count(*) FROM {ev}").fetchone()[0]
    key_sql = ", ".join(event_key)
    n_keys = con.execute(f"SELECT count(*) FROM (SELECT DISTINCT {key_sql} FROM {ev})").fetchone()[0]
    null_key = con.execute(
        f"SELECT count(*) FROM {ev} WHERE " + " OR ".join(f"{k} IS NULL" for k in event_key)).fetchone()[0]
    null_ts = con.execute(f"SELECT count(*) FROM {ev} WHERE ev_ts IS NULL").fetchone()[0]
    ts_src = dict(con.execute(f"SELECT ev_ts_src, count(*) FROM {ev} GROUP BY 1").fetchall())
    hosts = dict(con.execute(f"SELECT ev_host, count(*) FROM {ev} GROUP BY 1 ORDER BY 2 DESC").fetchall())
    t_min, t_max = con.execute(f"SELECT min(ev_ts), max(ev_ts) FROM {ev}").fetchone()
    con.execute(f"""COPY (SELECT ev_channel, ev_eid, count(*) AS n FROM {ev} GROUP BY 1, 2 ORDER BY n DESC, 1, 2)
                    TO {_sql_str((out_dir / 'event_counts.csv').as_posix())} (HEADER)""")

    problems = []
    if expected_rows is not None and n_rows != expected_rows:
        problems.append(f"số dòng {n_rows} khác kỳ vọng {expected_rows}")
    if n_keys != n_rows:
        problems.append(f"khóa {event_key} không duy nhất: {n_rows - n_keys} dòng trùng")
    if null_key:
        problems.append(f"{null_key} dòng thiếu giá trị khóa")

    manifest = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "source": src.as_posix(),
        "duckdb": duckdb.__version__,
        "rows": n_rows,
        "fields": len(cols),
        "renamed_fields": renamed,
        "event_key": event_key,
        "hosts": hosts,
        "ev_ts_src": ts_src,
        "ev_ts_null": null_ts,
        "ev_ts_range_utc": [str(t_min), str(t_max)],
        "problems": problems,
    }
    (out_dir / "ingest_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest
