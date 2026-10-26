"""Nhãn mức sự kiện v1 (v3 §6.3). Chỉ ĐỌC; nhãn v1 đã đóng băng, cần sửa thì tạo nhan_v2.

Hai phía chuẩn hóa giống nhau trước khi so: máy -> upper(split_part(., '.', 1)); channel -> lower(.);
record_number -> BIGINT. Khóa đủ ba cột vì RecordNumber chỉ duy nhất trong từng cặp (máy, channel).

Sau khi attach:
    attack_labels(ev_host, ev_channel, ev_rec, buoc)  -- 64.972 dòng kỳ vọng
    labeled = events LEFT JOIN attack_labels          -- buoc IS NULL nghĩa là hoạt động hợp lệ (TN)
"""
from __future__ import annotations

from pathlib import Path

import duckdb


class LabelJoinError(RuntimeError):
    pass


def attach(con: duckdb.DuckDBPyConnection, csv_path: Path, key_columns: dict[str, str],
           step_column: str, expected_rows: int | None = None) -> dict:
    src = f"read_csv('{csv_path.as_posix()}', all_varchar=true, header=true)"
    # File nhãn v1 là UTF-8 có BOM. DuckDB tự bỏ BOM; vẫn so tên cột sau khi bỏ \ufeff cho chắc.
    actual = {n.lstrip("\ufeff"): n for n in
              (r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {src}").fetchall())}
    wanted = list(key_columns.values()) + [step_column]
    missing = [c for c in wanted if c not in actual]
    if missing:
        raise LabelJoinError(
            f"{csv_path.name} thiếu cột {missing}. Cột thật: {list(actual)}. "
            "Sửa labels_v1.key_columns trong configs/dataset.yaml.")

    def q(name: str) -> str:
        return '"' + actual[name].replace('"', '""') + '"'

    h, c, r = (q(key_columns[k]) for k in ("ev_host", "ev_channel", "ev_rec"))
    con.execute(f"""
      CREATE OR REPLACE TABLE attack_labels AS
      SELECT upper(split_part({h}, '.', 1)) AS ev_host,
             lower({c}) AS ev_channel,
             TRY_CAST({r} AS BIGINT) AS ev_rec,
             {q(step_column)} AS buoc
      FROM {src}""")

    n = con.execute("SELECT count(*) FROM attack_labels").fetchone()[0]
    dup = con.execute("""SELECT count(*) FROM (SELECT ev_host, ev_channel, ev_rec FROM attack_labels
                         GROUP BY ALL HAVING count(*) > 1)""").fetchone()[0]
    unmatched = con.execute("""SELECT count(*) FROM attack_labels l ANTI JOIN events e
                               USING (ev_host, ev_channel, ev_rec)""").fetchone()[0]
    no_step = con.execute("SELECT count(*) FROM attack_labels WHERE buoc IS NULL OR buoc = ''").fetchone()[0]
    per_step = dict(con.execute("SELECT buoc, count(*) FROM attack_labels GROUP BY 1 ORDER BY 1").fetchall())

    problems = []
    if expected_rows is not None and n != expected_rows:
        problems.append(f"số dòng nhãn {n} khác kỳ vọng {expected_rows}")
    if dup:
        problems.append(f"{dup} khóa sự kiện xuất hiện nhiều lần trong nhãn")
    if unmatched:
        problems.append(f"{unmatched} dòng nhãn không khớp sự kiện nào (sai khóa hoặc sai chuẩn hóa)")
    if no_step:
        problems.append(f"{no_step} dòng nhãn thiếu bước")

    con.execute("""CREATE OR REPLACE VIEW labeled AS
                   SELECT e.*, l.buoc FROM events e LEFT JOIN attack_labels l
                   USING (ev_host, ev_channel, ev_rec)""")
    return {"rows": n, "duplicate_keys": dup, "unmatched": unmatched, "per_step": per_step,
            "problems": problems}
