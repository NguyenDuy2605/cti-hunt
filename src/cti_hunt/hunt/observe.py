"""Kết quả hunt chỉ từ events cho agent lập kế hoạch; không truy cập nhãn."""
from __future__ import annotations

from datetime import datetime

import duckdb

from . import runner

DETAIL_COLUMNS = ("ParentImage", "Image", "CommandLine", "User", "TargetUserName")
# Chỉ thêm vào hunt record cục bộ; mẫu cho planner giữ nguyên để không tăng đầu vào API.
RECORD_DETAIL_COLUMNS = DETAIL_COLUMNS + ("SubjectUserName", "TaskName", "TaskContent", "TaskContentNew")


def run_unlabeled(con: duckdb.DuckDBPyConnection, spec: dict, sample_limit: int = 5) -> dict:
    """Đếm từng tầng lọc và lấy mẫu sau lọc, chỉ bằng view ``events``."""
    return _observe(con, spec, sample_limit, DETAIL_COLUMNS)


def _observe(con: duckdb.DuckDBPyConnection, spec: dict, sample_limit: int,
             detail_columns: tuple[str, ...]) -> dict:
    runner.validate(spec, con=con)
    if sample_limit < 0 or sample_limit > 20:
        raise ValueError("sample_limit phải trong khoảng 0–20")
    scope = runner._scope_where(spec["scope"])
    predicates = [scope, f"({spec['candidates']})"]
    stages = []
    for stage in ["pham_vi", "ung_vien"] + [f"sau_{f['id']}" for f in spec.get("filters") or []]:
        if stage.startswith("sau_"):
            idx = len(stages) - 2
            predicates.append(f"({spec['filters'][idx]['where']}) IS NOT TRUE")
        where = " AND ".join(predicates[:1] if stage == "pham_vi" else predicates)
        hits = con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0]
        stages.append({"stage": stage, "hits": hits})
    extra = {}
    if spec.get("rang_buoc"):
        # Chỉ để xem ràng buộc loại bao nhiêu; tầng "ung_vien" đã gồm ràng buộc (ghép vào candidates ở ⑤).
        extra["truoc_rang_buoc"] = con.execute(f"SELECT count(*) FROM events WHERE {scope} AND "
                                               f"({spec['rang_buoc']['candidates_goc']})").fetchone()[0]
    cols = {row[0] for row in con.execute("DESCRIBE events").fetchall()}
    select = ["ev_host", "ev_channel", "ev_rec", "CAST(ev_ts AS VARCHAR) AS ev_ts"]
    select += [f'"{c}"' for c in detail_columns if c in cols]
    sql = (f"SELECT {', '.join(select)} FROM events WHERE {' AND '.join(predicates)} "
           f"ORDER BY ev_ts, ev_host, ev_rec LIMIT {sample_limit}")
    cur = con.execute(sql)
    names = [c[0] for c in cur.description]
    return {"hunt_id": spec["id"], "hypothesis_id": spec.get("hypothesis_id"),
            "source": {"channel": spec["scope"]["channel"], "event_ids": spec["scope"]["event_ids"]},
            "stages": stages, "sample": [dict(zip(names, row)) for row in cur.fetchall()], **extra}


def unlabeled_result(con: duckdb.DuckDBPyConnection, spec: dict, detail_limit: int = 20) -> dict:
    """Kết quả cùng khuôn với `runner.run` cho hunt record bản vận hành, nhưng chỉ từ ``events``.

    Không có `mau_so_fpr`, số tấn công, FP, recall hay cột bước: khâu ⑨ nhận được mà không cần nhãn, và
    `record --eval` từ chối khuôn này.
    """
    obs = _observe(con, spec, detail_limit, RECORD_DETAIL_COLUMNS)
    stages = obs["stages"]
    giai_doan = []
    for s in stages[1:]:                   # bỏ tầng "pham_vi": giai đoạn đầu của runner là "ung_vien"
        removed = giai_doan[-1]["hits"] - s["hits"] if giai_doan else 0
        giai_doan.append({"stage": s["stage"], "hits": s["hits"], "removed": removed})
    rows = [{k: (str(v) if k == "ev_ts" else v) for k, v in r.items() if k != "ev_channel"} for r in obs["sample"]]
    from ..filter_approval import result_contract
    return {
        **result_contract(spec),
        "hunt": {k: spec.get(k) for k in ("id", "nhanh", "gia_thuyet", "linked_ttps", "scope", "hypothesis_id")},
        "truy_van": {"candidates": spec["candidates"],
                     "filters": [{"id": f["id"], "where": f["where"]} for f in spec.get("filters") or []]},
        "hunt_file": spec.get("_path"), "hunt_sha256": spec.get("_sha256"),
        "chay_luc": datetime.now().isoformat(timespec="seconds"),
        "khong_nhan": True,
        "pham_vi": {"su_kien_trong_pham_vi": stages[0]["hits"]},
        "giai_doan": giai_doan,
        "muc_loc": [{k: f.get(k) for k in ("id", "mo_ta", "ly_do", "nguoi_chiu_trach_nhiem", "het_han", "nguon")}
                    for f in spec.get("filters") or []],
        "ket_qua_cuoi": rows,
        **({"rang_buoc": {"ung_vien_truoc_rang_buoc": obs["truoc_rang_buoc"],
                          "dieu_kien": spec["rang_buoc"]["dieu_kien"]}} if "truoc_rang_buoc" in obs else {}),
    }
