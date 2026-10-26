"""Chạy một hunt và đo theo v3 §6.1–6.2.

Một hunt là file YAML trong hunts/ (xem hunts/manual/H-03.yaml):
- scope: MỘT nguồn log (channel + event_ids) và khoảng thời gian -> mẫu số FPR.
  Giả thuyết cần nhiều nguồn log thì tách thành nhiều hunt, mỗi hunt một nguồn.
- candidates: điều kiện WHERE sinh ứng viên (khâu ⑤–⑥).
- filters: danh sách mục loại trừ có giải trình (khâu ⑦, v3 §4.3). Mỗi mục đo riêng số bị loại và
  số sự kiện tấn công bị loại nhầm.

Nhánh A (thủ công) và nhánh B (hệ thống) dùng chung runner này, nên số liệu hai nhánh so được.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import duckdb
import yaml

from ..eval.hunt_metrics import stage_metrics, step_recall
from ..labels.ground_truth import Step

KEY = "ev_host, ev_channel, ev_rec"
REQUIRED_FILTER_FIELDS = ("id", "where", "ly_do", "nguoi_chiu_trach_nhiem", "het_han")


class HuntSpecError(ValueError):
    pass


def load_spec(path: Path, *, con=None) -> dict:
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    spec["_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    spec["_path"] = path.as_posix()
    validate(spec, con=con)
    return spec


def validate(spec: dict, *, for_execution: bool = True, con=None) -> None:
    sc = spec.get("scope") or {}
    if not sc.get("channel"):
        raise HuntSpecError("scope.channel bắt buộc: mã sự kiện phải đi kèm channel (v3 §3.4)")
    if not sc.get("event_ids"):
        raise HuntSpecError("scope.event_ids bắt buộc")
    if not (spec.get("candidates") or "").strip():
        raise HuntSpecError("candidates trống")
    for f in spec.get("filters") or []:
        miss = [k for k in REQUIRED_FILTER_FIELDS if not str(f.get(k) or "").strip()]
        if miss:
            raise HuntSpecError(f"mục lọc {f.get('id', '?')} thiếu {miss} (v3 §4.3: mỗi mục loại trừ "
                                "phải có phạm vi, mẫu, người chịu trách nhiệm, lý do, thời hạn)")
    # Truy vấn săn không được nhìn nhãn.
    texts = [spec["candidates"]] + [f["where"] for f in spec.get("filters") or []]
    if any(re.search(r"\bbuoc\b|attack_labels|\blabeled\b", t, re.I) for t in texts):
        raise HuntSpecError("candidates/filters không được tham chiếu nhãn (buoc, attack_labels, labeled)")
    if for_execution:
        from ..filter_approval import require_executable
        require_executable(spec, con=con)


def _scope_where(sc: dict) -> str:
    ch = str(sc["channel"]).lower().replace("'", "''")
    eids = ", ".join(str(int(e)) for e in sc["event_ids"])
    parts = [f"ev_channel = '{ch}'", f"ev_eid IN ({eids})"]
    if sc.get("hosts"):
        hosts = ["'" + str(h).upper().replace("'", "''") + "'" for h in sc["hosts"]]
        parts.append("ev_host IN (" + ", ".join(hosts) + ")")
    if sc.get("time_from"):
        parts.append(f"ev_ts >= TIMESTAMP '{sc['time_from']}'")
    if sc.get("time_to"):
        parts.append(f"ev_ts < TIMESTAMP '{sc['time_to']}'")
    return " AND ".join(parts)


def run(con: duckdb.DuckDBPyConnection, spec: dict, steps: list[Step], independent_reports: list[str],
        detail_columns: list[str] | None = None, detail_limit: int = 300) -> dict:
    """Yêu cầu con đã có view `labeled` (labels.events.attach)."""
    validate(spec, con=con)
    con.execute(f"CREATE OR REPLACE TEMP VIEW scope AS SELECT * FROM labeled WHERE {_scope_where(spec['scope'])}")
    n_scope, n_pos = con.execute("SELECT count(*), count(buoc) FROM scope").fetchone()
    negatives = n_scope - n_pos
    steps_with_log = {r[0] for r in con.execute("SELECT DISTINCT buoc FROM attack_labels").fetchall()}

    con.execute(f"CREATE OR REPLACE TEMP TABLE rem_0 AS SELECT {KEY}, buoc FROM scope WHERE ({spec['candidates']})")
    stages = [stage_metrics("ung_vien", [r[0] for r in con.execute("SELECT buoc FROM rem_0").fetchall()], negatives)]

    filter_log = []
    for i, f in enumerate(spec.get("filters") or [], start=1):
        con.execute(f"""CREATE OR REPLACE TEMP TABLE removed_{i} AS
                        SELECT s.ev_host, s.ev_channel, s.ev_rec, s.buoc
                        FROM scope s SEMI JOIN rem_{i-1} r USING ({KEY}) WHERE ({f['where']})""")
        con.execute(f"CREATE OR REPLACE TEMP TABLE rem_{i} AS SELECT * FROM rem_{i-1} ANTI JOIN removed_{i} USING ({KEY})")
        removed = [r[0] for r in con.execute(f"SELECT buoc FROM removed_{i}").fetchall()]
        kept = [r[0] for r in con.execute(f"SELECT buoc FROM rem_{i}").fetchall()]
        stages.append(stage_metrics(f"sau_{f['id']}", kept, negatives, removed))
        filter_log.append({k: f.get(k) for k in ("id", "mo_ta", "ly_do", "nguoi_chiu_trach_nhiem", "het_han",
                                                 "nguon")})
    last = f"rem_{len(spec.get('filters') or [])}"

    detected = set(stages[-1].steps)
    recall = step_recall(detected, steps, steps_with_log, independent_reports)

    cols = detail_columns or ["ParentImage", "Image", "CommandLine", "User"]
    existing = {r[0].lower() for r in con.execute("DESCRIBE scope").fetchall()}
    cols = [c for c in cols if c.lower() in existing]
    sel = ", ".join(["s.ev_host", "CAST(s.ev_ts AS VARCHAR) AS ev_ts", "s.ev_rec", "s.buoc"] + [f's."{c}"' for c in cols])
    rows = con.execute(f"""SELECT {sel} FROM scope s SEMI JOIN {last} r USING ({KEY})
                           ORDER BY s.ev_ts LIMIT {int(detail_limit)}""").fetchall()
    names = ["ev_host", "ev_ts", "ev_rec", "buoc"] + cols

    from ..filter_approval import result_contract
    return {
        **result_contract(spec),
        "hunt": {k: spec.get(k) for k in ("id", "nhanh", "gia_thuyet", "linked_ttps", "scope", "hypothesis_id")},
        "truy_van": {"candidates": spec["candidates"],
                     "filters": [{"id": f["id"], "where": f["where"]} for f in spec.get("filters") or []]},
        "hunt_file": spec.get("_path"), "hunt_sha256": spec.get("_sha256"),
        "chay_luc": datetime.now().isoformat(timespec="seconds"),
        "mau_so_fpr": {"su_kien_trong_pham_vi": n_scope, "su_kien_tan_cong": n_pos, "am_tinh": negatives},
        "giai_doan": [s.as_dict() for s in stages],
        "muc_loc": filter_log,
        "recall_theo_buoc": recall,
        "ket_qua_cuoi": [dict(zip(names, r)) for r in rows],
    }


def save(result: dict, runs_dir: Path) -> Path:
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = runs_dir / f"{stamp}_{result['hunt']['id']}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return out


def format_summary(result: dict) -> str:
    m = result["mau_so_fpr"]
    lines = [f"Hunt {result['hunt']['id']} — phạm vi: {m['su_kien_trong_pham_vi']} sự kiện "
             f"({m['su_kien_tan_cong']} tấn công, {m['am_tinh']} âm tính = mẫu số FPR)", ""]
    lines.append(f"{'giai đoạn':<16}{'còn lại':>8}{'tấn công':>10}{'FP':>6}{'FPR':>9}{'precision':>11}"
                 f"{'bị loại':>9}{'loại nhầm':>11}  bước còn lại")
    for s in result["giai_doan"]:
        fpr = f"{s['fpr']:.2%}" if s["fpr"] is not None else "-"
        pr = f"{s['precision']:.2%}" if s["precision"] is not None else "-"
        steps = ", ".join(f"{k}×{v}" for k, v in s["steps"].items()) or "-"
        lines.append(f"{s['stage']:<16}{s['hits']:>8}{s['attacker_events']:>10}{s['fp']:>6}{fpr:>9}{pr:>11}"
                     f"{s['removed']:>9}{s['removed_attacker']:>11}  {steps}")
    r = result["recall_theo_buoc"]
    lines.append("")
    for label, blk in (("Tất cả report", r["tat_ca_report"]), ("Report độc lập", r["report_doc_lap"])):
        parts = [f"{name} {blk[name]['phat_hien']}/{blk[name]['mau_so']}"
                 for name in ("tuyet_doi", "tran_dau_vao", "tran_thuc_te")]
        lines.append(f"TP recall theo bước [{label}]: " + " · ".join(parts))
    lines.append(f"  bỏ sót (tuyệt đối): {', '.join(r['tat_ca_report']['tuyet_doi']['buoc_bo_sot']) or '-'}")
    if r["buoc_ngoai_scope_bat_duoc"]:
        lines.append(f"  bắt được bước ngoài scope: {', '.join(r['buoc_ngoai_scope_bat_duoc'])}")
    return "\n".join(lines)
