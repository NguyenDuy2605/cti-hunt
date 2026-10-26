"""Đo recall/FPR trên OTRF bằng nhãn dòng tiến trình (giao thức docs/METHODOLOGY.md).

Đo 9 lượt thật đã chạy với report công khai trên log OTRF (Emotet ×7, Volt Typhoon ×1, IcedID ×1). Kết quả cuối của mỗi hunt
tính lại từ hunt spec đã thực thi: phạm vi nguồn log ∧ điều kiện ứng viên ∧ không bị mục lọc đã áp loại. Nhãn đọc từ thư mục
`scripts/nhan_otrf.py` ghi ra (ngoài repo); SHA256 tệp nhãn ghi vào kết quả. Không đọc nhãn APT29, không gọi API.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_otrf.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from cti_hunt import config
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner

LABELED = {"microsoft-windows-sysmon/operational", "security", "microsoft-windows-powershell/operational", "windows powershell"}
EMO = "data/reports/moi/DEV-EMOTET-MVP-0810/extraction/hunts/"
RUNS = [  # (report, lượt) — chốt trong giao thức §3
    ("Emotet (CERT-EU)", "data/dev/report_emotet_28-9/case/handoff_send/hunt_v3"),
    ("Emotet (CERT-EU)", "data/dev/report_emotet_28-9/case/handoff_send/hunt_v4_n2_n5"),
    ("Emotet (CERT-EU)", EMO + "run_b1223ddf57674180aefb6a8333723b33"),
    ("Emotet (CERT-EU)", EMO + "run_8bd5310fd6564bd4abee344328f082bb"),
    ("Emotet (CERT-EU)", EMO + "run_5e3d3ae805824de8b4be1a613bf8a9db"),
    ("Emotet (CERT-EU)", EMO + "run_57fa2a87a45248f68d58036450f7b488"),
    ("Emotet (CERT-EU)", EMO + "run_02c1d0996892411eaae68c1e901eff3d"),
    ("Volt Typhoon (Microsoft)", "data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024/hunts/"
                                 "run_d261b5754c8246769acc939325eea81f"),
    ("IcedID (The DFIR Report)", "tmp/thu_cti_icedid_7-10/luot_graph"),
]
DETAIL = ("Image", "ParentImage", "CommandLine", "ScriptBlockText", "Name", "TargetObject", "ServiceName", "TaskName")


def load_labels(d: Path, ds: str) -> tuple[set, str]:
    path = d / f"{ds}.csv"
    rows = list(csv.reader(path.open(encoding="utf-8")))[1:]
    return {tuple(r) for r in rows}, hashlib.sha256(path.read_bytes()).hexdigest()


def keys(con, where: str) -> set:
    return {(str(h), str(c), str(r)) for h, c, r in
            con.execute(f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {where}").fetchall()}


def measure_spec(con, spec: dict, attack: set) -> dict:
    scope = runner._scope_where(spec["scope"])
    final = " AND ".join([scope, f"({spec['candidates']})"] +
                         [f"({f['where']}) IS NOT TRUE" for f in spec.get("filters") or []])
    kept, in_scope = keys(con, final), keys(con, scope)
    ch = str(spec["scope"]["channel"]).lower()
    tp = kept & attack
    out = {"hunt": spec["id"], "hypothesis_id": spec.get("hypothesis_id", ""), "kenh": ch,
           "eid": spec["scope"]["event_ids"], "giu": len(kept), "pham_vi": len(in_scope), "tp": len(tp),
           "tp_keys": sorted(tp)}
    if ch in LABELED:
        benign = in_scope - attack
        fp = len(kept - attack)
        out.update(fp=fp, benign=len(benign), fpr=fp / len(benign) if benign else None,
                   precision=len(tp) / len(kept) if kept else None)
    else:
        out.update(fp=None, ghi_chu="kênh không có nhãn: FP không đánh giá được")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    lab_dir = Path(a.nhan)
    results = []
    for report, run in RUNS:
        run_dir = config.resolve(run)
        rec = json.loads((run_dir / "agent_dev_record.json").read_text(encoding="utf-8"))
        ds = rec["dataset"]["id"] if isinstance(rec["dataset"], dict) else rec["dataset"]
        attack, sha = load_labels(lab_dir, ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        attack_labeled = {k for k in attack if k[1] in LABELED}
        hunts = []
        for item in rec.get("executed_specs") or []:
            path = Path(item["path"])
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            hunts.append(measure_spec(con, spec, attack))
        caught = set().union(*[set(map(tuple, h["tp_keys"])) for h in hunts]) if hunts else set()
        kinds = Counter()
        detail = []
        if caught:
            cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
            sel = [c for c in DETAIL if c in cols]
            for h, c, r in sorted(caught)[:400]:
                row = con.execute(f"SELECT ev_eid, {', '.join(chr(34) + x + chr(34) for x in sel)} FROM events WHERE "
                                  f"ev_host='{h}' AND ev_channel='{c}' AND ev_rec='{r}'").fetchone()
                kinds[f"{c} {row[0]}"] += 1
                if len(detail) < 12:
                    detail.append({"host": h, "kenh": c, "eid": row[0],
                                   **{x: str(v)[:120] for x, v in zip(sel, row[1:]) if v not in (None, "")}})
        fp_total = sum(h["fp"] or 0 for h in hunts)
        res = {"report": report, "luot": run, "bo_log": ds, "nhan_sha256": sha, "so_hunt": len(hunts),
               "bat_duoc_kich_ban": bool(caught), "su_kien_tan_cong_giu": len(caught),
               "su_kien_tan_cong_tong": len(attack), "su_kien_tan_cong_kenh_co_nhan": len(attack_labeled),
               "fp_cong_theo_hunt": fp_total, "loai_su_kien_bat": dict(kinds), "mau_bat": detail, "hunts": hunts}
        results.append(res)
        fprs = [h["fpr"] for h in hunts if h.get("fpr") is not None]
        top = f"{max(fprs):.2%}" if fprs else "—"
        print(f"{report:26s} {Path(run).name[:22]:22s} {ds:14s} hunt {len(hunts):2d} · bắt kịch bản "
              f"{'CÓ ' if caught else 'KHÔNG'} · giữ {len(caught)}/{len(attack)} sự kiện tấn công · FP {fp_total} · "
              f"FPR cao nhất {top}")
        for h in hunts:
            fpr = f"{h['fpr']:.2%}" if h.get("fpr") is not None else "—"
            print(f"      {h['hunt'][:60]:60s} giữ {h['giu']:5d}/{h['pham_vi']:6d} · TP {h['tp']:4d} · FP "
                  f"{h['fp'] if h['fp'] is not None else '—'} · FPR {fpr}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for r in results:
        for h in r["hunts"]:
            h.pop("tp_keys")
    (out / "ket_qua_co_nhan_otrf.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
