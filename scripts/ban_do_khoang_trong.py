"""Bản đồ khoảng trống phát hiện của từng report (không nhãn, không API).

Với mỗi TTP khâu ② rút từ report: (a) có rule SigmaHQ high/critical (stable/test, tag trùng chính xác) dịch được và chạy được
trên nguồn log của bộ dữ liệu không; (b) chỉ có rule mức thấp hơn; (c) không có rule cộng đồng nào chạy được; kèm trạng thái
danh mục ③ (huntable/partial/not_huntable) để tách "thiếu rule" với "thiếu log". Phần (c) là nơi hệ thống cần tự sinh hunt.

    .venv/Scripts/python.exe -X utf8 scripts/ban_do_khoang_trong.py --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from cti_hunt import config
from cti_hunt.contracts import ContractA
from cti_hunt.data.store import connect
from cti_hunt.stages import community_rules as cr

REPORTS = {
    "Solorigate (MS)": ("runs/khau2_20260925-161526/contract_a_MS.json", "data/work"),
    "Raindrop (SY)": ("runs/khau2_20260925-161526/contract_a_SY.json", "data/work"),
    "POSHSPY (PS)": ("runs/khau2_20260925-161526/contract_a_PS.json", "data/work"),
    "Emotet (CERT-EU)": ("data/reports/moi/DEV-EMOTET-MVP-0810/extraction/contract_a.json", "data/dev/otrf-wmi-exec"),
    "Volt Typhoon (Microsoft)": ("data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024/"
                                 "contract_a.json", "data/dev/otrf-wmi-exec"),
    "IcedID (The DFIR Report)": ("tmp/thu_cti_icedid_7-10/luot_graph/contract_a.json", "data/dev/otrf-wmi-sub"),
}
HIGH = {"high", "critical"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res = {}
    for name, (ca_path, events) in REPORTS.items():
        ca = ContractA.model_validate_json(config.resolve(ca_path).read_text(encoding="utf-8"))
        con = connect(config.resolve(events))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        status = {r[0]: r[1] for r in con.execute(
            "SELECT DISTINCT ev_channel, count(*) FROM events GROUP BY 1").fetchall()}
        per = {}
        for t in cr.techniques(ca):
            specs, _ = cr.compile_selected(cr.select([t]), cols)
            runnable = [s for s in specs if s["scope"]["channel"].lower() in status]
            levels = {s["nguon_rule"]["level"] for s in runnable}
            per[t] = ("cao" if levels & HIGH else "thap" if levels else
                      "co_rule_khong_co_log" if specs else "khong_co_rule")
        c = Counter(per.values())
        res[name] = {"ttp": len(per), **dict(c), "chi_tiet": per}
        print(f"{name:26s} {len(per):3d} TTP · có rule cao chạy được {c['cao']:2d} · chỉ rule thấp {c['thap']:2d} · "
              f"có rule nhưng log không có nguồn {c['co_rule_khong_co_log']:2d} · không có rule cộng đồng {c['khong_co_rule']:2d}")
    tot = Counter()
    for v in res.values():
        tot.update({k: v.get(k, 0) for k in ("cao", "thap", "co_rule_khong_co_log", "khong_co_rule")})
    print("TỔNG", dict(tot), "trên", sum(v["ttp"] for v in res.values()), "TTP")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ban_do_khoang_trong.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
