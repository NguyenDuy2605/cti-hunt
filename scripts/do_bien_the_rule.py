"""Biến thể mức kỹ thuật của rule đã sinh: chạy rule gốc và biến thể trên 7 bộ OTRF và trên APT29 day 2, không nhãn.

Rule lấy như scripts/do_rule_otrf.py (12 lượt được tính của bản tổng quát, bỏ hunt pivot/neo, gộp rule trùng). Với mỗi rule,
stages/rule_variant.py dựng biến thể (nếu có quy tắc). Đếm trên mỗi bộ: số sự kiện trong phạm vi nguồn log, số sự kiện rule
giữ (gốc: sau mục lọc đã duyệt; biến thể: không lọc), vài mẫu. Nhãn OTRF chỉ ở mức bộ dữ liệu (bộ nào mô phỏng kỹ thuật nào);
APT29 chỉ đếm, không nhãn. Hunt spec của biến thể ghi ra `specs/` để người thực hiện chạy lệnh có nhãn ở cửa sổ riêng.

    .venv/Scripts/python.exe -X utf8 scripts/do_bien_the_rule.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_rule_otrf as base  # noqa: E402

from cti_hunt.stages import rule_variant as rv  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.adapters.duckdb_sigma import load_catalog  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402


def load_specs() -> list[dict]:
    seen, specs = set(), []
    for run in base.COUNTED:
        for path in sorted(config.resolve(f"{base.EVAL}/{run}").glob("round_*/hunts_effective/*/*.yaml")):
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            b = spec["sigma_context"]["binding"]
            if b.get("pivot_value") or spec.get("rang_buoc") or spec["scope"].get("hosts") or spec["scope"].get("time_from"):
                continue
            key = (spec["scope"]["channel"].lower(), tuple(spec["scope"]["event_ids"]), spec["candidates"],
                   tuple(f["where"] for f in spec.get("filters") or []))
            if key in seen:
                continue
            seen.add(key)
            spec["ttp"] = sorted(set(spec.get("linked_ttps") or []))
            spec["filters"] = [f for f in spec.get("filters") or []]
            specs.append(spec)
    return specs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", default=rv.CONFIG)
    ap.add_argument("--khong-apt29", action="store_true", help="bỏ APT29 (chạy nhanh)")
    a = ap.parse_args(argv)
    cfg = rv.load_config(a.config)
    catalog = load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    specs = load_specs()
    pairs = []
    for s in specs:
        v, note = rv.variant_spec(s, cfg, catalog)
        pairs.append({"rule": s["id"], "ttp": s["ttp"], "goc": s, "bien_the": v, "ghi_chu": note})
    out = Path(a.out)
    (out / "specs").mkdir(parents=True, exist_ok=True)
    for p in pairs:
        if p["bien_the"]:
            spec = {k: v for k, v in p["bien_the"].items()}
            (out / "specs" / f"{spec['id']}.yaml").write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False),
                                                              encoding="utf-8", newline="\n")
    datasets = dict(base.DATASETS)
    if not a.khong_apt29:
        datasets["apt29_day2"] = set()
    table = {}
    for ds in datasets:
        con = connect(config.resolve("data/work" if ds == "apt29_day2" else f"data/dev/{ds}"))
        rows = []
        for p in pairs:
            g = base.count(con, {"scope": p["goc"]["scope"], "candidates": p["goc"]["candidates"], "filters": p["goc"]["filters"]})
            row = {"rule": p["rule"], "ttp": p["ttp"], "goc": g}
            if p["bien_the"]:
                row["bien_the"] = base.count(con, {"scope": p["bien_the"]["scope"], "candidates": p["bien_the"]["candidates"],
                                                   "filters": []}, sample=5)
            if ds != "apt29_day2":
                techs = base.DATASETS[ds]
                row["loai"] = ("dung_ky_thuat" if any(base.related(t, d) for t in p["ttp"] for d in techs)
                               else "khoi_chay_chung" if any(base.related(t, d) for t in p["ttp"] for d in base.COMMON)
                               else "ky_thuat_khac")
            rows.append(row)
        table[ds] = rows

    summary = {}
    for ds, rows in table.items():
        if ds == "apt29_day2":
            continue
        s = defaultdict(lambda: {"so_rule": 0, "goc_co_khop": 0, "co_bien_the": 0, "bien_the_co_khop": 0,
                                 "goc_hoac_bien_the_co_khop": 0})
        for r in rows:
            x = s[r["loai"]]
            x["so_rule"] += 1
            gk = r["goc"].get("cuoi", 0) > 0
            bk = "bien_the" in r and r["bien_the"].get("cuoi", 0) > 0
            x["goc_co_khop"] += gk
            x["co_bien_the"] += "bien_the" in r
            x["bien_the_co_khop"] += bk
            x["goc_hoac_bien_the_co_khop"] += gk or bk
        summary[ds] = dict(s)
    apt = [{"rule": r["rule"], "ttp": r["ttp"], "pham_vi": r["goc"].get("pham_vi"), "goc": r["goc"].get("cuoi"),
            "bien_the": r["bien_the"].get("cuoi")} for r in table.get("apt29_day2", []) if "bien_the" in r]
    reasons = defaultdict(int)
    for p in pairs:
        if not p["bien_the"]:
            reasons[p["ghi_chu"].split(" [")[0][:70]] += 1
    res = {"version": rv.VERSION, "so_rule": len(pairs), "so_bien_the": sum(1 for p in pairs if p["bien_the"]),
           "bien_the": [{"rule": p["rule"], "ttp": p["ttp"], "mo_ta": p["ghi_chu"],
                         "rule_bien_the": p["bien_the"]["bien_the"]["rule"]} for p in pairs if p["bien_the"]],
           "khong_bien_the": dict(reasons), "tong_hop_otrf": summary, "apt29_khong_nhan": apt, "chi_tiet": table}
    (out / "ket_qua_bien_the.json").write_text(json.dumps(res, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print(f"{len(pairs)} rule, {res['so_bien_the']} có biến thể")
    for k, n in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  không biến thể ({n}): {k}")
    for ds, s in summary.items():
        d = s.get("dung_ky_thuat")
        if d:
            print(f"{ds:16s} đúng kỹ thuật: gốc {d['goc_co_khop']}/{d['so_rule']} · có biến thể {d['co_bien_the']} · "
                  f"biến thể khớp {d['bien_the_co_khop']} · gốc hoặc biến thể {d['goc_hoac_bien_the_co_khop']}/{d['so_rule']}")
        o = s.get("ky_thuat_khac")
        if o:
            print(f"{'':16s} kỹ thuật khác: gốc {o['goc_co_khop']}/{o['so_rule']} · biến thể khớp {o['bien_the_co_khop']}/{o['co_bien_the']}")
    print("APT29 (không nhãn) — phạm vi · gốc · biến thể:")
    for x in apt:
        print(f"  {x['rule'][:58]:58s} {x['ttp']} {x['pham_vi']} · {x['goc']} · {x['bien_the']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
