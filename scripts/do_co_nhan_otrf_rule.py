"""Phần phụ của giao thức nhãn OTRF (§3): 93 rule bản tổng quát và 28 biến thể mức kỹ thuật trên 7 bộ, với nhãn sự kiện.

Rule và biến thể lấy như scripts/do_rule_otrf.py và scripts/do_bien_the_rule.py; nhãn từ scripts/nhan_otrf.py. Mỗi rule: TP,
FP, FPR trên từng bộ (kênh có nhãn). Không gọi API, không đọc nhãn APT29.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_otrf_rule.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import do_bien_the_rule as bt  # noqa: E402
import do_co_nhan_otrf as m  # noqa: E402
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.adapters.duckdb_sigma import load_catalog  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg, catalog = rv.load_config(), load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    specs = bt.load_specs()
    pairs = [(s, rv.variant_spec(s, cfg, catalog)[0]) for s in specs]
    out_rows, summary = [], {}
    for ds, techs in base.DATASETS.items():
        attack, sha = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        s = defaultdict(lambda: {"so_rule": 0, "goc_tp": 0, "bien_the_tp": 0, "goc_hoac_bt_tp": 0, "goc_fp": 0,
                                 "bt_fp_them": 0})
        for spec, var in pairs:
            kind = ("dung_ky_thuat" if any(base.related(t, d) for t in spec["ttp"] for d in techs)
                    else "khoi_chay_chung" if any(base.related(t, d) for t in spec["ttp"] for d in base.COMMON)
                    else "ky_thuat_khac")
            try:
                g = m.measure_spec(con, spec, attack)
                v = m.measure_spec(con, var, attack) if var else None
            except Exception as e:  # noqa: BLE001 — cột không có ở bộ này
                out_rows.append({"bo": ds, "rule": spec["id"], "loai": kind, "loi": f"{type(e).__name__}"})
                continue
            x = s[kind]
            x["so_rule"] += 1
            x["goc_tp"] += g["tp"] > 0
            x["bien_the_tp"] += bool(v and v["tp"] > 0)
            x["goc_hoac_bt_tp"] += g["tp"] > 0 or bool(v and v["tp"] > 0)
            x["goc_fp"] += g["fp"] or 0
            x["bt_fp_them"] += max(0, ((v or {}).get("fp") or 0) - (g["fp"] or 0)) if v else 0
            for h in (g, v):
                if h:
                    h.pop("tp_keys")
            out_rows.append({"bo": ds, "rule": spec["id"], "ttp": spec["ttp"], "loai": kind, "goc": g, "bien_the": v})
        summary[ds] = {"nhan_sha256": sha, **{k: dict(v) for k, v in s.items()}}
        d = s.get("dung_ky_thuat")
        o = s.get("ky_thuat_khac")
        c = s.get("khoi_chay_chung")
        print(f"{ds:16s} đúng kỹ thuật: " + (f"gốc TP {d['goc_tp']}/{d['so_rule']} → +biến thể {d['goc_hoac_bt_tp']}/{d['so_rule']}"
                                            f" · FP gốc {d['goc_fp']} · FP thêm do biến thể {d['bt_fp_them']}" if d else "—")
              + (f" | khởi chạy chung TP {c['goc_tp']}/{c['so_rule']} FP {c['goc_fp']}" if c else "")
              + (f" | kỹ thuật khác TP {o['goc_tp']}/{o['so_rule']} → {o['goc_hoac_bt_tp']} · FP {o['goc_fp']} · "
                 f"FP thêm {o['bt_fp_them']}" if o else ""))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_rule_co_nhan_otrf.json").write_text(json.dumps({"tong_hop": summary, "chi_tiet": out_rows},
                                                                   ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
