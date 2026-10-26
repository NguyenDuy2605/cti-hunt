"""Tác động của hai cổng mới (15/10) lên 9 lượt thật trên OTRF có nhãn dòng tiến trình.

Cổng độ rộng (configs/do_rong_rule.yaml) và biến thể mức kỹ thuật (stages/rule_variant.py) chỉ đưa thông tin và lựa chọn cho
người duyệt; script này tính ba tình huống trên chính các hunt đã thực thi, không chạy lại mô hình:
  (a) như đã chạy; (b) người duyệt bỏ mọi rule bị cổng độ rộng đánh dấu; (c) như (b) và chạy biến thể thay rule gốc khi rule
  có biến thể. Nhãn từ scripts/nhan_otrf.py (dữ liệu phát triển, không phải APT29). Không gọi API.

    .venv/Scripts/python.exe -X utf8 scripts/do_cong_moi_otrf.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_co_nhan_otrf as m  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg = rv.load_config()
    results = []
    for report, run in m.RUNS:
        run_dir = config.resolve(run)
        rec = json.loads((run_dir / "agent_dev_record.json").read_text(encoding="utf-8"))
        ds = rec["dataset"]["id"] if isinstance(rec["dataset"], dict) else rec["dataset"]
        attack, _ = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        specs = [yaml.safe_load(Path(i["path"]).read_text(encoding="utf-8")) for i in rec.get("executed_specs") or []]
        wide = _breadth(con, specs)
        cases = {"a_nhu_da_chay": [], "b_bo_rule_rong": [], "c_bo_rong_va_bien_the": []}
        detail = []
        for spec in specs:
            g = m.measure_spec(con, spec, attack)
            var, note = (rv.variant_spec(spec, cfg) if (spec.get("sigma_context") or {}).get("rule")
                         and rv._is_root(spec) else (None, ""))
            v = m.measure_spec(con, {**var, "scope": spec["scope"]}, attack) if var else None
            flagged = spec["id"] in wide
            detail.append({"hunt": spec["id"], "rong": wide.get(spec["id"]), "goc": {k: g[k] for k in ("giu", "tp", "fp")},
                           "bien_the": {k: v[k] for k in ("giu", "tp", "fp")} if v else None, "mo_ta_bien_the": note if var else ""})
            cases["a_nhu_da_chay"].append(g)
            if not flagged:
                cases["b_bo_rule_rong"].append(g)
                cases["c_bo_rong_va_bien_the"].append(v if v else g)
        summary = {}
        for k, hs in cases.items():
            caught = set().union(*[set(map(tuple, h["tp_keys"])) for h in hs]) if hs else set()
            summary[k] = {"so_hunt": len(hs), "bat_kich_ban": bool(caught), "su_kien_tan_cong_giu": len(caught),
                          "fp": sum(h["fp"] or 0 for h in hs)}
        results.append({"report": report, "luot": run, "bo_log": ds, "tom_tat": summary, "hunt": detail})
        s = summary
        print(f"{report:26s} {Path(run).name[:14]:14s} rộng {len(wide)} · "
              + " | ".join(f"{k[:1]}: {'bắt' if v['bat_kich_ban'] else 'KHÔNG'} {v['su_kien_tan_cong_giu']} sk, FP {v['fp']}"
                           for k, v in s.items()))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_cong_moi_otrf.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
