"""Công cụ lai (15/10): rule cộng đồng SigmaHQ theo TTP của report, so với hunt hệ thống sinh và với hợp của hai.

- OTRF (nhãn dòng tiến trình, dữ liệu phát triển): Emotet và Volt × wmi-exec, IcedID × wmi-sub — bắt kịch bản, sự kiện tấn
  công giữ được, FP, số sự kiện người săn phải rà (hợp các hunt).
- APT29 day 2 (MS, SY, PS): chỉ đếm, không nhãn; đo có nhãn ở scripts/do_co_nhan_sigmahq_apt29.py.
Hunt hệ thống = hunt gốc đã thực thi của các lượt thật (do_co_nhan_otrf.RUNS), gộp theo report, bỏ trùng. Không gọi API.

    .venv/Scripts/python.exe -X utf8 scripts/do_sigmahq_theo_ttp.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import do_co_nhan_otrf as m  # noqa: E402
import do_ma_tran_report_otrf as mt  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.hunt import runner  # noqa: E402
from cti_hunt.stages import community_rules as cr  # noqa: E402

OTRF = {  # report → (Contract A, bộ log ghép)
    "Emotet (CERT-EU)": ("data/reports/moi/DEV-EMOTET-MVP-0810/extraction/contract_a.json", "otrf-wmi-exec"),
    "Volt Typhoon (Microsoft)": ("data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024/"
                                 "contract_a.json", "otrf-wmi-exec"),
    "IcedID (The DFIR Report)": ("tmp/thu_cti_icedid_7-10/luot_graph/contract_a.json", "otrf-wmi-sub"),
}
APT29 = {r: f"runs/khau2_20260925-161526/contract_a_{r}.json" for r in ("MS", "SY", "PS")}
LEVELS = {"high_critical": {"high", "critical"}, "tu_medium": {"medium", "high", "critical"}}


def keys(con, spec: dict) -> set:
    where = " AND ".join([runner._scope_where(spec["scope"]), f"({spec['candidates']})"] +
                         [f"({f['where']}) IS NOT TRUE" for f in spec.get("filters") or []])
    return {(str(h), str(c), str(r)) for h, c, r in
            con.execute(f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {where}").fetchall()}


def union(con, specs: list[dict]) -> tuple[set, int]:
    out, err = set(), 0
    for s in specs:
        try:
            out |= keys(con, s)
        except Exception:  # noqa: BLE001 — cột không có ở bộ này
            err += 1
    return out, err


def score(kept: set, attack: set) -> dict:
    labeled = {k for k in kept if k[1] in m.LABELED}
    tp = kept & attack
    return {"bat": bool(tp), "tan_cong": len(tp), "fp": len(labeled - attack), "can_ra": len(kept)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    system = mt.report_hunts()
    res = {"otrf": {}, "apt29_khong_nhan": {}}
    for report, (ca_path, ds) in OTRF.items():
        ca = ContractA.model_validate_json(config.resolve(ca_path).read_text(encoding="utf-8"))
        attack, sha = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        selected = cr.select(cr.techniques(ca))
        specs, skipped = cr.compile_selected(selected, cols)
        sig, sig_err = union(con, specs)
        sysk, sys_err = union(con, system.get(report, []))
        per_rule = []
        for s in specs:
            try:
                k = keys(con, s)
            except Exception:  # noqa: BLE001
                continue
            if k:
                per_rule.append({"rule": s["nguon_rule"]["sigmahq"], **score(k, attack)})
        by_level = {}
        for name, levels in LEVELS.items():
            sub = [x for x in specs if x["nguon_rule"]["level"] in levels]
            k, _ = union(con, sub)
            by_level[name] = {"hunt": len(sub), **score(k, attack), "lai": score(k | sysk, attack)}
        res["otrf"][report] = {"bo_log": ds, "nhan_sha256": sha, "ttp": len(cr.techniques(ca)), "theo_muc": by_level,
                               "sigmahq": {"rule_chon": len(selected), "hunt": len(specs), "khong_dich": len(skipped),
                                           "loi_cot": sig_err, **score(sig, attack)},
                               "he_thong": {"hunt": len(system.get(report, [])), "loi_cot": sys_err, **score(sysk, attack)},
                               "lai": score(sig | sysk, attack),
                               "chi_sigmahq_bat": len((sig - sysk) & attack), "chi_he_thong_bat": len((sysk - sig) & attack),
                               "rule_sigmahq_co_ket_qua": sorted(per_rule, key=lambda x: -x["can_ra"])}
        r = res["otrf"][report]
        print(f"{report:26s} {ds:14s} TTP {r['ttp']:2d} | SigmaHQ {r['sigmahq']['rule_chon']} rule/{r['sigmahq']['hunt']} hunt: "
              f"{'bắt' if r['sigmahq']['bat'] else 'KHÔNG'} {r['sigmahq']['tan_cong']} sk, FP {r['sigmahq']['fp']}, rà "
              f"{r['sigmahq']['can_ra']} | hệ thống {r['he_thong']['hunt']} hunt: {'bắt' if r['he_thong']['bat'] else 'KHÔNG'} "
              f"{r['he_thong']['tan_cong']} sk, FP {r['he_thong']['fp']}, rà {r['he_thong']['can_ra']} | lai: "
              f"{r['lai']['tan_cong']} sk, FP {r['lai']['fp']} | chỉ SigmaHQ bắt {r['chi_sigmahq_bat']}, chỉ hệ thống bắt "
              f"{r['chi_he_thong_bat']}")
        for name, x in r["theo_muc"].items():
            print(f"      SigmaHQ {name:13s} {x['hunt']:3d} hunt: {x['tan_cong']} sk, FP {x['fp']}, rà {x['can_ra']} | lai với hệ "
                  f"thống: {x['lai']['tan_cong']} sk, FP {x['lai']['fp']}")
    con = connect(config.resolve("data/work"))
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    for report, path in APT29.items():
        ca = ContractA.model_validate_json(config.resolve(path).read_text(encoding="utf-8"))
        selected = cr.select(cr.techniques(ca))
        specs, skipped = cr.compile_selected(selected, cols)
        sig, err = union(con, specs)
        n_hit = 0
        for s in specs:
            try:
                n_hit += bool(keys(con, s))
            except Exception:  # noqa: BLE001
                pass
        res["apt29_khong_nhan"][report] = {"ttp": len(cr.techniques(ca)), "rule_chon": len(selected), "hunt": len(specs),
                                           "khong_dich": len(skipped), "loi_cot": err, "hunt_co_ket_qua": n_hit,
                                           "su_kien_giu_hop": len(sig)}
        x = res["apt29_khong_nhan"][report]
        print(f"APT29 {report}: TTP {x['ttp']} · {x['rule_chon']} rule SigmaHQ · {x['hunt']} hunt · {x['hunt_co_ket_qua']} có kết "
              f"quả · hợp giữ {x['su_kien_giu_hop']} sự kiện · không dịch {x['khong_dich']} · lỗi cột {err}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sigmahq_theo_ttp.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
