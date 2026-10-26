"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn, không đổi hunt hay lượt.

Công cụ lai (15/10) trên APT29 day 2, dòng MS+SY (2 report độc lập với kịch bản) và PS:
- **SigmaHQ theo TTP**: mọi rule SigmaHQ stable/test có tag trùng TTP khâu ② rút từ report (stages/community_rules.py,
  quy tắc chọn của G0(c)), ba mức: tất cả · từ medium · high+critical.
- **Hệ thống**: các lượt chính của bản tổng quát (tuyến B v3), như số đã công bố 08/10.
- **Lai**: hunt hệ thống ∪ SigmaHQ high+critical theo TTP.
Chỉ số giống do_co_nhan_v2_moi.py: bước bắt được trên 5, sự kiện tấn công, báo nhầm, precision. Chỉ dùng cho báo cáo; không
dùng chỉnh thiết kế. Quy tắc chọn rule SigmaHQ và ba mức chốt trước khi đo (docs/METHODOLOGY.md).

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_sigmahq_apt29.py --out runs/co_nhan_sigmahq_01
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_pipeline_v2 as V2  # noqa: E402
import do_co_nhan_v2_moi as M  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.stages import community_rules as cr  # noqa: E402

CONTRACT = "runs/khau2_20260925-161526/contract_a_{}.json"
LEVELS = {"tat_ca": None, "tu_medium": {"medium", "high", "critical"}, "high_critical": {"high", "critical"}}


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    out = M.check_out(ap.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    runs = [r for r in M.runs() if r[1] == M.B3 and r[4] == "chinh"]
    con = connect(config.resolve(ds["work_dir"]))
    try:
        summary = _labels_ready(con, ds)
        if summary["problems"]:
            raise SystemExit("Nhãn chưa join sạch, không tính: " + "; ".join(map(str, summary["problems"])))
        lv = ds["labels_v1"]
        steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
        independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
        with_log = {r[0] for r in con.execute("SELECT DISTINCT l.buoc FROM attack_labels l "
                                              "JOIN events e USING (ev_host, ev_channel, ev_rec)").fetchall()}
        frames = sorted(b for b in with_log if b and b not in {s.substep for s in steps})
        system = {}
        for name, _, report, paths, _, _ in runs:
            hunts = []
            for p in paths:
                spec, kiem = V2.load_executed(p, con)
                hunts.append(V2.measure_hunt(con, spec, steps, independent, kiem, p))
            system[name] = hunts
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        sigma, sigma_info = {}, {}
        for report in ("MS", "SY", "PS"):
            ca = ContractA.model_validate_json(config.resolve(CONTRACT.format(report)).read_text(encoding="utf-8"))
            specs, skipped = cr.compile_selected(cr.select(cr.techniques(ca)), columns)
            hunts, errors = [], 0
            for spec in specs:
                spec.update(_sha256="sigmahq", _path=None)
                try:
                    h = V2.measure_hunt(con, spec, steps, independent, {"cach": "sigmahq"}, Path(spec["nguon_rule"]["sigmahq"]))
                except Exception:  # noqa: BLE001 — cột/kiểu không có ở bộ này: đếm, không đoán
                    errors += 1
                    continue
                h["level"] = spec["nguon_rule"]["level"]
                hunts.append(h)
            sigma[report] = hunts
            sigma_info[report] = {"hunt": len(specs), "khong_dich": len(skipped), "loi_khi_chay": errors}
    finally:
        con.close()

    def summ(name, report, hunts, reports):
        r = V2.summarize(name, report, hunts, steps, with_log, frames, independent, reports)
        return {k: v for k, v in r.items() if k != "_keys"}

    def lvl(report, key):
        allowed = LEVELS[key]
        return [h for h in sigma[report] if allowed is None or h["level"] in allowed]

    pairs = [("pipeline", f"{M.B3} pipeline SY_02", f"{M.B3} pipeline MS_01")]
    pairs += [(f"agent lượt {k}", f"{M.B3} agent {sy}", f"{M.B3} agent {ms}")
              for k, (sy, ms) in enumerate(zip(M.V3_AGENT_SLOTS["SY"], M.V3_AGENT_SLOTS["MS"]), start=1)]
    rows = []
    for key in LEVELS:
        rows.append(summ(f"SigmaHQ theo TTP · {key} · MS+SY", "MS+SY", lvl("MS", key) + lvl("SY", key), independent))
    for label, sy, ms in pairs:
        rows.append(summ(f"Hệ thống · {label} · MS+SY", "MS+SY", system[sy] + system[ms], independent))
        rows.append(summ(f"Lai (hệ thống + SigmaHQ high_critical) · {label} · MS+SY", "MS+SY",
                         system[sy] + system[ms] + lvl("MS", "high_critical") + lvl("SY", "high_critical"), independent))
    for key in LEVELS:
        rows.append(summ(f"SigmaHQ theo TTP · {key} · PS", "PS", lvl("PS", key), ["PS"]))
    out.mkdir(parents=True)
    payload = {"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo; không dùng chỉnh thiết kế (docs/METHODOLOGY.md §4.2)",
               "sigmahq": sigma_info, "cach_chay": rows,
               "rule_sigmahq_co_tan_cong": [{"report": rep, "rule": h["tep"], "level": h["level"], "tan_cong": h["tan_cong"],
                                             "fp": h["fp"], "buoc": h["buoc_cuoi"]}
                                            for rep, hs in sigma.items() for h in hs if h["tan_cong"]]}
    (out / "ket_qua.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    lines = ["| Cách chạy | Số hunt | Bước /5 | Sự kiện tấn công | Báo nhầm | Precision |", "|---|---:|---|---:|---:|---:|"]
    for r in rows:
        pr = "—" if r["precision"] is None else f"{r['precision']:.2%}"
        lines.append(f"| {r['ten']} | {r['so_hunt']} | {len(r['buoc_5'])} ({', '.join(r['buoc_5'])}) | {r['tan_cong']} | "
                     f"{r['fp']} | {pr} |")
    md = "\n".join(lines)
    (out / "tom_tat.md").write_text(md + "\n", encoding="utf-8")
    print(md)
    print(json.dumps(sigma_info, ensure_ascii=False))
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
