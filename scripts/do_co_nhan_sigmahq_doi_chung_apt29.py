"""CÓ NHÃN — chỉ người vận hành chạy ở cửa sổ riêng (docs/METHODOLOGY.md §4.2). Không gọi API, không ghi nhãn.

Đối chứng cho scripts/do_co_nhan_sigmahq_apt29.py (đặt ra **sau** khi thấy kết quả chính 15/10: SigmaHQ high+critical theo TTP
của report bắt 5/5 bước). Câu hỏi: chính TTP của report có quyết định không?
  1. SigmaHQ high+critical **toàn bộ** cây rules/windows, không chọn theo report;
  2. SigmaHQ high+critical theo TTP của report **không liên quan** đến kịch bản (IcedID của The DFIR Report, Volt Typhoon của
     Microsoft — Contract A đã có từ các lượt trước).
Cùng hàm đo, cùng chỉ số. Chỉ dùng cho báo cáo.

    .venv/Scripts/python.exe -X utf8 scripts/do_co_nhan_sigmahq_doi_chung_apt29.py --out runs/co_nhan_sigmahq_doi_chung_01
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_co_nhan_pipeline_v2 as V2  # noqa: E402
import do_co_nhan_v2_moi as M  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.eval import g0c  # noqa: E402
from cti_hunt.stages import community_rules as cr  # noqa: E402

HIGH = {"high", "critical"}
UNRELATED = {
    "IcedID (The DFIR Report)": "tmp/thu_cti_icedid_7-10/luot_graph/contract_a.json",
    "Volt Typhoon (Microsoft)": "data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024/"
                                "contract_a.json",
}


def main(argv=None):
    from cti_hunt.cli import _ds, _labels_ready, _rp
    from cti_hunt.data.store import connect
    from cti_hunt.labels import ground_truth
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    out = M.check_out(ap.parse_args(argv).out)
    ds, rp = _ds(), _rp()
    root = config.resolve(cr.SIGMAHQ)
    metas, _ = cr._index(str(root))
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
        columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}

        def measure(selected):
            specs, skipped = cr.compile_selected(selected, columns)
            hunts, errors = [], 0
            for spec in specs:
                if spec["nguon_rule"]["level"] not in HIGH:
                    continue
                spec.update(_sha256="sigmahq", _path=None)
                try:
                    hunts.append(V2.measure_hunt(con, spec, steps, independent, {"cach": "sigmahq"},
                                                 Path(spec["nguon_rule"]["sigmahq"])))
                except Exception:  # noqa: BLE001
                    errors += 1
            return hunts, {"rule_chon": len(selected), "hunt": len(hunts), "khong_dich": len(skipped), "loi": errors}

        groups = {}
        everything = [m for m in metas if m["status"] in g0c.STATUSES]
        groups["SigmaHQ high+critical · toàn bộ, không theo report"] = measure(everything)
        for name, path in UNRELATED.items():
            ca = ContractA.model_validate_json(config.resolve(path).read_text(encoding="utf-8"))
            groups[f"SigmaHQ high+critical · theo TTP của {name} (không liên quan)"] = measure(cr.select(cr.techniques(ca)))
    finally:
        con.close()
    rows = []
    for name, (hunts, info) in groups.items():
        r = V2.summarize(name, "MS+SY", hunts, steps, with_log, frames, independent, independent)
        rows.append({**{k: v for k, v in r.items() if k != "_keys"}, "thong_tin": info})
    out.mkdir(parents=True)
    (out / "ket_qua.json").write_text(json.dumps({"canh_bao": "CÓ NHÃN — chỉ dùng cho báo cáo", "cach_chay": rows},
                                                 ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    lines = ["| Cách chạy | Số hunt | Bước /5 | Sự kiện tấn công | Báo nhầm | Precision |", "|---|---:|---|---:|---:|---:|"]
    for r in rows:
        pr = "—" if r["precision"] is None else f"{r['precision']:.2%}"
        lines.append(f"| {r['ten']} | {r['so_hunt']} | {len(r['buoc_5'])} ({', '.join(r['buoc_5'])}) | {r['tan_cong']} | "
                     f"{r['fp']} | {pr} |")
    md = "\n".join(lines)
    (out / "tom_tat.md").write_text(md + "\n", encoding="utf-8")
    print(md)
    print(f"Đầy đủ: {out / 'ket_qua.json'}")


if __name__ == "__main__":
    main()
