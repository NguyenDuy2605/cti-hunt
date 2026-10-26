"""Baseline không dùng mô hình cho khâu trích TTP: chỉ lấy gợi ý BM25 mà khâu ② gửi kèm mỗi đoạn, so với ánh xạ MITRE.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver. Gợi ý lấy đúng từ ``s2_report.prepare`` (cùng bộ đọc, cùng cách chọn
đoạn, cùng chỉ mục BM25 trên định nghĩa kỹ thuật ATT&CK v19.2) nên khác bản có mô hình đúng ở một chỗ: ai quyết đoạn nào có
kỹ thuật nào. Ba mức: top-1, top-3 mỗi đoạn, và cả 8 gợi ý (trần recall của bước gợi ý — mô hình được chọn ngoài 8 gợi ý nếu
ghi lý do). Đáp án như ``do_ttp_mitre.py``: kỹ thuật đích của quan hệ ``uses`` có trích dẫn tới đúng report; precision là cận
dưới vì MITRE không ánh xạ mọi kỹ thuật trong bài.

    .venv/Scripts/python.exe -X utf8 scripts/do_ttp_bm25_mitre.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_mitre import CASES, STIX, mitre_sets, parent, pr  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.stages import s2_report  # noqa: E402

NGOAI = "../workspace/ioc_14-10/report_moi"
# report: (bundle đã đọc bằng bộ đọc của hệ thống, source_name trích dẫn trong ATT&CK, tên lượt LLM trong do_ttp_mitre hoặc None)
REPORTS = {
    "Solorigate (Microsoft)": ("data/dev/kiem_ocr_ms_01", "Microsoft Deep Dive Solorigate January 2021",
                               "Solorigate deep dive (Microsoft, 01/2021)"),
    "Raindrop (Symantec)": ("data/dev/kiem_ocr_sy_01", "Symantec RAINDROP January 2021", "Raindrop (Symantec, 01/2021)"),
    "POSHSPY (FireEye)": ("data/reports/moi/NEW-REPORT-03", "FireEye POSHSPY April 2017", "POSHSPY (FireEye, 03/2017)"),
    "Volt Typhoon (Microsoft)": ("data/reports/moi/VOLT-MS-1310", "Microsoft Volt Typhoon May 2023",
                                 "Volt Typhoon (Microsoft, 05/2023)"),
    "OilRig Outer Space / Juicy Mix (ESET)": (f"{NGOAI}/IOC-MOI-03", "ESET OilRig Campaigns Sep 2023", None),
    "ToddyCat (Kaspersky)": (f"{NGOAI}/IOC-MOI-02", "Kaspersky ToddyCat Check Logs October 2023", None),
    "Latrodectus (Elastic)": (f"{NGOAI}/IOC-MOI-05", "Elastic Latrodectus May 2024", None),
}


def bm25_sets(bundle: Path) -> tuple[dict[int, set[str]], int]:
    _, requests = s2_report.prepare(bundle, config.resolve(STIX), config.resolve("prompts/khau2_ttp_v2.md"), {}, top_k=8)
    units = [t for r in requests for t in json.loads(r["user"])["targets"]]
    return {k: {c["technique_id"] for u in units for c in u["candidates"][:k]} for k in (1, 3, 8)}, len(units)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    sets = mitre_sets(json.loads(config.resolve(STIX).read_text(encoding="utf-8")))
    res = {}
    for name, (bundle, src, llm_case) in REPORTS.items():
        gold = sets.get(src, set())
        bm, n_units = bm25_sets(config.resolve(bundle))
        row = {"nguon_mitre": src, "so_doan_muc_tieu": n_units, "mitre": len(gold)}
        for k, pred in bm.items():
            row[f"bm25_top{k}"] = {"dung_ma": pr(pred, gold), "muc_ky_thuat_cha": pr({parent(t) for t in pred},
                                                                                      {parent(t) for t in gold})}
        if llm_case:
            c = json.loads(config.resolve(CASES[llm_case][0]).read_text(encoding="utf-8"))
            pred = {t["technique_id"] for t in c["ttps"]}
            row["llm"] = {"luot": CASES[llm_case][2], "dung_ma": pr(pred, gold),
                          "muc_ky_thuat_cha": pr({parent(t) for t in pred}, {parent(t) for t in gold})}
        res[name] = row
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_ttp_bm25_mitre.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    f = lambda v: "  —  " if v is None else f"{v:.2f}"
    for name, row in res.items():
        print(f"\n== {name}: MITRE {row['mitre']} kỹ thuật · {row['so_doan_muc_tieu']} đoạn mục tiêu")
        for key in ("bm25_top1", "bm25_top3", "bm25_top8", "llm"):
            if key in row:
                x, y = row[key]["dung_ma"], row[key]["muc_ky_thuat_cha"]
                print(f"  {key:10s} trích {x['du_doan']:4d} · trùng {x['dung']:3d} · R {f(x['recall'])} · P≥ {f(x['precision_can_duoi'])}"
                      f" · cha: R {f(y['recall'])} P≥ {f(y['precision_can_duoi'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
