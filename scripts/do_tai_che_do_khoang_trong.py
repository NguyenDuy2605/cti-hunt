"""Không nhãn, không API (15/10): chế độ chỉ săn khoảng trống bớt bao nhiêu TTP đưa vào khâu ④ trên 6 report.

Số TTP vào ④ quyết định số lô ④ (tối đa 10 TTP mỗi vòng), từ đó số giả thuyết người duyệt phải xem và số lời gọi ⑤. So hai
cấu hình của hệ thống: mặc định (mọi TTP huntable/partial) và `chi_san_khoang_trong` (bỏ TTP đã có rule SigmaHQ mức cao).
Danh mục ③ v2 hiệu lực theo bộ log của report (hồ sơ D17), độ phủ từ metadata SigmaHQ ghim.

    .venv/Scripts/python.exe -X utf8 scripts/do_tai_che_do_khoang_trong.py --out <thư mục ra>
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ban_do_khoang_trong import REPORTS  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.contracts import ContractA  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.stages import community_rules as cr, s3_telemetry, s4_hypothesis as S4  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    catalog = s3_telemetry.load_catalog(config.telemetry_catalog("v2"))
    rows = []
    for name, (ca_path, events) in REPORTS.items():
        ca = ContractA.model_validate_json(config.resolve(ca_path).read_text(encoding="utf-8"))
        con = connect(config.resolve(events))
        channels = {r[0] for r in con.execute("SELECT DISTINCT ev_channel FROM events").fetchall()}
        con.close()
        cov = cr.coverage(cr.techniques(ca), channels)
        full, _ = S4.select_inputs(ca, catalog, cov)
        gap, _ = S4.select_inputs(ca, catalog, cov, skip_covered=True)
        rows.append({"report": name, "bo_log": events, "ttp": len(ca.ttps),
                     "vao_khau4_mac_dinh": len(full), "vao_khau4_chi_khoang_trong": len(gap),
                     "vong_khau4_mac_dinh": math.ceil(len(full) / 10), "vong_khau4_chi_khoang_trong": math.ceil(len(gap) / 10),
                     "ky_thuat_khoang_trong": sorted({i["ttp"].technique_id for i in gap})})
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "tai_che_do_khoang_trong.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["| Report | Bộ log | TTP | Vào ④ mặc định | Vào ④ chỉ khoảng trống | Lô ④ (10 TTP/lô) | Kỹ thuật còn lại |",
             "|---|---|---:|---:|---:|---|---|"]
    tot = [0, 0, 0]
    for r in rows:
        tot = [tot[0] + r["ttp"], tot[1] + r["vao_khau4_mac_dinh"], tot[2] + r["vao_khau4_chi_khoang_trong"]]
        lines.append(f"| {r['report']} | {r['bo_log']} | {r['ttp']} | {r['vao_khau4_mac_dinh']} | "
                     f"{r['vao_khau4_chi_khoang_trong']} | {r['vong_khau4_mac_dinh']} → {r['vong_khau4_chi_khoang_trong']} | "
                     f"{', '.join(r['ky_thuat_khoang_trong']) or '—'} |")
    lines.append(f"| **Tổng** | | **{tot[0]}** | **{tot[1]}** | **{tot[2]}** | | |")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
