"""Ma trận report × kịch bản OTRF với nhãn dòng tiến trình: hunt hệ thống đã sinh từ mỗi report chạy trên cả 7 bộ.

Lấy hunt gốc (không pivot, không ràng buộc nhiều sự kiện) đã thực thi của 9 lượt thật (scripts/do_co_nhan_otrf.py: Emotet ×7,
Volt ×1, IcedID ×1), gộp theo report và bỏ hunt trùng truy vấn; chạy nguyên truy vấn và mục lọc đã áp trên từng bộ OTRF. Ô có
kịch bản khớp report (Emotet/Volt × wmi-exec) là phép đo bắt; ô khác chủ yếu đo báo nhầm khi report không mô tả kịch bản.
Nhãn là dữ liệu phát triển (scripts/nhan_otrf.py). Không gọi API.

    .venv/Scripts/python.exe -X utf8 scripts/do_ma_tran_report_otrf.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import do_co_nhan_otrf as m  # noqa: E402
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402


def report_hunts() -> dict[str, list[dict]]:
    out, seen = {}, set()
    for report, run in m.RUNS:
        rec = json.loads((config.resolve(run) / "agent_dev_record.json").read_text(encoding="utf-8"))
        for item in rec.get("executed_specs") or []:
            spec = yaml.safe_load(Path(item["path"]).read_text(encoding="utf-8"))
            if not rv._is_root(spec):
                continue
            key = (report, spec["scope"]["channel"].lower(), tuple(spec["scope"]["event_ids"]), spec["candidates"],
                   tuple(f["where"] for f in spec.get("filters") or []))
            if key in seen:
                continue
            seen.add(key)
            out.setdefault(report, []).append(spec)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    hunts = report_hunts()
    table = {}
    for ds in base.DATASETS:
        attack, sha = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        for report, specs in hunts.items():
            caught, fp, err, hit_hunts = set(), 0, 0, 0
            for spec in specs:
                try:
                    h = m.measure_spec(con, spec, attack)
                except Exception:  # noqa: BLE001 — cột không có ở bộ này
                    err += 1
                    continue
                caught |= set(map(tuple, h["tp_keys"]))
                fp += h["fp"] or 0
                hit_hunts += h["tp"] > 0
            table.setdefault(report, {})[ds] = {"so_hunt": len(specs), "hunt_co_tp": hit_hunts, "bat": bool(caught),
                                                "su_kien_tan_cong": len(caught), "fp": fp, "loi_cot": err}
    print(f"{'report':26s} " + " ".join(f"{d.replace('otrf-', ''):>14s}" for d in base.DATASETS))
    for report, row in table.items():
        print(f"{report:26s} " + " ".join(
            f"{('bắt ' if c['bat'] else '— ') + str(c['su_kien_tan_cong']) + '/FP ' + str(c['fp']):>14s}"
            for c in row.values()) + f"   ({next(iter(row.values()))['so_hunt']} hunt)")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ma_tran_report_otrf.json").write_text(json.dumps(table, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
