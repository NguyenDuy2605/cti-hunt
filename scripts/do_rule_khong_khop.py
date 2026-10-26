"""Câu hỏi 3: rule qua kiểm tĩnh mà không bao giờ khớp (định nghĩa ghi trước ở ``docs/METHODOLOGY.md`` §1). Không nhãn.

Tập rule: A = 93 hunt hiệu lực của Claude ở 12 lượt bản tổng quát (``do_rule_otrf.load_rules``); B, C… = hunt của các lượt
``huong2_sinh_rule.py`` (``--tap tên=thư_mục``). Mỗi hunt chỉ chạy phần chọn ứng viên trong đúng channel và mã sự kiện của
nó, không áp mục lọc, trên ba nhóm log: APT29 day 2, 7 bộ OTRF phát triển, 664 bộ attack_data (tệp DuckDB của bước C).
Phép bằng không phân biệt hoa thường như hệ thống (``default_collation='nocase'``).

    python scripts/do_rule_khong_khop.py --tap 7b=<sinh_rule> --attack-db <events.duckdb> --out <thư mục>
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import duckdb
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.eval.thong_ke import wilson  # noqa: E402
from cti_hunt.hunt import runner  # noqa: E402


def rule_luot_sinh(sinh: Path) -> list[dict]:
    out = []
    for f in sorted(sinh.glob("ky_thuat/*/hunts/*.yaml")):
        s = yaml.safe_load(f.read_text(encoding="utf-8"))
        out.append({"id": s["id"], "ky_thuat": f.parent.parent.name, "scope": s["scope"], "candidates": s["candidates"]})
    return out


def dem(con, rule: dict) -> tuple[int | None, str]:
    """Số sự kiện khớp phần chọn ứng viên trong phạm vi của hunt; None kèm lỗi nếu không chạy được trên bộ này."""
    try:
        return con.execute(f"SELECT count(*) FROM events WHERE {runner._scope_where(rule['scope'])} "
                           f"AND ({rule['candidates']})").fetchone()[0], ""
    except duckdb.Error as e:
        return None, f"{type(e).__name__}: {str(e).splitlines()[0][:160]}"


def mo_attack(db: Path):
    con = duckdb.connect(str(db), read_only=True)
    con.execute("SET enable_progress_bar = false")
    con.execute("SET default_collation = 'nocase'")
    return con


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tap", action="append", default=[], help="tên=thư mục huong2_sinh_rule")
    ap.add_argument("--attack-db", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    taps = {"A_claude_v3": base.load_rules()}
    for s in a.tap:
        ten, _, duong = s.partition("=")
        taps[ten] = rule_luot_sinh(Path(duong))
    nhom = {"apt29": [config.resolve("data/work")], "otrf": [config.resolve(f"data/dev/{d}") for d in sorted(base.DATASETS)],
            "attack_data": [Path(a.attack_db)]}
    goc = {"A_claude_v3": "apt29"}
    # Khóa theo vị trí: hai hunt khác lượt có thể trùng mã (vd MS-H06 ở pipeline MS_01 và agent MS_03), không gộp chúng.
    dong = {(t, i): {"tap": t, "hunt": r["id"], "luot": ";".join(r.get("luot") or []), "channel": r["scope"]["channel"],
                     "event_ids": r["scope"]["event_ids"], **{g: None for g in nhom}, "loi": []}
            for t, rs in taps.items() for i, r in enumerate(rs)}
    for g, paths in nhom.items():
        for p in paths:
            con = mo_attack(p) if g == "attack_data" else connect(p)
            for t, rs in taps.items():
                for i, r in enumerate(rs):
                    n, loi = dem(con, r)
                    d = dong[(t, i)]
                    if n is None:
                        d["loi"].append(f"{g}/{p.name}: {loi}")
                    else:
                        d[g] = (d[g] or 0) + n
            con.close()
    kq = {"dinh_nghia": "docs/METHODOLOGY.md", "tap": {}}
    for t, rs in taps.items():
        ds = [dong[(t, i)] for i in range(len(rs))]
        chay = [d for d in ds if any(d[g] is not None for g in nhom)]
        khong = [d for d in chay if all((d[g] or 0) == 0 for g in nhom)]
        g0 = goc.get(t, "attack_data")
        lo, hi = wilson(len(khong), len(chay)) if chay else (0, 0)
        kq["tap"][t] = {"so_hunt": len(ds), "chay_duoc": len(chay), "khong_chay_duoc": len(ds) - len(chay),
                        "khong_bao_gio_khop": len(khong), "wilson95": [lo, hi],
                        "nhom_goc": g0, "khop_0_tren_nhom_goc": sum(1 for d in chay if d[g0] == 0),
                        "chay_duoc_tren_nhom_goc": sum(1 for d in chay if d[g0] is not None),
                        "theo_nhom": {g: {"chay_duoc": sum(1 for d in ds if d[g] is not None),
                                          "khop_0": sum(1 for d in ds if d[g] == 0)} for g in nhom},
                        "hunt_khong_bao_gio_khop": [d["hunt"] for d in khong]}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
    with open(out / "theo_hunt.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["tap", "hunt", "luot", "channel", "event_ids", *nhom, "loi"])
        w.writeheader()
        for d in dong.values():
            w.writerow({**d, "event_ids": json.dumps(d["event_ids"]), "loi": " | ".join(d["loi"])})
    for t, v in kq["tap"].items():
        print(f"{t}: {v['khong_bao_gio_khop']}/{v['chay_duoc']} hunt không bao giờ khớp (Wilson {v['wilson95'][0]:.2f}–"
              f"{v['wilson95'][1]:.2f}); không chạy được {v['khong_chay_duoc']}; khớp 0 trên {v['nhom_goc']}: "
              f"{v['khop_0_tren_nhom_goc']}/{v['chay_duoc_tren_nhom_goc']}; theo nhóm {v['theo_nhom']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
