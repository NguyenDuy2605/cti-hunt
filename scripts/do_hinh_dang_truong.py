"""Đánh giá phép kiểm hình dạng trường (``stages/field_shape.py``) theo giao thức ``docs/METHODOLOGY.md``. Không nhãn.

Tập hunt: A = 93 hunt Claude bản tổng quát (``do_rule_otrf.load_rules``); các lượt ``huong2_sinh_rule.py`` (``--tap``); và
SigmaHQ (``--sigmahq``: mọi rule stable/test, mọi mức, biên dịch với danh mục chấm của bước C). Hồ sơ trường dựng từ ba nhóm
log: APT29 day 2, 7 bộ OTRF, 664 bộ attack_data. Với A và các lượt sinh rule, nối với kết quả "không bao giờ khớp" của
``do_rule_khong_khop.py`` (cùng thứ tự hunt) và với cách đọc tay ở ``25_…`` §3.

    python scripts/do_hinh_dang_truong.py --attack-db <events.duckdb> --khong-khop <thư mục ket_qua của 25>
        [--tap 7b=<sinh_rule>] [--sigmahq] --out <thư mục>
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_rule_khong_khop as kk  # noqa: E402
import do_rule_otrf as base  # noqa: E402
import huong2_cham as h2  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.eval import g0c  # noqa: E402
from cti_hunt.stages import community_rules, field_shape  # noqa: E402

# Cách đọc tay ở 25 §3 cho tập A (theo lượt và tiền tố mã hunt). Mọi hunt không bao giờ khớp còn lại là "hành vi vắng mặt".
DOC_TAY_A = {("pipeline/MS_01", "MS-H02__wmi-commandlineeventconsumer-executing"): "sai_ngu_nghia",
             ("agent/MS_04", "MS-H02__wmi-commandlineeventconsumer-binding"): "sai_ngu_nghia",
             ("pipeline/MS_01", "MS-H16__"): "sai_ngu_nghia",
             ("pipeline/MS_01", "MS-H22__"): "sai_ngu_nghia",
             ("pipeline/MS_01", "MS-H31__"): "chua_ro"}
HAT_GIONG = 20261019


def nhom_cua(tap: str, rule: dict, khong_khop: bool) -> str:
    if not khong_khop:
        return "co_khop"
    if tap != "A_claude_v3":
        return "khong_khop"            # các lượt sinh rule: đọc tay riêng theo giao thức 26 §4
    for (luot, tien_to), nhom in DOC_TAY_A.items():
        if luot in (rule.get("luot") or []) and rule["id"].startswith(tien_to):
            return nhom
    return "vang_mat"


def doc_khong_khop(thu_muc: Path) -> dict[str, list[bool]]:
    """{tập: [không bao giờ khớp?] theo đúng thứ tự hunt} từ theo_hunt.csv của do_rule_khong_khop."""
    out = collections.defaultdict(list)
    for r in csv.DictReader(open(thu_muc / "theo_hunt.csv", encoding="utf-8")):
        vals = [r[g] for g in ("apt29", "otrf", "attack_data")]
        chay = [v for v in vals if v not in ("", "None")]
        out[r["tap"]].append(bool(chay) and all(int(v) == 0 for v in chay))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--attack-db", required=True)
    ap.add_argument("--khong-khop", required=True)
    ap.add_argument("--tap", action="append", default=[])
    ap.add_argument("--sigmahq", action="store_true")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cons = [connect(config.resolve("data/work"))] + [connect(config.resolve(f"data/dev/{d}")) for d in sorted(base.DATASETS)]
    cons.append(kk.mo_attack(Path(a.attack_db)))
    checker = field_shape.Checker(cons)
    kk_map = doc_khong_khop(Path(a.khong_khop))
    taps = {"A_claude_v3": base.load_rules()}
    for s in a.tap:
        ten, _, duong = s.partition("=")
        taps[ten] = kk.rule_luot_sinh(Path(duong))
    kq = {"phien_ban": field_shape.VERSION, "nguong": {"N_MIN": field_shape.N_MIN, "DONG_MAX": field_shape.DONG_MAX,
                                                      "TY_LE": field_shape.TY_LE}, "tap": {}}
    dong = []
    for t, rs in taps.items():
        nk = kk_map.get(t, [])
        if len(nk) != len(rs):
            raise SystemExit(f"{t}: {len(rs)} hunt nhưng kết quả không bao giờ khớp có {len(nk)} dòng — chạy lại do_rule_khong_khop")
        bang = collections.defaultdict(lambda: [0, 0])
        ly_do = collections.Counter()
        for r, khong in zip(rs, nk):
            issues = checker.check({"scope": r["scope"], "candidates": r["candidates"]})
            g = nhom_cua(t, r, khong)
            bang[g][0] += 1
            bang[g][1] += bool(issues)
            ly_do.update({x for i in issues for x in i["ly_do"]})
            dong.append({"tap": t, "hunt": r["id"], "luot": ";".join(r.get("luot") or []), "nhom": g, "co_co": int(bool(issues)),
                         "chi_tiet": json.dumps(issues, ensure_ascii=False)})
        kq["tap"][t] = {"so_hunt": len(rs), "gan_co": sum(v[1] for v in bang.values()),
                        "theo_nhom": {g: {"so_hunt": v[0], "gan_co": v[1]} for g, v in sorted(bang.items())},
                        "ly_do": dict(ly_do.most_common())}
    if a.sigmahq:
        cols = set()
        for c in cons:
            cols |= {r[0] for r in c.execute("DESCRIBE events").fetchall()}
        dm = h2.danh_muc_cham(config.resolve("eval/inputs/huong2/bo_sung_danh_muc_cham.yaml"), out)
        metas, _ = community_rules._index(str(config.resolve(community_rules.SIGMAHQ)))
        specs, _ = community_rules.compile_selected([m for m in metas if m["status"] in g0c.STATUSES], cols,
                                                    community_rules.SIGMAHQ, dm)
        specs = [s for s in specs if s["scope"]["event_ids"]]
        co, ly_do, theo_muc = [], collections.Counter(), collections.defaultdict(lambda: [0, 0])
        for s in specs:
            issues = checker.check(s)
            lv = s["nguon_rule"]["level"]
            theo_muc[lv][0] += 1
            theo_muc[lv][1] += bool(issues)
            if issues:
                co.append((s, issues))
                ly_do.update({x for i in issues for x in i["ly_do"]})
        mau = random.Random(HAT_GIONG).sample(co, min(20, len(co)))
        kq["tap"]["sigmahq"] = {"so_hunt": len(specs), "gan_co": len(co), "ly_do": dict(ly_do.most_common()),
                                "theo_muc": {k: {"so_hunt": v[0], "gan_co": v[1]} for k, v in sorted(theo_muc.items())},
                                "mau_20_de_doc_tay": [{"hunt": s["id"], "rule": s["nguon_rule"]["sigmahq"], "co": i} for s, i in mau]}
        for s, i in co:
            dong.append({"tap": "sigmahq", "hunt": s["id"], "luot": s["nguon_rule"]["sigmahq"], "nhom": s["nguon_rule"]["level"],
                         "co_co": 1, "chi_tiet": json.dumps(i, ensure_ascii=False)})
    (out / "ket_qua.json").write_text(json.dumps(kq, ensure_ascii=False, indent=1), encoding="utf-8")
    with open(out / "theo_hunt.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["tap", "hunt", "luot", "nhom", "co_co", "chi_tiet"])
        w.writeheader()
        w.writerows(dong)
    for t, v in kq["tap"].items():
        print(f"{t}: gắn cờ {v['gan_co']}/{v['so_hunt']} · {v.get('theo_nhom') or v.get('theo_muc')} · lý do {v['ly_do']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
