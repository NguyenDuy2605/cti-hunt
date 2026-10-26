"""Bảy kịch bản OTRF có nhãn dòng tiến trình (dữ liệu phát triển): mỗi kịch bản hai đơn vị — bước kỹ thuật chính (sự kiện tấn
công khớp truy vấn "cốt lõi" của kỹ thuật, định nghĩa lúc kiểm nhãn 14/10, trước khi đo hunt) và mọi hoạt động tấn công.

Cách chạy so sánh (không gọi API, không đọc nhãn APT29):
  - Hệ thống: 93 rule bản tổng quát sinh từ report APT29 (tính di chuyển sang kịch bản khác), như sinh; và với hai cổng mới
    (bỏ rule bị cổng độ rộng đánh dấu, chạy biến thể khi có).
  - SigmaHQ high+critical toàn bộ (không theo report).
  - SigmaHQ high+critical theo kỹ thuật của kịch bản (như một report chỉ nêu kỹ thuật đó, cộng bước khởi chạy T1059.001).

    .venv/Scripts/python.exe -X utf8 scripts/do_otrf_7_kich_ban.py --nhan ../workspace/nhan_otrf_14-10 --out <thư mục>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import do_bien_the_rule as bt  # noqa: E402
import do_co_nhan_otrf as m  # noqa: E402
import do_rule_otrf as base  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.adapters.duckdb_sigma import load_catalog  # noqa: E402
from cti_hunt.data.store import connect  # noqa: E402
from cti_hunt.eval import g0c  # noqa: E402
from cti_hunt.filter_approval import _breadth  # noqa: E402
from cti_hunt.stages import community_rules as cr  # noqa: E402
from cti_hunt.stages import rule_variant as rv  # noqa: E402

HIGH = {"high", "critical"}
# Bước kỹ thuật chính: cùng truy vấn đã dùng để kiểm nhãn (scratchpad kiem_cot_loi.py, 14/10, trước khi đo hunt)
CORE = {
    "otrf-runkeys": "ev_channel LIKE '%sysmon%' AND ev_eid IN (12,13) AND TargetObject ILIKE '%CurrentVersion%Run%'",
    "otrf-psexec": "(ev_channel='system' AND ev_eid=7045) OR (ev_channel='security' AND ev_eid=4697)",
    "otrf-schtasks": "ev_channel='security' AND ev_eid IN (4698,4699,4700,4702)",
    "otrf-wmi-sub": "ev_channel LIKE '%sysmon%' AND ev_eid IN (19,20,21)",
    "otrf-wmi-exec": "ev_channel LIKE '%sysmon%' AND ev_eid=1 AND ParentImage ILIKE '%wmiprvse%'",
    "otrf-psremoting": "ev_channel LIKE '%sysmon%' AND ev_eid=1 AND ParentImage ILIKE '%wsmprovhost%'",
    "otrf-dcom": "ev_channel LIKE '%sysmon%' AND ev_eid=1 AND (ParentImage ILIKE '%mmc%' OR ParentImage ILIKE '%explorer%')",
}


def keys_of(con, specs):
    out = set()
    for s in specs:
        try:
            out |= m.keys(con, s) if hasattr(m, "keys") else set()
        except Exception:  # noqa: BLE001
            pass
    return out


def kept(con, spec) -> set:
    from cti_hunt.hunt import runner
    where = " AND ".join([runner._scope_where(spec["scope"]), f"({spec['candidates']})"] +
                         [f"({f['where']}) IS NOT TRUE" for f in spec.get("filters") or []])
    return {(str(h), str(c), str(r)) for h, c, r in
            con.execute(f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {where}").fetchall()}


def union(con, specs) -> set:
    out = set()
    for s in specs:
        try:
            out |= kept(con, s)
        except Exception:  # noqa: BLE001 — cột không có ở bộ này
            pass
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nhan", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    vcfg = rv.load_config()
    catalog = load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    system = bt.load_specs()
    metas, _ = cr._index(str(config.resolve(cr.SIGMAHQ)))
    table, totals = {}, {}
    for ds, techs in base.DATASETS.items():
        attack, _ = m.load_labels(Path(a.nhan), ds)
        con = connect(config.resolve(f"data/dev/{ds}"))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        core = {(str(h), str(c), str(r)) for h, c, r in
                con.execute(f"SELECT ev_host, ev_channel, ev_rec FROM events WHERE {CORE[ds]}").fetchall()} & attack
        wide = _breadth(con, system)
        gated = []
        for s in system:
            if s["id"] in wide:
                continue
            var, _ = rv.variant_spec(s, vcfg, catalog) if rv._is_root(s) else (None, "")
            gated.append({**var, "scope": s["scope"]} if var else s)
        all_high, _ = cr.compile_selected([x for x in metas if x["status"] in g0c.STATUSES], cols)
        all_high = [s for s in all_high if s["nguon_rule"]["level"] in HIGH]
        tech_high, _ = cr.compile_selected(cr.select(sorted(t.lower() for t in techs | {"T1059.001"})), cols)
        tech_high = [s for s in tech_high if s["nguon_rule"]["level"] in HIGH]
        ways = {"he_thong": system, "he_thong_cong": gated, "sigmahq_high_toan_bo": all_high,
                "sigmahq_high_theo_ky_thuat": tech_high}
        row = {}
        for w, specs in ways.items():
            k = union(con, specs)
            labeled = {x for x in k if x[1] in m.LABELED}
            row[w] = {"hunt": len(specs), "ky_thuat_chinh": bool(k & core), "co_tan_cong": bool(k & attack),
                      "su_kien_tan_cong": len(k & attack), "bao_nham": len(labeled - attack), "phai_ra": len(k)}
        table[ds] = {"ky_thuat": sorted(techs), "su_kien_cot_loi": len(core), "su_kien_tan_cong": len(attack), **row}
        print(f"{ds:16s} cốt lõi {len(core):3d} | " + " | ".join(
            f"{w}: {'CHÍNH' if v['ky_thuat_chinh'] else '-'}{'/tc' if v['co_tan_cong'] else ''} {v['su_kien_tan_cong']} sk FP "
            f"{v['bao_nham']}" for w, v in row.items()))
    for w in ("he_thong", "he_thong_cong", "sigmahq_high_toan_bo", "sigmahq_high_theo_ky_thuat"):
        totals[w] = {"ky_thuat_chinh": sum(t[w]["ky_thuat_chinh"] for t in table.values()),
                     "co_tan_cong": sum(t[w]["co_tan_cong"] for t in table.values()),
                     "su_kien_tan_cong": sum(t[w]["su_kien_tan_cong"] for t in table.values()),
                     "bao_nham": sum(t[w]["bao_nham"] for t in table.values()),
                     "phai_ra": sum(t[w]["phai_ra"] for t in table.values())}
        print(f"TỔNG {w:28s} kỹ thuật chính {totals[w]['ky_thuat_chinh']}/7 · có tấn công {totals[w]['co_tan_cong']}/7 · "
              f"sk tấn công {totals[w]['su_kien_tan_cong']} · báo nhầm {totals[w]['bao_nham']} · phải rà {totals[w]['phai_ra']}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "otrf_7_kich_ban.json").write_text(json.dumps({"bang": table, "tong": totals}, ensure_ascii=False, indent=1),
                                              encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
