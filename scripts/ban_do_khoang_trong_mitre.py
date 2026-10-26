"""Không nhãn, không API, không tải (15/10): rule cộng đồng SigmaHQ phủ bao nhiêu phần kỹ thuật mà các report CTI nêu, trên
toàn bộ report được MITRE ATT&CK v19.2 trích dẫn.

Mỗi "report" là một URL trích dẫn trong quan hệ `uses` (nhóm, phần mềm, chiến dịch → kỹ thuật) của STIX ATT&CK v19.2; kỹ thuật
của report là các kỹ thuật MITRE gắn với trích dẫn đó. Chỉ giữ kỹ thuật còn hiệu lực có nền tảng Windows (SigmaHQ ghim chỉ có
rule Windows), và report có từ 5 kỹ thuật Windows. Độ phủ dùng đúng `community_rules.coverage` của hệ thống (rule stable/test,
tag trùng chính xác, mức high/critical là "cao"), với giả định thu thập đủ mọi kênh log trong danh mục logsource (Sysmon,
Security, PowerShell, System, WMI…). Kèm trạng thái quan sát được của kỹ thuật theo danh mục ③ v2.

    .venv/Scripts/python.exe -X utf8 scripts/ban_do_khoang_trong_mitre.py --out <thư mục ra>
"""
from __future__ import annotations

import argparse
import collections
import json
import statistics
import sys
from pathlib import Path

from cti_hunt import config
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.stages import community_rules as cr, s3_telemetry

MIN_TTP = 5


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    stix = config.resolve(config.load("reports")["attack"]["stix_path"])
    objs = json.loads(stix.read_text(encoding="utf-8"))["objects"]
    tech = {}
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ext and "Windows" in (o.get("x_mitre_platforms") or []):
            tech[o["id"]] = ext.lower()
    reports: dict[str, set[str]] = collections.defaultdict(set)
    names: dict[str, str] = {}
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        t = tech.get(o.get("target_ref"))
        if not t:
            continue
        for e in o.get("external_references") or []:
            if e.get("url"):
                reports[e["url"]].add(t)
                names.setdefault(e["url"], e.get("source_name", ""))
    reports = {u: ts for u, ts in reports.items() if len(ts) >= MIN_TTP}

    catalog = duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    channels = {str(s.get("channel", "")).lower() for srcs in catalog.values() for s in srcs if s.get("channel")}
    union = sorted(set().union(*reports.values()))
    cov = cr.coverage(union, channels)
    tel = s3_telemetry.load_catalog(config.telemetry_catalog("v2"))

    pairs = collections.Counter()
    per_report = []
    gap_count = collections.Counter()
    for u, ts in reports.items():
        c = collections.Counter(cov[t]["muc"] for t in ts)
        pairs.update(c)
        per_report.append({"url": u, "ten": names[u], "so_ky_thuat": len(ts), "cao": c["cao"], "thap": c["thap"],
                           "khong_co_rule": c["khong_co_rule"], "ty_le_cao": round(c["cao"] / len(ts), 4)})
        for t in ts:
            if cov[t]["muc"] != "cao":
                gap_count[t] += 1
    total = sum(pairs.values())
    ratios = sorted(r["ty_le_cao"] for r in per_report)
    q = statistics.quantiles(ratios, n=4)
    status = collections.Counter()
    for t, n in gap_count.items():
        status[s3_telemetry.map_technique(t.upper(), tel)["status"]] += n
    uniq = collections.Counter(cov[t]["muc"] for t in union)
    res = {"so_report": len(reports), "nguong_ky_thuat": MIN_TTP, "so_cap_report_ky_thuat": total,
           "cap_theo_muc": dict(pairs), "ky_thuat_khac_nhau": len(union), "ky_thuat_theo_muc": dict(uniq),
           "ty_le_cao_moi_report": {"q1": q[0], "trung_vi": q[1], "q3": q[2], "min": ratios[0], "max": ratios[-1]},
           "khoang_trong_theo_trang_thai_quan_sat": dict(status),
           "khoang_trong_hay_gap": [{"ky_thuat": t.upper(), "so_report": n,
                                     "trang_thai": s3_telemetry.map_technique(t.upper(), tel)["status"]}
                                    for t, n in gap_count.most_common(20)],
           "report": sorted(per_report, key=lambda r: r["ty_le_cao"])}
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "ban_do_khoang_trong_mitre.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    pc = lambda x: f"{x / total:.1%}"  # noqa: E731
    print(f"{len(reports)} report MITRE trích dẫn (≥ {MIN_TTP} kỹ thuật Windows); {total} cặp report–kỹ thuật; "
          f"{len(union)} kỹ thuật khác nhau")
    print(f"Cặp: cao {pairs['cao']} ({pc(pairs['cao'])}) · chỉ mức thấp {pairs['thap']} ({pc(pairs['thap'])}) · "
          f"không có rule {pairs['khong_co_rule']} ({pc(pairs['khong_co_rule'])})")
    print(f"Kỹ thuật khác nhau: {dict(uniq)}")
    print(f"Tỷ lệ kỹ thuật có rule cao mỗi report: Q1 {q[0]:.0%} · trung vị {q[1]:.0%} · Q3 {q[2]:.0%} "
          f"(min {ratios[0]:.0%}, max {ratios[-1]:.0%})")
    print(f"Khoảng trống (cặp) theo trạng thái quan sát của danh mục ③: {dict(status)}")
    print("Khoảng trống hay gặp:", ", ".join(f"{g['ky_thuat']}({g['so_report']},{g['trang_thai'][:4]})"
                                            for g in res["khoang_trong_hay_gap"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
