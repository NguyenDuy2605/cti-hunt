"""Đo TTP khâu ② so với ánh xạ của MITRE ATT&CK v19.2 cho đúng report đó — đáp án độc lập với Silver v1.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver. Đáp án = các kỹ thuật là đích của quan hệ `uses` trong ATT&CK v19.2
có trích dẫn nguồn (external_references.source_name) là report đang xét. MITRE chỉ ánh xạ phần liên quan tới hồ sơ nhóm /
phần mềm, nên đáp án là tập con của những gì report mô tả: recall so với MITRE có nghĩa; precision so với MITRE là cận dưới
(kỹ thuật hệ thống trích mà MITRE không ánh xạ chưa chắc là sai). Hai mức so: đúng mã (kể cả kỹ thuật con) và mức kỹ thuật
cha (T1003.001 → T1003). Khâu ② không dùng procedure example của ATT&CK khi trích (bộ gợi ý BM25 chỉ dùng định nghĩa kỹ thuật),
nên không có rò rỉ trực tiếp từ đáp án; mô hình có thể đã thấy ATT&CK lúc huấn luyện — không loại được.

    .venv/Scripts/python.exe -X utf8 scripts/do_ttp_mitre.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

STIX = "data/attack/enterprise-attack-19.2.json"
# tên report: (Contract A đã lưu ngoài runs/, source_name trích dẫn trong ATT&CK, ghi chú về lượt trích)
# Hai tệp trong runs/ chỉ là đầu ra khâu ② (không phải nhãn); người vận hành cho mở đúng hai tệp này ngày 14/10 để chấm với MITRE.
CASES = {
    "Solorigate deep dive (Microsoft, 01/2021)": (
        "runs/khau2_20260925-161526/contract_a_MS.json",
        "Microsoft Deep Dive Solorigate January 2021", "report đánh giá; lượt chính thức 25/9 (Opus 5.5 high)"),
    "Raindrop (Symantec, 01/2021)": (
        "runs/khau2_20260925-161526/contract_a_SY.json",
        "Symantec RAINDROP January 2021", "report đánh giá; lượt chính thức 25/9 (Opus 5.5 high)"),
    "POSHSPY (FireEye, 03/2017)": (
        "data/reports/moi/NEW-REPORT-03/extractions/extract_6edb7b7bfccd40e38c01677c52c51da6/contract_a.json",
        "FireEye POSHSPY April 2017", "report đánh giá; nguyên đầu ra chính thức 25/9 (Opus 5.5 high), bản chép kiểm hash"),
    "Volt Typhoon (Microsoft, 05/2023)": (
        "data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024/contract_a.json",
        "Microsoft Volt Typhoon May 2023", "report mới; lượt trích 13/10 (Sonnet 5 high), bản tổng quát"),
    "Solorigate deep dive — lượt phụ 28/9": (
        "data/reports/moi/NEW-REPORT-01/extraction/contract_a.json",
        "Microsoft Deep Dive Solorigate January 2021", "lượt phụ 28/9 qua bộ đọc HTML (Sonnet 5 high), không phải số chính"),
}


def mitre_sets(stix: dict) -> dict[str, set[str]]:
    by_id = {o["id"]: o for o in stix["objects"]}
    out: dict[str, set[str]] = {}
    for o in stix["objects"]:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        tgt = by_id.get(o.get("target_ref", ""))
        if not tgt or tgt.get("type") != "attack-pattern" or tgt.get("revoked") or tgt.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in tgt.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        for r in o.get("external_references", []) or []:
            if tid and r.get("source_name"):
                out.setdefault(r["source_name"], set()).add(tid)
    return out


def parent(t: str) -> str:
    return t.split(".")[0]


def pr(pred: set[str], gold: set[str]) -> dict:
    tp = pred & gold
    p = len(tp) / len(pred) if pred else None
    r = len(tp) / len(gold) if gold else None
    return {"dap_an": len(gold), "du_doan": len(pred), "dung": len(tp), "precision_can_duoi": p, "recall": r,
            "thieu": sorted(gold - pred), "ngoai_mitre": sorted(pred - gold)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    stix = json.loads(Path(STIX).read_text(encoding="utf-8"))
    sets = mitre_sets(stix)
    res = {}
    for name, (path, src, note) in CASES.items():
        c = json.loads(Path(path).read_text(encoding="utf-8"))
        pred = {t["technique_id"] for t in c["ttps"]}
        gold = sets.get(src, set())
        res[name] = {"contract_a": path, "nguon_mitre": src, "ghi_chu": note, "so_ttp": len(c["ttps"]),
                     "dung_ma": pr(pred, gold), "muc_ky_thuat_cha": pr({parent(t) for t in pred}, {parent(t) for t in gold})}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_ttp_mitre.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    for name, r in res.items():
        print(f"\n== {name} — {r['ghi_chu']}; {r['so_ttp']} TTP")
        for lv in ("dung_ma", "muc_ky_thuat_cha"):
            x = r[lv]
            f = lambda v: "—" if v is None else f"{v:.2f}"
            print(f"  {lv:17s} MITRE {x['dap_an']} · hệ thống {x['du_doan']} · trùng {x['dung']} · recall {f(x['recall'])} · "
                  f"precision (cận dưới) {f(x['precision_can_duoi'])}")
            print(f"  {'':17s} thiếu: {x['thieu']}")
            print(f"  {'':17s} ngoài MITRE: {x['ngoai_mitre']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
