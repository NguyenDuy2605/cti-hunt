"""Khoảng tin cậy và kiểm định cặp cho khâu trích TTP: LLM so với gợi ý BM25, trên cùng đáp án MITRE ATT&CK v19.2.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver. Dùng lại đúng đầu vào của ``do_ttp_mitre.py`` (Contract A đã lưu của
lượt LLM) và ``do_ttp_bm25_mitre.py`` (gợi ý BM25 khâu ② gửi kèm mỗi đoạn), chỉ trên 4 report có lượt LLM.

Mỗi "mục" là một cặp (report, kỹ thuật MITRE ánh xạ cho report đó). Với mỗi mục ghi: LLM có trích không, BM25 top-1 / top-3 /
cả 8 gợi ý có chứa không. Từ bảng đó tính:
- recall của từng cách kèm khoảng tin cậy Wilson 95%;
- precision cận dưới kèm khoảng Wilson (mẫu số là số kỹ thuật mỗi cách trích, khác nhau giữa các cách nên không ghép cặp);
- kiểm định McNemar chính xác cho recall, LLM so với từng mức BM25 (cùng mục nên ghép cặp được);
- kiểm định dấu ở mức report (đơn vị độc lập thô nhất: 4 report).
Hai mức so: đúng mã (kể cả kỹ thuật con) và kỹ thuật cha.

Giới hạn ghi trong kết quả: các mục cùng một report không độc lập (cùng văn bản, cùng lượt mô hình), nên p của McNemar trên
mục lạc quan hơn thực tế; kiểm định dấu trên 4 report là cận bảo thủ.

    .venv/Scripts/python.exe -X utf8 scripts/thong_ke_ttp_llm_bm25.py --out <thư mục ra ngoài data/>
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS, bm25_sets  # noqa: E402
from do_ttp_mitre import CASES, STIX, mitre_sets, parent  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact, sign_test, wilson  # noqa: E402

CACH = ("llm", "bm25_top1", "bm25_top3", "bm25_top8")
# Lượt LLM nào thấy gợi ý BM25: lượt chính thức 25/9 (v1, Opus 5.5, prompt khau2_ttp_v1.md) không gửi gợi ý; đường trích report
# mới (s2_report, Sonnet 5) gửi 8 gợi ý mỗi đoạn. Tách hai nhóm vì ý nghĩa khác nhau: "LLM tự đọc" và "LLM chọn trong gợi ý".
CO_GOI_Y = {"Volt Typhoon (Microsoft)"}


def bang_muc(level: str) -> tuple[list[dict], dict[str, dict[str, int]]]:
    """Bảng mục (report, kỹ thuật đáp án) và số kỹ thuật mỗi cách trích theo report, ở mức 'ma' hoặc 'cha'."""
    norm = (lambda s: s) if level == "ma" else (lambda s: {parent(t) for t in s})
    sets = mitre_sets(json.loads(config.resolve(STIX).read_text(encoding="utf-8")))
    rows, so_trich = [], {}
    for name, (bundle, src, llm_case) in REPORTS.items():
        if not llm_case:
            continue
        gold = norm(sets.get(src, set()))
        bm, _ = bm25_sets(config.resolve(bundle))
        c = json.loads(config.resolve(CASES[llm_case][0]).read_text(encoding="utf-8"))
        pred = {"llm": norm({t["technique_id"] for t in c["ttps"]}),
                "bm25_top1": norm(bm[1]), "bm25_top3": norm(bm[3]), "bm25_top8": norm(bm[8])}
        so_trich[name] = {k: len(v) for k, v in pred.items()}
        for t in sorted(gold):
            rows.append({"report": name, "ky_thuat": t, **{k: int(t in pred[k]) for k in CACH}})
    return rows, so_trich


def tom_tat(rows: list[dict], so_trich: dict[str, dict[str, int]]) -> dict:
    n = len(rows)
    out = {"so_muc": n, "recall": {}, "precision_can_duoi": {}, "mcnemar_llm_so_voi": {}, "dau_theo_report": {}}
    for k in CACH:
        x = sum(r[k] for r in rows)
        lo, hi = wilson(x, n)
        out["recall"][k] = {"dung": x, "tren": n, "ty_le": x / n, "wilson95": [lo, hi]}
        trich = sum(v[k] for v in so_trich.values())
        lo, hi = wilson(x, trich)
        out["precision_can_duoi"][k] = {"dung": x, "tren": trich, "ty_le": x / trich, "wilson95": [lo, hi]}
    for k in CACH[1:]:
        b = sum(1 for r in rows if r["llm"] and not r[k])
        c = sum(1 for r in rows if r[k] and not r["llm"])
        out["mcnemar_llm_so_voi"][k] = {"llm_dung_bm25_sai": b, "bm25_dung_llm_sai": c,
                                        "ca_hai_dung": sum(1 for r in rows if r["llm"] and r[k]),
                                        "ca_hai_sai": sum(1 for r in rows if not r["llm"] and not r[k]),
                                        "p_hai_phia": mcnemar_exact(b, c)}
        thang = thua = hoa = 0
        for name in so_trich:
            rr = [r for r in rows if r["report"] == name]
            a, z = sum(r["llm"] for r in rr), sum(r[k] for r in rr)
            thang, thua, hoa = thang + (a > z), thua + (a < z), hoa + (a == z)
        out["dau_theo_report"][k] = {"llm_hon": thang, "llm_kem": thua, "bang": hoa, "p_hai_phia": sign_test(thang, thua)}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    res = {"gioi_han": "Mục trong cùng report không độc lập: p trên mục lạc quan; kiểm định dấu trên 4 report là cận bảo thủ. "
                       "Precision là cận dưới vì MITRE không ánh xạ mọi kỹ thuật trong bài."}
    for level in ("ma", "cha"):
        rows, so_trich = bang_muc(level)
        with open(out / f"muc_ttp_{level}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["report", "ky_thuat", *CACH])
            w.writeheader()
            w.writerows(rows)
        res[level] = tom_tat(rows, so_trich)
        res[level]["so_trich_theo_report"] = so_trich
        for nhom, chon in (("llm_khong_goi_y", lambda r: r not in CO_GOI_Y), ("llm_co_goi_y", lambda r: r in CO_GOI_Y)):
            st = {r: v for r, v in so_trich.items() if chon(r)}
            res[level][nhom] = {"report": sorted(st), **tom_tat([x for x in rows if x["report"] in st], st)}
    (out / "thong_ke_ttp_llm_bm25.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")

    pct = lambda v: f"{v * 100:.0f}%"
    for level, ten in (("ma", "đúng mã"), ("cha", "kỹ thuật cha")):
        r = res[level]
        print(f"\n== Mức {ten}: {r['so_muc']} mục (report, kỹ thuật MITRE ánh xạ)")
        for k in CACH:
            x, y = r["recall"][k], r["precision_can_duoi"][k]
            print(f"  {k:10s} recall {x['dung']:3d}/{x['tren']} = {pct(x['ty_le'])} [{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}]"
                  f" · precision ≥ {y['dung']}/{y['tren']} = {pct(y['ty_le'])} [{pct(y['wilson95'][0])}–{pct(y['wilson95'][1])}]")
        for k in CACH[1:]:
            m, s = r["mcnemar_llm_so_voi"][k], r["dau_theo_report"][k]
            print(f"  LLM vs {k:10s}: chỉ LLM đúng {m['llm_dung_bm25_sai']:2d} · chỉ BM25 đúng {m['bm25_dung_llm_sai']:2d}"
                  f" · McNemar p = {m['p_hai_phia']:.2g} · theo report {s['llm_hon']} hơn / {s['llm_kem']} kém / {s['bang']} bằng,"
                  f" p = {s['p_hai_phia']:.3g}")
        for nhom in ("llm_khong_goi_y", "llm_co_goi_y"):
            g = r[nhom]
            print(f"  -- {nhom} ({', '.join(g['report'])}): {g['so_muc']} mục")
            for k in CACH:
                x, y = g["recall"][k], g["precision_can_duoi"][k]
                print(f"     {k:10s} recall {x['dung']}/{x['tren']} [{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}]"
                      f" · precision ≥ {y['dung']}/{y['tren']}")
            for k in CACH[1:]:
                m = g["mcnemar_llm_so_voi"][k]
                print(f"     LLM vs {k:10s}: chỉ LLM đúng {m['llm_dung_bm25_sai']} · chỉ BM25 đúng {m['bm25_dung_llm_sai']}"
                      f" · p = {m['p_hai_phia']:.2g}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
