"""rcATT (học máy cổ điển, huấn luyện lại) so với LLM và BM25 trên cùng đáp án MITRE ATT&CK v19.2, mức kỹ thuật cha.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver. Hai bước, chạy bằng venv của repo:

1. ``xuat``: với mỗi report trong ``do_ttp_bm25_mitre.REPORTS``, ghi đúng phần văn bản mà khâu ② và baseline BM25 lấy làm
   mục tiêu (``s2_report.prepare``: đoạn đọc được, bỏ đoạn nhiễu H3), nối bằng dòng trống, vào ``<thư mục>/<mã>.txt`` kèm
   ``danh_sach.json`` (tên report, bundle, SHA256 văn bản).
2. Chạy ``scripts/rcatt_huan_luyen_du_doan.py`` bằng venv riêng của rcATT (scikit-learn, nltk; không thuộc phụ thuộc của
   repo) để huấn luyện lại và dự đoán.
3. ``cham``: đọc dự đoán của rcATT (mã ATT&CK kiểu cũ, trước khi có kỹ thuật con), đổi sang mã v19.2 qua quan hệ
   ``revoked-by`` (``AttackCatalog.resolve``; mã chỉ bị "deprecated" thì bỏ), lấy kỹ thuật cha rồi chấm như
   ``thong_ke_ttp_llm_bm25.py``: recall, precision cận dưới kèm Wilson 95%, McNemar chính xác cho recall so với LLM và
   BM25 trên cùng mục.

Chỉ so ở mức kỹ thuật cha vì rcATT không biết kỹ thuật con. Mức cha của rcATT còn thiệt ở chỗ: rcATT chỉ học 215 kỹ thuật
có từ 5 report trở lên trong dữ liệu năm 2019–2020; kỹ thuật ra đời sau đó nó không thể nêu.

    .venv/Scripts/python.exe -X utf8 scripts/do_ttp_rcatt_mitre.py xuat --out <thư mục văn bản>
    <venv rcATT>/python.exe -I scripts/rcatt_huan_luyen_du_doan.py --rcatt <repo rcATT> --van-ban <thư mục văn bản> ...
    .venv/Scripts/python.exe -X utf8 scripts/do_ttp_rcatt_mitre.py cham --du-doan <du_doan_rcatt.json> --out <thư mục ra>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS, bm25_sets  # noqa: E402
from do_ttp_mitre import CASES, STIX, mitre_sets, parent  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.attack.catalog import AttackCatalog  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact, wilson  # noqa: E402
from cti_hunt.stages import s2_report  # noqa: E402


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def xuat(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, (bundle, src, llm_case) in REPORTS.items():
        _, requests = s2_report.prepare(config.resolve(bundle), config.resolve(STIX),
                                        config.resolve("prompts/khau2_ttp_v2.md"), {}, top_k=8)
        texts = [t["text"] for r in requests for t in json.loads(r["user"])["targets"]]
        text = "\n\n".join(texts)
        path = out / f"{slug(name)}.txt"
        path.write_text(text, encoding="utf-8", newline="\n")
        rows.append({"report": name, "tep": path.name, "bundle": bundle, "nguon_mitre": src, "co_llm": bool(llm_case),
                     "so_doan": len(texts), "so_ky_tu": len(text),
                     "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
        print(f"{name}: {len(texts)} đoạn, {len(text)} ký tự")
    (out / "danh_sach.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


def cham(du_doan: Path, out: Path) -> int:
    pred_raw = json.loads(du_doan.read_text(encoding="utf-8"))
    cat = AttackCatalog.from_stix(config.resolve(STIX))
    gold_all = mitre_sets(json.loads(config.resolve(STIX).read_text(encoding="utf-8")))
    doi_ma, rows, so_trich = {}, [], {}
    for name, (bundle, src, llm_case) in REPORTS.items():
        old = pred_raw["du_doan"][slug(name)]["ma"]
        mapped = set()
        for tid in old:
            r = cat.resolve(tid)
            doi_ma[tid] = {"trang_thai": r.status, "ma_v19_2": r.final}
            if r.final:
                mapped.add(parent(r.final))
        gold = {parent(t) for t in gold_all.get(src, set())}
        bm, _ = bm25_sets(config.resolve(bundle))
        preds = {"rcatt": mapped, "bm25_top1": {parent(t) for t in bm[1]}, "bm25_top8": {parent(t) for t in bm[8]}}
        if llm_case:
            c = json.loads(config.resolve(CASES[llm_case][0]).read_text(encoding="utf-8"))
            preds["llm"] = {parent(t["technique_id"]) for t in c["ttps"]}
        so_trich[name] = {k: len(v) for k, v in preds.items()}
        for t in sorted(gold):
            rows.append({"report": name, "ky_thuat_cha": t, "co_llm": bool(llm_case),
                         **{k: int(t in v) for k, v in preds.items()}})

    def tong(rr: list[dict], cach: list[str], st: dict) -> dict:
        n = len(rr)
        res = {"so_muc": n, "report": sorted({r["report"] for r in rr}), "recall": {}, "precision_can_duoi": {}}
        for k in cach:
            x = sum(r[k] for r in rr)
            trich = sum(v[k] for name, v in st.items() if name in res["report"])
            res["recall"][k] = {"dung": x, "tren": n, "wilson95": wilson(x, n)}
            res["precision_can_duoi"][k] = {"dung": x, "tren": trich, "wilson95": wilson(x, trich)}
        res["mcnemar_rcatt_so_voi"] = {}
        for k in cach:
            if k == "rcatt":
                continue
            b = sum(1 for r in rr if r["rcatt"] and not r[k])
            c = sum(1 for r in rr if r[k] and not r["rcatt"])
            res["mcnemar_rcatt_so_voi"][k] = {"chi_rcatt_dung": b, "chi_cach_kia_dung": c, "p_hai_phia": mcnemar_exact(b, c)}
        return res

    res = {"gioi_han": "Mức kỹ thuật cha. rcATT huấn luyện lại (không phải bản phát hành), dữ liệu học 2019–2020, đã bỏ "
                       "report POSHSPY; mã kiểu cũ đổi sang v19.2 qua revoked-by, mã chỉ deprecated bị bỏ. Mục trong cùng "
                       "report không độc lập; precision là cận dưới.",
           "du_doan_rcatt": str(du_doan), "meta_rcatt": pred_raw.get("meta", {}),
           "ca_7_report": tong(rows, ["rcatt", "bm25_top1", "bm25_top8"], so_trich),
           "4_report_co_llm": tong([r for r in rows if r["co_llm"]], ["rcatt", "bm25_top1", "bm25_top8", "llm"],
                                   {k: v for k, v in so_trich.items() if "llm" in v}),
           "so_trich_theo_report": so_trich, "doi_ma": doi_ma}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_ttp_rcatt_mitre.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    pct = lambda v: f"{v * 100:.0f}%"
    for key in ("ca_7_report", "4_report_co_llm"):
        g = res[key]
        print(f"\n== {key}: {g['so_muc']} mục (report, kỹ thuật cha MITRE ánh xạ)")
        for k, x in g["recall"].items():
            y = g["precision_can_duoi"][k]
            print(f"  {k:10s} recall {x['dung']:3d}/{x['tren']} [{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}]"
                  f" · precision ≥ {y['dung']}/{y['tren']}"
                  + (f" [{pct(y['wilson95'][0])}–{pct(y['wilson95'][1])}]" if y["tren"] else ""))
        for k, m in g["mcnemar_rcatt_so_voi"].items():
            print(f"  rcATT vs {k:10s}: chỉ rcATT đúng {m['chi_rcatt_dung']:2d} · chỉ {k} đúng {m['chi_cach_kia_dung']:2d}"
                  f" · p = {m['p_hai_phia']:.2g}")
    for name, v in so_trich.items():
        print(f"  {name}: số kỹ thuật cha trích {v}")
    trang_thai = {}
    for v in doi_ma.values():
        trang_thai[v["trang_thai"]] = trang_thai.get(v["trang_thai"], 0) + 1
    print(f"  đổi mã rcATT: {trang_thai}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("xuat")
    p.add_argument("--out", required=True)
    p = sub.add_parser("cham")
    p.add_argument("--du-doan", required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    return xuat(Path(a.out)) if a.lenh == "xuat" else cham(Path(a.du_doan), Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
