"""Đo câu hỏi 1 (TTP) trên bộ report mở rộng theo giao thức đặt trước `docs/METHODOLOGY.md` §5.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver, không dùng mạng (bundle đã tải bằng ``bo_report_mo_rong.py``).
Cách không dùng LLM: BM25 (gợi ý đứng đầu / 3 đầu / cả 8 mỗi đoạn, đúng ``s2_report.prepare``) và rcATT huấn luyện lại
(``rcatt_huan_luyen_du_doan.py``). Đáp án: kỹ thuật MITRE ATT&CK v19.2 ánh xạ cho đúng report (``do_ttp_mitre.mitre_sets``).

- ``xuat --bo <thư mục bộ> --out <thư mục văn bản>``: ghi văn bản mục tiêu từng report nhận (``rm_xxx.txt`` + danh_sach.json)
  để chạy rcATT bằng venv riêng.
- ``cham --bo <thư mục bộ> [--rcatt <du_doan_rcatt.json>] --out <thư mục ra>``: recall, precision cận dưới (Wilson 95%),
  McNemar chính xác trên mục, kiểm định dấu theo report (phép so chính, giao thức §5), mức kỹ thuật cha (chính) và đúng mã
  (chỉ BM25).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import bm25_sets  # noqa: E402
from do_ttp_mitre import STIX, mitre_sets, parent  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.attack.catalog import AttackCatalog  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact, sign_test, wilson  # noqa: E402
from cti_hunt.stages import s2_report  # noqa: E402


def nhan(bo: Path) -> list[dict]:
    log = json.loads((bo / "nhat_ky_tai.json").read_text(encoding="utf-8"))
    return [e for e in log if e["ket_qua"] == "nhan"]


def xuat(bo: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in nhan(bo):
        _, requests = s2_report.prepare(bo / "bundles" / e["ma"], config.resolve(STIX),
                                        config.resolve("prompts/khau2_ttp_v2.md"), {}, top_k=8)
        text = "\n\n".join(t["text"] for r in requests for t in json.loads(r["user"])["targets"])
        tep = f"{e['ma'].lower().replace('-', '_')}.txt"
        (out / tep).write_text(text, encoding="utf-8", newline="\n")
        rows.append({"report": e["ma"], "tep": tep, "source_name": e["source_name"], "so_ky_tu": len(text),
                     "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
    (out / "danh_sach.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Ghi {len(rows)} report vào {out}")
    return 0


def _so_sanh(rows: list[dict], a: str, b: str, reports: list[str]) -> dict:
    bb = sum(1 for r in rows if r[a] and not r[b])
    cc = sum(1 for r in rows if r[b] and not r[a])
    hon = kem = bang = 0
    for rp in reports:
        rr = [r for r in rows if r["report"] == rp]
        ra, rb = sum(r[a] for r in rr), sum(r[b] for r in rr)
        hon, kem, bang = hon + (ra > rb), kem + (ra < rb), bang + (ra == rb)
    return {"a": a, "b": b, "muc_chi_a_dung": bb, "muc_chi_b_dung": cc, "mcnemar_p": mcnemar_exact(bb, cc),
            "report_a_hon": hon, "report_a_kem": kem, "report_bang": bang, "dau_p": sign_test(hon, kem)}


def cham(bo: Path, rcatt: Path | None, out: Path) -> int:
    stix_path = config.resolve(STIX)
    gold_all = mitre_sets(json.loads(stix_path.read_text(encoding="utf-8")))
    cat = AttackCatalog.from_stix(stix_path)
    rc = json.loads(rcatt.read_text(encoding="utf-8")) if rcatt else None
    res = {"giao_thuc": "docs/METHODOLOGY.md (bản 2)",
           "gioi_han": "Precision là cận dưới (MITRE ánh xạ một phần). Mục trong cùng report không độc lập: phép so chính là "
                       "kiểm định dấu theo report. rcATT huấn luyện lại, không hậu xử lý, chỉ mức kỹ thuật cha."}
    for level in ("cha", "ma"):
        norm = (lambda s: {parent(t) for t in s}) if level == "cha" else (lambda s: set(s))
        cach = ["bm25_top1", "bm25_top3", "bm25_top8"] + (["rcatt"] if rc and level == "cha" else [])
        rows, per_report, so_trich = [], [], {}
        for e in nhan(bo):
            gold = norm(gold_all.get(e["source_name"], set()))
            bm, n_units = bm25_sets(bo / "bundles" / e["ma"])
            preds = {"bm25_top1": norm(bm[1]), "bm25_top3": norm(bm[3]), "bm25_top8": norm(bm[8])}
            if "rcatt" in cach:
                old = rc["du_doan"][e["ma"].lower().replace("-", "_")]["ma"]
                preds["rcatt"] = {parent(r.final) for r in map(cat.resolve, old) if r.final}
            so_trich[e["ma"]] = {k: len(v) for k, v in preds.items()}
            for t in sorted(gold):
                rows.append({"report": e["ma"], "ky_thuat": t, **{k: int(t in preds[k]) for k in cach}})
            per_report.append({"report": e["ma"], "source_name": e["source_name"], "nam": e["nam"], "so_doan": n_units,
                               "dap_an": len(gold),
                               **{f"recall_{k}": (len(gold & preds[k]) / len(gold) if gold else None) for k in cach},
                               **{f"trich_{k}": len(preds[k]) for k in cach}})
        n = len(rows)
        summary = {"so_report": len(per_report), "so_muc": n, "recall": {}, "precision_can_duoi": {}}
        for k in cach:
            x, t = sum(r[k] for r in rows), sum(v[k] for v in so_trich.values())
            summary["recall"][k] = {"dung": x, "tren": n, "wilson95": wilson(x, n)}
            summary["precision_can_duoi"][k] = {"dung": x, "tren": t, "wilson95": wilson(x, t)}
        reports = [p["report"] for p in per_report]
        cap = [("bm25_top3", "bm25_top1"), ("bm25_top8", "bm25_top1")]
        if "rcatt" in cach:
            cap += [("bm25_top1", "rcatt"), ("bm25_top8", "rcatt")]
        summary["so_sanh"] = [_so_sanh(rows, a, b, reports) for a, b in cap]
        summary["theo_report"] = per_report
        res[level] = summary
        out.mkdir(parents=True, exist_ok=True)
        with open(out / f"muc_{level}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["report", "ky_thuat", *cach])
            w.writeheader()
            w.writerows(rows)
    (out / "ket_qua_ttp_bo_mo_rong.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    pct = lambda v: f"{v * 100:.0f}%"
    for level, ten in (("cha", "kỹ thuật cha"), ("ma", "đúng mã")):
        s = res[level]
        print(f"\n== Mức {ten}: {s['so_report']} report, {s['so_muc']} mục")
        for k, x in s["recall"].items():
            y = s["precision_can_duoi"][k]
            print(f"  {k:10s} recall {x['dung']:4d}/{x['tren']} = {pct(x['dung'] / x['tren'])} "
                  f"[{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}] · precision ≥ {y['dung']}/{y['tren']} = "
                  f"{pct(y['dung'] / y['tren'])} [{pct(y['wilson95'][0])}–{pct(y['wilson95'][1])}]")
        for c in s["so_sanh"]:
            print(f"  {c['a']} vs {c['b']}: mục chỉ {c['a']} {c['muc_chi_a_dung']} / chỉ {c['b']} {c['muc_chi_b_dung']}"
                  f" (p = {c['mcnemar_p']:.2g}); theo report {c['report_a_hon']} hơn / {c['report_a_kem']} kém /"
                  f" {c['report_bang']} bằng (p = {c['dau_p']:.2g})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("xuat")
    p.add_argument("--bo", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("cham")
    p.add_argument("--bo", required=True)
    p.add_argument("--rcatt")
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.lenh == "xuat":
        return xuat(Path(a.bo), Path(a.out))
    return cham(Path(a.bo), Path(a.rcatt) if a.rcatt else None, Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
