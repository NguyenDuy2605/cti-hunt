"""Gợi ý kỹ thuật ATT&CK: BM25 so với embedding và cách lai (RRF). 0 API, không nhãn sự kiện, không Silver.

- ``phat-trien --out <thư mục>``: đề luyện = 400 câu ``chinh`` của tập phát triển N3 (``data/dev/n3/chuan_bi_v1``; 200 câu
  ``giu_lai`` không dùng). Lưới cấu hình: mô hình {bge-base, e5-base} × cỡ khúc {120, 300} từ.
  **Quy tắc chọn (ghi trước khi chạy):** cấu hình embedding có recall@8 mức kỹ thuật cha cao nhất; bằng nhau thì
  recall@1 mức cha; vẫn bằng thì khúc nhỏ hơn, rồi bge-base trước e5-base. Cách lai luôn dùng cấu hình embedding đã chọn,
  RRF hằng số 60, độ sâu 30 (không chỉnh).
- ``cham``: đề thi (30 report + 4 report cũ), chạy một lần sau khi giao thức đặt trước đã băm (``docs/METHODOLOGY.md`` §2.4).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cti_hunt import config  # noqa: E402
from cti_hunt.attack.dense_retrieval import MODELS, RRF_DEPTH, DenseIndex, load_encoder, rrf  # noqa: E402
from cti_hunt.attack.retrieval import TechniqueIndex  # noqa: E402

STIX = "data/attack/enterprise-attack-19.2.json"
DEV = "data/dev/n3/chuan_bi_v1/tap_phat_trien.jsonl"
DEV_SHA256 = "affc0e3350fe37a6e208b8bcfb8d8206b8f16a221199a18df017522e83659757"
GRID = [(m, c) for m in ("bge-base", "e5-base") for c in (120, 300)]
KS = (1, 3, 8)


def parent(t: str) -> str:
    return t.split(".")[0]


def recall_rows(rankings: list[list[str]], gold: list[str]) -> dict:
    out = {}
    for k in KS:
        ma = sum(g in r[:k] for r, g in zip(rankings, gold))
        cha = sum(any(parent(t) == parent(g) for t in r[:k]) for r, g in zip(rankings, gold))
        out[f"r@{k}"] = {"dung_ma": ma, "cung_cha": cha, "tren": len(gold)}
    return out


def cache_dir(out: Path) -> Path:
    return Path(os.environ.get("CTI_EMBED_CACHE", out / "cache"))


def phat_trien(out: Path) -> int:
    raw = config.resolve(DEV).read_bytes()
    if hashlib.sha256(raw).hexdigest() != DEV_SHA256:
        raise SystemExit("Tập phát triển lệch SHA256")
    items = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    items = [i for i in items if i["tap"] == "chinh"]
    queries, gold = [i["text"] for i in items], [i["technique_id"] for i in items]
    bm = TechniqueIndex.from_stix(config.resolve(STIX))
    t0 = time.time()
    bm_rank = [[c["technique_id"] for c in bm.search(q, RRF_DEPTH)] for q in queries]
    res = {"de_luyen": {"tap": "chinh", "so_cau": len(items), "sha256": DEV_SHA256},
           "bm25": {**recall_rows(bm_rank, gold), "giay": round(time.time() - t0, 1)}, "embedding": {}, "lai": {}}
    encoders = {}
    for model, chunk in GRID:
        enc = encoders.setdefault(model, load_encoder(model))
        t0 = time.time()
        idx = DenseIndex(bm.documents, enc, model, chunk, cache_dir=cache_dir(out))
        t1 = time.time()
        dense_rank = [[c["technique_id"] for c in r] for r in idx.search_many(queries, RRF_DEPTH)]
        t2 = time.time()
        hyb = [[c["technique_id"] for c in rrf([b, d], k=RRF_DEPTH)] for b, d in zip(bm_rank, dense_rank)]
        name = f"{model}_{chunk}"
        res["embedding"][name] = {**recall_rows(dense_rank, gold), "so_khuc": len(idx.chunks),
                                  "giay_dung_chi_muc": round(t1 - t0, 1), "giay_truy_van": round(t2 - t1, 1),
                                  "chi_muc_sha256": idx.key}
        res["lai"][name] = recall_rows(hyb, gold)
        print(f"xong {name}: {len(idx.chunks)} khúc, {t1 - t0:.0f} s dựng, {t2 - t1:.0f} s truy vấn", flush=True)
    order = sorted(GRID, key=lambda mc: (-res["embedding"][f"{mc[0]}_{mc[1]}"]["r@8"]["cung_cha"],
                                         -res["embedding"][f"{mc[0]}_{mc[1]}"]["r@1"]["cung_cha"],
                                         mc[1], list(MODELS).index(mc[0])))
    res["chon"] = {"mo_hinh": order[0][0], "co_khuc": order[0][1], "quy_tac": __doc__.split("**Quy tắc chọn (ghi trước khi chạy):**")[1].split("- ``cham``")[0].strip()}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_de_luyen.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    n = len(items)
    line = lambda name, r: print(f"  {name:22s}" + "".join(
        f" | r@{k} mã {r[f'r@{k}']['dung_ma']:3d} cha {r[f'r@{k}']['cung_cha']:3d}" for k in KS) + f"  (/{n})")
    print("\n== Đề luyện: 400 câu")
    line("bm25", res["bm25"])
    for name in res["embedding"]:
        line("emb " + name, res["embedding"][name])
        line("lai " + name, res["lai"][name])
    print(f"\nChọn: {res['chon']['mo_hinh']}, khúc {res['chon']['co_khuc']} từ")
    return 0


def report_units(bundle: Path) -> tuple[list[str], list[list[str]]]:
    """Đúng các đoạn mục tiêu khâu ② gửi đi (``s2_report.prepare``), cùng thứ tự."""
    from cti_hunt.stages import s2_report
    _, requests = s2_report.prepare(bundle, config.resolve(STIX), config.resolve("prompts/khau2_ttp_v2.md"), {}, top_k=8)
    targets = [t for r in requests for t in json.loads(r["user"])["targets"]]
    return [t["text"] for t in targets], [[c["technique_id"] for c in t["candidates"]] for t in targets]


def rankings_for(texts: list[str], bm: TechniqueIndex, idx: DenseIndex, published_top8: list[list[str]]) -> dict:
    bm_rank = [[c["technique_id"] for c in bm.search(q, RRF_DEPTH)] for q in texts]
    if [r[:8] for r in bm_rank] != published_top8:
        raise SystemExit("BM25 độ sâu 30 không khớp 8 gợi ý của khâu ②")
    dense = [[c["technique_id"] for c in r] for r in idx.search_many(texts, RRF_DEPTH)]
    hyb = [[c["technique_id"] for c in rrf([b, d], k=RRF_DEPTH)] for b, d in zip(bm_rank, dense)]
    return {"bm25": bm_rank, "embedding": dense, "lai": hyb}


CACH = [f"{a}_top{k}" for a in ("bm25", "embedding", "lai") for k in KS]
# Phép so đặt trước (giao thức 35 §4): chính là top-8 mức cha, theo report (kiểm định dấu).
CAP = [("lai_top8", "bm25_top8"), ("embedding_top8", "bm25_top8"), ("lai_top8", "embedding_top8"),
       ("lai_top1", "bm25_top1"), ("embedding_top1", "bm25_top1"), ("lai_top3", "bm25_top3"),
       ("embedding_top3", "bm25_top3")]


def cham(bo: Path, chon: Path, out: Path) -> int:
    from do_ttp_bm25_mitre import REPORTS
    from do_ttp_bo_mo_rong import _so_sanh, nhan
    from do_ttp_mitre import mitre_sets

    from cti_hunt.eval.thong_ke import wilson

    sel = json.loads(chon.read_text(encoding="utf-8"))["chon"]
    stix_path = config.resolve(STIX)
    gold_all = mitre_sets(json.loads(stix_path.read_text(encoding="utf-8")))
    bm = TechniqueIndex.from_stix(stix_path)
    idx = DenseIndex(bm.documents, load_encoder(sel["mo_hinh"]), sel["mo_hinh"], sel["co_khuc"], cache_dir=cache_dir(out))
    bo_list = [(e["ma"], bo / "bundles" / e["ma"], e["source_name"]) for e in nhan(bo)]
    cu_list = [(name, config.resolve(b), src) for name, (b, src, _) in REPORTS.items()]
    preds_cache = {}
    t0 = time.time()
    for ma, bundle, _ in bo_list + cu_list:
        texts, top8 = report_units(bundle)
        preds_cache[ma] = (len(texts), rankings_for(texts, bm, idx, top8))
        print(f"  {ma}: {len(texts)} đoạn", flush=True)
    res = {"giao_thuc": "docs/METHODOLOGY.md §2.4 (đặt trước, băm 03/11/2026)", "cau_hinh": sel,
           "chi_muc_sha256": idx.key, "giay": round(time.time() - t0, 1)}
    for bo_ten, reports in (("bo_30", bo_list), ("bo_cu_4", cu_list)):
        for level in ("cha", "ma"):
            norm = (lambda s: {parent(t) for t in s}) if level == "cha" else (lambda s: set(s))
            rows, per_report, so_trich = [], [], {}
            for ma, _, src in reports:
                gold = norm(gold_all.get(src, set()))
                n_units, rk = preds_cache[ma]
                preds = {f"{a}_top{k}": norm({t for r in rk[a] for t in r[:k]}) for a in rk for k in KS}
                so_trich[ma] = {c: len(preds[c]) for c in CACH}
                for t in sorted(gold):
                    rows.append({"report": ma, "ky_thuat": t, **{c: int(t in preds[c]) for c in CACH}})
                per_report.append({"report": ma, "so_doan": n_units, "dap_an": len(gold),
                                   **{f"recall_{c}": (len(gold & preds[c]) / len(gold) if gold else None) for c in CACH},
                                   **{f"trich_{c}": len(preds[c]) for c in CACH}})
            n = len(rows)
            s = {"so_report": len(per_report), "so_muc": n, "recall": {}, "precision_can_duoi": {}}
            for c in CACH:
                x, t = sum(r[c] for r in rows), sum(v[c] for v in so_trich.values())
                s["recall"][c] = {"dung": x, "tren": n, "wilson95": wilson(x, n)}
                s["precision_can_duoi"][c] = {"dung": x, "tren": t, "wilson95": wilson(x, t)}
            s["so_sanh"] = [_so_sanh(rows, a, b, [p["report"] for p in per_report]) for a, b in CAP]
            s["theo_report"] = per_report
            res[f"{bo_ten}_{level}"] = s
            out.mkdir(parents=True, exist_ok=True)
            import csv
            with open(out / f"muc_{bo_ten}_{level}.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["report", "ky_thuat", *CACH])
                w.writeheader()
                w.writerows(rows)
    (out / "ket_qua_de_thi.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    pct = lambda v: f"{v * 100:.0f}%"
    for key in ("bo_30_cha", "bo_30_ma", "bo_cu_4_cha", "bo_cu_4_ma"):
        s = res[key]
        print(f"\n== {key}: {s['so_report']} report, {s['so_muc']} mục")
        for c in CACH:
            x, y = s["recall"][c], s["precision_can_duoi"][c]
            print(f"  {c:16s} recall {x['dung']:4d}/{x['tren']} = {pct(x['dung'] / x['tren'])} "
                  f"[{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}] · precision ≥ {y['dung']}/{y['tren']} = "
                  f"{pct(y['dung'] / max(y['tren'], 1))}")
        for c in s["so_sanh"]:
            print(f"  {c['a']} vs {c['b']}: mục chỉ A {c['muc_chi_a_dung']} / chỉ B {c['muc_chi_b_dung']} "
                  f"(McNemar p = {c['mcnemar_p']:.2g}); report {c['report_a_hon']} hơn / {c['report_a_kem']} kém / "
                  f"{c['report_bang']} bằng (dấu p = {c['dau_p']:.2g})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("phat-trien")
    p.add_argument("--out", required=True)
    p = sub.add_parser("cham")
    p.add_argument("--bo", required=True, help="thư mục bộ 30 report (bundles/, nhat_ky_tai.json)")
    p.add_argument("--chon", required=True, help="ket_qua_de_luyen.json của bước phat-trien")
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.lenh == "phat-trien":
        return phat_trien(Path(a.out))
    return cham(Path(a.bo), Path(a.chon), Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
