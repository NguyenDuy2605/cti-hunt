"""Câu hỏi 1, phần IOC trên 19 report (đáp án = danh sách IOC tác giả công bố): chuẩn bị gói và chấm A, B.

Không gọi API, không đọc nhãn sự kiện. Dựng lại đúng đáp án và văn bản của ba script đã dùng 14–15/10
(``do_ioc_tac_gia.py`` 8 report, ``do_ioc_report_chua_thay.py`` 3 report, ``do_ioc_report_chua_thay_dot2.py`` 8 report), chỉ
bốn loại lõi: mã băm, IP, tên miền, URL. Quy ước giống đáp án: tên miền/IP nằm trong URL hay đường dẫn không tính thành mục
riêng; ``loc_doc_lap`` áp quy ước này như nhau cho mọi cách.

- ``chuan-bi --out <thư mục>``: ghi ``goi_ioc_19.json``: văn bản bộ rút đọc, đáp án, ứng viên của bộ rút hệ thống (giá trị
  đã đưa về dạng thật, loại) kèm mức mạnh/yếu/bỏ của luật viết tay (``s2_ioc_sweep.classify``).
- ``cham-cong-cu --goi … --cong-cu <ket_qua_cong_cu.json> --out …``: A — bộ rút hệ thống so với iocsearcher, iocextract.
- ``cham-llm --goi … --nhan <nhan_llm.json> --out …``: B — luật viết tay so với LLM mở gán nhãn (``ioc_phan_loai_mo_hinh_mo.py``).
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_ioc_tac_gia as T  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact, wilson  # noqa: E402
from cti_hunt.stages import s1_ingest, s2_ioc, s2_ioc_sweep  # noqa: E402

CORE = ("hash", "ip", "domain", "url")


def _nhom() -> list[tuple[str, dict, dict, list, object]]:
    """(tên nhóm, REPORTS, EXCLUDE, DEFANG, gold_from_section) đúng như lúc mỗi script chạy riêng."""
    base_defang, base_gold = list(T.DEFANG), T.gold_from_section
    out = [("8 report 14/10", dict(T.REPORTS), dict(T.EXCLUDE), base_defang, base_gold)]
    importlib.import_module("do_ioc_report_chua_thay")          # đổi T.REPORTS, T.EXCLUDE, T.DEFANG
    out.append(("3 report chưa thấy 15/10 đợt 1", dict(T.REPORTS), dict(T.EXCLUDE), list(T.DEFANG), base_gold))
    importlib.import_module("do_ioc_report_chua_thay_dot2")     # đổi T.REPORTS, T.EXCLUDE, T.gold_from_section
    out.append(("8 report chưa thấy 15/10 đợt 2", dict(T.REPORTS), dict(T.EXCLUDE), base_defang, T.gold_from_section))
    T.DEFANG, T.gold_from_section = base_defang, base_gold
    return out


def loc_doc_lap(values: dict[str, set[str]], text: str) -> dict[str, set[str]]:
    """Bỏ tên miền/IP chỉ xuất hiện bên trong URL hay đường dẫn (quy ước của đáp án). ``text`` là văn bản đã đưa về dạng thật."""
    low = text.lower()
    rest = T.RX_PATH.sub(" ", T.RX_URL.sub(" ", low))
    out = {k: set(v) for k, v in values.items()}
    for k in ("domain", "ip"):
        out[k] = {v for v in out[k] if re.search(r"(?<![a-z0-9.\-])" + re.escape(v) + r"(?![a-z0-9\-]|\.[a-z0-9])", rest)}
    return out


def chuan_bi(out: Path) -> int:
    rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
    reports = []
    groups = _nhom()
    for nhom, reps, exclude, defang, gold_fn in groups:
        T.DEFANG = defang
        for name, (d, first, after) in reps.items():
            manifest, rows, prov = s1_ingest.load_bundle(Path(d))
            src = str(manifest.get("resolved_source") or "")
            publisher = (urlsplit(src).hostname or "").lower().removeprefix("www.") if src.startswith("http") else ""
            ids = [r["ma_doan"] for r in rows]
            section = rows[ids.index(first):(ids.index(after) if after else len(rows))]
            gold = gold_fn("\n".join(r.get("van_ban", "") for r in section))
            for k in gold:
                gold[k] -= set(exclude.get(name, {}))
            text_rows = [s for s in rows if s1_ingest.extraction_ready(s, prov)]
            body = {r["ma_doan"]: r.get("van_ban", "") for r in text_rows}
            ung_vien = {}
            for ioc in s2_ioc.extract_report(text_rows, rules):
                kind = T.kind_of(ioc.type)
                if kind not in CORE:
                    continue
                value = s2_ioc.normalize(ioc.value, rules)
                ioc = ioc.model_copy(update={"source_span": ioc.source_span.model_copy(
                    update={"text": body.get(ioc.source_span.segment_id, "")})})
                muc, ly_do = s2_ioc_sweep.classify(ioc, value, publisher)
                ung_vien.setdefault(f"{kind}|{value}", {"loai": kind, "gia_tri": value, "goc": ioc.value, "muc_luat": muc,
                                                        "ly_do_luat": ly_do, "doan": ioc.source_span.segment_id or ""})
            reports.append({"report": name, "nhom": nhom, "nha_xuat_ban": publisher, "nguon": src,
                            "van_ban": "\n\n".join(r.get("van_ban", "") for r in text_rows),
                            "dap_an": {k: sorted(gold[k]) for k in CORE}, "ung_vien": list(ung_vien.values())})
    T.DEFANG = groups[0][3]
    out.mkdir(parents=True, exist_ok=True)
    (out / "goi_ioc_19.json").write_text(json.dumps({"bo_rut": "configs/ioc_rules.yaml + s2_ioc + s2_ioc_sweep (hiện hành)",
                                                    "report": reports}, ensure_ascii=False, indent=1), encoding="utf-8")
    tong = sum(len(r["dap_an"][k]) for r in reports for k in CORE)
    tim = sum(1 for r in reports for k in CORE for v in r["dap_an"][k]
              if any(u["loai"] == k and u["gia_tri"] == v for u in r["ung_vien"]))
    for nhom in dict.fromkeys(r["nhom"] for r in reports):
        rr = [r for r in reports if r["nhom"] == nhom]
        g = sum(len(r["dap_an"][k]) for r in rr for k in CORE)
        print(f"{nhom}: {len(rr)} report, đáp án lõi {g}")
    print(f"19 report: đáp án lõi {tong}, bộ rút hệ thống tìm {tim}; ghi {out / 'goi_ioc_19.json'}")
    return 0


def _pr(pred: dict[str, set[str]], gold: dict[str, set[str]]) -> dict:
    p = sum(len(pred[k]) for k in CORE)
    g = sum(len(gold[k]) for k in CORE)
    tp = sum(len(pred[k] & gold[k]) for k in CORE)
    return {"dung": tp, "du_doan": p, "dap_an": g}


def _bang(rows: list[dict], cach: list[str]) -> dict:
    """rows: {report, nhom, loai, gia_tri, trong_dap_an, <cách>: 0/1 có nêu}. Recall/precision, Wilson, McNemar trên đáp án."""
    res = {}
    gold_items = [r for r in rows if r["trong_dap_an"]]
    for c in cach:
        tp = sum(1 for r in gold_items if r[c])
        pred = sum(1 for r in rows if r[c])
        res[c] = {"recall": [tp, len(gold_items), wilson(tp, len(gold_items))],
                  "precision": [tp, pred, wilson(tp, pred) if pred else None],
                  "theo_loai": {k: {"recall": [sum(1 for r in gold_items if r["loai"] == k and r[c]),
                                               sum(1 for r in gold_items if r["loai"] == k)],
                                    "precision": [sum(1 for r in gold_items if r["loai"] == k and r[c]),
                                                  sum(1 for r in rows if r["loai"] == k and r[c])]} for k in CORE}}
    return res


def _so_cap(rows: list[dict], a: str, b: str, chi_dap_an: bool) -> dict:
    rr = [r for r in rows if r["trong_dap_an"]] if chi_dap_an else rows
    dung = (lambda r, c: r[c]) if chi_dap_an else (lambda r, c: r[c] == r["trong_dap_an"])
    x = sum(1 for r in rr if dung(r, a) and not dung(r, b))
    y = sum(1 for r in rr if dung(r, b) and not dung(r, a))
    return {"chi_a_dung": x, "chi_b_dung": y, "p": mcnemar_exact(x, y)}


def _in(res: dict, ten: str) -> None:
    pct = lambda a, b: f"{a}/{b} = {a / b * 100:.0f}%" if b else f"{a}/0"
    print(f"\n== {ten}")
    for c, v in res.items():
        (tp, g, ci), (tp2, p, ci2) = v["recall"], v["precision"]
        loai = " · ".join(f"{k} R {pct(*v['theo_loai'][k]['recall'])} P {pct(*v['theo_loai'][k]['precision'])}" for k in CORE)
        print(f"  {c:14s} recall {pct(tp, g)} [{ci[0] * 100:.0f}–{ci[1] * 100:.0f}%] · precision {pct(tp2, p)}"
              + (f" [{ci2[0] * 100:.0f}–{ci2[1] * 100:.0f}%]" if ci2 else ""))
        print(f"      {loai}")


def cham_cong_cu(goi: Path, cong_cu: Path, out: Path) -> int:
    G = json.loads(goi.read_text(encoding="utf-8"))
    C = json.loads(cong_cu.read_text(encoding="utf-8"))
    rows, cach = [], ["he_thong"] + sorted(C["cong_cu"])
    for r in G["report"]:
        text = T.refang(r["van_ban"])
        gold = {k: set(r["dap_an"][k]) for k in CORE}
        preds = {"he_thong": loc_doc_lap({k: {u["gia_tri"] for u in r["ung_vien"] if u["loai"] == k} for k in CORE}, text)}
        for tool in C["cong_cu"]:
            raw = C["ket_qua"][r["report"]][tool]
            norm = {k: {v.lower().rstrip("./,;)") for v in raw.get(k, [])} for k in CORE}
            preds[tool] = loc_doc_lap(norm, text)
        keys = set()
        for k in CORE:
            keys |= {(k, v) for v in gold[k]} | {(k, v) for p in preds.values() for v in p[k]}
        for k, v in sorted(keys):
            rows.append({"report": r["report"], "nhom": r["nhom"], "loai": k, "gia_tri": v, "trong_dap_an": v in gold[k],
                         **{c: int(v in preds[c][k]) for c in cach}})
    res = {"ghi_chu": "Bốn loại lõi; quy ước tên miền/IP trong URL không tính riêng áp như nhau cho mọi cách (loc_doc_lap). "
                      "Bộ rút hệ thống là mã hiện hành (luật đã sửa trên cả 19 report: số trong mẫu).",
           "phien_ban_cong_cu": C.get("phien_ban", {}), "ca_19": _bang(rows, cach),
           "theo_nhom": {n: _bang([x for x in rows if x["nhom"] == n], cach) for n in dict.fromkeys(x["nhom"] for x in rows)},
           "so_cap_recall": {c: _so_cap(rows, "he_thong", c, True) for c in cach[1:]},
           "so_cap_dung_sai": {c: _so_cap(rows, "he_thong", c, False) for c in cach[1:]}}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_A_cong_cu.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "muc_A.json").write_text(json.dumps(rows, ensure_ascii=False, indent=0), encoding="utf-8")
    _in(res["ca_19"], "A · 19 report")
    for n, v in res["theo_nhom"].items():
        _in(v, f"A · {n}")
    for c in cach[1:]:
        a, b = res["so_cap_recall"][c], res["so_cap_dung_sai"][c]
        print(f"  hệ thống vs {c}: recall — chỉ hệ thống {a['chi_a_dung']} / chỉ {c} {a['chi_b_dung']} (p = {a['p']:.2g}); "
              f"đúng/sai trên mọi mục — {b['chi_a_dung']} / {b['chi_b_dung']} (p = {b['p']:.2g})")
    return 0


def cham_llm(goi: Path, nhan: Path, out: Path) -> int:
    G = json.loads(goi.read_text(encoding="utf-8"))
    L = json.loads(nhan.read_text(encoding="utf-8"))
    rows = []
    for r in G["report"]:
        text = T.refang(r["van_ban"])
        gold = {k: set(r["dap_an"][k]) for k in CORE}
        cand = {k: {u["gia_tri"] for u in r["ung_vien"] if u["loai"] == k} for k in CORE}
        keep = loc_doc_lap(cand, text)
        lab = L["nhan"].get(r["report"], {})
        for u in r["ung_vien"]:
            if u["gia_tri"] not in keep[u["loai"]]:
                continue
            key = f"{u['loai']}|{u['gia_tri']}"
            llm = lab.get(key, {}).get("la_ioc")
            rows.append({"report": r["report"], "nhom": r["nhom"], "loai": u["loai"], "gia_tri": u["gia_tri"],
                         "trong_dap_an": u["gia_tri"] in gold[u["loai"]], "bo_rut": 1,
                         "luat": int(u["muc_luat"] == "manh"), "llm": int(bool(llm)),
                         "luat_va_llm": int(u["muc_luat"] == "manh" and bool(llm)), "llm_thieu_nhan": llm is None})
        for k in CORE:
            for v in gold[k] - keep[k]:      # đáp án bộ rút không tìm ra: không cách nào nêu được
                rows.append({"report": r["report"], "nhom": r["nhom"], "loai": k, "gia_tri": v, "trong_dap_an": True,
                             "bo_rut": 0, "luat": 0, "llm": 0, "luat_va_llm": 0, "llm_thieu_nhan": False})
    cach = ["bo_rut", "luat", "llm", "luat_va_llm"]
    res = {"ghi_chu": "Ứng viên = bộ rút hệ thống (bốn loại lõi). 'luat' = luật viết tay xếp mạnh (đã sửa trên cả 19 report: "
                      "thiên vị cho luật). 'llm' = mô hình mở gán là IOC thật. Thiếu nhãn LLM tính là không phải IOC.",
           "mo_hinh": L.get("mo_hinh"), "llm_thieu_nhan": sum(1 for x in rows if x["llm_thieu_nhan"]),
           "ca_19": _bang(rows, cach),
           "theo_nhom": {n: _bang([x for x in rows if x["nhom"] == n], cach) for n in dict.fromkeys(x["nhom"] for x in rows)},
           "so_cap_dung_sai_luat_vs_llm": _so_cap([x for x in rows if x["bo_rut"]], "luat", "llm", False),
           "so_cap_recall_luat_vs_llm": _so_cap(rows, "luat", "llm", True)}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ket_qua_B_llm.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "muc_B.json").write_text(json.dumps(rows, ensure_ascii=False, indent=0), encoding="utf-8")
    _in(res["ca_19"], "B · 19 report")
    for n, v in res["theo_nhom"].items():
        _in(v, f"B · {n}")
    a, b = res["so_cap_dung_sai_luat_vs_llm"], res["so_cap_recall_luat_vs_llm"]
    print(f"  luật vs LLM: đúng/sai trên ứng viên — chỉ luật {a['chi_a_dung']} / chỉ LLM {a['chi_b_dung']} (p = {a['p']:.2g}); "
          f"recall — {b['chi_a_dung']} / {b['chi_b_dung']} (p = {b['p']:.2g}); thiếu nhãn LLM {res['llm_thieu_nhan']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("chuan-bi")
    p.add_argument("--out", required=True)
    p = sub.add_parser("cham-cong-cu")
    p.add_argument("--goi", required=True)
    p.add_argument("--cong-cu", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("cham-llm")
    p.add_argument("--goi", required=True)
    p.add_argument("--nhan", required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.lenh == "chuan-bi":
        return chuan_bi(Path(a.out))
    if a.lenh == "cham-cong-cu":
        return cham_cong_cu(Path(a.goi), Path(a.cong_cu), Path(a.out))
    return cham_llm(Path(a.goi), Path(a.nhan), Path(a.out))


if __name__ == "__main__":
    raise SystemExit(main())
