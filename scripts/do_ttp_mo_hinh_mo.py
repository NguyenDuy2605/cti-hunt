"""Chấm phần trích TTP của mô hình mở (Ollama, PC 17–18/10) theo giao thức đặt trước `docs/METHODOLOGY.md`.

Không gọi API, không đọc nhãn sự kiện, không đọc Silver, không dùng mạng. Đáp án: kỹ thuật MITRE ATT&CK v19.2 ánh xạ cho đúng
report (``do_ttp_mitre.mitre_sets``). Dùng lại đúng cách chấm của ``do_ttp_bo_mo_rong`` (BM25, rcATT) và ``do_ttp_mitre``
(lượt Claude ở bộ cũ).

- §3 bộ 30 report: mô hình mở so với BM25 (gợi ý đứng đầu / 3 đầu / cả 8) và rcATT; recall theo report (kiểm định dấu, phép
  so chính), precision theo report (bổ sung), McNemar trên mục (kèm); mức kỹ thuật cha (chính) và đúng mã.
- §4 kiểm độ vững: bỏ 5 report có lô hỏng.
- §5 bộ 4 report cũ: mô hình mở cạnh lượt Claude, chỉ mô tả.
- §6 phân tích phụ (a): đầu ra thô trước cổng kiểm câu trích.
- §7 phân tích phụ (b): report đăng trước và sau ngày phát hành Qwen2.5, chỉ mô tả.

    .venv/Scripts/python.exe -X utf8 scripts/do_ttp_mo_hinh_mo.py cham ^
        --mo-hinh-mo ../workspace/tu_pc_17-10/mo_hinh_mo_16-10 ^
        --bo ../workspace/bo_mo_rong_16-10 ^
        --rcatt ../workspace/bo_mo_rong_16-10/rcatt/du_doan_rcatt.json ^
        --out ../workspace/cham_ttp_mo_hinh_mo_18-10
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from do_ttp_bm25_mitre import REPORTS, bm25_sets  # noqa: E402
from do_ttp_bo_mo_rong import _so_sanh, nhan  # noqa: E402
from do_ttp_mitre import CASES, STIX, mitre_sets, parent  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.attack.catalog import AttackCatalog  # noqa: E402
from cti_hunt.eval.thong_ke import mcnemar_exact, sign_test, wilson  # noqa: E402

GIAO_THUC = "docs/METHODOLOGY.md"
# §4: report có lô hỏng (hết num_predict), kiểm từ lo_hong.jsonl và giờ bắt đầu từng report trong trich_ttp_mo_rong.log.
LO_HONG = ("RM-002", "RM-005", "RM-013", "RM-014", "RM-016")
# §7: ngày phát hành Qwen2.5 (blog chính thức) và nhóm "sau" ghi trong giao thức; script kiểm lại từ trích dẫn ATT&CK.
MOC_PHAT_HANH = dt.date(2024, 9, 19)
NHOM_SAU = ("RM-004", "RM-006", "RM-019", "RM-021", "RM-030", "RM-032", "RM-033", "RM-038")
# Lượt Claude ở Volt: cùng prompt, cùng lô với lượt mô hình mở (giao thức §1); evidence_audit.json dùng cho §6.
CLAUDE_VOLT = "data/reports/moi/VOLT-MS-1310/extractions/extract_e53933206e104a43ab00e2cd68475024"
CU_TEN_THU_MUC = {"Volt Typhoon (Microsoft)": "volt_typhoon", "POSHSPY (FireEye)": "poshspy",
                  "Raindrop (Symantec)": "raindrop", "Solorigate (Microsoft)": "solorigate"}
THANG = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july", "august",
                                     "september", "october", "november", "december"], 1)}

CHUAN = {"cha": lambda s: {parent(t) for t in s}, "ma": lambda s: set(s)}


def ttp_contract(path: Path) -> set[str]:
    return {t["technique_id"] for t in json.loads(path.read_text(encoding="utf-8"))["ttps"]}


def bang_muc(gold: dict[str, set[str]], preds: dict[str, dict[str, set[str]]], cach: list[str]) -> list[dict]:
    """Mỗi mục là (report, kỹ thuật trong đáp án); ghi từng cách có nêu kỹ thuật đó không."""
    return [{"report": rp, "ky_thuat": t, **{k: int(t in preds[k][rp]) for k in cach}}
            for rp in gold for t in sorted(gold[rp])]


def tong_hop(rows: list[dict], preds: dict[str, dict[str, set[str]]], cach: list[str], reports: list[str]) -> dict:
    n = sum(1 for r in rows if r["report"] in reports)
    out = {"so_report": len(reports), "so_muc": n, "recall": {}, "precision_can_duoi": {}, "so_ky_thuat_neu": {}}
    for k in cach:
        x = sum(r[k] for r in rows if r["report"] in reports)
        t = sum(len(preds[k][rp]) for rp in reports)
        out["recall"][k] = {"dung": x, "tren": n, "wilson95": wilson(x, n)}
        out["precision_can_duoi"][k] = {"dung": x, "tren": t, "wilson95": wilson(x, t)}
        out["so_ky_thuat_neu"][k] = t
    return out


def so_precision(gold: dict[str, set[str]], preds: dict[str, dict[str, set[str]]], a: str, b: str,
                 reports: list[str]) -> dict:
    """§3 bổ sung: kiểm định dấu theo report trên precision cận dưới; bỏ report mà một bên không nêu mã nào."""
    hon = kem = bang = 0
    bo_qua = []
    for rp in reports:
        pa, pb = preds[a][rp], preds[b][rp]
        if not pa or not pb:
            bo_qua.append(rp)
            continue
        xa, xb = len(pa & gold[rp]) / len(pa), len(pb & gold[rp]) / len(pb)
        hon, kem, bang = hon + (xa > xb), kem + (xa < xb), bang + (xa == xb)
    return {"a": a, "b": b, "report_a_hon": hon, "report_a_kem": kem, "report_bang": bang,
            "report_bo_qua": bo_qua, "dau_p": sign_test(hon, kem)}


def phep_so(gold, preds, cach_so, reports) -> dict:
    """Recall (kiểm định dấu theo report + McNemar trên mục, như ``_so_sanh``) và precision theo report."""
    rows = [r for r in bang_muc({rp: gold[rp] for rp in reports}, preds, ["mo_hinh_mo", *cach_so])]
    return {b: {"recall": _so_sanh(rows, "mo_hinh_mo", b, reports),
                "precision": so_precision(gold, preds, "mo_hinh_mo", b, reports)} for b in cach_so}


def ma_tho(audit: list[dict], cat: AttackCatalog) -> tuple[set[str], dict[str, list[str]]]:
    """§6: mã hiện hành còn hiệu lực của mọi mục (nhận và bị loại), và lý do loại theo mã."""
    tho, ly_do = set(), {}
    for r in audit:
        tid = r.get("final_technique_id") if r.get("status") == "accepted" else r.get("technique_id")
        if not tid:
            continue
        res = cat.resolve(tid)
        if not res.final or cat.resolve(res.final).status != "ok":
            continue
        tho.add(res.final)
        if r.get("status") != "accepted":
            ly_do.setdefault(res.final, []).append(r.get("reason") or "")
    return tho, ly_do


def phan_tich_tho(gold_ma: dict[str, set[str]], sau: dict[str, set[str]], audits: dict[str, list[dict]],
                  cat: AttackCatalog) -> dict:
    out = {}
    for level, norm in CHUAN.items():
        gold = {rp: norm(g) for rp, g in gold_ma.items()}
        p_sau, p_tho, mat = {}, {}, []
        ly_do_dem: dict[str, int] = {}
        for rp in gold:
            tho, ly_do = ma_tho(audits[rp], cat)
            p_sau[rp], p_tho[rp] = norm(sau[rp]), norm(tho)
            if not p_sau[rp] <= p_tho[rp]:
                raise SystemExit(f"§6: tập sau cổng không nằm trong tập thô ở {rp}")
            for t in sorted((p_tho[rp] - p_sau[rp]) & gold[rp]):
                lys = sorted({x for m, xs in ly_do.items() if norm({m}) == {t} for x in xs})
                mat.append({"report": rp, "ky_thuat": t, "ly_do": lys})
                for x in lys:
                    ly_do_dem[x] = ly_do_dem.get(x, 0) + 1
        preds = {"sau_cong": p_sau, "tho": p_tho}
        rows = bang_muc(gold, preds, ["sau_cong", "tho"])
        out[level] = {**tong_hop(rows, preds, ["sau_cong", "tho"], list(gold)),
                      "muc_dap_an_cong_lam_mat": len(mat), "chi_tiet_mat": mat,
                      "ly_do_cua_muc_bi_mat": dict(sorted(ly_do_dem.items(), key=lambda kv: -kv[1]))}
    return out


def ngay_dang(description: str) -> tuple[str, bool | None]:
    """Ngày đăng trong cặp ngoặc đầu tiên của trích dẫn ATT&CK ("(2024, March 7)", "(2021, January)", "(2022)").

    Trả về (chuỗi ngày đọc được, đăng sau mốc phát hành?). None khi không phân loại được: thiếu năm, hoặc thiếu tháng/ngày
    đúng ở chỗ cần để so với mốc (năm 2024 không có tháng; tháng 9/2024 không có ngày)."""
    m = re.search(r"\((\d{4})(?:, ([A-Za-z]+)(?: (\d{1,2}))?)?", description or "")
    if not m:
        return "", None
    nam, thang, ngay = int(m.group(1)), m.group(2), m.group(3)
    so_thang = THANG.get((thang or "").lower())
    chuoi = "-".join(x for x in (m.group(1), f"{so_thang:02d}" if so_thang else "", f"{int(ngay):02d}" if ngay and so_thang else "") if x)
    if nam != MOC_PHAT_HANH.year:
        return chuoi, nam > MOC_PHAT_HANH.year
    if not so_thang:
        return chuoi, None
    if so_thang != MOC_PHAT_HANH.month:
        return chuoi, so_thang > MOC_PHAT_HANH.month
    if not ngay:
        return chuoi, None
    return chuoi, int(ngay) > MOC_PHAT_HANH.day


def kiem_nhom_nam(entries: list[dict], ung_vien: list[dict]) -> dict[str, tuple[str, bool]]:
    """§7: dựng lại nhóm 'sau' từ trích dẫn ATT&CK; không phân loại được hoặc khác danh sách trong giao thức thì dừng."""
    desc = {c["source_name"]: c.get("description", "") for c in ung_vien}
    ngay = {e["ma"]: ngay_dang(desc.get(e["source_name"], "")) for e in entries}
    thieu = sorted(m for m, (_, sau) in ngay.items() if sau is None)
    if thieu:
        raise SystemExit(f"§7: không phân loại được ngày đăng của {thieu}")
    sau = {m for m, (_, s) in ngay.items() if s}
    if sau != set(NHOM_SAU):
        raise SystemExit(f"§7: nhóm 'sau' dựng lại {sorted(sau)} khác giao thức {sorted(NHOM_SAU)}")
    return ngay


def phan_tich_nam(gold_cha, preds_cha, ngay: dict[str, tuple[str, bool]]) -> dict:
    out = {"moc_phat_hanh_qwen2_5": MOC_PHAT_HANH.isoformat()}
    for ten, chon in (("sau", lambda m: ngay[m][1]), ("truoc", lambda m: not ngay[m][1])):
        reports = sorted(m for m in gold_cha if chon(m))
        rows = bang_muc({rp: gold_cha[rp] for rp in reports}, preds_cha, ["mo_hinh_mo", "bm25_top1", "bm25_top8"])
        g = {"report": reports, **tong_hop(rows, preds_cha, ["mo_hinh_mo", "bm25_top1", "bm25_top8"], reports)}
        for b in ("bm25_top1", "bm25_top8"):
            hieu = []
            for rp in reports:
                n = len(gold_cha[rp])
                ra = len(preds_cha["mo_hinh_mo"][rp] & gold_cha[rp]) / n
                rb = len(preds_cha[b][rp] & gold_cha[rp]) / n
                hieu.append(ra - rb)
            g[f"hieu_recall_tru_{b}"] = {"trung_vi": statistics.median(hieu), "hon": sum(h > 0 for h in hieu),
                                         "kem": sum(h < 0 for h in hieu), "bang": sum(h == 0 for h in hieu)}
        out[ten] = g
    return out


def cham(mo_hinh_mo: Path, bo: Path, rcatt: Path, out: Path) -> dict:
    stix_path = config.resolve(STIX)
    gold_all = mitre_sets(json.loads(stix_path.read_text(encoding="utf-8")))
    cat = AttackCatalog.from_stix(stix_path)
    res: dict = {"giao_thuc": GIAO_THUC,
                 "gioi_han": "Precision là cận dưới (MITRE ánh xạ một phần). Mục trong cùng report không độc lập: phép so "
                             "chính là kiểm định dấu theo report. Phân tích phụ (a), (b) và bộ cũ chỉ mô tả."}
    out.mkdir(parents=True, exist_ok=True)

    # §3, §4: bộ 30 report.
    entries = nhan(bo)
    rc = json.loads(rcatt.read_text(encoding="utf-8"))
    ma_list = [e["ma"] for e in entries]
    gold_ma = {e["ma"]: gold_all.get(e["source_name"], set()) for e in entries}
    pred_ma = {"mo_hinh_mo": {}, "bm25_top1": {}, "bm25_top3": {}, "bm25_top8": {}, "rcatt": {}}
    audits = {}
    for e in entries:
        run = mo_hinh_mo / "mo_rong" / e["ma"].lower()
        pred_ma["mo_hinh_mo"][e["ma"]] = ttp_contract(run / "contract_a.json")
        audits[e["ma"]] = json.loads((run / "evidence_audit.json").read_text(encoding="utf-8"))
        bm, _ = bm25_sets(bo / "bundles" / e["ma"])
        for k in (1, 3, 8):
            pred_ma[f"bm25_top{k}"][e["ma"]] = bm[k]
        old = rc["du_doan"][e["ma"].lower().replace("-", "_")]["ma"]
        pred_ma["rcatt"][e["ma"]] = {parent(r.final) for r in map(cat.resolve, old) if r.final}
    giu = [m for m in ma_list if m not in LO_HONG]
    for level, norm in CHUAN.items():
        cach = ["mo_hinh_mo", "bm25_top1", "bm25_top3", "bm25_top8"] + (["rcatt"] if level == "cha" else [])
        gold = {m: norm(g) for m, g in gold_ma.items()}
        preds = {k: {m: norm(v[m]) for m in ma_list} for k, v in pred_ma.items() if k in cach}
        rows = bang_muc(gold, preds, cach)
        with open(out / f"muc_bo_mo_rong_{level}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["report", "ky_thuat", *cach])
            w.writeheader()
            w.writerows(rows)
        res[f"bo_mo_rong_{level}"] = {
            **tong_hop(rows, preds, cach, ma_list),
            "phep_so": phep_so(gold, preds, cach[1:], ma_list),
            "kiem_do_vung_bo_5_report_lo_hong": {
                "report_bo": list(LO_HONG),
                **tong_hop([r for r in rows if r["report"] in giu], preds, cach, giu),
                "phep_so": phep_so(gold, preds, cach[1:], giu)},
            "theo_report": [{"report": m, "dap_an": len(gold[m]),
                             **{f"recall_{k}": len(preds[k][m] & gold[m]) / len(gold[m]) for k in cach},
                             **{f"neu_{k}": len(preds[k][m]) for k in cach}} for m in ma_list]}
    # §6 (a) trên bộ 30 report.
    res["tho_bo_mo_rong"] = phan_tich_tho(gold_ma, pred_ma["mo_hinh_mo"], audits, cat)
    # §7 (b).
    ung_vien = json.loads((bo / "ung_vien.json").read_text(encoding="utf-8"))["ung_vien"]
    ngay = kiem_nhom_nam(entries, ung_vien)
    res["nam_dang"] = {"ngay": {m: d for m, (d, _) in sorted(ngay.items())},
                       **phan_tich_nam({m: CHUAN["cha"](g) for m, g in gold_ma.items()},
                                       {k: {m: CHUAN["cha"](v[m]) for m in ma_list} for k, v in pred_ma.items()},
                                       ngay)}

    # §5: bộ 4 report cũ, mô hình mở cạnh lượt Claude; §6 cho bộ cũ và lượt Claude ở Volt.
    cu_gold, cu_mo, cu_claude, cu_audit = {}, {}, {}, {}
    for name, ten in CU_TEN_THU_MUC.items():
        _, src, llm_case = REPORTS[name]
        cu_gold[name] = gold_all.get(src, set())
        run = mo_hinh_mo / "cu" / ten
        cu_mo[name] = ttp_contract(run / "contract_a.json")
        cu_audit[name] = json.loads((run / "evidence_audit.json").read_text(encoding="utf-8"))
        cu_claude[name] = ttp_contract(config.resolve(CASES[llm_case][0]))
    for level, norm in CHUAN.items():
        gold = {m: norm(g) for m, g in cu_gold.items()}
        preds = {"mo_hinh_mo": {m: norm(v) for m, v in cu_mo.items()}, "claude": {m: norm(v) for m, v in cu_claude.items()}}
        rows = bang_muc(gold, preds, ["mo_hinh_mo", "claude"])
        b = sum(1 for r in rows if r["mo_hinh_mo"] and not r["claude"])
        c = sum(1 for r in rows if r["claude"] and not r["mo_hinh_mo"])
        res[f"bo_cu_{level}"] = {
            **tong_hop(rows, preds, ["mo_hinh_mo", "claude"], list(gold)),
            "mcnemar_tren_muc": {"chi_mo_hinh_mo_dung": b, "chi_claude_dung": c, "p": mcnemar_exact(b, c),
                                 "canh_bao": "4 report, mục không độc lập; chỉ Volt cùng điều kiện"},
            "theo_report": [{"report": m, "cung_dieu_kien": m == "Volt Typhoon (Microsoft)", "dap_an": len(gold[m]),
                             **{f"{k}_dung": len(preds[k][m] & gold[m]) for k in preds},
                             **{f"{k}_neu": len(preds[k][m]) for k in preds}} for m in gold]}
    res["tho_bo_cu"] = phan_tich_tho(cu_gold, cu_mo, cu_audit, cat)
    claude_audit = json.loads((config.resolve(CLAUDE_VOLT) / "evidence_audit.json").read_text(encoding="utf-8"))
    volt = "Volt Typhoon (Microsoft)"
    res["tho_volt_claude"] = phan_tich_tho({volt: cu_gold[volt]}, {volt: cu_claude[volt]}, {volt: claude_audit}, cat)

    (out / "ket_qua.json").write_text(json.dumps(res, ensure_ascii=False, indent=1, default=list), encoding="utf-8")
    return res


def in_tom_tat(res: dict) -> None:
    pct = lambda v: f"{v * 100:.0f}%"
    w = lambda x: f"{x['dung']}/{x['tren']} = {pct(x['dung'] / x['tren']) if x['tren'] else '—'} " \
                  f"[{pct(x['wilson95'][0])}–{pct(x['wilson95'][1])}]"
    for level, ten in (("cha", "kỹ thuật cha"), ("ma", "đúng mã")):
        for khoa, nhan_ in ((f"bo_mo_rong_{level}", "30 report"),):
            s = res[khoa]
            for phan, s2 in (("chính", s), ("bỏ 5 report lô hỏng", s["kiem_do_vung_bo_5_report_lo_hong"])):
                print(f"\n== Bộ {nhan_}, mức {ten}, {phan}: {s2['so_report']} report, {s2['so_muc']} mục")
                for k in s2["recall"]:
                    print(f"  {k:11s} recall {w(s2['recall'][k])} · precision ≥ {w(s2['precision_can_duoi'][k])}")
                for b, c in s2["phep_so"].items():
                    r, p = c["recall"], c["precision"]
                    print(f"  mô hình mở vs {b}: recall theo report {r['report_a_hon']} hơn / {r['report_a_kem']} kém / "
                          f"{r['report_bang']} bằng (p = {r['dau_p']:.2g}); mục chỉ mô hình mở {r['muc_chi_a_dung']} / chỉ "
                          f"{b} {r['muc_chi_b_dung']} (p = {r['mcnemar_p']:.2g}); precision theo report {p['report_a_hon']} "
                          f"hơn / {p['report_a_kem']} kém / {p['report_bang']} bằng, bỏ {len(p['report_bo_qua'])} "
                          f"(p = {p['dau_p']:.2g})")
        s = res[f"bo_cu_{level}"]
        print(f"\n== Bộ cũ 4 report, mức {ten} (chỉ mô tả)")
        for k in s["recall"]:
            print(f"  {k:11s} recall {w(s['recall'][k])} · precision ≥ {w(s['precision_can_duoi'][k])}")
        for r in s["theo_report"]:
            print(f"  {r['report']}{' (cùng điều kiện)' if r['cung_dieu_kien'] else ''}: đáp án {r['dap_an']} · mô hình mở "
                  f"{r['mo_hinh_mo_dung']}/{r['mo_hinh_mo_neu']} nêu · Claude {r['claude_dung']}/{r['claude_neu']} nêu")
        m = s["mcnemar_tren_muc"]
        print(f"  mục chỉ mô hình mở {m['chi_mo_hinh_mo_dung']} / chỉ Claude {m['chi_claude_dung']} (p = {m['p']:.2g})")
    for khoa, nhan_ in (("tho_bo_mo_rong", "30 report"), ("tho_bo_cu", "4 report cũ"), ("tho_volt_claude", "Volt, Claude")):
        for level in ("cha", "ma"):
            s = res[khoa][level]
            print(f"\n== (a) Đầu ra thô, {nhan_}, mức {level}: sau cổng recall {w(s['recall']['sau_cong'])}, "
                  f"precision ≥ {w(s['precision_can_duoi']['sau_cong'])}; thô recall {w(s['recall']['tho'])}, "
                  f"precision ≥ {w(s['precision_can_duoi']['tho'])}; cổng làm mất {s['muc_dap_an_cong_lam_mat']} mục")
            for x, n in list(s["ly_do_cua_muc_bi_mat"].items())[:6]:
                print(f"     {n:4d} · {x[:90]}")
    s = res["nam_dang"]
    for nhom in ("truoc", "sau"):
        g = s[nhom]
        print(f"\n== (b) Nhóm {nhom} ngày {s['moc_phat_hanh_qwen2_5']}: {g['so_report']} report, {g['so_muc']} mục (chỉ mô tả)")
        for k in g["recall"]:
            print(f"  {k:11s} recall {w(g['recall'][k])} · precision ≥ {w(g['precision_can_duoi'][k])}")
        for b in ("bm25_top1", "bm25_top8"):
            h = g[f"hieu_recall_tru_{b}"]
            print(f"  recall mô hình mở trừ {b}: trung vị {h['trung_vi'] * 100:+.0f} điểm %; hơn {h['hon']} / kém {h['kem']}"
                  f" / bằng {h['bang']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("cham")
    p.add_argument("--mo-hinh-mo", required=True, help="thư mục mo_hinh_mo_16-10 (có cu/, mo_rong/)")
    p.add_argument("--bo", required=True, help="thư mục bộ 30 report (nhat_ky_tai.json, ung_vien.json, bundles/)")
    p.add_argument("--rcatt", required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    out = Path(a.out)
    if "cti-hunt/data" in out.resolve().as_posix().lower():
        raise SystemExit("không ghi vào data/ của repo")
    in_tom_tat(cham(Path(a.mo_hinh_mo), Path(a.bo), Path(a.rcatt), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
