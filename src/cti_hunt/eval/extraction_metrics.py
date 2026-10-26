"""Đo khâu ② theo v3 §6.2 — mức mã kỹ thuật. Lịch dùng: T3 29/9.

Khóa so khớp (report, technique_id) theo R9/R13. Trình tự:
1. Đếm mã thô không hợp lệ và bị thu hồi TRƯỚC khi quy đổi (quyết định B4 trong DuyetQuyTac).
2. Quy đổi mã bị thu hồi sang mã thay thế ở v19.2; bỏ mã không tồn tại (tính là FP).
3. Tính precision / recall / F1 theo từng report và gộp.

Báo hai lần (quyết định 21/09/2026, sau khi rà Silver v1):
- `du`: toàn bộ cặp.
- `bo_ma_co_san`: bỏ, ở CẢ nhãn lẫn dự đoán, mọi cặp mà mã kỹ thuật xuất hiện nguyên văn trong văn bản report đó
  (vd bảng ATT&CK vendor tự viết ở cuối report MS). Mô hình chép được các mã này, nên chỉ con số thứ hai đo khả năng
  suy ra kỹ thuật từ văn xuôi. Mã cũ đã thu hồi trong văn bản cũng tính, sau khi quy về mã thay thế ở v19.2.

P/R TỪNG TRƯỜNG CONTEXT (2b, cách tính đã chốt):
- Ghép dòng dự đoán với dòng nhãn theo (segment_id, mã kỹ thuật) — khóa 1-1 với dòng nhãn theo R1, dùng
  segment_id của D2. Dự đoán không có segment_id thì không ghép được và được đếm riêng.
- So giá trị: chuẩn hóa nhẹ (gộp khoảng trắng, chữ thường, bỏ dấu câu hai đầu) rồi khớp chặt. `khong_ro`
  quy về '' ở CẢ nhãn lẫn dự đoán (D3+D4). Số phụ `khop_chua_them` đếm cặp lệch mà một bên chứa bên kia,
  và `lech` giữ danh sách để đọc định tính — số chính vẫn là khớp chặt, tức một GIỚI HẠN DƯỚI.
  Không có từ điển đồng nghĩa: lập được từ điển thì phải đọc giá trị trong bộ tham chiếu (docs/METHODOLOGY.md §4.1).
- Mẫu số: chỉ dòng nhãn `in_scope=co`, vì theo R6 chỉ những dòng đó mới điền context. Dòng ngoài scope
  CHỈ được đếm (`ngoai_scope`), không tính vào precision: ở đó nhãn trống do thiết kế R6 chứ không phải vì
  report không nêu, nên mô hình điền vào đó không có nghĩa là bịa.
- Mỗi trường: TP = hai bên cùng có giá trị và khớp · FP = dự đoán có, nhãn trống hoặc khác · FN = nhãn có,
  dự đoán trống hoặc khác · `ca_hai_trong` đếm riêng, không vào mẫu số.
"""
from __future__ import annotations

import re

from ..attack.catalog import AttackCatalog

_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def normalize_predictions(pred: set[tuple[str, str]], catalog: AttackCatalog) -> tuple[set, dict]:
    out, stats = set(), {"tong": len(pred), "khong_ton_tai": [], "bi_thu_hoi": [], "deprecated": []}
    for report, tid in sorted(pred):
        res = catalog.resolve(tid)
        if res.status == "ok":
            out.add((report, res.final))
        elif res.status == "revoked" and res.final:
            stats["bi_thu_hoi"].append(f"{report}:{tid}->{res.final}")
            out.add((report, res.final))
        elif res.status == "deprecated":
            stats["deprecated"].append(f"{report}:{tid}")
            out.add((report, tid))            # vẫn tính, để hiện là FP nếu nhãn không có
        else:
            stats["khong_ton_tai"].append(f"{report}:{tid}")
            out.add((report, tid))            # giữ lại để bị tính FP, không lặng lẽ bỏ
    return out, stats


def prf(gold: set, pred: set) -> dict:
    tp = len(gold & pred)
    p = tp / len(pred) if pred else None
    r = tp / len(gold) if gold else None
    f1 = 2 * p * r / (p + r) if p and r else None
    return {"tp": tp, "fp": len(pred - gold), "fn": len(gold - pred), "precision": p, "recall": r, "f1": f1,
            "fp_list": sorted(pred - gold), "fn_list": sorted(gold - pred)}


def evaluate_iocs(gold_rows, pred_rows, normalize) -> dict:
    """So theo tập (report, giá trị) như R10; giá trị chuẩn hóa bằng refang + chữ thường.

    gold_rows / pred_rows: chuỗi các bộ (report, gia_tri, loai). Loại được đo riêng, vì sai loại
    (vd ghi domain thay vì url) nhẹ hơn hẳn so với bỏ sót.
    """
    gold = {(r, normalize(v)): (t or "").strip() for r, v, t in gold_rows}
    pred = {(r, normalize(v)): (t or "").strip() for r, v, t in pred_rows}
    trung = sorted(set(gold) & set(pred))
    sai_loai = [{"report": r, "gia_tri": v, "nhan": gold[(r, v)], "he_thong": pred[(r, v)]}
                for r, v in trung if gold[(r, v)] != pred[(r, v)]]
    res = prf(set(gold), set(pred))
    res["sai_loai"] = sai_loai
    res["dung_ca_loai"] = len(trung) - len(sai_loai)
    return res


def evaluate(gold: set[tuple[str, str]], pred_raw: set[tuple[str, str]], catalog: AttackCatalog) -> dict:
    pred, stats = normalize_predictions(pred_raw, catalog)
    reports = sorted({r for r, _ in gold | pred})
    return {
        "ma_tho": stats,
        "gop": prf(gold, pred),
        "theo_report": {rp: prf({x for x in gold if x[0] == rp}, {x for x in pred if x[0] == rp})
                        for rp in reports},
    }


def literal_pairs(texts_by_report: dict[str, list[str]], catalog: AttackCatalog) -> set[tuple[str, str]]:
    """(report, mã) cho mọi mã kỹ thuật xuất hiện nguyên văn trong văn bản report, kèm mã thay thế nếu bị thu hồi."""
    out: set[tuple[str, str]] = set()
    for report, texts in texts_by_report.items():
        for t in texts:
            for m in _TID.findall(t or ""):
                out.add((report, m))
                res = catalog.resolve(m)
                if res.final:
                    out.add((report, res.final))
    return out


def score(gold: set, gold_in_scope: set, pred_raw: set, catalog: AttackCatalog, literal: set,
          independent: set[str]) -> dict:
    """P/R `du` và `bo_ma_co_san`, mỗi bản có: gộp, theo report, gộp riêng report độc lập với kịch bản, và recall
    trên cặp in-scope (dự đoán không mang cờ in-scope nên chỉ tính được recall)."""
    pred, stats = normalize_predictions(pred_raw, catalog)

    def block(g: set, gi: set, pr: set) -> dict:
        reports = sorted({r for r, _ in g | pr})
        ind = lambda xs: {x for x in xs if x[0] in independent}
        return {
            "gop": prf(g, pr),
            "report_doc_lap": prf(ind(g), ind(pr)),
            "theo_report": {rp: prf({x for x in g if x[0] == rp}, {x for x in pr if x[0] == rp}) for rp in reports},
            "recall_in_scope": {"tp": len(gi & pr), "mau_so": len(gi), "thieu": sorted(gi - pr)},
        }

    return {
        "ma_tho": stats,
        "du": block(gold, gold_in_scope, pred),
        "bo_ma_co_san": block(gold - literal, gold_in_scope - literal, pred - literal),
        "ma_co_san": {"so_cap": len(literal), "trong_nhan": sorted(gold & literal),
                      "trong_du_doan": sorted(pred & literal)},
    }


CONTEXT_FIELDS = ("tool", "execution_path", "source_role", "target_role", "account_type",
                  "preceded_by", "command_example")
_ID_FIELDS = ("preceded_by",)
_STRIP = " \t\r\n.,;:!?\"\u2019'\u201c\u201d()[]"


def norm_text(v) -> str:
    """Chuẩn hóa nhẹ một ô context. 'khong_ro' và '' là một (D3+D4)."""
    s = " ".join(str("" if v is None else v).split()).strip(_STRIP).lower()
    return "" if s == "khong_ro" else s


def norm_ids(v, catalog: AttackCatalog) -> tuple[str, ...]:
    """preceded_by -> tập mã đã quy đổi mã thu hồi. Nhận cả list (dự đoán) lẫn chuỗi 'T1047, T1059.001' (nhãn)."""
    raw = v if isinstance(v, (list, tuple, set)) else _TID.findall(str(v or "").upper())
    out = set()
    for x in raw:
        for m in _TID.findall(str(x).upper()):
            out.add(catalog.resolve(m).final or m)
    return tuple(sorted(out))


def _empty(x) -> bool:
    return x == "" or x == ()


def _contains(a, b) -> bool:
    """Một bên chứa bên kia: chuỗi con, hoặc tập con. Chỉ dùng cho số phụ."""
    if isinstance(a, tuple):
        return bool(a) and bool(b) and (set(a) <= set(b) or set(b) <= set(a))
    return bool(a) and bool(b) and (a in b or b in a)


def _field_values(row: dict, catalog: AttackCatalog) -> dict:
    return {f: (norm_ids(row.get(f), catalog) if f in _ID_FIELDS else norm_text(row.get(f)))
            for f in CONTEXT_FIELDS}


def _field_block(pairs: list[tuple[tuple[str, str], dict, dict]]) -> dict:
    """pairs: (khóa, giá trị nhãn, giá trị dự đoán) của các dòng in_scope=co ghép được."""
    out = {}
    for f in CONTEXT_FIELDS:
        tp = fp = fn = ca_hai_trong = chua = 0
        lech = []
        for (seg, tid), g, pr in pairs:
            a, b = g[f], pr[f]
            if _empty(a) and _empty(b):
                ca_hai_trong += 1
            elif a == b:
                tp += 1
            else:
                if not _empty(b):
                    fp += 1
                if not _empty(a):
                    fn += 1
                if not _empty(a) and not _empty(b):
                    chua += int(_contains(a, b))
                    lech.append({"ma_doan": seg, "technique_id": tid, "nhan": a, "he_thong": b})
        pr_ = tp / (tp + fp) if tp + fp else None
        rc = tp / (tp + fn) if tp + fn else None
        out[f] = {"tp": tp, "fp": fp, "fn": fn, "precision": pr_, "recall": rc,
                  "f1": 2 * pr_ * rc / (pr_ + rc) if pr_ and rc else None,
                  "ca_hai_trong": ca_hai_trong, "khop_chua_them": chua, "so_lech": len(lech), "lech": lech}
    return out


def _outside_scope(pairs: list[tuple[tuple[str, str], dict, dict]]) -> dict:
    """Dòng ghép được nhưng nhãn in_scope=khong: CHỈ đếm, không tính precision (quyết định 23/9)."""
    theo_truong = {f: sum(1 for _, _, pr in pairs if not _empty(pr[f])) for f in CONTEXT_FIELDS}
    return {"so_dong_ghep": len(pairs),
            "co_dien_context": sum(1 for _, _, pr in pairs if any(not _empty(pr[f]) for f in CONTEXT_FIELDS)),
            "theo_truong": theo_truong}


def score_context(gold_ctx: dict[tuple[str, str], dict], pred_ctx: dict[tuple[str, str], dict],
                  catalog: AttackCatalog, literal: set[tuple[str, str]], thieu_ma_doan: int = 0,
                  trung_khoa: int = 0) -> dict:
    """P/R từng trường context, bản `du` và bản `bo_ma_co_san` (D6). Xem docstring đầu module."""
    ghep = sorted(set(gold_ctx) & set(pred_ctx))
    gv = {k: _field_values(gold_ctx[k], catalog) for k in ghep}
    pv = {k: _field_values(pred_ctx[k], catalog) for k in ghep}

    def block(keys: list[tuple[str, str]]) -> dict:
        trong = [(k, gv[k], pv[k]) for k in keys if gold_ctx[k].get("in_scope") == "co"]
        ngoai = [(k, gv[k], pv[k]) for k in keys if gold_ctx[k].get("in_scope") != "co"]
        return {"so_dong": len(trong), "truong": _field_block(trong), "ngoai_scope": _outside_scope(ngoai)}

    co_san = lambda k: (gold_ctx[k]["report"], k[1]) in literal
    return {
        "ghep": {"dong_nhan": len(gold_ctx), "dong_du_doan": len(pred_ctx) + thieu_ma_doan + trung_khoa,
                 "ghep_duoc": len(ghep), "du_doan_thieu_ma_doan": thieu_ma_doan,
                 "du_doan_trung_khoa": trung_khoa,
                 "nhan_khong_ghep_duoc": sorted(set(gold_ctx) - set(pred_ctx)),
                 "du_doan_khong_ghep_duoc": sorted(set(pred_ctx) - set(gold_ctx))},
        "du": block(ghep),
        "bo_ma_co_san": block([k for k in ghep if not co_san(k)]),
    }


def format_context(res: dict) -> str:
    f = lambda x: "-" if x is None else f"{x:.2f}"
    g = res["ghep"]
    kn = lambda tp, sai: "-" if tp + sai == 0 else f"{tp}/{tp + sai}"
    lines = [f"Ghép theo (đoạn, mã kỹ thuật): {g['ghep_duoc']}/{g['dong_nhan']} dòng nhãn "
             f"· dự đoán {g['dong_du_doan']} dòng, thiếu mã đoạn {g['du_doan_thieu_ma_doan']}, "
             f"trùng khóa {g['du_doan_trung_khoa']}",
             f"{'':<16}{'trường':<16}{'P (k/n)':>9}{'R (k/n)':>9}{'P':>6}{'R':>6}{'F1':>6}"
             f"{'trống2':>8}{'chứa':>6}"]
    for key, label in (("du", "đủ"), ("bo_ma_co_san", "bỏ mã có sẵn")):
        b = res[key]
        so_dong = b["so_dong"]
        lines.append(f"{label:<16}(in_scope=co: {so_dong} dòng)")
        for name in CONTEXT_FIELDS:
            m = b["truong"][name]
            lines.append(f"{'':<16}{name:<16}{kn(m['tp'], m['fp']):>9}{kn(m['tp'], m['fn']):>9}"
                         f"{f(m['precision']):>6}{f(m['recall']):>6}{f(m['f1']):>6}"
                         f"{m['ca_hai_trong']:>8}{m['khop_chua_them']:>6}")
        ns = b["ngoai_scope"]
        lines.append(f"{'':<16}ngoài scope: {ns['co_dien_context']}/{ns['so_dong_ghep']} dòng ghép được có điền "
                     f"context (chỉ đếm, không tính precision)")
    return "\n".join(lines)


def format_score(res: dict) -> str:
    f = lambda x: "-" if x is None else f"{x:.2f}"
    lines = [f"{'':<16}{'':<14}{'TP':>4}{'FP':>4}{'FN':>4}{'P':>7}{'R':>7}{'F1':>7}"]
    for key, label in (("du", "đủ"), ("bo_ma_co_san", "bỏ mã có sẵn")):
        b = res[key]
        rows = [("gộp", b["gop"]), ("report độc lập", b["report_doc_lap"])] + list(b["theo_report"].items())
        for name, m in rows:
            lines.append(f"{label:<16}{name:<14}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}{f(m['precision']):>7}"
                         f"{f(m['recall']):>7}{f(m['f1']):>7}")
        ri = b["recall_in_scope"]
        lines.append(f"{label:<16}{'in-scope (R)':<14}{ri['tp']:>4}{'':>4}{ri['mau_so'] - ri['tp']:>4}{'':>7}"
                     f"{f(ri['tp'] / ri['mau_so'] if ri['mau_so'] else None):>7}")
        label = ""
    return "\n".join(lines)
