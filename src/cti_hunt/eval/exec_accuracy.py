"""Execution accuracy cho khâu ⑤ (v3 §6.2): chạy rule sinh ra và rule chuẩn trên cùng dữ liệu, so tập kết quả.

Chỉ số này tách hai loại lỗi hay bị trộn: giả thuyết sai (khâu ④) và giả thuyết đúng nhưng rule sai (khâu ⑤).
Rule chuẩn là rule SigmaHQ tương ứng kỹ thuật, hoặc truy vấn viết tay ở nhánh A.

Không dùng nhãn: chỉ so hai tập khóa sự kiện (ev_host, ev_channel, ev_rec), nên chạy được bất cứ lúc nào có
events.parquet. Precision/recall ở đây là của rule sinh ra SO VỚI rule chuẩn, không phải so với ground truth.

Chỉ so khi hai bên cùng phạm vi (channel, event_ids, hosts, thời gian): khác nguồn log thì hai tập không cùng
không gian, Jaccard vô nghĩa — trả về lý do thay vì con số.

So ở hai giai đoạn: `ung_vien` (chỉ điều kiện sinh ứng viên) và `cuoi` (sau mọi mục loại trừ). Rule sinh đúng
ứng viên nhưng sai khối lọc sẽ lộ ra ở chỗ hai giai đoạn cho số khác nhau.
"""
from __future__ import annotations

import duckdb

from ..hunt.runner import _scope_where

KEY = ("ev_host", "ev_channel", "ev_rec")


def _scope_sig(spec: dict) -> tuple:
    sc = spec["scope"]
    return (str(sc["channel"]).lower(), tuple(sorted(int(e) for e in sc["event_ids"])),
            tuple(sorted(h.upper() for h in sc.get("hosts") or [])),
            sc.get("time_from") or None, sc.get("time_to") or None)


def same_scope(a: dict, b: dict) -> bool:
    return _scope_sig(a) == _scope_sig(b)


def result_keys(con: duckdb.DuckDBPyConnection, spec: dict) -> dict[str, set[tuple]]:
    """Tập khóa sự kiện ở giai đoạn ứng viên và sau lọc. Chạy trên view `events`, không nhìn nhãn."""
    from ..filter_approval import require_executable
    require_executable(spec, con=con)
    base = f"SELECT {', '.join(KEY)} FROM events WHERE {_scope_where(spec['scope'])}"
    cand = set(con.execute(f"{base} AND ({spec['candidates']})").fetchall())
    removed: set[tuple] = set()
    for f in spec.get("filters") or []:
        removed |= set(con.execute(f"{base} AND ({spec['candidates']}) AND ({f['where']})").fetchall())
    return {"ung_vien": cand, "cuoi": cand - removed}


def compare(ref: set, gen: set, sample: int = 10) -> dict:
    both = ref & gen
    union = ref | gen
    return {
        "chuan": len(ref), "sinh": len(gen), "chung": len(both),
        "chi_chuan": len(ref - gen), "chi_sinh": len(gen - ref),
        "jaccard": len(both) / len(union) if union else None,
        "precision": len(both) / len(gen) if gen else None,     # phần kết quả rule sinh có trong rule chuẩn
        "recall": len(both) / len(ref) if ref else None,        # phần kết quả rule chuẩn mà rule sinh bắt được
        "vi_du_chi_chuan": [list(k) for k in sorted(ref - gen)[:sample]],
        "vi_du_chi_sinh": [list(k) for k in sorted(gen - ref)[:sample]],
    }


def evaluate(con: duckdb.DuckDBPyConnection, ref_spec: dict, gen_spec: dict) -> dict:
    out = {"chuan": ref_spec.get("id"), "sinh": gen_spec.get("id"),
           "pham_vi": dict(zip(("channel", "event_ids", "hosts", "time_from", "time_to"), _scope_sig(ref_spec)))}
    if not same_scope(ref_spec, gen_spec):
        out["so_duoc"] = False
        out["ly_do"] = (f"khác phạm vi: chuẩn {_scope_sig(ref_spec)} · sinh {_scope_sig(gen_spec)}. "
                        "So trên hai nguồn log khác nhau thì tập kết quả không cùng không gian.")
        return out
    r, g = result_keys(con, ref_spec), result_keys(con, gen_spec)
    out["so_duoc"] = True
    out["giai_doan"] = {st: compare(r[st], g[st]) for st in ("ung_vien", "cuoi")}
    return out


def evaluate_union(con: duckdb.DuckDBPyConnection, ref_specs: list[dict], gen_spec: dict) -> dict:
    """G0(c): so với hợp tập các rule chuẩn ĐÃ CHỌN, tách từng giai đoạn; không chọn chuẩn theo kết quả.

    Mọi chuẩn phải cùng phạm vi với hunt sinh. Không có chuẩn/khác phạm vi thì không chạy truy vấn hay tính điểm.
    Việc chọn metadata SigmaHQ và ghim danh sách chuẩn thực hiện trước theo docs/METHODOLOGY.md.
    """
    out = {"chuan": " ∪ ".join(str(r.get("id")) for r in ref_specs) or "không có chuẩn",
           "sinh": gen_spec.get("id"), "cach_gop": "hop_tap",
           "pham_vi": dict(zip(("channel", "event_ids", "hosts", "time_from", "time_to"), _scope_sig(gen_spec)))}
    if not ref_specs:
        return {**out, "so_duoc": False, "ly_do": "không có chuẩn"}
    different = [r.get("id") for r in ref_specs if not same_scope(r, gen_spec)]
    if different:
        return {**out, "so_duoc": False, "ly_do": f"khác phạm vi: {different}; không hợp tập khác nguồn/phạm vi"}
    union = {stage: set() for stage in ("ung_vien", "cuoi")}
    for ref in ref_specs:
        keys = result_keys(con, ref)
        for stage in union:
            union[stage].update(keys[stage])
    gen = result_keys(con, gen_spec)
    return {**out, "so_duoc": True,
            "giai_doan": {stage: compare(union[stage], gen[stage]) for stage in union}}


def format_summary(res: dict) -> str:
    head = f"{res['chuan']}  vs  {res['sinh']}"
    if not res["so_duoc"]:
        return f"{head}\n  KHÔNG SO: {res['ly_do']}"
    fmt = lambda x: "-" if x is None else f"{x:.3f}"
    lines = [head, f"  {'giai đoạn':<10}{'chuẩn':>7}{'sinh':>7}{'chung':>7}{'Jaccard':>9}{'P':>7}{'R':>7}"]
    for st, c in res["giai_doan"].items():
        lines.append(f"  {st:<10}{c['chuan']:>7}{c['sinh']:>7}{c['chung']:>7}{fmt(c['jaccard']):>9}"
                     f"{fmt(c['precision']):>7}{fmt(c['recall']):>7}")
    return "\n".join(lines)
