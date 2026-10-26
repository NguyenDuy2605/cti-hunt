"""Rule cộng đồng SigmaHQ theo TTP của report (15/10): chọn, biên dịch, đếm trên log; không nhãn, không gọi mô hình.

Câu hỏi của một SOC: report nêu TTP nào thì bật rule cộng đồng cho TTP đó, cần gì mô hình viết rule? Mô-đun này dựng phần
"rule cộng đồng" của công cụ lai: với mỗi TTP mà khâu ② rút từ report, lấy mọi rule SigmaHQ trạng thái stable/test có tag kỹ
thuật trùng chính xác (cùng quy tắc chọn của G0(c), `eval/g0c.py`: không mở rộng cha/con, không chọn theo tactic), biên dịch
qua cùng adapter DuckDB của khâu ⑤ (khối `filter_*` của rule cộng đồng giữ làm mục lọc), rồi đếm trên `events`.
Kết quả chỉ để người săn xem cạnh hunt hệ thống sinh; không vào cổng duyệt, không đổi lượt săn.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from .. import config
from ..adapters import duckdb_sigma
from ..eval import g0c

VERSION = "rule_cong_dong_v1"
SIGMAHQ = "data/work/sigmahq"          # bản ghim trong docs/METHODOLOGY.md (commit d1c16224…, rules/windows)


@lru_cache(maxsize=2)
def _index(root: str) -> tuple:
    metas, errors = g0c.index_rules(Path(root))
    return tuple(metas), tuple(e["relative_path"] for e in errors)


def techniques(contract) -> list[str]:
    return sorted({t.technique_id.strip().lower() for t in contract.ttps if t.technique_id})


def select(ttps: list[str], root: str | Path = SIGMAHQ) -> list[dict]:
    """Rule stable/test có tag kỹ thuật trùng chính xác ít nhất một TTP của report."""
    metas, _ = _index(str(config.resolve(root)))
    wanted = {t.lower() for t in ttps}
    return [m for m in metas if m["status"] in g0c.STATUSES and wanted & set(m["techniques"])]


def compile_selected(selected: list[dict], columns: set[str], root: str | Path = SIGMAHQ,
                     catalog_path: str = "configs/logsource_catalog.yaml") -> tuple[list[dict], list[dict]]:
    """Hunt spec của các rule đã chọn trên những nguồn log có trong danh mục; rule không dịch được ghi lý do."""
    base = config.resolve(root)
    catalog = duckdb_sigma.load_catalog(config.resolve(catalog_path))
    specs, skipped = [], []
    for m in selected:
        try:
            level = str((yaml.safe_load((base / m["relative_path"]).read_text(encoding="utf-8")) or {}).get("level") or "")
            hunts, skip = duckdb_sigma.compile_rule(base / m["relative_path"], catalog, columns)
        except Exception as e:  # noqa: BLE001 — rule cộng đồng dùng cú pháp adapter chưa hỗ trợ: ghi lại, không đoán
            skipped.append({"rule": m["relative_path"], "ly_do": f"{type(e).__name__}: {str(e)[:120]}"})
            continue
        skipped += [{"rule": m["relative_path"], "ly_do": s.ly_do} for s in skip]
        for h in hunts:
            spec = h.to_hunt_spec()
            spec.update(id=f"sigmahq__{Path(m['relative_path']).stem}__{h.source}",
                        nguon_rule={"sigmahq": m["relative_path"], "title": m["title"], "id": m["id"],
                                    "level": level.lower(), "techniques": [t for t in m["techniques"]]})
            specs.append(spec)
    return specs, skipped


HIGH = ("high", "critical")
# Ưu tiên khoảng trống (15/10): TTP không có rule cộng đồng mức cao được cộng điểm liên quan để hệ thống sinh hunt trước.
GAP_BONUS = {"khong_co_rule": 40, "thap": 20, "cao": 0}


@lru_cache(maxsize=4096)
def _level(path: str) -> str:
    try:
        return str((yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}).get("level") or "").lower()
    except (OSError, yaml.YAMLError):
        return ""


def coverage(ttps: list[str], channels: set[str], root: str | Path = SIGMAHQ,
             catalog_path: str = "configs/logsource_catalog.yaml") -> dict[str, dict]:
    """Trạng thái phủ của rule cộng đồng cho từng TTP, chỉ từ metadata (không biên dịch, không đếm sự kiện): rule
    stable/test có tag trùng chính xác và logsource ánh xạ được tới một channel có trong bộ log. `cao` = có rule mức
    high/critical; `thap` = chỉ rule mức thấp hơn; `khong_co_rule` = không có rule nào dùng được."""
    base = config.resolve(root)
    metas, _ = _index(str(base))
    catalog = duckdb_sigma.load_catalog(config.resolve(catalog_path))
    have = {c.lower() for c in channels}
    out = {}
    for t in sorted({x.lower() for x in ttps}):
        usable = []
        for m in metas:
            if m["status"] not in g0c.STATUSES or t not in m["techniques"]:
                continue
            ls = m["logsource"]
            key = ls.get("category") or (f"service:{ls['service']}" if ls.get("service") else None)
            if any(str(s.get("channel", "")).lower() in have for s in catalog.get(key or "", [])):
                usable.append(m)
        high = [m for m in usable if _level(str(base / m["relative_path"])) in HIGH]
        out[t] = {"muc": "cao" if high else "thap" if usable else "khong_co_rule",
                  "so_rule_cao": len(high), "so_rule": len(usable)}
    return out


def render_coverage(cov: dict[str, dict]) -> str:
    """Hunt record: TTP nào bật rule cộng đồng, TTP nào là khoảng trống hệ thống ưu tiên săn."""
    if not cov:
        return ""
    rows = ["### Rule cộng đồng và khoảng trống (ưu tiên khoảng trống)", "",
            "TTP có rule SigmaHQ mức high/critical dùng được trên log: bật rule cộng đồng (lệnh community-rules, tab 3). TTP "
            "không có hoặc chỉ có rule mức thấp: khoảng trống, hệ thống ưu tiên sinh hunt. Chỉ từ metadata rule, không nhãn.", "",
            "| TTP | Rule cộng đồng high/critical | Mọi mức | Xử lý |", "|---|---:|---:|---|"]
    for t, v in sorted(cov.items(), key=lambda x: (GAP_BONUS[x[1]["muc"]] * -1, x[0])):
        todo = "bật rule cộng đồng" if v["muc"] == "cao" else "khoảng trống: hệ thống ưu tiên sinh hunt"
        rows.append(f"| {t.upper()} | {v['so_rule_cao']} | {v['so_rule']} | {todo} |")
    return "\n".join(rows)


def count(con, spec: dict) -> dict:
    from ..hunt import runner
    scope = runner._scope_where(spec["scope"])
    where = [scope, f"({spec['candidates']})"]
    total = con.execute(f"SELECT count(*) FROM events WHERE {scope}").fetchone()[0]
    cand = con.execute(f"SELECT count(*) FROM events WHERE {' AND '.join(where)}").fetchone()[0]
    final = " AND ".join(where + [f"({f['where']}) IS NOT TRUE" for f in spec.get("filters") or []])
    kept = con.execute(f"SELECT count(*) FROM events WHERE {final}").fetchone()[0]
    return {"pham_vi": total, "ung_vien": cand, "cuoi": kept}


def run(con, contract, root: str | Path = SIGMAHQ, levels: tuple | None = None) -> dict:
    """Chọn, biên dịch, đếm. Rule lỗi cột ở bộ log này ghi `loi`, không bỏ im lặng. `levels`: chỉ giữ rule các mức này
    (trong lượt săn dùng high+critical, vì mức thấp hơn báo nhầm nhiều)."""
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    ttps = techniques(contract)
    selected = select(ttps, root)
    if levels:
        selected = [m for m in selected if _level(str(config.resolve(root) / m["relative_path"])) in levels]
    specs, skipped = compile_selected(selected, columns, root)
    rows = []
    for spec in specs:
        try:
            c = count(con, spec)
        except Exception as e:  # noqa: BLE001
            c = {"loi": f"{type(e).__name__}"}
        rows.append({"hunt": spec["id"], **spec["nguon_rule"], "kenh": spec["scope"]["channel"],
                     "eid": spec["scope"]["event_ids"], **c})
    return {"version": VERSION, "ttp": ttps, "so_rule_chon": len(selected), "so_hunt": len(specs),
            "muc": list(levels) if levels else None, "khong_dich_duoc": skipped, "rule": rows,
            "co_ket_qua": sum(1 for r in rows if r.get("cuoi"))}


def render(result: dict, title: str = "### Rule cộng đồng SigmaHQ theo TTP của report (chỉ để xem)") -> str:
    rows = sorted(result["rule"], key=lambda r: -(r.get("cuoi") or 0))
    out = [title, "",
           f"{result['so_rule_chon']} rule SigmaHQ (stable/test) có tag trùng {len(result['ttp'])} TTP; {result['so_hunt']} hunt "
           f"dịch được trên log này, {result['co_ket_qua']} có kết quả; {len(result['khong_dich_duoc'])} trường hợp không dịch "
           f"được ({VERSION}). Số là số sự kiện trên bộ log của lượt, không nhãn.", "",
           "| Rule | Mức | Kỹ thuật | Nguồn | Trong phạm vi | Sau mục lọc của rule |", "|---|---|---|---|---:|---:|"]
    for r in rows[:40]:
        cell = "lỗi cột" if "loi" in r else str(r["cuoi"])
        out.append(f"| {r['title']} | {r.get('level', '')} | {', '.join(r['techniques'])} | {r['kenh']} {r['eid']} | "
                   f"{r.get('pham_vi', '—')} | {cell} |")
    if len(rows) > 40:
        out.append(f"| … còn {len(rows) - 40} rule | | | | | |")
    return "\n".join(out)
