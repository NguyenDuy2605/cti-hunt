"""Khâu ⑨ — hunt record theo 4 mục LOCK của D13 (Learn / Observe / Check / Keep).

"Chỉ diễn đạt lại dữ liệu đã có": bản này là renderer xác định, không gọi mô hình. Mọi con số lấy từ Contract A,
danh mục khâu ③, Contract B đã duyệt và kết quả runner. Điểm khâu ⑦ chỉ hiện khi được cung cấp cùng hash hunt;
các ô khâu ⑦/⑧ chưa có đầu vào ghi rõ là chưa có, không để trống im lặng.

HAI CHẾ ĐỘ, và đây là chỗ dễ làm hỏng cả đánh giá:
- vận hành (mặc định): thứ người duyệt đọc và dùng để quyết định pivot. KHÔNG chứa gì suy ra từ nhãn: không cột
  `buoc`, không số tấn công/FP/FPR/precision, không recall. Kết quả runner có đủ các trường đó (vì runner chạy
  trên view `labeled`), nên renderer phải lọc bỏ. Nếu người duyệt nhìn thấy nhãn, mọi quyết định pivot sau đó
  đều bị nhiễm và giá trị vòng lặp (v3 §6.2 ⑧) không còn đo được.
- đánh giá (--eval): thêm phụ lục riêng với chỉ số theo ground truth. Chỉ dùng cho báo cáo đề tài.
"""
from __future__ import annotations

import json
import re
from html import escape
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from ..contracts import ContractA, ContractB, SourceSpan
from ..integrity import sha256_file
from .s3_telemetry import map_technique
from .s7_rarity import SCORE_VERSION

PRIO = {"cao": 0, "trung_binh": 1, "thap": 2, "": 3}
LABEL_KEYS = {"buoc"}
FEEDBACK = "☐ Xác nhận đúng · ☐ Dương tính giả · ☐ Cần điều tra thêm"
MISSING_7 = "chưa có (chưa cung cấp kết quả khâu ⑦)"
MISSING_8 = "chưa có (chưa cung cấp kết quả khâu ⑧)"
NO_SOURCE = "không có tham chiếu"
EXCERPT_CHARS = 80

# Số đếm của một bộ dữ liệu trong ghi chú danh mục ③: "4697 = 18", "(716 sự kiện)", "4697 chỉ 18 sự kiện".
_PAREN_COUNT = re.compile(r"\s*\([^()]*(?:=\s*\d|\d[\d.,]*\s+sự kiện)[^()]*\)")
_COUNT = re.compile(r"=\s*\d|\d[\d.,]*\s+sự kiện|\bchỉ\s+\d")


def _md(text) -> str:
    # TaskContent là XML: phải hiện nguyên văn, không bị Markdown coi là thẻ HTML.
    value = escape(str(text if text is not None else ""), quote=False)
    return value.replace("|", "\\|").replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")


def catalog_note(text: str) -> str:
    """Ghi chú danh mục ③ khi in vào hunt record, bỏ số đếm đặc thù của bộ dữ liệu đã lập danh mục (D13 bổ sung 25/9).

    Danh mục mô tả môi trường đánh giá, còn hunt record dựng cho mọi bộ dữ liệu (kể cả OTRF phát triển): số sự kiện
    của APT29 in trên lượt chạy khác là sai. Chỉ lọc khi in; ghi chú gốc trong danh mục (đầu vào prompt ④) không đổi.
    Bỏ ngoặc chứa số đếm, rồi bỏ từng vế (tách theo dấu phẩy) còn chứa số đếm; câu rỗng thì bỏ cả câu.
    """
    kept = []
    for sentence in re.split(r"(?<=[.;])\s+", _PAREN_COUNT.sub("", text or "").strip()):
        end = sentence[-1] if sentence[-1:] in (".", ";") else ""
        parts = [p for p in (sentence[:-1] if end else sentence).split(", ") if p.strip() and not _COUNT.search(p)]
        if parts:
            kept.append(", ".join(parts).strip() + end)
    out = " ".join(kept).strip()
    out = out[:-1] + "." if out.endswith(";") else out
    return out[:1].upper() + out[1:]


def source_refs(spans: list[SourceSpan]) -> str:
    """Tham chiếu câu gốc của một giả thuyết: mã đoạn + trích ngắn, mọi span có mã đoạn hoặc câu trích."""
    refs = []
    for s in spans or []:
        text = " ".join((s.text or "").split())
        if not (s.segment_id or text):
            continue
        excerpt = text if len(text) <= EXCERPT_CHARS else text[:EXCERPT_CHARS].rstrip() + "…"
        refs.append(f"`{s.segment_id or '?'}`" + (f" “{excerpt}”" if excerpt else ""))
    return "; ".join(refs) or NO_SOURCE


def coverage(contract_a: ContractA, telemetry: dict[str, dict]) -> list[dict]:
    rows: dict[str, dict] = {}
    for t in contract_a.ttps:
        r = rows.get(t.technique_id)
        if r is None:
            m = map_technique(t.technique_id, telemetry)
            r = rows[t.technique_id] = {
                "technique_id": t.technique_id, "technique_name": t.technique_name, "status": m["status"],
                "sources": [f"{s['channel']} {s['event_ids']}" for s in m.get("sources") or []],
                "ghi_chu": m.get("ly_do") or m.get("ghi_chu") or "", "so_lan": 0, "doan": []}
        r["so_lan"] += 1
        if t.source_span.segment_id:
            r["doan"].append(t.source_span.segment_id)
    return sorted(rows.values(), key=lambda r: (("huntable", "partial", "not_huntable").index(r["status"]),
                                                r["technique_id"]))


def _final(res: dict) -> dict:
    return res["giai_doan"][-1]


def _constraint_text(d: dict) -> str:
    """Điều kiện `rang_buoc` (contracts.RangBuoc) bằng lời, đúng tham số người duyệt đã thấy ở ◆."""
    parts = []
    if d.get("dem_khac_nhau"):
        x = d["dem_khac_nhau"]
        parts.append(f"≥ {x['toi_thieu']} giá trị {x['truong']} khác nhau cùng {', '.join(x['theo'])} "
                     f"trong ±{x['cua_so_giay']} giây")
    if d.get("vang_mat"):
        x = d["vang_mat"]
        pairs = ", ".join(f"{p['ung_vien']}={p['nguon']}" for p in x["khop"])
        parts.append(f"không có {x['channel']} EID {x['event_ids']} khớp {pairs} trong {x['truoc_giay']} giây trước")
    if d.get("moc_neo"):
        x = d["moc_neo"]
        parts.append(f"sau sự kiện của {x['gia_thuyet']} không quá {x['trong_vong_giay']} giây, "
                     f"cùng {', '.join(x['cung'])}")
    return _md("; ".join(parts))


def _finding_rows(res: dict, n: int) -> tuple[list[str], list[list[str]]]:
    rows = (res.get("ket_qua_cuoi") or [])[:n]
    cols = list(dict.fromkeys(c for r in rows for c in r if c not in LABEL_KEYS))
    # Chỉ bỏ cột rỗng trong phần mẫu hiển thị; 0/False vẫn là bằng chứng có giá trị.
    cols = [c for c in cols if any(r.get(c) is not None and str(r[c]).strip() for r in rows)]
    return cols, [[_md(r.get(c)) for c in cols] for r in rows]


def render(contract_a: ContractA, telemetry: dict[str, dict], hypotheses: list[ContractB], results: list[dict],
           pivot_log: list[dict] | None = None, eval_mode: bool = False, detail_rows: int = 5,
           triage: dict | None = None, rarity: dict | None = None) -> str:
    """triage: đầu ra s8_triage.triage. Có thì mục 4–5 và dòng pivot từng phát hiện lấy từ đó (đủ dữ liệu, không
    bị cắt 300 dòng); không có thì mục 4 tính tạm trên phần chi tiết runner trả về.

    results: kết quả `runner.run` hoặc `observe.unlabeled_result` (khuôn không nhãn, chỉ dùng cho bản vận hành).
    pivot_log: mỗi vòng một dòng; `selected` (thực thể đã pivot, có `tu_gia_thuyet`) hiện ở từng phát hiện."""
    if eval_mode and any("mau_so_fpr" not in r for r in results):
        raise ValueError("--eval cần kết quả `hunt` có nhãn; kết quả không nhãn chỉ dùng cho bản vận hành")
    hyp = {h.hypothesis_id: h for h in hypotheses}
    cov = coverage(contract_a, telemetry)
    by_h: dict[str, list[dict]] = defaultdict(list)
    filter_forms, filter_refs = {}, {}
    for r in results:
        from .s8_triage import spec_from_result
        from .. import filter_approval as filters
        if r.get("filter_contract") or (r.get("hunt_file") and filters.path_policy(r["hunt_file"])):
            spec = spec_from_result(r)
            rd = spec["filter_review"]["dir"]
            if rd not in filter_forms:
                filter_forms[rd] = filters.load_form(Path(rd))
                filter_refs[rd] = spec["filter_review"]
        by_h[r["hunt"].get("hypothesis_id") or r["hunt"]["id"]].append(r)
    findings = sorted([r for r in results if _final(r)["hits"] > 0],
                      key=lambda r: (PRIO.get(getattr(hyp.get(r["hunt"].get("hypothesis_id")), "priority", ""), 3),
                                     r["hunt"].get("hypothesis_id") or "", r["hunt"]["id"]))
    status_n = {s: sum(1 for h in hypotheses if h.status == s) for s in ("approved", "rejected", "pending_review")}
    L: list[str] = []
    add = L.append
    sections: dict[str, list[str]] = {name: [] for name in ("Learn", "Observe", "Check", "Keep")}
    if filter_forms:
        rows = sections["Observe"]
        rows.append("\n### Quyết định lọc sau ⑤\n")
        rows.append("Chỉ mục approved được áp; rejected giữ ứng viên. Preview không phải kết quả thực thi.")
        rows.append("| Hunt / mục | Quyết định | Người duyệt | Lý do / căn cứ | Người chịu trách nhiệm | Hiệu lực UTC |")
        rows.append("|---|---|---|---|---|---|")
        for form in filter_forms.values():
            if not form["muc_loc"]:
                rows.append("Gói không có mục lọc; không cần quyết định lọc của người duyệt.")
            for row in form["muc_loc"]:
                rows.append(f"| {_md(row['id'])} | {row['quyet_dinh']} | {_md(form['nguoi_duyet'])} | "
                            f"{_md(row['ly_do'])} / {_md(row['can_cu'])} | {_md(row['nguoi_chiu_trach_nhiem'])} | "
                            f"{_md(row['hieu_luc_den_utc'])} |")
        # Thiết kế duyệt lọc v2 §9: Observe ghi hash gói đã áp. Hash phát hiện gói/phiếu/log bị đổi,
        # không xác thực danh tính người điền.
        rows.append("\nHash gói duyệt lọc đã áp (phát hiện gói, phiếu hoặc log bị đổi; "
                    "không xác thực danh tính người điền):\n")
        rows.append("| Gói | SHA256 manifest | SHA256 phiếu | SHA256 log duyệt | SHA256 manifest hiệu lực |")
        rows.append("|---|---|---|---|---|")
        from .. import filter_approval as filters
        for rd, ref in filter_refs.items():
            packet = Path(rd)
            log, effective = packet / "approval_log.json", packet / filters.EFFECTIVE
            form_sha = json.loads(log.read_text(encoding="utf-8"))["phieu_sha256"] if log.exists() else "chưa có"
            effective_sha = sha256_file(effective) if effective.exists() else "chưa có"
            rows.append(f"| {_md(packet.parent.parent.name + '/' + packet.name)} | {ref['manifest_sha256']} | "
                        f"{form_sha} | {ref['approval_log_sha256']} | {effective_sha} |")

    add(f"# Hunt record — {contract_a.report_id}" + (f" · {contract_a.title}" if contract_a.title else ""))
    add("")
    add("> **ĐÁNH GIÁ** — có số liệu theo ground truth ở mục 9. Không đưa bản này cho người duyệt."
        if eval_mode else "> Bản vận hành: không chứa nhãn hay số liệu suy ra từ ground truth.")
    add(f"> Sinh lúc {datetime.now().isoformat(timespec='seconds')}. Mọi con số lấy từ dữ liệu đầu vào; "
        "không có đoạn nào do mô hình ngôn ngữ viết.")

    add = sections["Learn"].append
    add("\n### Tóm tắt\n")
    st = {s: sum(1 for c in cov if c["status"] == s) for s in ("huntable", "partial", "not_huntable")}
    add(f"- TTP rút được: {len(contract_a.ttps)} dòng, {len(cov)} kỹ thuật khác nhau")
    add(f"- Độ phủ nguồn log: huntable {st['huntable']} · partial {st['partial']} · not_huntable {st['not_huntable']}")
    add(f"- Giả thuyết: {len(hypotheses)} (đã duyệt {status_n['approved']} · từ chối {status_n['rejected']} · "
        f"chờ duyệt {status_n['pending_review']})")
    add(f"- Hunt đã chạy: {len(results)} · có kết quả sau lọc: {len(findings)}")

    add("\n### Bảng độ phủ\n")
    add("| Kỹ thuật | Tên | Trạng thái | Nguồn log | Số lần / đoạn | Ghi chú |")
    add("|---|---|---|---|---|---|")
    for c in cov:
        add(f"| {c['technique_id']} | {_md(c['technique_name'])} | {c['status']} | {_md('; '.join(c['sources']) or '-')}"
            f" | {c['so_lan']} / {_md(', '.join(c['doan']) or '-')} | {_md(catalog_note(c['ghi_chu'])) or '-'} |")

    if findings:
        sections["Learn"].append("\n### Nguồn CTI theo phát hiện\n")
        sections["Observe"].append("\n### Kết quả chạy theo phát hiện\n")
    add = sections["Check"].append
    add("\n### Phát hiện\n")
    if not findings:
        add("Không hunt nào còn kết quả sau lọc.")
    for n, r in enumerate(findings, start=1):
        h = hyp.get(r["hunt"].get("hypothesis_id"))
        g0, gz = r["giai_doan"][0], _final(r)
        sc = r["hunt"]["scope"]
        hid = r["hunt"].get("hypothesis_id") or r["hunt"]["id"]
        learn_add = sections["Learn"].append
        observe_add = sections["Observe"].append
        learn_add(f"#### {hid}\n")
        learn_add(f"- **Giả thuyết:** {_md(h.behavior if h else r['hunt'].get('gia_thuyet'))}")
        learn_add(f"- **ATT&CK:** {', '.join((h.linked_ttps if h else r['hunt'].get('linked_ttps')) or []) or '-'}")
        if h and h.source_spans:
            learn_add("- **Nguồn CTI:**")
            for s in h.source_spans:
                learn_add(f"  - `{s.segment_id or '?'}` — “{_md(s.text) or '(không có câu trích)'}”")
        learn_add("")

        observe_add(f"#### {hid}\n")
        if h:
            observe_add(f"- **Phạm vi / thời gian:** {_md(h.scope)} · {_md(h.timeframe)}")
        n_scope = (r.get("mau_so_fpr") or r.get("pham_vi") or {}).get("su_kien_trong_pham_vi", "?")
        observe_add(f"- **Nguồn log:** {sc['channel']} EID {sc['event_ids']} · {n_scope} sự kiện trong phạm vi")
        removed = sum(g["removed"] for g in r["giai_doan"][1:])
        observe_add(f"- **Kết quả:** {g0['hits']} ứng viên → loại {removed} → **{gz['hits']} cần xem xét**")
        if r.get("rang_buoc"):
            observe_add(f"- **Ràng buộc nhiều sự kiện (mã thực thi, không có trong SPL):** "
                        f"{_constraint_text(r['rang_buoc']['dieu_kien'])}; "
                        f"{r['rang_buoc']['ung_vien_truoc_rang_buoc']} ứng viên trước ràng buộc → {g0['hits']}")
        observe_add("")

        add(f"#### FINDING #{n:02d} · {hid}"
            + (f" · ưu tiên {h.priority}" if h and h.priority else ""))
        add("")
        score_rows = (rarity or {}).get("su_kien", []) if (rarity or {}).get("tham_so", {}).get("version") == SCORE_VERSION else []
        scores = [x["score"] for x in score_rows
                  if x.get("hunt_id") == r["hunt"]["id"] and
                  x.get("hunt_sha256") == r.get("hunt_sha256")]
        add(f"- **Điểm độ hiếm:** cao nhất {max(scores):.4f} / 6; {len(scores)} sự kiện đã xếp hạng "
            "(chỉ ưu tiên xem xét)" if scores and len(scores) == gz["hits"]
            else f"- **Điểm độ hiếm:** {MISSING_7}")
        cols, rows = _finding_rows(r, detail_rows)
        if rows:
            add(f"- **Ví dụ** ({len(rows)}/{gz['hits']}):\n")
            add("| " + " | ".join(cols) + " |")
            add("|" + "---|" * len(cols))
            for row in rows:
                add("| " + " | ".join(row) + " |")
            add("")
        add("- **Nhận định:** chuyên viên ghi khi duyệt")
        done = [(p, v.get("vong", "")) for v in pivot_log or [] for p in v.get("selected") or []
                if hid in (p.get("tu_gia_thuyet") or [])]
        if done:
            add("- **Pivot đã chạy:** " + "; ".join(f"{p['loai']} `{_md(p['gia_tri'])}` (vòng {vong}) — "
                                                     f"{_md(p.get('ly_do'))}" for p, vong in done))
        if triage is None and not done:
            add(f"- **Pivot đề xuất:** {MISSING_8}")
        elif triage is not None:
            mine = [p for p in triage["pivot"]["de_xuat"] if hid in p["tu_gia_thuyet"]]
            if mine or not done:
                add("- **Pivot đề xuất:** " + ("; ".join(f"{p['loai']} `{_md(p['gia_tri'])}` — {_md(p['ly_do'])}, "
                                                         "chờ duyệt" for p in mine)
                                               or "không (chưa thực thể nào vượt ngưỡng)"))
        add("- **Verdict:**")
        add(f"- **Phiếu phản hồi:** {FEEDBACK}")
        add("")

    add("### Bản đồ tương quan\n")
    if triage is not None:
        _triage_sections(add, triage)
    seen: dict[tuple[str, str], set[str]] = defaultdict(set)
    truncated = []
    for r in (findings if triage is None else []):
        fid = r["hunt"].get("hypothesis_id") or r["hunt"]["id"]
        rows = r.get("ket_qua_cuoi") or []
        if len(rows) < _final(r)["hits"]:
            truncated.append(fid)
        for row in rows:
            if row.get("ev_host"):
                seen[("máy", str(row["ev_host"]))].add(fid)
            for k in ("User", "SubjectUserName", "TargetUserName"):
                if row.get(k):
                    seen[("tài khoản", str(row[k]))].add(fid)
    multi = sorted(((k, v) for k, v in seen.items() if len(v) >= 2), key=lambda kv: (-len(kv[1]), kv[0]))
    if triage is not None:
        pass
    elif multi:
        add("| Loại | Thực thể | Số phát hiện | Phát hiện |")
        add("|---|---|---|---|")
        for (kind, ent), fids in multi:
            add(f"| {kind} | {_md(ent)} | {len(fids)} | {', '.join(sorted(fids))} |")
    else:
        add("Không có máy hay tài khoản nào xuất hiện ở từ hai phát hiện trở lên.")
    if truncated:
        add(f"\n_Lưu ý: chi tiết của {', '.join(truncated)} bị cắt theo giới hạn của runner, "
            "bảng trên chỉ tính trên phần chi tiết có._")

    add("\n### Nhật ký vòng lặp\n")
    if triage is not None and not pivot_log:
        pivot_log = [triage["nhat_ky_vong"]]
    if pivot_log:
        add("| Vòng | Giả thuyết | Độ sâu | Thực thể pivot | Quyết định / lý do dừng |")
        add("|---|---|---|---|---|")
        for p in pivot_log:
            targets = ", ".join(f"{x['loai']}={x['gia_tri']}" for x in p.get("selected") or []) or "—"
            add(f"| {p.get('vong', '')} | {_md(p.get('hypothesis_id') or str(p.get('so_de_xuat', '')) + ' đề xuất')} | "
                f"{p.get('pivot_depth', '')} | {_md(targets)} | {_md(p.get('ly_do_dung'))} |")
    else:
        add(f"Chưa có vòng pivot — {MISSING_8}.")

    add = sections["Keep"].append
    add("\n### Khoảng trống quan sát\n")
    gaps = [c for c in cov if c["status"] != "huntable"]
    if gaps:
        add("| Kỹ thuật | Tên | Trạng thái | Ghi chú nguồn log |")
        add("|---|---|---|---|")
        for c in gaps:
            add(f"| **{c['technique_id']}** | {_md(c['technique_name']) or '-'} | {c['status']} | "
                f"{_md(catalog_note(c['ghi_chu'])) or 'không có ghi chú'} |")
    else:
        add("Mọi kỹ thuật rút được đều huntable.")

    add = sections["Observe"].append
    add("\n### Nhật ký lọc\n")
    for r in results:
        rid = r["hunt"].get("hypothesis_id") or r["hunt"]["id"]
        add(f"**{rid}** — {r['hunt']['id']}\n")
        add("| Giai đoạn | Còn lại | Bị loại | Lý do | Chịu trách nhiệm | Nguồn mục lọc |")
        add("|---|---|---|---|---|---|")
        add(f"| {r['giai_doan'][0]['stage']} | {r['giai_doan'][0]['hits']} | - | điều kiện sinh ứng viên | - | - |")
        for g, f in zip(r["giai_doan"][1:], r.get("muc_loc") or []):
            add(f"| {g['stage']} | {g['hits']} | {g['removed']} | {_md(f.get('ly_do'))} | "
                f"{_md(f.get('nguoi_chiu_trach_nhiem'))} | {f.get('nguon') or 'viết tay'} |")
        add("")
    ran = set(by_h)
    waiting = [h.hypothesis_id for h in hypotheses if h.status == "approved" and h.hypothesis_id not in ran]
    if waiting:
        add(f"Giả thuyết đã duyệt nhưng chưa chạy: {', '.join(waiting)}\n")

    add = sections["Learn"].append
    add("\n### Giả thuyết\n")
    add("| ID | Trạng thái | Xuất phát | Pivot | Nguồn log | ATT&CK | Hành vi | Nguồn CTI |")
    add("|---|---|---|---|---|---|---|---|")
    for h in hypotheses:
        target = f"{h.pivot_kind}={h.pivot_value} (sâu {h.pivot_depth})" if h.origin == "pivot" else "—"
        add(f"| {h.hypothesis_id} | {h.status} | {h.origin} | {_md(target)} | "
            f"{h.evidence.data_source} EID {h.evidence.event_ids} | "
            f"{', '.join(h.linked_ttps)} | {_md(h.behavior)} | {_md(source_refs(h.source_spans))} |")
    add = sections["Observe"].append
    add("\n### Truy vấn đã chạy\n")
    for r in results:
        q = r.get("truy_van") or {}
        add(f"**{r['hunt']['id']}** · `{r.get('hunt_file') or '-'}` · sha256 `{(r.get('hunt_sha256') or '-')[:16]}`\n")
        add("```sql")
        sc = r["hunt"].get("scope") or {}
        add(f"-- phạm vi: {sc.get('channel')} EID {sc.get('event_ids')}"
            + (f" · máy {', '.join(map(str, sc['hosts']))}" if sc.get("hosts") else ""))
        add(f"-- ứng viên\n{q.get('candidates', '(không có trong kết quả runner)').strip()}")
        for f in q.get("filters") or []:
            add(f"-- loại trừ {f['id']}\n{f['where'].strip()}")
        add("```\n")

    eval_lines: list[str] = []
    add = eval_lines.append
    if eval_mode:
        add("## 9. Đánh giá theo ground truth (không đưa cho người duyệt)\n")
        for r in results:
            m = r["mau_so_fpr"]
            add(f"**{r['hunt']['id']}** — mẫu số FPR {m['am_tinh']} (= {m['su_kien_trong_pham_vi']} trong phạm vi − "
                f"{m['su_kien_tan_cong']} tấn công)\n")
            add("| Giai đoạn | Còn lại | Tấn công | FP | FPR | Precision | Loại nhầm | Bước còn lại |")
            add("|---|---|---|---|---|---|---|---|")
            for g in r["giai_doan"]:
                fpr = "-" if g["fpr"] is None else f"{g['fpr']:.2%}"
                pr = "-" if g["precision"] is None else f"{g['precision']:.2%}"
                steps = ", ".join(f"{k}×{v}" for k, v in g["steps"].items()) or "-"
                add(f"| {g['stage']} | {g['hits']} | {g['attacker_events']} | {g['fp']} | {fpr} | {pr} | "
                    f"{g['removed_attacker']} | {steps} |")
            rec = r.get("recall_theo_buoc") or {}
            for label, key in (("tất cả report", "tat_ca_report"), ("report độc lập", "report_doc_lap")):
                b = rec.get(key)
                if b:
                    add(f"\nTP recall theo bước [{label}]: " + " · ".join(
                        f"{n} {b[n]['phat_hien']}/{b[n]['mau_so']}" for n in ("tuyet_doi", "tran_dau_vao", "tran_thuc_te")))
            add("")
    for name, lines in sections.items():
        L.append(f"\n## {name}\n")
        L.extend(lines)
    L.extend(eval_lines)
    return "\n".join(L).rstrip() + "\n"


def _triage_sections(add, tr: dict) -> None:
    multi = [e for e in tr["thuc_the"] if e["so_gia_thuyet"] >= 2]
    if multi:
        add("| Loại | Thực thể | Số giả thuyết | Số nguồn log | Số sự kiện | Giả thuyết | Khoảng thời gian |")
        add("|---|---|---|---|---|---|---|")
        for e in multi:
            add(f"| {e['loai']} | {_md(e['gia_tri'])} | {e['so_gia_thuyet']} | {e['so_nguon_log']} | {e['so_su_kien']} | "
                f"{', '.join(e['gia_thuyet'])} | {e['dau_tien']} → {e['cuoi_cung']} |")
    else:
        add("Không có máy hay tài khoản nào khớp từ hai giả thuyết trở lên.")
    if tr["cum_thoi_gian"]:
        add(f"\nCụm thời gian (cùng máy, cửa sổ {tr['tham_so']['time_window_minutes']} phút, từ 2 giả thuyết trở lên — "
            "không nối giữa các máy):\n")
        add("| Máy | Từ | Đến | Giả thuyết | Sự kiện | Tiến trình |")
        add("|---|---|---|---|---|---|")
        for c in tr["cum_thoi_gian"]:
            add(f"| {c['may']} | {c['bat_dau']} | {c['ket_thuc']} | {', '.join(c['gia_thuyet'])} | {c['so_su_kien']} | "
                f"{_md(', '.join(c['tien_trinh']))} |")
    if tr["loai_tru"]:
        add("\nThực thể không làm ứng viên pivot: " + "; ".join(
            f"`{_md(e['gia_tri'])}` ({e['so_gia_thuyet']} giả thuyết) — {_md(e['ly_do'])}" for e in tr["loai_tru"]))
    p = tr["pivot"]
    if p["chua_xet"]:
        add(f"\nỨng viên chưa được xét do trần: " + ", ".join(f"{x['loai']} `{_md(x['gia_tri'])}`" for x in p["chua_xet"]))
