"""Small UI service layer. Immutable report/run folders, no evaluation data."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from . import approval, config, integrity
from .agent import session, dev_data
from .contracts import ContractA
from .hunt import runner
from .stages import s1_ingest, s2_report


def inside(path: Path, root: Path) -> Path:
    path, root = path.resolve(), root.resolve()
    if path == root or not path.is_relative_to(root):
        raise ValueError("Đường dẫn phải nằm trong thư mục đã chọn")
    return path


def report_folder(report_id: str, root: Path | None = None) -> Path:
    root = root or config.ROOT / "data/reports/moi"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", report_id):
        raise ValueError("Mã report chỉ gồm chữ ASCII, số, gạch ngang/gạch dưới (1–80 ký tự)")
    return inside(root / report_id, root)


def ingest(source: str, report_id: str, selector: str = "", root: Path | None = None) -> Path:
    folder = report_folder(report_id, root)
    if folder.exists():
        raise ValueError("Mã report đã tồn tại; chọn mã mới hoặc mở bản đã có. Dữ liệu cũ được giữ nguyên")
    s1_ingest.ingest(source, report_id, folder, selector.strip() or None)
    return folder


def new_run(parent: Path, prefix: str) -> Path:
    return inside(parent / f"{prefix}_{uuid.uuid4().hex}", parent)


def ocr_bundle(bundle: Path, *, engine=None) -> Path:
    """H4 (12/10): OCR cục bộ từ UI, không gọi API. Kết quả là thư mục report mới `<tên>-ocr` cạnh bản gốc; bản gốc giữ
    nguyên. Chữ OCR chưa rà không vào TTP/IOC (cổng ở `s1_ingest.extraction_ready`)."""
    from .stages import s1_ocr
    out = report_folder(f"{bundle.name}-ocr", bundle.parent)
    s1_ocr.enrich(bundle, out, engine=engine)
    return out


def ocr_review(bundle: Path) -> dict | None:
    """Mẫu phiếu rà OCR của bundle, mỗi đoạn kèm đường dẫn ảnh để đối chiếu; None khi không còn đoạn nào chờ rà."""
    path = bundle / "ocr_review_template.json"
    if not path.is_file():
        return None
    form = json.loads(path.read_text(encoding="utf-8"))
    if not form.get("decisions"):
        return None
    _, _, provenance = s1_ingest.load_bundle(bundle)
    for d in form["decisions"]:
        d["image"] = str(inside(bundle / provenance[d["segment_id"]]["image_file"], bundle))
    return form


def ocr_apply(bundle: Path, reviewer: str, choices: dict[str, dict]) -> Path:
    """Ghi phiếu người dùng vừa điền theo đúng định dạng của lệnh `review-ocr`, rồi áp vào thư mục report mới `<tên>-ra`.

    Mọi kiểm tra (tên người rà, lý do, bản chép không trống, hash ảnh, ít nhất một quyết định) do `s1_ocr.apply_review`
    làm. Đoạn không được chọn vẫn là `pending`; không có chấp nhận tự động."""
    from datetime import datetime, timezone
    from .stages import s1_ocr
    form = json.loads((bundle / "ocr_review_template.json").read_text(encoding="utf-8"))
    if set(choices) - {d["segment_id"] for d in form["decisions"]}:
        raise ValueError("Quyết định chứa mã đoạn không thuộc phiếu OCR")
    for d in form["decisions"]:
        choice = choices.get(d["segment_id"], {})
        d.update(status=choice.get("status") or "pending", text=choice.get("text", d["text"]),
                 reason=str(choice.get("reason", "")).strip())
    form.update(reviewer=reviewer.strip(), reviewed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    out = report_folder(f"{bundle.name}-ra", bundle.parent)
    if out.exists():
        raise ValueError("Đã có bản sau rà của bundle này; bản cũ được giữ nguyên")
    review = new_run(bundle.parent.parent / "tmp_uploads", "ocr_review")
    review.mkdir(parents=True)
    s1_ingest.write_json(review / "review.json", form)
    s1_ocr.apply_review(bundle, review / "review.json", out)
    return out


def extraction_cost(bundle: Path, extraction: Path | None = None) -> dict | None:
    """Preview before the UI send button; no output files or API/ledger access."""
    if extraction is not None:
        extraction = inside(extraction, bundle)
        meta = json.loads((extraction / "meta.json").read_text(encoding="utf-8"))
        if "uoc_tinh_chi_phi" in meta:
            return meta["uoc_tinh_chi_phi"]
        # Old metadata stays untouched; estimate from its own saved requests/config.
        requests = json.loads((extraction / "requests.json").read_text(encoding="utf-8"))
        return s2_report.estimate_cost(requests, meta["llm_config"])
    rp = config.load("reports")
    stix = config.resolve(rp["attack"]["stix_path"])
    if integrity.sha256_file(stix) != rp["attack"]["stix_sha256"]:
        raise ValueError("ATT&CK khác bản đã ghim")
    llm_config = config.load("llm_hunt")
    _, requests = s2_report.prepare(bundle, stix, config.resolve("prompts/report_extract_v1.md"), llm_config)
    return s2_report.estimate_cost(requests, llm_config)


def extraction_noise(bundle: Path, extraction: Path | None = None) -> str | None:
    """H3 (12/10): dòng báo số đoạn không gửi khâu ②; chỉ đọc. Lượt đã lưu lấy từ meta của chính nó (lượt trước H3
    không có mục này), chưa có lượt thì tính từ bundle."""
    if extraction is not None:
        meta = json.loads((inside(extraction, bundle) / "meta.json").read_text(encoding="utf-8"))
        return s2_report.noise_summary(meta.get("khong_gui_khau2"))
    marks = s2_report.noise_marks(*s1_ingest.load_bundle(bundle))
    return s2_report.noise_summary(s2_report.marked_meta(marks)) if marks else None


def extract(bundle: Path, out: Path, *, send: bool, resume: bool, accept_partial: bool) -> dict:
    rp = config.load("reports")
    stix = config.resolve(rp["attack"]["stix_path"])
    if integrity.sha256_file(stix) != rp["attack"]["stix_sha256"]:
        raise ValueError("ATT&CK khác bản đã ghim")
    from .stages import s2_ioc
    return s2_report.run(bundle, stix, config.resolve("prompts/report_extract_v1.md"),
                         config.load("llm_hunt"), out,
                         s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml")),
                         send=send, resume=resume, accept_partial=accept_partial)


def verified_contract(bundle: Path, extraction: Path) -> Path:
    manifest, segments, prov = s1_ingest.load_bundle(bundle)
    meta = json.loads((extraction / "meta.json").read_text(encoding="utf-8"))
    if meta.get("status") != "complete":
        raise ValueError("Khâu trích chưa hoàn tất")
    if meta.get("bundle_manifest_sha256") != integrity.sha256_file(bundle / "manifest.json"):
        raise ValueError("Bundle không còn khớp lượt trích; cần snapshot đúng hoặc lượt mới")
    path = extraction / "contract_a.json"
    if meta.get("contract_a_sha256") != integrity.sha256_file(path):
        raise ValueError("Contract A đã thay đổi")
    from . import saved_extraction
    if meta.get("version") == saved_extraction.VERSION:
        saved_extraction.verify(bundle, extraction, meta)
        return path
    ca = ContractA.model_validate_json(path.read_text(encoding="utf-8"))
    if ca.report_id != manifest["report_id"]:
        raise ValueError("Contract A sai report")
    by_id = {s["ma_doan"]: s for s in segments}
    for t in ca.ttps:
        s = by_id.get(t.source_span.segment_id)
        if (not s or not s1_ingest.extraction_ready(s, prov) or not t.source_span.text.strip()
                or t.source_span.text not in s["van_ban"]):
            raise ValueError("TTP thiếu bằng chứng nguyên văn ở phần nguồn được phép sử dụng")
    return path


def saved_options() -> dict:
    entries = config.load("saved_extractions")
    return {key: {**entry, **{field: config.resolve(entry[field], config.ROOT)
                            for field in ("contract", "metadata", "segments")}}
            for key, entry in entries.items()}


def saved_options_for(title: str, saved: dict | None = None) -> dict:
    """Q2 (09/10): chỉ kết quả trích đã lưu của đúng report đang mở (tiêu đề chứa `source_title_contains`)."""
    saved = saved_options() if saved is None else saved
    return {key: entry for key, entry in saved.items()
            if entry.get("source_title_contains") and entry["source_title_contains"].casefold() in title.casefold()}


def selection_alerts(manifest: dict) -> list[dict]:
    """H1 (10/10): cảnh báo có thể đã đọc nhầm vùng nội dung; UI hiện riêng, không lẫn vào cảnh báo ảnh chưa đọc."""
    return [w for w in manifest.get("warnings") or [] if w.get("code") in s1_ingest.SELECTION_ALERTS]


def report_label(folder: Path) -> str:
    """Q5 (09/10): mã thư mục kèm tiêu đề report trong manifest; manifest lỗi thì chỉ hiện mã."""
    try:
        title = json.loads((folder / "manifest.json").read_text(encoding="utf-8")).get("title") or ""
    except (OSError, ValueError):
        title = ""
    return f"{folder.name} — {title}" if title else folder.name


def memory_note(search_root: Path, version: str) -> str:
    """Q3 (09/10): kho mà ô tra cứu tìm và kho mà planner của phiên bản đang chọn đọc — có thể là hai kho khác nhau."""
    planner_root = config.resolve(config.agent_config(version).get("memory_root", "data/reports/moi"), config.ROOT)

    def shown(p: Path) -> str:
        p = p.resolve()
        return p.relative_to(config.ROOT.resolve()).as_posix() if p.is_relative_to(config.ROOT.resolve()) else str(p)

    if planner_root.resolve() == search_root.resolve():
        return f"Tìm trong {shown(search_root)} — cũng là kho planner {version} đọc."
    return (f"Tìm trong {shown(search_root)} (record của các lượt chạy trên giao diện). Planner {version} đọc kho khác: "
            f"{shown(planner_root)}, nên record ở đây không đi vào planner.")


def markdown_safe(text: str) -> str:
    """Q7 (09/10): Streamlit coi `$…$` là công thức; thoát `$` khi hiển thị, tệp gốc giữ nguyên."""
    return text.replace("$", "\\$")


def reuse_saved(bundle: Path, entry: dict) -> Path:
    from .saved_extraction import import_saved
    out = new_run(bundle / "extractions", "extract")
    import_saved(bundle, out, entry)
    return out


def dataset(folder: Path) -> dict:
    inside(folder, config.ROOT / "data/dev")
    m = json.loads((folder / "ingest_manifest.json").read_text(encoding="utf-8"))
    if m.get("dataset_kind") != "otrf_dev":
        raise ValueError("Demo chỉ dùng bộ OTRF phát triển đã kiểm E1")
    dev_data.check_manifest(folder, m["dataset_id"], m["source_sha256"])
    return m


def start(bundle: Path, extraction: Path, events: Path, run: Path, *, mode: str, dry_run: bool, version: str = "v1") -> dict:
    ca = verified_contract(bundle, extraction)
    m = dataset(events)
    result = session.start(mode, ca, events, run, dataset_kind="otrf_dev", dataset_id=m["dataset_id"],
                           dataset_sha256=m["source_sha256"], dry_run=dry_run,
                           **({"version": version} if version == "v2" else {}))
    return result


def ioc_sweep(contract: ContractA, events: Path) -> dict:
    """Tab 3: khâu quét IOC trên bộ OTRF đã kiểm E1. Không gọi API, không đọc nhãn."""
    import yaml
    from .stages import s2_ioc, s2_ioc_sweep
    dataset(events)
    rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
    excl = (yaml.safe_load(config.resolve("configs/agent.yaml").read_text(encoding="utf-8")) or {}).get(
        "triage", {}).get("exclude_accounts")
    return s2_ioc_sweep.sweep_dir(s2_ioc_sweep.plan(contract, rules), events, exclude_accounts=excl)


def ioc_table(result: dict) -> list[dict]:
    """Tab 3: bảng quét IOC, mục có khớp lên trước."""
    status = {"khong_quet": "không quét", "khong_co_truong": "log không có trường"}
    rows = sorted(result["muc"], key=lambda r: (-r["so_su_kien"], {"manh": 0, "yeu": 1, "bo": 2}[r["muc"]], r["gia_tri"]))
    return [{"gia_tri": r["gia_tri"], "loai": r["loai"], "muc": r["muc"], "ly_do": r["ly_do"],
             "su_kien_khop": r["so_su_kien"] if r["trang_thai"] == "da_quet" else status[r["trang_thai"]],
             "may": ", ".join(r["may"]), "tai_khoan": ", ".join(r["tai_khoan"]), "doan": r["doan"]} for r in rows]


def community_rules(contract: ContractA, events: Path) -> dict:
    """Tab 3: rule cộng đồng SigmaHQ theo TTP của report trên bộ log này. Không gọi API, không đọc nhãn."""
    from .data.store import connect
    from .stages import community_rules as cr
    dataset(events)
    return cr.run(connect(events), contract)


def community_table(result: dict) -> list[dict]:
    """Tab 3: bảng rule cộng đồng, rule giữ nhiều sự kiện lên trước."""
    rows = sorted(result["rule"], key=lambda r: (-(r.get("cuoi") or 0), r["title"] or ""))
    return [{"rule": r["title"], "muc": r.get("level", ""), "ky_thuat": ", ".join(r["techniques"]),
             "nguon": f"{r['kenh']} {r['eid']}", "trong_pham_vi": r.get("pham_vi"),
             "giu": "lỗi cột" if "loi" in r else r.get("cuoi"), "tep": r["sigmahq"]} for r in rows]

def coverage_table(rows: list[dict]) -> list[dict]:
    """Tab 3: nguồn log và câu nguồn thành chữ đọc được (bảng không hiện được danh sách object).
    Chỉ đổi cách hiển thị; không sửa kết quả đối chiếu."""
    def source(s: dict) -> str:
        text = f"{s['channel']} · EID {', '.join(str(e) for e in s['event_ids'])}"
        return text + (f" · trường: {', '.join(s['key_fields'])}" if s.get("key_fields") else "")

    def span(e: dict) -> str:
        return f"{e.get('segment_id') or 'không có mã đoạn'}: “{e.get('text', '')}”"

    return [{**row, "sources": " ; ".join(source(s) for s in row.get("sources", [])),
             "evidence": " ; ".join(span(e) for e in row.get("evidence", []))} for row in rows]


def rule_grounding(rule_path: Path) -> list[dict] | None:
    """B3 (09/10): đối chiếu giá trị điều kiện của rule ⑤ với giả thuyết đã duyệt cùng vòng; chỉ để người xem, không
    chặn rule hay đổi kết quả. None khi vòng không có giả thuyết đã duyệt trùng tên tệp rule."""
    from sigma.collection import SigmaCollection
    from .stages import rule_fidelity
    approved = rule_path.parent.parent / approval.APPROVED_FILE
    if not approved.exists():
        return None
    h = next((h for h in approval.load_hypotheses(approved)
              if h.hypothesis_id == rule_path.stem and h.status == "approved"), None)
    if h is None:
        return None
    rules = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")).rules
    return rule_fidelity.condition_grounding(rules[0], h) if len(rules) == 1 else None


def rule_missing(rule_path: Path) -> list[dict] | None:
    """H6 (12/10): chuỗi kỹ thuật của giả thuyết đã duyệt không thấy trong điều kiện sinh ứng viên của rule cùng vòng;
    chỉ để người xem. None trong cùng các trường hợp với `rule_grounding`."""
    from sigma.collection import SigmaCollection
    from .stages import rule_fidelity
    approved = rule_path.parent.parent / approval.APPROVED_FILE
    if not approved.exists():
        return None
    h = next((h for h in approval.load_hypotheses(approved)
              if h.hypothesis_id == rule_path.stem and h.status == "approved"), None)
    if h is None:
        return None
    rules = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8")).rules
    return rule_fidelity.missing_conditions(rules[0], h) if len(rules) == 1 else None


def shortened_rules(run: Path) -> list[tuple[str, str, list[dict]]]:
    """10/10: rule người duyệt rút gọn, đọc từ manifest đã băm của mỗi bản sửa: (nhãn, YAML, các mục đã bỏ). Chỉ đọc."""
    import yaml
    out = []
    for manifest in sorted(Path(run).glob("round_*/filter_review/r*/manifest.json")):
        m = json.loads(manifest.read_text(encoding="utf-8"))
        specs = {s["id"]: s for s in m["specs"]}
        for c in (m["context"].get("ban_sua_cua") or {}).get("rut_gon", []):
            label = f"{manifest.parent.relative_to(run).as_posix()}/{c['id']}"
            out.append((label, yaml.safe_dump(specs[c["id"]]["sigma_context"]["rule"], allow_unicode=True,
                                              sort_keys=False), c["bo_muc"]))
    return out


def sql_stages(spec: dict) -> list[dict]:
    """Same scope and NULL-safe exclusions as hunt.observe; never use candidates as a table."""
    runner.validate(spec)
    clauses = [runner._scope_where(spec["scope"]), f"({spec['candidates']})"]
    result = [{"stage": "ung_vien", "sql": "SELECT * FROM events WHERE " + " AND ".join(clauses)}]
    for f in spec.get("filters", []):
        clauses.append(f"({f['where']}) IS NOT TRUE")
        result.append({"stage": f"sau_{f['id']}", "sql": "SELECT * FROM events WHERE " + " AND ".join(clauses)})
    return result


def result_summary(run: Path) -> dict:
    """Read every saved execution round, including runs still waiting for review."""
    from .hunt.breadth import from_observation
    rows = []
    for path in sorted(run.glob("round_*/agent_execute.json")):
        saved = json.loads(path.read_text(encoding="utf-8"))
        for obs in saved.get("observations", []):
            rows.append({"round": path.parent.name, "source": obs.get("source", {}), **from_observation(obs)})
    # Historical replay has no graph rounds; observations live in its record.
    record_path = run / "agent_dev_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8")) if record_path.exists() else {}
    if not rows:
        rows = [{"source": obs.get("source", {}), **from_observation(obs)} for obs in record.get("observations", [])]
    decisions = [{"round": i, "action": h["decision"]["action"], "reason": h["decision"]["reason"]}
                 for i, h in enumerate(record.get("history", []), 1)]
    return {"hunts": rows, "decisions": decisions}
