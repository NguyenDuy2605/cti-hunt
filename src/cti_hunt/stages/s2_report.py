"""Report-native extraction. No labels, no modifications to the frozen v1 path."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from pydantic import Field, ValidationError

from ..attack.catalog import AttackCatalog, tactic_key
from ..attack.retrieval import TechniqueIndex
from ..contracts import ContractA
from ..llm import budget, providers
from . import s1_ingest, s2_ioc, s2_ttp

VERSION = "report_extract_dev_v1"


def estimate_cost(requests: list[dict], llm_config: dict) -> dict | None:
    """Local estimate only: no token-count API, client or ledger access.

    Calibrated on 54 saved extraction calls (12/10): 2.7 chars/input token,
    5,200 output tokens/batch. The reserve is estimated, not a billing cap.
    """
    model = llm_config.get("model")
    if model not in budget.RATES:
        return None
    batches = len(requests)
    # Integer arithmetic keeps ceil(chars / 2.7) exact, rounded per batch.
    input_tokens = sum((10 * (len(r["system"]) + len(r["user"]) + len(json.dumps(r["schema"]))) + 26) // 27
                       for r in requests)
    max_output = int(llm_config.get("max_output_tokens", 4096))
    if max_output <= 0:
        raise ValueError("max_output_tokens phải lớn hơn 0")
    # A smaller configured output cap also bounds the historical typical value.
    typical_output = min(5200, max_output)
    reserved_input = (input_tokens * 110 + 99) // 100 + 256 * batches
    ir, ore = budget.RATES[model]
    return {"model": model, "rate_version": budget.RATE_VERSION, "batches": batches,
            "chars_per_input_token": 2.7, "input_tokens": input_tokens,
            "output_tokens_per_batch": typical_output, "output_tokens": batches * typical_output,
            "max_output_tokens_per_batch": max_output, "reserved_input_tokens": reserved_input,
            "typical_usd": budget.usd(input_tokens * ir + batches * typical_output * ore),
            "reserve_usd": budget.usd(reserved_input * ir + batches * max_output * ore),
            "warnings": ([f"Report dài ({batches} lô). Cân nhắc chọn đoạn bằng --segments trước khi gửi."]
                         if batches > 50 else [])}


def cost_summary(estimate: dict) -> str:
    return (f"Ước tính khâu ② ({estimate['model']}): {estimate['batches']} lô · "
            f"~{estimate['input_tokens']:,} token vào / {estimate['output_tokens']:,} token ra · "
            f"mức thường gặp ~{estimate['typical_usd']} USD · "
            f"giữ trước ước tính ~{estimate['reserve_usd']} USD. "
            "Dự toán toàn bộ lượt, không phải chi phí thực tế hay giới hạn billing.")


class GroundedItem(s2_ttp.ExtractedTTP):
    rationale: str = Field(min_length=1)
    outside_candidates_reason: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class GroundedBatch(s2_ttp.ExtractionBatch):
    items: list[GroundedItem] = Field(default_factory=list)


NOISE_RULES = "h3_v1"
NOISE_LABELS = {"khong_co_chu": "không có chữ", "lap_tren_nhieu_trang": "lặp trên nhiều trang",
                "chu_giao_dien": "chữ nút bấm của trang web"}
_REPEAT_MAX_CHARS = 80
_REPEAT_MIN_PAGES = 3
# Một động từ nút bấm, theo sau chỉ là từ trong danh sách đóng: "Download PDF", "Share this publication".
# "Download payload via BITS" không khớp vì có từ ngoài danh sách.
_UI_ACTION = re.compile(r"(?:download|share|print|subscribe|tweet|copy)(?:\s+(?:this|the|as|pdf|json|markdown|csv|"
                        r"xml|stix|report|publication|article|post|page|link|iocs?))*", re.I)


def _repeat_key(text: str) -> str:
    return re.sub(r"\d+", "#", " ".join(text.split())).casefold()


def noise_marks(manifest: dict, segments: list[dict], provenance: dict) -> dict[str, str]:
    """H3 (12/10): đoạn đọc được nhưng không mang nội dung để trích TTP → {mã đoạn: lý do}.

    Chỉ quyết định đoạn nào làm mục tiêu/ngữ cảnh của ②. Bundle không đổi và phần quét IOC vẫn đọc mọi đoạn.
    - khong_co_chu: không có chữ cái nào (dòng bảng rỗng, dấu đầu dòng, số trang, tỷ lệ phần trăm, địa chỉ IP đứng
      riêng). Không làm mục tiêu nhưng vẫn làm ngữ cảnh cho đoạn kề nó.
    - lap_tren_nhieu_trang (PDF): chuỗi ngắn có mặt nguyên văn ở ít nhất 3 trang và 1/3 số trang (đầu trang, thanh
      mục lục lặp), hoặc cùng khuôn chữ với con số đi theo số trang trên chừng ấy trang (chân trang đánh số).
    - chu_giao_dien (HTML): nhãn nút bấm theo danh sách đóng. Nhãn ngắn khác ("MD5", "History:") không bị đánh dấu,
      vì mục danh sách ngắn có thể là nội dung thật.
    Bảo thủ: thà gửi thừa một đoạn nhiễu còn hơn bỏ một đoạn nội dung."""
    ready = [s for s in segments if s1_ingest.extraction_ready(s, provenance)]
    fmt = manifest.get("format")
    pages = {provenance[s["ma_doan"]].get("page", 0) for s in ready}
    need = max(_REPEAT_MIN_PAGES, -(-len(pages) // 3))
    same_text: dict[str, set] = {}            # nguyên văn → các trang có nó
    numbered: dict[str, list] = {}            # nguyên văn đã thay số bằng # → [(mã đoạn, trang, các số)]
    if fmt == "pdf":
        for s in ready:
            text = " ".join(s["van_ban"].split())
            if len(text) > _REPEAT_MAX_CHARS:
                continue
            page = provenance[s["ma_doan"]].get("page", 0)
            same_text.setdefault(text.casefold(), set()).add(page)
            numbers = [int(x) for x in re.findall(r"\d+", text)]
            if numbers:
                numbered.setdefault(_repeat_key(text), []).append((s["ma_doan"], page, numbers))
    # Chân trang có số trang ("Page 3 of 9"): cùng khuôn chữ, và một con số lệch số trang PDF một khoảng cố định.
    # Câu nội dung chỉ khác nhau một con số ("bước 1…", "bước 2…") không theo số trang nên không bị bắt.
    page_numbered = set()
    for rows in numbered.values():
        for field in range(len(rows[0][2])):
            offset = Counter(numbers[field] - page for _, page, numbers in rows).most_common(1)[0][0]
            hits = [(sid, page) for sid, page, numbers in rows if numbers[field] - page == offset]
            if len({page for _, page in hits}) >= need:
                page_numbered.update(sid for sid, _ in hits)
    marks = {}
    for s in ready:
        text = " ".join(s["van_ban"].split())
        if not any(c.isalpha() for c in text):
            marks[s["ma_doan"]] = "khong_co_chu"
        elif len(same_text.get(text.casefold(), ())) >= need or s["ma_doan"] in page_numbered:
            marks[s["ma_doan"]] = "lap_tren_nhieu_trang"
        elif fmt == "html" and _UI_ACTION.fullmatch(text.rstrip(" :.")):
            marks[s["ma_doan"]] = "chu_giao_dien"
    return marks


def noise_summary(marked: dict | None) -> str | None:
    """Một dòng cho CLI/UI từ `meta["khong_gui_khau2"]`; None khi không đoạn nào bị đánh dấu."""
    if not marked or not marked.get("so_doan"):
        return None
    parts = ", ".join(f"{NOISE_LABELS.get(k, k)} {n}" for k, n in marked["theo_ly_do"].items())
    return (f"Không gửi khâu ② {marked['so_doan']} đoạn không mang nội dung ({parts}). Các đoạn này vẫn nằm trong "
            "bundle và vẫn được quét IOC; chọn đích danh bằng --segments thì vẫn gửi.")


def marked_meta(skip: dict[str, str]) -> dict:
    reasons = [r for r in NOISE_LABELS if r in skip.values()]
    return {"quy_tac": NOISE_RULES, "so_doan": len(skip),
            "theo_ly_do": {r: sum(v == r for v in skip.values()) for r in reasons},
            "doan": dict(sorted(skip.items()))}


def units(segments: list[dict], provenance: dict, max_chars: int = 6000, skip=frozenset(),
          no_context=frozenset()) -> list[dict]:
    """H3: mã đoạn trong `skip` không làm mục tiêu; trong `no_context` không làm ngữ cảnh lân cận."""
    if max_chars < 500:
        raise ValueError("max_chars phải >= 500")
    result = []
    for n, seg in enumerate(segments):
        if not s1_ingest.extraction_ready(seg, provenance) or seg["ma_doan"] in skip:
            continue
        text = seg["van_ban"]
        start = 0
        while start < len(text):
            end = min(start + max_chars, len(text))
            if end < len(text):
                boundary = text.rfind(" ", start + max_chars // 2, end)
                if boundary > start:
                    end = boundary + 1
            neighbors = []
            for other in segments[max(0, n - 1):n] + segments[n + 1:n + 2]:
                if other["ma_doan"] in no_context:
                    continue
                if s1_ingest.extraction_ready(other, provenance) or other["loai"] == "tiêu đề":
                    neighbors.append({"segment_id": other["ma_doan"], "text": other["van_ban"][:1200],
                                      "context_only": True})
            result.append({"segment_id": seg["ma_doan"], "kind": seg["loai"], "text": text[start:end],
                           "char_start": start, "char_end": end,
                           "section": provenance[seg["ma_doan"]].get("section", ""), "neighbors": neighbors,
                           "evidence_origin": provenance[seg["ma_doan"]].get("extraction", "text"),
                           "same_segment_context_before": text[max(0, start - 500):start],
                           "same_segment_context_after": text[end:end + 500]})
            start = end
    return result


def select_segments(segments: list[dict], provenance: dict, selected) -> list[str] | None:
    """Optional partial extraction (07/10): only these readable segment IDs become targets; neighbours stay context."""
    if selected is None:
        return None
    wanted = list(dict.fromkeys(selected))
    known = {s["ma_doan"]: s for s in segments}
    missing = [w for w in wanted if w not in known]
    unreadable = [w for w in wanted if w in known and not s1_ingest.extraction_ready(known[w], provenance)]
    if not wanted or missing or unreadable:
        raise ValueError(f"Chọn đoạn không hợp lệ: thiếu {missing}, không đọc được {unreadable}")
    return wanted


def prepare(bundle: Path, stix: Path, prompt_path: Path, llm_config: dict,
            batch_size: int = 4, top_k: int = 8, segments_selected=None) -> tuple[dict, list[dict]]:
    if not 1 <= batch_size <= 8:
        raise ValueError("batch-size phải từ 1 đến 8")
    manifest, segments, provenance = s1_ingest.load_bundle(bundle)
    selected = select_segments(segments, provenance, segments_selected)
    # H3: đoạn nhiễu không làm mục tiêu; đoạn người dùng chọn đích danh thì vẫn gửi.
    skip = {k: v for k, v in noise_marks(manifest, segments, provenance).items() if k not in set(selected or ())}
    # Dòng không có chữ (số, địa chỉ IP, cổng) vẫn làm ngữ cảnh cho đoạn kề nó; đầu/chân trang và nhãn nút bấm thì không.
    all_targets = units(segments, provenance, skip=frozenset(skip),
                        no_context=frozenset(k for k, v in skip.items() if v != "khong_co_chu"))
    targets = all_targets if selected is None else [u for u in all_targets if u["segment_id"] in set(selected)]
    if not targets:
        raise ValueError("Report không có nội dung đọc được; cần xử lý OCR/HTML trước")
    index = TechniqueIndex.from_stix(stix)
    system = prompt_path.read_text(encoding="utf-8")
    requests = []
    for start in range(0, len(targets), batch_size):
        batch = targets[start:start + batch_size]
        # Retrieve per target so a long unrelated paragraph cannot crowd out another.
        enriched = [{**unit, "candidates": index.search(unit["text"], top_k)} for unit in batch]
        user = json.dumps({"report_id": manifest["report_id"], "title": manifest["title"],
                           "targets": enriched}, ensure_ascii=False, indent=2)
        requests.append({"batch": len(requests), "system": system, "user": user,
                         "schema": GroundedBatch.model_json_schema()})
    code_paths = [Path(__file__), Path(s1_ingest.__file__), Path(s2_ttp.__file__), Path(s2_ioc.__file__),
                  Path(providers.__file__), Path(__file__).parents[1] / "attack" / "retrieval.py",
                  Path(__file__).parents[1] / "attack" / "catalog.py",
                  Path(__file__).parents[1] / "llm" / "budget.py", Path(__file__).parents[1] / "contracts.py"]
    meta = {"version": VERSION, "report_id": manifest["report_id"], "ingestion_status": manifest["status"],
            "ingestion_warnings": manifest["warnings"], "bundle": str(bundle.resolve()),
            "bundle_manifest_sha256": s1_ingest.digest((bundle / "manifest.json").read_bytes()),
            "attack_sha256": index.source_sha256, "prompt_sha256": s1_ingest.digest(system.encode()),
            "llm_config": llm_config, "batch_size": batch_size, "top_k": top_k,
            "retrieval": "BM25 active technique definitions only; no procedure examples",
            "code_sha256": {p.name: s1_ingest.digest(p.read_bytes()) for p in code_paths},
            "target_units": len(targets), "batches": len(requests),
            "requests_sha256": s1_ingest.digest(json.dumps(requests, ensure_ascii=False, sort_keys=True).encode())}
    if skip:
        # Chỉ ghi khi có đoạn bị đánh dấu: report không có nhiễu giữ nguyên meta và requests như trước H3.
        meta["khong_gui_khau2"] = marked_meta(skip)
    if selected is not None:
        # Recorded in the fingerprint: a partial Contract A never passes for an extraction of the whole report.
        meta.update(partial_extraction=True, selected_segments=selected, target_units_total=len(all_targets))
    return meta, requests


def validate_items(raw: dict, request: dict, segments: list[dict], provenance: dict,
                   catalog: AttackCatalog) -> tuple[list, list[dict]]:
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        raise ValueError("Phản hồi thiếu danh sách items")
    target_units = json.loads(request["user"])["targets"]
    by_id = {s["ma_doan"]: s for s in segments}
    accepted, decisions = [], []
    for n, value in enumerate(raw["items"]):
        audit = {"item": n, "status": "rejected"}
        try:
            item = GroundedItem.model_validate(value)
            audit.update(segment_id=item.segment_id, technique_id=item.technique_id)
            targets = [u for u in target_units if u["segment_id"] == item.segment_id]
            quote_target = next((u for u in targets if item.quote.strip() and item.quote in u["text"]), None)
            if quote_target is None:
                raise ValueError("Câu trích trống/không nguyên văn/không thuộc đoạn mục tiêu trong lô")
            res = catalog.resolve(item.technique_id)
            if not res.final or catalog.resolve(res.final).status != "ok":
                raise ValueError("Kỹ thuật không còn hiệu lực hoặc không có mã thay thế")
            technique = catalog.techniques[res.final]
            if tactic_key(item.tactic) not in technique.tactics:
                raise ValueError("Tactic không thuộc kỹ thuật đã chọn")
            item.tactic = catalog.tactics.get(tactic_key(item.tactic), item.tactic)
            candidates = {c["technique_id"] for c in quote_target["candidates"]}
            if res.final not in candidates and not item.outside_candidates_reason.strip():
                raise ValueError("Chọn ngoài ứng viên nhưng thiếu lý do")
            if not item.behavior_description.strip() or not item.rationale.strip():
                raise ValueError("Thiếu mô tả hành vi hoặc căn cứ ánh xạ")
            if item.context.command_example and item.context.command_example not in by_id[item.segment_id]["van_ban"]:
                raise ValueError("command_example không có nguyên văn trong đoạn")
            # Reuse stable context/code normalization without weakening the strict evidence gate.
            ttps, fixes = s2_ttp.postprocess([item], by_id, catalog, drop_unquoted=True)
            if len(ttps) != 1:
                raise ValueError("Mục không qua hậu xử lý")
            ttp = ttps[0]
            p = provenance[item.segment_id]
            ttp.source_span.section = p.get("section", "")
            ttp.source_span.page = p.get("page", 0)
            accepted.append(ttp)
            audit.update(status="accepted", final_technique_id=ttp.technique_id, quote=item.quote,
                         rationale=item.rationale, outside_candidates=res.final not in candidates,
                         outside_candidates_reason=item.outside_candidates_reason, normalization=dict(fixes),
                         source=p, semantic_review="not_independently_verified")
        except (ValidationError, ValueError) as e:
            audit["reason"] = str(e)
        decisions.append(audit)
    return accepted, decisions


def run(bundle: Path, stix: Path, prompt_path: Path, llm_config: dict, out: Path,
        ioc_rules: dict, *, send: bool = False, resume: bool = False, llm=None,
        batch_size: int = 4, top_k: int = 8, accept_partial: bool = False, segments_selected=None) -> dict:
    meta, requests = prepare(bundle, stix, prompt_path, llm_config, batch_size, top_k, segments_selected)
    meta["ioc_rules_sha256"] = s1_ingest.digest(json.dumps(ioc_rules, sort_keys=True, ensure_ascii=False,
                                                        default=lambda x: sorted(x) if isinstance(x, set) else str(x)).encode())
    fingerprint = s1_ingest.digest(json.dumps(meta, ensure_ascii=False, sort_keys=True).encode())
    # Informational only: absent in old metadata and never part of the resume fingerprint.
    meta["uoc_tinh_chi_phi"] = estimate_cost(requests, llm_config)
    out = Path(out)
    if out.exists():
        if not resume:
            raise ValueError("Thư mục lượt đã tồn tại; dùng --resume với đúng đầu vào/cấu hình hoặc thư mục mới")
        previous = json.loads((out / "meta.json").read_text(encoding="utf-8"))
        if previous.get("fingerprint") != fingerprint:
            raise ValueError("Đầu vào/prompt/cấu hình/mã thay đổi; không thể resume lượt cũ")
        if send and previous.get("error_type") == "RefusalError":
            raise ValueError("Lượt đã bị mô hình từ chối; không gọi lại hoặc đổi provider để vượt từ chối")
    elif resume:
        raise ValueError("Không có lượt để resume")
    out.mkdir(parents=True, exist_ok=True)
    meta.update(fingerprint=fingerprint, status="prepared", api_called=False)
    s1_ingest.write_json(out / "requests.json", requests)
    if not send:
        # Do not downgrade a completed/failed run merely because it was previewed again.
        if not (out / "meta.json").exists():
            s1_ingest.write_json(out / "meta.json", meta)
        return meta
    if llm is None:
        if meta["ingestion_status"] != "extracted" and not accept_partial:
            raise ValueError("Cần rà và chấp nhận cảnh báo/phần chưa đọc trước khi gọi mô hình")
        if llm_config.get("provider") != "anthropic" or not llm_config.get("budget_ledger"):
            raise ValueError("Gọi thật yêu cầu Anthropic và budget_ledger; không bỏ qua kiểm soát chi phí")
        from .. import config
        from ..llm.budget import Ledger
        Ledger(config.resolve(llm_config["budget_ledger"])).require_ready()
    client = llm or providers.from_config(llm_config)
    meta["ingestion_warnings_acknowledged"] = bool(accept_partial)
    manifest, segments, provenance = s1_ingest.load_bundle(bundle)
    catalog = AttackCatalog.from_stix(stix)
    kept, audit = {}, []
    meta["status"] = "running"
    s1_ingest.write_json(out / "meta.json", meta)
    try:
        for request in requests:
            response_path = out / f"response_{request['batch']:04d}.json"
            request_hash = s1_ingest.digest(json.dumps(request, ensure_ascii=False, sort_keys=True).encode())
            if response_path.exists():
                saved = json.loads(response_path.read_text(encoding="utf-8"))
                if saved.get("request_sha256") != request_hash:
                    raise ValueError("Phản hồi lưu không khớp yêu cầu")
                raw = saved["raw"]
            else:
                api_events, recorder = providers.event_recorder()
                try:
                    meta["api_called"] = not isinstance(client, providers.MockClient)
                    raw = client.complete_json(request["system"], request["user"], request["schema"], log=recorder)
                finally:
                    s1_ingest.write_json(out / f"usage_{request['batch']:04d}.json", api_events)
                s1_ingest.write_json(response_path, {"request_sha256": request_hash, "raw": raw, "api_events": api_events})
            saved = json.loads(response_path.read_text(encoding="utf-8"))
            if any(e.get("stop_reason") == "max_tokens" for e in saved.get("api_events", [])):
                raise ValueError("Phản hồi chạm max_tokens; không công bố kết quả hoàn tất, cần cấu hình/lượt mới")
            ttps, decisions = validate_items(raw, request, segments, provenance, catalog)
            audit.extend({"batch": request["batch"], **d} for d in decisions)
            for ttp in ttps:
                key = (ttp.source_span.segment_id, ttp.technique_id)
                if key not in kept or ttp.confidence > kept[key].confidence:
                    kept[key] = ttp
            s1_ingest.write_json(out / "evidence_audit.json", audit)
        text_segments = [s for s in segments if s1_ingest.extraction_ready(s, provenance)
                         and (not meta.get("partial_extraction") or s["ma_doan"] in meta["selected_segments"])]
        iocs = s2_ioc.extract_report(text_segments, ioc_rules)
        for ioc in iocs:
            p = provenance[ioc.source_span.segment_id]
            ioc.source_span.section, ioc.source_span.page = p.get("section", ""), p.get("page", 0)
            body = next(s["van_ban"] for s in segments if s["ma_doan"] == ioc.source_span.segment_id)
            at = body.find(ioc.value)
            ioc.source_span.text = body[max(0, at - 100):at + len(ioc.value) + 100]
        contract = ContractA(report_id=manifest["report_id"], title=manifest["title"],
                             source_url=manifest["resolved_source"] if manifest["resolved_source"].startswith(("https://", "http://")) else "",
                             ttps=list(kept.values()), iocs=iocs)
        (out / "contract_a.json").write_text(contract.model_dump_json(indent=2), encoding="utf-8")
        meta.update(status="complete", accepted_ttp=len(kept), rejected_items=sum(d["status"] == "rejected" for d in audit),
                    iocs=len(iocs), semantic_quality="not_evaluated", contract_a_sha256=s1_ingest.digest((out / "contract_a.json").read_bytes()))
    except Exception as e:
        meta.update(status="failed", error_type=type(e).__name__)
        s1_ingest.write_json(out / "meta.json", meta)
        raise
    s1_ingest.write_json(out / "meta.json", meta)
    return meta
