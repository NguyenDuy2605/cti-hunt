"""Khâu ④ — sinh giả thuyết theo LOCK (v3 §4.2 ④, §4.5 Contract B). Tuần 4.

Đầu vào: Contract A (khâu ②) + danh mục nguồn log (khâu ③). Kỹ thuật not_huntable không vào khâu này mà ra
thẳng mục "khoảng trống quan sát" của hunt record.

Mô hình chỉ viết nội dung giả thuyết. Mọi thứ kiểm được bằng mã thì mã làm, và mỗi lần sửa/loại đều đếm vào log
(v3 §4.2: thiếu nguồn log, mã sự kiện hoặc tên trường thì bị loại ở tầng kiểm tra đầu ra):

    ttp_refs trỏ ra ngoài đầu vào       bỏ ref đó; không còn ref nào thì loại giả thuyết      ttp_ref_la / khong_neo_ttp
    nguồn log ngoài allowed_sources     loại                                                   nguon_log_ngoai_danh_muc
    mã sự kiện không thuộc nguồn đó     loại                                                   ma_su_kien_ngoai_danh_muc
    tên trường ngoài danh mục           bỏ trường; không còn trường nào thì loại               truong_ngoai_danh_muc / thieu_truong
    behavior/scope/timeframe rỗng       loại                                                   thieu_thanh_phan
    extra_techniques sai mã             bỏ mã đó                                               mo_rong_ma_sai
    extra_techniques hợp lệ             giữ, đếm riêng (v3 §5.1 bước 4)                        mo_rong_ky_thuat
    trùng (nguồn log, mã sự kiện, hành vi)  giữ bản đầu                                        trung_gia_thuyet
    vượt max_hypotheses_per_round       cắt                                                    vuot_tran

Cách đếm: mục "sửa" (ttp_ref_la, truong_ngoai_danh_muc, mo_rong_*, priority_la) chỉ tính trên giả thuyết ĐƯỢC
GIỮ; giả thuyết bị loại chỉ đếm đúng một lý do loại. Nếu không, mo_rong_ky_thuat bị phồng bởi bản trùng.

hypothesis_id, source_spans, origin, pivot_depth, status do mã điền: source_spans lấy từ chính các TTP được trỏ
tới, nên mô hình không bịa được tham chiếu nguồn.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..contracts import (ContractA, ContractB, Evidence, RangBuoc, DemKhacNhau,
                         MocNeo, VangMat, CapTruong)
from ..llm import providers
from ..llm.prompting import fill
from .s3_telemetry import map_technique

PRIORITIES = ("cao", "trung_binh", "thap")
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")


class PivotLimitError(ValueError):
    pass


class LLMHypothesis(BaseModel):
    ttp_refs: list[int] = Field(default_factory=list)
    behavior: str = ""
    scope: str = ""
    timeframe: str = ""
    data_source: str = ""
    event_ids: list[int] = Field(default_factory=list)
    key_fields: list[str] = Field(default_factory=list)
    extra_techniques: list[str] = Field(default_factory=list)
    priority: str = ""
    rationale: str = ""
    required_operations: list[Literal['distinct_count', 'event_sequence', 'absence']] = Field(default_factory=list)


class LLMHypothesisBatch(BaseModel):
    items: list[LLMHypothesis] = Field(default_factory=list)


class LLMHypothesisV2(LLMHypothesis):
    rang_buoc: RangBuoc | None = None

    @field_validator("rang_buoc", mode="before")
    @classmethod
    def reject_unknown_constraint_parameters(cls, value):
        # Mock/local providers must not silently lose an unsupported condition either.
        def check(obj, model):
            if isinstance(obj, dict) and set(obj) - set(model.model_fields):
                raise ValueError("tham số ràng buộc chưa hỗ trợ")
        check(value, RangBuoc)
        # Lược đồ strict bắt mô hình gửi đủ ba khóa; "không ràng buộc" có thể đến dưới dạng object có đủ ba khóa, cả ba
        # null (gặp 5 lần ở đánh giá v2 mới 08/10, làm validator loại cả lô). Chỉ đúng dạng đó mới quy về null;
        # object rỗng hay thiếu khóa vẫn bị từ chối như trước.
        if isinstance(value, dict) and set(value) == set(RangBuoc.model_fields) and all(v is None for v in value.values()):
            return None
        if isinstance(value, dict):
            for name, model in (("dem_khac_nhau", DemKhacNhau), ("moc_neo", MocNeo), ("vang_mat", VangMat)):
                part = value.get(name)
                check(part, model)
                if name == "vang_mat" and isinstance(part, dict) and isinstance(part.get("khop"), list):
                    for pair in part["khop"]:
                        check(pair, CapTruong)
        return value


class LLMHypothesisBatchV2(BaseModel):
    # Keep the dispatch title used by mock clients; the properties differ only for v2.
    model_config = ConfigDict(title="LLMHypothesisBatch")
    items: list[LLMHypothesisV2] = Field(default_factory=list)


def output_model(cfg: dict):
    return LLMHypothesisBatchV2 if cfg.get("sinh_rang_buoc") else LLMHypothesisBatch


def render_anchors(hypotheses: list[ContractB]) -> str:
    """Only callers with executed hunts may supply these; no counts or labels."""
    return json.dumps([{"hypothesis_id": h.hypothesis_id, "behavior": h.behavior,
                        "data_source": h.evidence.data_source, "event_ids": h.evidence.event_ids,
                        "key_fields": h.evidence.key_fields,
                        "source_quotes": [s.text for s in h.source_spans]} for h in hypotheses],
                      ensure_ascii=False, indent=2)


def validate_constraints(rb: RangBuoc, sources: list[dict], primary: list[dict],
                         anchors: list[ContractB]) -> str | None:
    """Reject the whole hypothesis; never strip an unexecutable constraint."""
    def fields(rows):
        return {"ev_host"} | {f.lower() for s in rows for f in s.get("key_fields") or []}
    main = fields(primary)
    if rb.dem_khac_nhau:
        d = rb.dem_khac_nhau
        if "ev_host" not in {f.lower() for f in d.theo}:
            return "rang_buoc_thieu_may"
        if not {d.truong.lower(), *(f.lower() for f in d.theo)} <= main:
            return "rang_buoc_truong_ngoai_danh_muc"
    if rb.vang_mat:
        v = rb.vang_mat
        if not any(p.ung_vien.lower() == p.nguon.lower() == "ev_host" for p in v.khop):
            return "rang_buoc_thieu_may"
        secondary = [s for s in sources if s["channel"].lower() == v.channel.lower()
                     and set(v.event_ids) <= set(s["event_ids"])]
        if not secondary:
            return "rang_buoc_nguon_ngoai_danh_muc"
        if any(p.ung_vien.lower() not in main or p.nguon.lower() not in fields(secondary) for p in v.khop):
            return "rang_buoc_truong_ngoai_danh_muc"
    if rb.moc_neo:
        m = rb.moc_neo
        if "ev_host" not in {f.lower() for f in m.cung}:
            return "rang_buoc_thieu_may"
        anchor = next((h for h in anchors if h.hypothesis_id == m.gia_thuyet and h.status == "approved"), None)
        if anchor is None:
            return "rang_buoc_moc_neo_chua_chay"
        if not {f.lower() for f in m.cung} <= main & fields([{"key_fields": anchor.evidence.key_fields}]):
            return "rang_buoc_truong_ngoai_danh_muc"
    return None


def select_inputs(contract_a: ContractA, telemetry: dict[str, dict],
                  coverage: dict[str, dict] | None = None,
                  skip_covered: bool = False) -> tuple[list[dict], list[dict]]:
    """Chia TTP thành đầu vào khâu 4 (huntable / partial) và khoảng trống quan sát (not_huntable).
    `coverage` (15/10, tùy chọn): trạng thái phủ của rule cộng đồng theo mã kỹ thuật; TTP chưa có rule cộng đồng mức cao
    được cộng điểm để hệ thống săn trước. Không truyền thì điểm giữ nguyên như trước."""
    inputs, gaps = [], []
    
    tech_stats = {}
    for t in contract_a.ttps:
        st = tech_stats.setdefault(t.technique_id, {"segments": set(), "max_conf": 0.0, "is_target": False})
        # N5 đếm đoạn nguồn, không đếm số dòng suy luận trùng trong cùng đoạn.
        if t.source_span.segment_id and t.source_span.segment_id.strip():
            st["segments"].add(t.source_span.segment_id.strip())
        if t.confidence > st["max_conf"]:
            st["max_conf"] = t.confidence
        if t.tactic.strip().lower() in ("lateral movement", "persistence"):
            st["is_target"] = True
            
    for ref, t in enumerate(contract_a.ttps):
        m = map_technique(t.technique_id, telemetry)
        if m["status"] == "not_huntable":
            gaps.append({"ref": ref, "technique_id": t.technique_id, "technique_name": t.technique_name,
                         "ly_do": m.get("ly_do") or m.get("ghi_chu") or "không có nguồn log"})
        else:
            st = tech_stats[t.technique_id]
            status_score = 100 if m["status"] == "huntable" else 50
            tactic_score = 20 if st["is_target"] else 0
            conf_score = st["max_conf"] * 10
            segment_count = len(st["segments"])
            score = status_score + tactic_score + conf_score + segment_count
            components = {"segment_count": segment_count, "max_confidence": st["max_conf"],
                          "telemetry_status": m["status"], "target_tactic": st["is_target"]}
            if coverage is not None:
                from .community_rules import GAP_BONUS
                cov = coverage.get(t.technique_id.strip().lower(), {"muc": "khong_co_rule"})["muc"]
                # 15/10, chế độ chỉ săn khoảng trống: TTP đã có rule cộng đồng mức cao để rule cộng đồng lo
                if skip_covered and cov == "cao":
                    continue
                score += GAP_BONUS[cov]
                components["community_coverage"] = cov
            inputs.append({"ref": ref, "ttp": t, "mapping": m, "score": score, "score_components": components})
            
    inputs.sort(key=lambda x: x["score"], reverse=True)
    return inputs, gaps


def render_inputs(inputs: list[dict]) -> str:
    rows = []
    for i in inputs:
        t, m = i["ttp"], i["mapping"]
        row = {
            "ref": i["ref"], "technique_id": t.technique_id, "technique_name": t.technique_name,
            "tactic": t.tactic, "behavior_description": t.behavior_description,
            "context": t.context.model_dump(), "quote": t.source_span.text,
            "telemetry_status": m["status"], "telemetry_note": m.get("ghi_chu", ""),
            "allowed_sources": [{"channel": s["channel"], "event_ids": s["event_ids"],
                                 "key_fields": s.get("key_fields") or []} for s in m.get("sources") or []],
        }
        if "score" in i:
            row["n5_relevance_score"] = round(i["score"], 2)
        rows.append(row)
    return json.dumps(rows, ensure_ascii=False, indent=2)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def postprocess(items: list[LLMHypothesis], inputs: list[dict], report_id: str, max_items: int,
                attack_catalog=None, origin: str = "telemetry_mapping", pivot_depth: int = 0,
                start_index: int = 1, pivot_kind: str | None = None,
                pivot_value: str = "", anchors: list[ContractB] | None = None) -> tuple[list[ContractB], Counter]:
    log: Counter = Counter()
    by_ref = {i["ref"]: i for i in inputs}
    out: list[ContractB] = []
    seen: set[tuple] = set()
    for it in items:
        fix: Counter = Counter()                  # sửa trên giả thuyết này; chỉ cộng vào log nếu nó được giữ
        refs = [r for r in dict.fromkeys(it.ttp_refs) if r in by_ref]
        fix["ttp_ref_la"] += len(set(it.ttp_refs)) - len(refs)
        if not refs:
            log["khong_neo_ttp"] += 1
            continue
        if not (it.behavior.strip() and it.scope.strip() and it.timeframe.strip()):
            log["thieu_thanh_phan"] += 1
            continue

        # Nguồn log phải là một nguồn của chính các kỹ thuật được trỏ tới (khâu ③ quyết định, không phải mô hình).
        channel = it.data_source.strip().lower()
        allowed = [s for r in refs for s in by_ref[r]["mapping"].get("sources") or []
                   if s["channel"].lower() == channel]
        if not allowed:
            log["nguon_log_ngoai_danh_muc"] += 1
            continue
        eids = sorted(set(it.event_ids))
        match = [s for s in allowed if eids and set(eids) <= set(s["event_ids"])]
        if not match:
            log["ma_su_kien_ngoai_danh_muc"] += 1
            continue
        rb = getattr(it, "rang_buoc", None)
        if rb is not None:
            sources = [s for r in refs for s in by_ref[r]["mapping"].get("sources") or []]
            error = validate_constraints(rb, sources, match, anchors or [])
            if error:
                log[error] += 1
                continue
        key = (channel, tuple(eids), _norm(it.behavior))
        if isinstance(it, LLMHypothesisV2):
            key += (_norm(it.scope), _norm(it.timeframe),
                    json.dumps(rb.model_dump(mode="json") if rb else None, sort_keys=True))
        if key in seen:
            log["trung_gia_thuyet"] += 1
            continue

        allowed_fields = {f.lower(): f for s in match for f in s.get("key_fields") or []}
        fields = [allowed_fields[f.lower()] for f in dict.fromkeys(it.key_fields) if f.lower() in allowed_fields]
        fix["truong_ngoai_danh_muc"] += len(set(it.key_fields)) - len(fields)
        if not fields:
            log["thieu_truong"] += 1
            continue

        extra = []
        for tid in dict.fromkeys(x.strip().upper() for x in it.extra_techniques):
            ok = bool(_TID.match(tid))
            if ok and attack_catalog is not None:
                r = attack_catalog.resolve(tid)
                ok, tid = r.status in ("ok", "revoked") and bool(r.final), (r.final or tid)
            if ok:
                extra.append(tid)
            else:
                fix["mo_rong_ma_sai"] += 1
        base_ttps = {by_ref[r]["ttp"].technique_id for r in refs}
        extra = [t for t in extra if t not in base_ttps]
        fix["mo_rong_ky_thuat"] += len(extra)

        if len(out) >= max_items:
            log["vuot_tran"] += 1
            continue
        prio = it.priority.strip().lower()
        if prio and prio not in PRIORITIES:
            fix["priority_la"] += 1
            prio = ""
        seen.add(key)
        log.update(fix)
        out.append(ContractB(
            hypothesis_id=f"{report_id}-H{start_index + len(out):02d}",
            behavior=it.behavior.strip(), scope=it.scope.strip(), timeframe=it.timeframe.strip(),
            evidence=Evidence(data_source=channel, event_ids=eids, key_fields=fields),
            linked_ttps=sorted(base_ttps | set(extra)),
            source_spans=[by_ref[r]["ttp"].source_span for r in refs],
            priority=prio, status="pending_review", origin=origin, pivot_depth=pivot_depth,
            pivot_kind=pivot_kind, pivot_value=pivot_value,
            required_operations=it.required_operations, rang_buoc=rb))
    return out, log


def generate(contract_a: ContractA, telemetry: dict[str, dict], llm, prompt: dict, cfg: dict,
             attack_catalog=None, run_dir: Path | None = None, origin: str = "telemetry_mapping",
             pivot_depth: int = 0, anchors: list[ContractB] | None = None,
             coverage: dict | None = None) -> dict:
    """Một lần chạy khâu ④ cho một report. Trả giả thuyết (pending_review), khoảng trống quan sát và log sửa.
    `coverage` (15/10, ưu tiên khoảng trống): cùng độ phủ rule cộng đồng đã dùng để chọn lô, để điểm N5 trong prompt khớp."""
    if pivot_depth > int(cfg["max_pivot_depth"]):
        raise PivotLimitError(f"pivot_depth {pivot_depth} vượt trần {cfg['max_pivot_depth']} (configs/agent.yaml)")
    inputs, gaps = select_inputs(contract_a, telemetry, coverage)
    log: Counter = Counter()
    hyps: list[ContractB] = []
    raw: list[LLMHypothesis] = []
    api_events, record = providers.event_recorder()
    if inputs:
        sec = prompt["sections"]
        user = fill(sec["USER"], report_id=contract_a.report_id, techniques=render_inputs(inputs),
                    max_items=str(cfg["max_hypotheses_per_round"]),
                    executed_hypotheses=render_anchors(anchors or []))
        if run_dir:     # ghi trước lời gọi: yêu cầu bị từ chối hay lỗi mạng vẫn còn để phân tích
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "request.json").write_text(json.dumps({"system": sec["SYSTEM"], "user": user},
                                                             ensure_ascii=False, indent=2), encoding="utf-8")
        batch_model = output_model(cfg)
        data = llm.complete_json(sec["SYSTEM"], user, batch_model.model_json_schema(), log=record)
        if run_dir:
            (run_dir / "response_raw.json").write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                                       encoding="utf-8")
        try:
            raw = batch_model.model_validate(data).items
        except ValidationError:
            log["dau_ra_sai_luoc_do"] += 1
        hyps, plog = postprocess(raw, inputs, contract_a.report_id, int(cfg["max_hypotheses_per_round"]),
                                 attack_catalog, origin, pivot_depth, anchors=anchors)
        log.update(plog)
    return {"hypotheses": hyps, "khoang_trong": gaps,
            "log": {"so_ttp_dau_vao": len(inputs), "so_ttp_not_huntable": len(gaps), "so_muc_tho": len(raw),
                    "so_gia_thuyet": len(hyps), "ma_sua": {k: v for k, v in log.items() if v},
                    "prompt": prompt["path"], "prompt_sha256": prompt["sha256"],
                    "model": getattr(llm, "model_id", "?"),
                    "api_events": api_events, "token": providers.token_totals(api_events)}}
