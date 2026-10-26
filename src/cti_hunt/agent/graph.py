"""Khung LangGraph D10, giữ rào chắn và phiếu duyệt D5, không đọc nhãn.

Hai chế độ dùng CHUNG graph, công cụ, rào chắn và trần; chỉ khác chỗ ra quyết định:
- chế độ pipeline (mốc so sánh): `PipelinePlanner`, quyết định bằng mã;
- chế độ agent: `LLMPlanner` với cấu hình E3.
Nhờ vậy chênh lệch kết quả giữa hai chế độ quy được về cách quyết định, không về đường ống.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, Protocol, TypedDict

from pydantic import BaseModel, Field

from .. import approval, config, integrity
from ..contracts import ContractB
from ..llm import providers
from ..llm.budget import BudgetExhausted
from ..llm.prompting import fill, load_sections
from .limits import api_budget, budget_stop_reason, hypothesis_budget


class AgentGuardError(ValueError):
    pass


class PivotTarget(BaseModel):
    loai: Literal["may", "tai_khoan"]
    gia_tri: str = Field(min_length=1)


class Decision(BaseModel):
    action: Literal["hunt", "pivot", "stop"]
    ttp_refs: list[int] = Field(default_factory=list)
    pivot_targets: list[PivotTarget] = Field(default_factory=list)
    reason: str = Field(min_length=1)

class TraHuntMemoryArgs(BaseModel):
    technique: str | None = None
    report_id: str | None = None

class DocHuntRecordArgs(BaseModel):
    record_id: str = Field(min_length=1, max_length=512)

class _PlannerOutput(BaseModel):
    action: Literal["hunt", "pivot", "stop", "tra_hunt_memory", "doc_hunt_record"]
    ttp_refs: list[int] = Field(default_factory=list)
    pivot_targets: list[PivotTarget] = Field(default_factory=list)
    tra_hunt_memory: TraHuntMemoryArgs | None = None
    doc_hunt_record: DocHuntRecordArgs | None = None
    reason: str = Field(min_length=1)

class AgentState(TypedDict, total=False):
    report_id: str
    techniques: list[dict]
    remaining_refs: list[int]
    observations: list[dict]
    rarity_summary: dict
    eligible_pivots: list[dict]
    pivot_depth: int
    queries_reserved: int
    history: list[dict]
    decision: dict
    planner_meta: dict
    review_dir: str
    filter_review_dir: str
    generated_ids: list[str]
    approved_file: str
    approved_files: list[str]
    approved_ids: list[str]
    executed_rounds: list[int]
    executed_specs: list[dict]
    budget_exhausted: str          # lời gọi bị từ chối vì không đủ tiền giữ trước: vòng sau dừng, ghi record
    filter_revision_pending: bool  # 10/10: cổng lọc vừa phát bản sửa (rút gọn rule) → quay lại cổng, chưa thực thi
    record: str


class Planner(Protocol):
    def __call__(self, view: dict) -> dict: ...


class LLMPlanner:
    """Adapter trung lập về provider; lưu dấu vết E3 ở mỗi lần lập kế hoạch."""

    def __init__(self, llm, prompt: dict, run_dir: Path | None = None,
                 llm_config_sha256: str | None = None, root: Path | None = None,
                 memory_root: Path | None = None, hide_budget_amounts: bool = False):
        self.llm = llm
        self.prompt = prompt
        self.run_dir = Path(run_dir) if run_dir else None
        self.llm_config_sha256 = llm_config_sha256
        self.root = root
        self.hide_budget_amounts = hide_budget_amounts
        if root is not None or memory_root is not None:
            from cti_hunt.record_store import RecordStore
            self.store = RecordStore(memory_root if memory_root is not None else self.root / 'data/reports/moi')
        else:
            self.store = None

    def metadata(self) -> dict:
        describe = getattr(self.llm, "describe", None)
        return {"prompt": self.prompt.get("path"),
                "prompt_sha256": self.prompt.get("sha256"),
                "model": getattr(self.llm, "model_id", "?"),
                "llm_config_sha256": self.llm_config_sha256,
                "llm_parameters": describe() if callable(describe) else {}}

    def __call__(self, view: dict) -> dict:
        sec = self.prompt["sections"]
        current_view = dict(view)
        current_view["memory_tool_results"] = []
        found_records = set()
        for _ in range(4):
            api_events, safe_event = providers.event_recorder()
            fresh_budget = api_budget(self.llm)
            local_budget = fresh_budget if fresh_budget is not None else view.get('api_budget')
            reason = budget_stop_reason(local_budget)
            if reason:
                return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [], 'reason': reason}
            if self.hide_budget_amounts:
                current_view.pop('api_budget', None)
                current_view['api_call_allowed'] = True
            elif fresh_budget is not None:
                current_view['api_budget'] = fresh_budget
            user = fill(sec["USER"], context=json.dumps(current_view, ensure_ascii=False, indent=2))
            raw = None
            error_type = None
            try:
                raw = self.llm.complete_json(sec["SYSTEM"], user, _PlannerOutput.model_json_schema(), log=safe_event)
                out = _PlannerOutput.model_validate(raw)
            except Exception as e:
                error_type = type(e).__name__
                if self.run_dir:
                    self.run_dir.mkdir(parents=True, exist_ok=True)
                    with open(self.run_dir / "agent_plan_requests.jsonl", "a", encoding="utf-8") as f:
                        f.write(json.dumps({"system": sec["SYSTEM"], "user": user, "response_raw": raw,
                                            "api_events": api_events, "error_type": error_type,
                                            **self.metadata()}, ensure_ascii=False) + "\n")
                if isinstance(e, BudgetExhausted):     # chưa gửi yêu cầu: dừng gọn thay vì làm vỡ lượt
                    return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [],
                            'reason': f'hết ngân sách API cục bộ trước lời gọi planner: {e}'}
                if isinstance(e, providers.RefusalError):     # không gọi lại: dừng gọn, record ghi lý do
                    return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [],
                            'reason': f'mô hình từ chối lời gọi planner, không gọi lại: {e}'}
                raise

            if self.run_dir:
                self.run_dir.mkdir(parents=True, exist_ok=True)
                with open(self.run_dir / "agent_plan_requests.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"system": sec["SYSTEM"], "user": user, "response_raw": raw,
                                        "api_events": api_events, "error_type": error_type,
                                        **self.metadata()}, ensure_ascii=False) + "\n")

            if out.action in ("hunt", "pivot", "stop"):
                return {"action": out.action, "ttp_refs": out.ttp_refs, "pivot_targets": [t.model_dump() for t in out.pivot_targets], "reason": out.reason}

            if out.action == "tra_hunt_memory":
                if self.store:
                    tech = out.tra_hunt_memory.technique if out.tra_hunt_memory else None
                    rep = out.tra_hunt_memory.report_id if out.tra_hunt_memory else None
                    try:
                        matches = self.store.find(technique=tech or "", report=rep or "")
                        res = [{k: row[k] for k in ('record_id', 'report_id', 'executed_hunts') if k in row}
                               for row in matches[:10]]
                        found_records.update(r['record_id'] for r in res)
                        current_view["memory_tool_results"].append({"action": "tra_hunt_memory", "args": out.tra_hunt_memory.model_dump() if out.tra_hunt_memory else {}, "result": res, 'truncated': len(matches) > len(res)})
                    except Exception as e:
                        current_view["memory_tool_results"].append({"action": "tra_hunt_memory", "error": type(e).__name__})
                else:
                    current_view["memory_tool_results"].append({"action": "tra_hunt_memory", "error": "RecordStore not configured"})
            elif out.action == "doc_hunt_record":
                if self.store:
                    rec_id = out.doc_hunt_record.record_id if out.doc_hunt_record else ""
                    try:
                        if rec_id not in found_records:
                            raise ValueError('Record must come from this turn memory search')
                        item = self.store.read(rec_id)
                        rec = item['record']
                        # Never pass raw Markdown, arbitrary record metadata or filesystem paths to the planner.
                        res = {'record_id': rec_id, 'report_id': rec.get('report_id'),
                               'executed_hunts': len(rec.get('executed_specs') or []),
                               'observations': _safe_observations((rec.get('observations') or [])[:10]),
                               'decisions': [{'action': h['decision']['action'],
                                              'reason': str(h['decision'].get('reason', ''))[:1000]}
                                             for h in (rec.get('history') or [])[-10:]]}
                        preview = json.dumps(res, ensure_ascii=False)
                        current_view["memory_tool_results"].append({"action": "doc_hunt_record", "args": {"record_id": rec_id},
                            "result": {'summary_json_preview': preview[:12000], 'truncated': len(preview) > 12000}})
                    except Exception as e:
                        current_view["memory_tool_results"].append({"action": "doc_hunt_record", "error": type(e).__name__})
                else:
                    current_view["memory_tool_results"].append({"action": "doc_hunt_record", "error": "RecordStore not configured"})

        return {"action": "stop", "ttp_refs": [], "pivot_targets": [], "reason": "agent: reached maximum memory tool loops"}


class PipelinePlanner:
    """Chế độ pipeline (D10 A1): các khâu chạy theo thứ tự cố định, pivot do ngưỡng của mã quyết. Không gọi mô hình.

    1. Còn TTP huntable/partial chưa săn → theo điểm N5 giảm dần do StageTools cấp;
       hòa điểm giữ thứ tự Contract A, mỗi lô tối đa trần giả thuyết D7.
    2. Hết TTP → pivot vào các ứng viên đầu bảng do khâu ⑧ xếp hạng (cùng thứ tự `de_xuat` của lệnh `pivot`),
       trong trần pivot mỗi vòng và tổng suất truy vấn.
    3. Dừng khi chạm trần độ sâu, hết suất, hết ứng viên, hoặc vòng pivot vừa chọn không có giả thuyết nào được
       duyệt để chạy — lệnh `pivot` cũng dừng ở đó vì không có kết quả vòng mới.
    """

    def metadata(self) -> dict:
        return {"mode": "pipeline", "model": None,
                "quy_tac": "TTP theo điểm N5 giảm dần (hòa điểm giữ thứ tự Contract A), rồi pivot theo ngưỡng D7"}

    @staticmethod
    def _stop(reason: str) -> dict:
        return {"action": "stop", "ttp_refs": [], "pivot_targets": [], "reason": f"pipeline: {reason}"}

    def __call__(self, view: dict) -> dict:
        lim = view["limits"]
        refs = list(view.get("remaining_refs") or [])
        if refs:
            batch = refs[:int(lim["hypotheses_per_round"])]
            return {"action": "hunt", "ttp_refs": batch, "pivot_targets": [],
                    "reason": f"pipeline: săn {len(batch)}/{len(refs)} TTP còn lại theo thứ tự ưu tiên đầu vào N5"}
        prior = view.get("prior_decisions") or []
        if prior and prior[-1]["action"] == "pivot" and not view.get("last_round_executed"):
            return self._stop("vòng pivot trước không có giả thuyết được duyệt để thực thi")
        depth = int(view.get("pivot_depth", 0))
        if depth + 1 > int(lim["max_pivot_depth"]):
            return self._stop(f"đạt trần độ sâu ({lim['max_pivot_depth']})")
        room = min(int(lim["pivots_per_round"]), int(lim["queries_total"]) - int(view.get("queries_reserved", 0)))
        if room <= 0:
            return self._stop("hết suất truy vấn pivot")
        used = {(t["loai"], t["gia_tri"]) for d in prior for t in d.get("pivot_targets") or []}
        cands = [p for p in view.get("eligible_pivots") or []
                 if p["pivot_depth"] == depth + 1 and (p["loai"], p["gia_tri"]) not in used]
        if not cands:
            return self._stop("không còn thực thể vượt ngưỡng")
        chosen = cands[:room]
        return {"action": "pivot", "ttp_refs": [],
                "pivot_targets": [{"loai": p["loai"], "gia_tri": p["gia_tri"]} for p in chosen],
                "reason": f"pipeline: {len(chosen)}/{len(cands)} ứng viên đầu bảng theo ngưỡng D7"}


def configured_planner(run_dir: Path | None = None, *, root: Path = config.ROOT, version: str = "v1") -> LLMPlanner:
    """Dựng planner từ E3; chỉ tạo client, chưa gọi API hoặc mở tập dữ liệu."""
    root = Path(root)
    agent_cfg = config.agent_config(version, root)
    llm_cfg = config.load("agent_planner", root)
    if llm_cfg.get("budget_ledger"):
        llm_cfg["budget_ledger"] = str(config.resolve(llm_cfg["budget_ledger"], root))
    prompt = load_sections(config.resolve(agent_cfg["prompt_agent_plan"], root))
    return LLMPlanner(providers.from_config(llm_cfg), prompt, run_dir,
                      llm_config_sha256=integrity.sha256_file(root / "configs" / "agent_planner.yaml"), root=root,
                      memory_root=config.resolve(agent_cfg.get('memory_root', 'data/reports/moi'), root),
                      hide_budget_amounts=version == "v2")


class AgentTools(Protocol):
    def propose(self, state: AgentState, decision: Decision, run_dir: Path) -> list[ContractB]: ...
    def execute(self, state: AgentState, approved: list[ContractB]) -> dict: ...
    def record(self, state: AgentState) -> str: ...


_SAMPLE_FIELDS = {"ev_host", "ev_channel", "ev_rec", "ev_ts", "ParentImage", "Image",
                  "CommandLine", "User", "TargetUserName"}


def _safe_observations(observations: list[dict]) -> list[dict]:
    """Chỉ đưa trường sự kiện đã cho phép vào state/planner, kể cả tool trả thừa."""
    safe = []
    for obs in observations:
        stages = [{"stage": str(s["stage"]), "hits": int(s["hits"])} for s in obs["stages"]]
        sample = [{k: v for k, v in row.items() if k in _SAMPLE_FIELDS} for row in obs.get("sample") or []]
        safe.append({"hunt_id": str(obs["hunt_id"]), "hypothesis_id": str(obs.get("hypothesis_id") or ""),
                     "source": {"channel": str(obs["source"]["channel"]),
                                "event_ids": [int(x) for x in obs["source"]["event_ids"]]},
                     "stages": stages, "sample": sample})
    return safe


def _safe_pivots(pivots: list[dict]) -> list[dict]:
    return [{"loai": p["loai"], "gia_tri": str(p["gia_tri"]), "pivot_depth": int(p["pivot_depth"]),
             "tu_gia_thuyet": list(p["tu_gia_thuyet"]), "ly_do": str(p.get("ly_do") or "")}
            for p in pivots]


def _safe_rarity(summary: dict) -> dict:
    return {"so_su_kien": int(summary.get("so_su_kien", 0)),
            "top": [{k: row[k] for k in ("hunt_id", "ev_host", "ev_rec", "score") if k in row}
                    for row in (summary.get("top") or [])[:5]]}


def _safe_techniques(techniques: list[dict], remaining: set[int]) -> list[dict]:
    """Giữ whitelist cả ở mức thành phần điểm; không chuyển nguyên dict vào prompt."""
    rows = []
    for t in techniques:
        if t.get("ref") not in remaining:
            continue
        row = {k: t.get(k) for k in ("ref", "technique_id", "tactic", "behavior_description")}
        if "relevance_score" in t:
            row["relevance_score"] = t["relevance_score"]
            parts = t.get("relevance_components") or {}
            row["relevance_components"] = {
                k: parts[k] for k in ("segment_count", "max_confidence", "telemetry_status", "target_tactic",
                                      "community_coverage")
                if k in parts}
        rows.append(row)
    return rows


def _check_decision(choice: Decision, state: AgentState, cfg: dict) -> None:
    if choice.action == "stop":
        if choice.ttp_refs or choice.pivot_targets:
            raise AgentGuardError("dừng không được kèm TTP hoặc pivot")
        return
    if choice.action == "hunt":
        if not hypothesis_budget(state, cfg)['remaining']:
            raise AgentGuardError('đã hết trần giả thuyết độc lập (N5)')
        refs = choice.ttp_refs
        if choice.pivot_targets or not refs or len(refs) != len(set(refs)) or len(refs) > int(cfg["max_hypotheses_per_round"]):
            raise AgentGuardError("lô TTP không hợp lệ hoặc vượt trần D7")
        if not set(refs) <= set(state.get("remaining_refs") or []):
            raise AgentGuardError("planner chọn TTP ngoài danh sách còn lại")
        return
    targets = choice.pivot_targets
    t = cfg["triage"]
    if choice.ttp_refs or not targets or len(targets) > int(t["max_pivots_per_round"]):
        raise AgentGuardError("lô pivot không hợp lệ hoặc vượt trần mỗi vòng")
    if state.get("pivot_depth", 0) + 1 > int(cfg["max_pivot_depth"]):
        raise AgentGuardError("pivot vượt trần độ sâu D7")
    if state.get("queries_reserved", 0) + len(targets) > int(t["max_queries_total"]):
        raise AgentGuardError("pivot vượt trần tổng truy vấn D7")
    allowed = {(p["loai"], p["gia_tri"]) for p in state.get("eligible_pivots") or []
               if p["pivot_depth"] == state.get("pivot_depth", 0) + 1}
    chosen = {(p.loai, p.gia_tri) for p in targets}
    used = {(p["loai"], p["gia_tri"]) for h in state.get("history") or []
            for p in h["decision"].get("pivot_targets") or []}
    if len(chosen) != len(targets) or not chosen <= allowed or chosen & used:
        raise AgentGuardError("planner chọn thực thể không đủ điều kiện hoặc đã pivot")


def build_graph(planner: Planner, tools: AgentTools, cfg: dict, review_root: Path, checkpointer=None):
    """Graph phát triển trong một tiến trình; caller có thể cấp checkpointer bền vững sau này."""
    try:
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import interrupt
    except ImportError as e:
        raise RuntimeError("Cài extra [agent] để dùng LangGraph") from e

    review_root = Path(review_root)
    max_rounds = cfg.get("max_rounds", 20)
    if type(max_rounds) is not int or max_rounds < 1:
        raise AgentGuardError("max_rounds phải là số nguyên dương")
    try:
        hypothesis_budget({}, cfg)
    except ValueError as exc:
        raise AgentGuardError(str(exc)) from exc

    def plan(state: AgentState) -> dict:
        history_before = state.get("history") or []
        used = sum(h["decision"]["action"] in ("hunt", "pivot") for h in history_before)
        round_budget = {"used": used, "remaining": max(0, max_rounds - used), "limit": max_rounds}
        hyp_budget = hypothesis_budget(state, cfg)
        money_budget = api_budget(getattr(planner, 'llm', None),
                                  getattr(tools, 'llm_hypotheses', None), getattr(tools, 'llm_rules', None))
        meta = getattr(planner, "metadata", None)
        planner_meta = meta() if callable(meta) else None
        stop = ('đạt giới hạn số vòng tối đa (N5)' if used >= max_rounds else
                'đạt trần tổng giả thuyết độc lập (N5)' if not hyp_budget['remaining'] else
                f"hết ngân sách API cục bộ ở vòng trước: {state['budget_exhausted']}"
                if state.get('budget_exhausted') else budget_stop_reason(money_budget))
        if stop:
            choice = {"action": "stop", "ttp_refs": [], "pivot_targets": [], "reason": stop}
            update = {"decision": choice, "history": [*history_before,
                      {"decision": choice, "pivot_depth": state.get("pivot_depth", 0),
                       "round_budget": round_budget, 'hypothesis_budget': hyp_budget,
                       'api_budget': money_budget}]}
            if planner_meta is not None:
                update["planner_meta"] = planner_meta
            return update

        remaining = set(state.get("remaining_refs") or [])
        # Chỉ đưa planner đúng tập _check_decision cho phép: độ sâu kế tiếp, chưa pivot. 09/10 (UI, OTRF): vòng pivot
        # bị từ chối hết thì không có execute, danh sách cũ còn thực thể đã pivot; planner chọn lại và lượt dừng ở rào.
        next_depth = state.get("pivot_depth", 0) + 1
        pivoted = {(t["loai"], t["gia_tri"]) for h in state.get("history") or []
                   for t in h["decision"].get("pivot_targets") or []}
        view = {"report_id": state["report_id"], "remaining_refs": list(state.get("remaining_refs") or []),
                "techniques": _safe_techniques(state.get("techniques") or [], remaining),
                "round_budget": round_budget,
                "api_budget": money_budget,
                "hypothesis_budget": hyp_budget,
                "observations": _safe_observations(state.get("observations") or []),
                "rarity_summary": _safe_rarity(state.get("rarity_summary") or {}),
                "eligible_pivots": [p for p in _safe_pivots(state.get("eligible_pivots") or [])
                                    if p["pivot_depth"] == next_depth and (p["loai"], p["gia_tri"]) not in pivoted],
                "pivot_depth": state.get("pivot_depth", 0),
                "queries_reserved": state.get("queries_reserved", 0),
                "limits": {"hypotheses_per_round": cfg["max_hypotheses_per_round"],
                           "max_rounds": max_rounds,
                           "max_pivot_depth": cfg["max_pivot_depth"],
                           "pivots_per_round": cfg["triage"]["max_pivots_per_round"],
                           "queries_total": cfg["triage"]["max_queries_total"]},
                "prior_decisions": [h["decision"] for h in state.get("history") or []],
                # Vòng gần nhất có hunt nào được thực thi không (None khi chưa có vòng nào).
                "last_round_executed": (len(state["history"]) in (state.get("executed_rounds") or [])
                                        if state.get("history") else None)}
        choice = Decision.model_validate(planner(view))
        _check_decision(choice, state, cfg)
        entry = {"decision": choice.model_dump(), "pivot_depth": state.get("pivot_depth", 0),
                 "round_budget": round_budget, "candidate_scores": view["techniques"],
                 "hypothesis_budget": hyp_budget, "api_budget": money_budget}
        if choice.action == "stop":
            # N5 (02/10): planner chọn dừng khi mọi bộ chặn bằng mã (vòng, trần giả thuyết, ngân sách) chưa kích hoạt;
            # ghi phần còn lại để đếm được các lần dừng sớm, không đổi quyết định của planner (D10).
            entry["dung_do_planner"] = {"ttp_con_lai": len(view["remaining_refs"]),
                                        "pivot_du_dieu_kien": len(view["eligible_pivots"]),
                                        "bo_chan_ngan_sach_kich_hoat": False}
        if choice.action == "pivot":
            targets = {(p.loai, p.gia_tri) for p in choice.pivot_targets}
            entry["selected"] = [p for p in _safe_pivots(state.get("eligible_pivots") or [])
                                 if (p["loai"], p["gia_tri"]) in targets
                                 and p["pivot_depth"] == state.get("pivot_depth", 0) + 1]
        history = [*(state.get("history") or []), entry]
        update = {"decision": choice.model_dump(), "history": history}
        if planner_meta is not None:
            update["planner_meta"] = planner_meta
        if choice.action == "hunt":
            update["remaining_refs"] = [r for r in state["remaining_refs"] if r not in choice.ttp_refs]
        elif choice.action == "pivot":
            update["queries_reserved"] = state.get("queries_reserved", 0) + len(choice.pivot_targets)
        return update

    def after_plan(state: AgentState) -> str:
        return "record" if state["decision"]["action"] == "stop" else "propose"

    def propose(state: AgentState) -> dict:
        choice = Decision.model_validate(state["decision"])
        run_dir = review_root / f"round_{len(state['history']):02d}"
        if run_dir.exists() and any(run_dir.iterdir()):
            raise AgentGuardError(f"thư mục vòng đã có nội dung: {run_dir}")
        try:
            hyps = tools.propose(state, choice, run_dir)
        except BudgetExhausted as exc:
            # Chưa gửi yêu cầu ④: vòng này không có giả thuyết; ghi lý do để hunt record thấy TTP/pivot bị bỏ dở.
            history = [*state["history"][:-1], {**state["history"][-1], "generated_ids": [],
                                                 "het_ngan_sach": str(exc)}]
            return {"review_dir": "", "approved_ids": [], "history": history, "budget_exhausted": str(exc)}
        except providers.RefusalError as exc:
            # Đã gửi và đã tính tiền; không gọi lại, không đổi mô hình. Vòng này không có giả thuyết, lượt đi tiếp.
            history = [*state["history"][:-1], {**state["history"][-1], "generated_ids": [],
                                                 "mo_hinh_tu_choi": str(exc)}]
            return {"review_dir": "", "approved_ids": [], "history": history}
        if len(hyps) > int(cfg["max_hypotheses_per_round"]):
            raise AgentGuardError("công cụ sinh vượt trần giả thuyết D7")
        if choice.action == 'hunt' and len(hyps) > hypothesis_budget(state, cfg)['remaining']:
            raise AgentGuardError('công cụ sinh vượt trần tổng giả thuyết độc lập (N5)')
        if any(h.status != "pending_review" for h in hyps):
            raise AgentGuardError("giả thuyết mới phải chờ duyệt ◆")
        if choice.action == "pivot":
            targets = {(p.loai, p.gia_tri) for p in choice.pivot_targets}
            if any(h.origin != "pivot" or h.pivot_depth != state.get("pivot_depth", 0) + 1 or
                   (h.pivot_kind, h.pivot_value) not in targets for h in hyps):
                raise AgentGuardError("giả thuyết pivot không khớp thực thể/độ sâu đã chọn")
            used_targets = [(h.pivot_kind, h.pivot_value) for h in hyps]
            if len(used_targets) != len(set(used_targets)):
                raise AgentGuardError("mỗi thực thể pivot chỉ được một giả thuyết")
        elif any(h.origin != "telemetry_mapping" for h in hyps):
            raise AgentGuardError("giả thuyết vòng gốc có origin sai")
        if len({h.hypothesis_id for h in hyps}) != len(hyps):
            raise AgentGuardError("hypothesis_id trùng trong lô")
        generated = [*(state.get("generated_ids") or []), *(h.hypothesis_id for h in hyps)]
        if len(generated) != len(set(generated)):
            raise AgentGuardError("hypothesis_id trùng giữa các vòng")
        history = [*state["history"][:-1], {**state["history"][-1], "generated_ids": [h.hypothesis_id for h in hyps]}]
        if not hyps:
            return {"review_dir": "", "approved_ids": [], "generated_ids": generated, "history": history}
        # H5: danh mục hiệu lực của lượt làm căn cứ cho cảnh báo trên phiếu; tools không có thì chỉ so với câu nguồn.
        approval.write_review(hyps, run_dir, telemetry=getattr(tools, "telemetry", None))
        return {"review_dir": str(run_dir), "approved_ids": [], "generated_ids": generated, "history": history}

    def after_propose(state: AgentState) -> str:
        return "review" if state.get("review_dir") else "plan"

    def review(state: AgentState) -> dict:
        response = interrupt({"review_dir": state["review_dir"], "instruction": "Điền duyet.yaml rồi tiếp tục",
                              **({"review_kind": "hypothesis"} if cfg.get("filter_policy_id") else {})})
        if response is not True:
            raise AgentGuardError("chỉ tiếp tục sau khi người duyệt điền phiếu ◆")
        approval.apply_review(Path(state["review_dir"]))
        approved_file = Path(state["review_dir"]) / approval.APPROVED_FILE
        hyps = approval.load_hypotheses(approved_file)
        return {"approved_file": str(approved_file),
                "approved_files": [*(state.get("approved_files") or []), str(approved_file)],
                "approved_ids": [h.hypothesis_id for h in hyps if h.status == "approved"]}

    def after_review(state: AgentState) -> str:
        if not state.get("approved_ids"):
            return "plan"
        return "prepare_rules" if cfg.get("filter_policy_id") else "execute"

    def prepare_rules(state: AgentState) -> dict:
        hyps = [h for h in approval.load_hypotheses(Path(state["approved_file"])) if h.status == "approved"]
        return tools.prepare_rules(state, hyps)

    def after_prepare_rules(state: AgentState) -> str:
        from .. import filter_approval as filters
        return "review_filters" if filters.needs_review(Path(state["filter_review_dir"])) else "execute"

    def review_filters(state: AgentState) -> dict:
        from .. import filter_approval as filters
        rd = Path(state["filter_review_dir"])
        response = interrupt({"review_dir": str(rd), "review_kind": "filter",
                              "instruction": "Điền duyet_loc.yaml (và duyet_rule.yaml nếu có) rồi tiếp tục; "
                                             "không sinh lại rule; rút gọn rule thì phát bản sửa của gói để duyệt lại"})
        if response is not True:
            raise AgentGuardError("chỉ tiếp tục sau khi người duyệt điền phiếu lọc")
        filters.validate_form(rd, con=getattr(tools, "con", None))
        if filters.revision_requested(rd):
            # 10/10: rút gọn rule → phát bản sửa ngay trong node: rút gọn không làm được thì lỗi giữ lượt ở cổng để người
            # duyệt đổi quyết định. Bản sửa luôn quay lại cổng để người duyệt xem rule đã rút gọn trước khi chạy.
            return {**tools.revise_rules(state), "filter_revision_pending": True}
        return {"filter_revision_pending": False}

    def after_review_filters(state: AgentState) -> str:
        return "review_filters" if state.get("filter_revision_pending") else "execute"

    def execute(state: AgentState) -> dict:
        hyps = [h for h in approval.load_hypotheses(Path(state["approved_file"])) if h.status == "approved"]
        depths = {h.pivot_depth for h in hyps}
        if len(depths) != 1:
            raise AgentGuardError("một lô thực thi phải có cùng độ sâu pivot")
        output = tools.execute(state, hyps)
        observations = _safe_observations(output.get("observations") or [])
        pivots = _safe_pivots(output.get("eligible_pivots") or [])
        update = {"observations": observations, "eligible_pivots": pivots,
                  "rarity_summary": _safe_rarity(output.get("rarity_summary") or {}),
                  "pivot_depth": depths.pop(),
                  "executed_rounds": [*(state.get("executed_rounds") or []), len(state["history"])],
                  "executed_specs": [*(state.get("executed_specs") or []), *(output.get("spec_files") or [])]}
        if cfg.get("filter_policy_id") and not output.get("spec_files"):
            update["executed_rounds"] = state.get("executed_rounds") or []
        if output.get("budget_exhausted"):
            update["budget_exhausted"] = output["budget_exhausted"]
        return update

    def record(state: AgentState) -> dict:
        return {"record": tools.record(state)}

    builder = StateGraph(AgentState)
    for name, node in (("plan", plan), ("propose", propose), ("review", review),
                       ("prepare_rules", prepare_rules), ("review_filters", review_filters),
                       ("execute", execute), ("record", record)):
        builder.add_node(name, node)
    builder.add_edge(START, "plan")
    builder.add_conditional_edges("plan", after_plan, {"record": "record", "propose": "propose"})
    builder.add_conditional_edges("propose", after_propose, {"review": "review", "plan": "plan"})
    builder.add_conditional_edges("review", after_review, {"execute": "execute", "plan": "plan", "prepare_rules": "prepare_rules"})
    builder.add_conditional_edges("prepare_rules", after_prepare_rules, {"review_filters": "review_filters", "execute": "execute"})
    builder.add_conditional_edges("review_filters", after_review_filters,
                                  {"review_filters": "review_filters", "execute": "execute"})
    builder.add_edge("execute", "plan")
    builder.add_edge("record", END)
    return builder.compile(checkpointer=checkpointer or InMemorySaver())


@contextmanager
def open_sqlite_graph(planner: Planner, tools: AgentTools, cfg: dict, review_root: Path, db_path: Path):
    """Giữ trạng thái graph trên đĩa để tiếp tục sau khi người vận hành điền phiếu D5."""
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
    except ImportError as e:
        raise RuntimeError("Cài extra [agent] để có checkpoint SQLite") from e
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with SqliteSaver.from_conn_string(str(db_path)) as saver:
        yield build_graph(planner, tools, cfg, review_root, checkpointer=saver)
