"""Đề xuất A: không đủ tiền giữ trước thì lượt dừng gọn và vẫn có hunt record.

Chỉ lỗi trước khi gửi (BudgetExhausted) được xử lý mềm; lỗi sau khi đã gửi hoặc yêu cầu chưa rõ chi phí vẫn dừng lượt.
Sổ ngân sách tổng hợp, công cụ và mô hình giả; không gọi API, không đọc nhãn.
"""
import copy
import json
from types import SimpleNamespace

import pytest
import yaml
from langgraph.types import Command

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.agent.graph import LLMPlanner, PipelinePlanner, build_graph, open_sqlite_graph
from cti_hunt.agent.limits import api_budget, budget_stop_reason
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.llm.budget import BudgetError, BudgetExhausted, Ledger, min_reserve
from cti_hunt.llm.prompting import load_sections
from cti_hunt.stages import s3_telemetry, s5_rule, s8_pivot

SYS = "microsoft-windows-sysmon/operational"
AGENT = load_cfg("agent")
LS = duckdb_sigma.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
RULE_PROMPT = load_sections(ROOT / AGENT["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
CFG = {"max_rounds": 20, "max_total_independent_hypotheses": 10, "max_hypotheses_per_round": 2,
       "max_pivot_depth": 2, "triage": {"max_pivots_per_round": 3, "max_queries_total": 20}}
CA = ContractA(report_id="TU", ttps=[TTP(
    tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi qua WMI",
    source_span=SourceSpan(segment_id="TU-001", text="Mô tả tự soạn về WMI."), confidence=0.9)])
NO_MONEY = "Không đủ ngân sách: cần dự phòng 0.330000 USD, còn 0.100000 USD. Chưa gửi yêu cầu sinh nội dung"


def _hyp(hid, **changes):
    data = {"hypothesis_id": hid, "behavior": f"Tiến trình con của WMI {hid}", "scope": "mọi máy",
            "timeframe": "toàn bộ log", "evidence": Evidence(data_source=SYS, event_ids=[1],
                                                       key_fields=["ParentImage", "Image"]),
            "linked_ttps": ["T1047"], "source_spans": [CA.ttps[0].source_span], "status": "approved"}
    return ContractB(**{**data, **changes})


class Scripted:
    """Trả lần lượt từng đầu ra; phần tử là ngoại lệ thì ném ra (mô phỏng sổ từ chối trước khi gửi)."""
    model_id = "synthetic"

    def __init__(self, *outputs):
        self.outputs, self.calls = list(outputs), 0

    def complete_json(self, system, user, schema, log=None):
        self.calls += 1
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def test_only_pre_send_refusals_are_budget_exhaustion(tmp_path):
    ledger = Ledger(tmp_path / "b.sqlite")
    ledger.init("0.5")
    with pytest.raises(BudgetExhausted, match="Không đủ ngân sách"):
        ledger.reserve("claude-sonnet-5", 600_000)
    rid = ledger.reserve("claude-sonnet-5", 100_000)
    with pytest.raises(BudgetError) as pending:                    # yêu cầu chưa quyết toán: không phải hết tiền
        ledger.require_ready()
    assert not isinstance(pending.value, BudgetExhausted)
    ledger.settle(rid, "claude-sonnet-5", {"input_tokens": 0, "output_tokens": 50_000})     # 0,5 USD
    with pytest.raises(BudgetExhausted, match="hết hạn mức"):
        ledger.require_ready()


def test_stop_before_a_call_that_cannot_be_reserved(tmp_path):
    ledger = Ledger(tmp_path / "b.sqlite")
    ledger.init("0.3")
    client = SimpleNamespace(budget_ledger=ledger.path, model_id="claude-sonnet-5", max_output_tokens=32000)
    assert min_reserve("claude-sonnet-5", 32000) == 256 * 2 + 32000 * 10
    budget = api_budget(client)
    assert budget["min_reserve_usd"] == "0.320512"
    assert "không đủ giữ trước" in budget_stop_reason(budget)
    ledger.set_limit("0.4")
    assert budget_stop_reason(api_budget(client)) == ""


def test_rule_generation_stops_without_losing_paid_attempts():
    r = s5_rule.generate_rule(_hyp("TU-H01"), Scripted(BudgetExhausted(NO_MONEY)), RULE_PROMPT, LS, 2)
    assert (r["hop_le"], r["so_lan_sua"], r["rule_yaml"]) == (False, 0, None)
    assert r["lan_thu"][0]["loi"][0]["kind"] == "het_ngan_sach" and NO_MONEY in s5_rule.budget_exhausted(r)

    llm = Scripted({"rule_yaml": "title: [", "note": "rule hỏng"}, BudgetExhausted(NO_MONEY))
    r = s5_rule.generate_rule(_hyp("TU-H01"), llm, RULE_PROMPT, LS, 2)
    assert llm.calls == 2 and [a["loai"] for a in r["lan_thu"]] == ["sinh", "bo_qua"]
    assert r["lan_thu"][0]["rule_yaml"] == "title: [" and not r["hop_le"] and r["hunt_specs"] == []
    skipped = s5_rule.budget_skipped(_hyp("TU-H02"), s5_rule.budget_exhausted(r))
    assert skipped["lan_thu"][0]["loi"] == [{"kind": "het_ngan_sach", "message": s5_rule.budget_exhausted(r)}]


def test_other_llm_errors_still_stop_rule_generation():
    with pytest.raises(BudgetError, match="usage"):
        s5_rule.generate_rule(_hyp("TU-H01"), Scripted(BudgetError("API không trả usage hợp lệ")),
                              RULE_PROMPT, LS, 2)


def _pivot_plan():
    selected = [{"loai": "may", "gia_tri": host, "pivot_depth": 1, "tu_gia_thuyet": ["TU-H01"]}
                for host in ("A", "B")]
    return {"selected": selected, "triage": {"pivot": {"de_xuat": selected}}, "source_depth": 0}


def test_pivot_keeps_paid_hypotheses_and_logs_skipped_entities(tmp_path):
    telemetry = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
    prompt = load_sections(ROOT / AGENT["prompt_khau4_pivot"])
    cfg = copy.deepcopy(AGENT)
    item = {"ttp_refs": [0], "behavior": "Tiến trình con của WMI trên máy được chọn", "scope": "máy được chọn",
            "timeframe": "toàn bộ khoảng thời gian của log", "data_source": SYS, "event_ids": [1],
            "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}
    out = s8_pivot.generate_round(CA, telemetry, [_hyp("TU-H01")], _pivot_plan(),
                                  Scripted({"items": [item]}, BudgetExhausted(NO_MONEY)), prompt, cfg,
                                  run_dir=tmp_path)
    assert [(h.pivot_kind, h.pivot_value) for h in out["hypotheses"]] == [("may", "A")]
    skipped = [d for d in out["log"]["chi_tiet"] if "ly_do_bo" in d]
    assert [(d["gia_tri"], "hết ngân sách" in d["ly_do_bo"]) for d in skipped] == [("B", True)]
    with pytest.raises(BudgetExhausted):                            # chưa có giả thuyết nào: báo graph dừng
        s8_pivot.generate_round(CA, telemetry, [_hyp("TU-H01")], _pivot_plan(),
                                Scripted(BudgetExhausted(NO_MONEY)), prompt, cfg)


class Tools:
    def __init__(self, propose_error=None, execute_output=None):
        self.propose_error, self.execute_output, self.executed = propose_error, execute_output or {}, 0

    def propose(self, state, decision, run_dir):
        if self.propose_error:
            raise self.propose_error
        return [_hyp(f"TU-H{i}", status="pending_review") for i in (1, 2)]

    def execute(self, state, approved):
        self.executed += 1
        return dict(self.execute_output)

    def record(self, state):
        return "record"


def _initial():
    return {"report_id": "TU", "remaining_refs": [0, 1, 2], "history": [], "generated_ids": []}


def test_exhausted_proposal_ends_the_run_with_a_record(tmp_path):
    views = []

    def planner(view):
        views.append(view)
        return PipelinePlanner()(view)
    out = build_graph(planner, Tools(propose_error=BudgetExhausted(NO_MONEY)), CFG, tmp_path).invoke(
        _initial(), {"configurable": {"thread_id": "het-tien-4"}})
    assert out["record"] == "record" and len(views) == 1
    hunt, stop = out["history"]
    assert hunt["decision"]["action"] == "hunt" and hunt["het_ngan_sach"] == NO_MONEY
    assert stop["decision"]["action"] == "stop" and "hết ngân sách" in stop["decision"]["reason"]
    assert not (tmp_path / "round_01" / approval.REVIEW_FILE).exists()


def test_post_send_errors_are_not_swallowed_by_the_graph(tmp_path):
    with pytest.raises(BudgetError, match="usage"):
        build_graph(PipelinePlanner(), Tools(propose_error=BudgetError("API không trả usage hợp lệ")),
                    CFG, tmp_path).invoke(_initial(), {"configurable": {"thread_id": "sau-khi-gui"}})


def test_exhausted_rules_stop_the_next_round_without_planning(tmp_path):
    calls = []

    def planner(view):
        calls.append(view)
        return PipelinePlanner()(view)
    tools = Tools(execute_output={"budget_exhausted": NO_MONEY})
    db, thread = tmp_path / "checkpoint.sqlite", {"configurable": {"thread_id": "het-tien-5"}}
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        assert "__interrupt__" in graph.invoke(_initial(), thread)
    form_path = tmp_path / "round_01" / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "người thử"
    for row in form["gia_thuyet"]:
        row.update(quyet_dinh="approved", ly_do="thử")
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        out = graph.invoke(Command(resume=True), thread)
    assert tools.executed == 1 and len(calls) == 1 and out["record"] == "record"
    assert out["remaining_refs"] == [2]                             # TTP còn lại không bị tiêu vào vòng không tiền
    assert "vòng trước" in out["history"][-1]["decision"]["reason"]


def test_llm_planner_stops_instead_of_crashing(tmp_path):
    prompt = {"sections": {"SYSTEM": "tổng hợp", "USER": "{context}"}}
    decision = LLMPlanner(Scripted(BudgetExhausted(NO_MONEY)), prompt, tmp_path)({})
    assert decision["action"] == "stop" and "hết ngân sách" in decision["reason"]
    log = json.loads((tmp_path / "agent_plan_requests.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert log["error_type"] == "BudgetExhausted"
    with pytest.raises(BudgetError, match="usage"):
        LLMPlanner(Scripted(BudgetError("API không trả usage hợp lệ")), prompt, tmp_path)({})
