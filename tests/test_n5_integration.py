"""N5 trên fixture tự soạn: không API, không dữ liệu đánh giá hay nhãn thật."""
import json

import pytest
import yaml
from langgraph.types import Command

from cti_hunt import approval
from cti_hunt.agent.graph import AgentGuardError, PipelinePlanner, build_graph, open_sqlite_graph
from cti_hunt.agent.stage_tools import StageTools
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.stages.s4_hypothesis import select_inputs


def settings(**overrides):
    return {"max_rounds": 20, "max_hypotheses_per_round": 1, "max_pivot_depth": 2,
            "triage": {"max_pivots_per_round": 3, "max_queries_total": 20}, **overrides}


def ttp(tid, segment, confidence=.8):
    return TTP(technique_id=tid, tactic="Discovery", confidence=confidence,
               source_span=SourceSpan(segment_id=segment, text="Mô tả tự soạn"))


def state(count=25):
    return {"report_id": "SYN", "remaining_refs": list(range(count)),
            "techniques": [{"ref": i, "technique_id": "T1047"} for i in range(count)],
            "history": [], "generated_ids": [], "pivot_depth": 0}


class EmptyTools:
    def __init__(self):
        self.proposals = 0

    def propose(self, state, decision, run_dir):
        self.proposals += 1
        return []

    def execute(self, state, approved):
        raise AssertionError("không có giả thuyết thì không thực thi")

    def record(self, state):
        return "fixture-record"


def test_score_counts_unique_source_segments_not_duplicate_ttp_rows():
    ca = ContractA(report_id="SYN", ttps=[ttp("T1047", "S1"), ttp("T1047", "S1"),
                                          ttp("T1047", None), ttp("T1021", "S2"),
                                          ttp("T1021", "S3")])
    telemetry = {tid: {"status": "huntable", "sources": []} for tid in ("T1047", "T1021")}
    inputs, _ = select_inputs(ca, telemetry)
    assert [i["ref"] for i in inputs] == [3, 4, 0, 1, 2]
    assert inputs[0]["score_components"]["segment_count"] == 2
    assert inputs[-1]["score_components"]["segment_count"] == 1


def test_score_ties_preserve_refs_and_missing_sources_do_not_invent_mentions():
    ca = ContractA(report_id="SYN", ttps=[ttp("T1047", None), ttp("T1021", " "),
                                          ttp("T1047", None), ttp("T1059", "S4")])
    telemetry = {tid: {"status": "huntable", "sources": []} for tid in ("T1047", "T1021")}
    inputs, gaps = select_inputs(ca, telemetry)
    assert [i["ref"] for i in inputs] == [0, 1, 2]
    assert all(i["score_components"]["segment_count"] == 0 for i in inputs)
    assert [g["ref"] for g in gaps] == [3]


def test_scores_reach_planner_and_history_while_agent_can_choose_lower_score(tmp_path):
    ca = ContractA(report_id="SYN", ttps=[ttp("T1047", "S1", .2), ttp("T1021", "S2", .9)])
    telemetry = {"T1047": {"status": "partial", "sources": []},
                 "T1021": {"status": "huntable", "sources": []}}
    stage = StageTools(ca, telemetry, {}, None, settings(), None, None, {}, {}, {}, tmp_path,
                       dataset_kind="fixture", dataset_id="synthetic-N5")
    initial = stage.initial_state()
    assert initial["remaining_refs"] == [1, 0]
    assert initial["techniques"][0]["relevance_score"] > initial["techniques"][1]["relevance_score"]
    # Even injected fields must not leak through the planner whitelist.
    initial["techniques"][0]["attack_labels"] = "fixture sentinel"
    initial["techniques"][0]["relevance_components"]["attack_labels"] = "fixture sentinel"
    views = []

    def planner(view):
        views.append(view)
        assert "attack_labels" not in json.dumps(view)
        assert view["techniques"][0]["relevance_score"] > view["techniques"][1]["relevance_score"]
        assert view["round_budget"] == {"used": 0, "remaining": 1, "limit": 1}
        return {"action": "hunt", "ttp_refs": [0], "reason": "chọn điểm thấp hơn vì bối cảnh fixture"}

    tools = EmptyTools()
    done = build_graph(planner, tools, settings(max_rounds=1), tmp_path).invoke(
        initial, {"configurable": {"thread_id": "scores"}})
    assert len(views) == tools.proposals == 1
    assert done["remaining_refs"] == [1]
    assert done["history"][0]["candidate_scores"] == views[0]["techniques"]
    assert done["history"][-1]["round_budget"]["remaining"] == 0
    assert done["record"] == "fixture-record"


@pytest.mark.parametrize("mode", ["pipeline", "agent"])
def test_twenty_empty_rounds_stop_normally_without_langgraph_recursion_error(tmp_path, mode):
    calls = []

    def agent(view):
        calls.append(view)
        return {"action": "hunt", "ttp_refs": view["remaining_refs"][:1], "reason": "fixture"}

    planner = PipelinePlanner() if mode == "pipeline" else agent
    tools = EmptyTools()
    done = build_graph(planner, tools, settings(), tmp_path).invoke(
        state(), {"configurable": {"thread_id": mode}})
    assert tools.proposals == 20
    assert done["record"] == "fixture-record"
    assert len(done["history"]) == 21  # 20 attempts plus the explicit stop record.
    assert done["remaining_refs"] == [20, 21, 22, 23, 24]
    assert done["history"][-1]["round_budget"] == {"used": 20, "remaining": 0, "limit": 20}
    if mode == "agent":
        assert len(calls) == 20  # No billable planner call after exhaustion.
    else:
        assert done["planner_meta"]["mode"] == "pipeline"


@pytest.mark.parametrize("approved", [True, False])
def test_round_limit_survives_checkpoint_and_finishes_last_review(tmp_path, approved):
    class ReviewTools(EmptyTools):
        executions = 0

        def propose(self, state, decision, run_dir):
            self.proposals += 1
            return [ContractB(hypothesis_id="SYN-H01", behavior="fixture", scope="fixture", timeframe="fixture",
                              evidence=Evidence(data_source="Security", event_ids=[4688], key_fields=["Image"]),
                              linked_ttps=["T1047"])]

        def execute(self, state, hypotheses):
            self.executions += 1
            return {"observations": []}

    cfg = settings(max_rounds=1)
    tools = ReviewTools()
    db = tmp_path / "state.sqlite"
    thread = {"configurable": {"thread_id": "resume"}}
    with open_sqlite_graph(PipelinePlanner(), tools, cfg, tmp_path, db) as graph:
        first = graph.invoke(state(2), thread)
    assert "__interrupt__" in first and tools.executions == 0
    form_file = tmp_path / "round_01" / approval.REVIEW_FILE
    form = yaml.safe_load(form_file.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "fixture tester"
    form["gia_thuyet"][0]["quyet_dinh"] = "approved" if approved else "rejected"
    form["gia_thuyet"][0]["ly_do"] = "quyết định fixture tự soạn"
    form_file.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    with open_sqlite_graph(PipelinePlanner(), tools, cfg, tmp_path, db) as graph:
        done = graph.invoke(Command(resume=True), thread)
    assert tools.proposals == 1 and tools.executions == int(approved)
    assert done["record"] == "fixture-record" and done["remaining_refs"] == [1]
    assert done["history"][-1]["round_budget"]["remaining"] == 0


@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, "20", None])
def test_invalid_round_limit_rejected_before_any_planner_call(tmp_path, invalid):
    with pytest.raises(AgentGuardError, match="max_rounds"):
        build_graph(PipelinePlanner(), EmptyTools(), settings(max_rounds=invalid), tmp_path)


