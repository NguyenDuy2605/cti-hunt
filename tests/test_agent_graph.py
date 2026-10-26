"""Graph D10 chạy trên fixture tự tạo; không đọc tập đánh giá hay nhãn."""
import duckdb
import json
import pytest
import yaml
from langgraph.types import Command

from cti_hunt import approval
from cti_hunt.agent.graph import (AgentGuardError, Decision, LLMPlanner, _check_decision,
                                  configured_planner, open_sqlite_graph)
from cti_hunt.agent.stage_tools import StageTools
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.integrity import sha256_file
from cti_hunt.contracts import ContractA, ContractB, Evidence, SourceSpan, TTP
from cti_hunt.hunt.observe import run_unlabeled
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s3_telemetry, s8_triage

SYS = "microsoft-windows-sysmon/operational"
CFG = load_cfg("agent")


@pytest.fixture
def con():
    c = duckdb.connect()
    c.execute("""CREATE TABLE events (
        ev_host VARCHAR, ev_channel VARCHAR, ev_rec INTEGER, ev_eid INTEGER, ev_ts TIMESTAMP,
        ParentImage VARCHAR, Image VARCHAR, CommandLine VARCHAR, "User" VARCHAR)""")
    c.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        ("A", SYS, 1, 1, "2020-01-01 00:00:00", "C:\\WmiPrvSE.exe", "C:\\powershell.exe", "whoami", "D\\alice"),
        ("A", SYS, 2, 1, "2020-01-01 00:00:02", "C:\\WmiPrvSE.exe", "C:\\cmd.exe", "net user", "D\\alice"),
        ("B", SYS, 3, 1, "2020-01-01 00:00:04", "C:\\WmiPrvSE.exe", "C:\\powershell.exe", "", "D\\bob"),
    ])
    return c


def _hyp(hid, **kw):
    return ContractB(hypothesis_id=hid, behavior=f"Dấu vết {hid}", scope="máy được chọn",
                     timeframe="toàn bộ", evidence=Evidence(data_source=SYS, event_ids=[1],
                                                              key_fields=["ParentImage", "Image"]),
                     linked_ttps=["T1047"], source_spans=[SourceSpan(text="Đoạn CTI tự soạn")], **kw)


def _spec(hid, expression):
    return {"id": hid, "hypothesis_id": hid, "scope": {"channel": SYS, "event_ids": [1]},
            "candidates": expression, "filters": []}


def test_unlabeled_hunt_counts_filters_and_exposes_only_events(con):
    spec = _spec("TU-H01", "ParentImage ILIKE '%WmiPrvSE.exe'")
    spec["filters"] = [{"id": "good", "where": "ev_host = 'B'", "ly_do": "tự tạo",
                        "nguoi_chiu_trach_nhiem": "tester", "het_han": "2027-01-01"}]
    output = run_unlabeled(con, spec)
    assert [s["hits"] for s in output["stages"]] == [3, 3, 2]
    assert {row["ev_host"] for row in output["sample"]} == {"A"}
    assert "buoc" not in str(output) and "attack_labels" not in str(output)


class FixtureTools:
    def __init__(self, con):
        self.con = con
        self.executions = 0

    def propose(self, state, decision, run_dir):
        if decision.action == "hunt":
            if state.get("generated_ids"):
                return [_hyp("TU-H04")]
            return [_hyp("TU-H01"), _hyp("TU-H02")]
        p = decision.pivot_targets[0]
        return [_hyp("TU-H03", origin="pivot", pivot_depth=1,
                     pivot_kind=p.loai, pivot_value=p.gia_tri)]

    def execute(self, state, approved):
        self.executions += 1
        if state["decision"]["action"] == "hunt":
            if any(h.hypothesis_id == "TU-H04" for h in approved):
                specs = [_spec("TU-H04", "ev_host = 'B'")]
            else:
                specs = [_spec("TU-H01", "ParentImage ILIKE '%WmiPrvSE.exe'"),
                         _spec("TU-H02", "ev_host = 'A' AND Image ILIKE '%powershell.exe'")]
        else:
            specs = [_spec("TU-H03", "ev_host = 'A'")]
        observations = [run_unlabeled(self.con, s) for s in specs]
        observations[0]["sample"][0]["buoc"] = "không được tới planner"
        tri = s8_triage.triage(self.con, specs, CFG, pivot_depth=approved[0].pivot_depth,
                              queries_used=state.get("queries_reserved", 0))
        return {"observations": observations, "eligible_pivots": tri["pivot"]["de_xuat"]}

    def record(self, state):
        return f"record:{len(state['history'])}"


def _approve(path):
    form_path = path / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "người vận hành"
    for h in form["gia_thuyet"]:
        h["quyet_dinh"] = "approved"
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")


def test_graph_pauses_for_review_and_never_sends_label_fields(con, tmp_path):
    seen = []

    def planner(view):
        seen.append(view)
        assert "buoc" not in str(view)
        if len(seen) == 1:
            assert [t["ref"] for t in view["techniques"]] == [0, 1, 2]
            return {"action": "hunt", "ttp_refs": [0, 1], "reason": "thử hai dấu vết"}
        if len(seen) == 2:
            assert any(p["gia_tri"] == "A" for p in view["eligible_pivots"])
            return {"action": "pivot", "pivot_targets": [{"loai": "may", "gia_tri": "A"}],
                    "reason": "hai giả thuyết cùng máy"}
        if len(seen) == 3:
            assert view["pivot_depth"] == 1
            return {"action": "hunt", "ttp_refs": [2], "reason": "quay lại TTP còn lại"}
        return {"action": "stop", "reason": "đã kiểm đủ"}

    tools = FixtureTools(con)
    config = {"configurable": {"thread_id": "fixture-TU"}}
    initial = {"report_id": "TU", "remaining_refs": [0, 1, 2],
               "techniques": [{"ref": 0, "technique_id": "T1047", "tactic": "Lateral Movement",
                               "behavior_description": "Dấu vết WMI"},
                              {"ref": 1, "technique_id": "T1047", "tactic": "Lateral Movement",
                               "behavior_description": "Tiến trình con WMI"},
                              {"ref": 2, "technique_id": "T1047", "tactic": "Lateral Movement",
                               "behavior_description": "Dấu vết còn lại"}], "observations": [],
               "eligible_pivots": [], "pivot_depth": 0, "queries_reserved": 0, "history": []}
    db = tmp_path / "checkpoint.sqlite"
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        first = graph.invoke(initial, config)
    assert "__interrupt__" in first and tools.executions == 0
    _approve(tmp_path / "round_01")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        second = graph.invoke(Command(resume=True), config)
    assert "__interrupt__" in second and tools.executions == 1
    _approve(tmp_path / "round_02")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        third = graph.invoke(Command(resume=True), config)
    assert "__interrupt__" in third and tools.executions == 2
    _approve(tmp_path / "round_03")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        done = graph.invoke(Command(resume=True), config)
    assert done["record"] == "record:4"
    assert done["queries_reserved"] == 1 and done["pivot_depth"] == 0
    assert tools.executions == 3


def test_planner_view_drops_pivoted_entity_after_rejected_pivot_round(con, tmp_path):
    """Vòng pivot bị từ chối hết thì không execute; danh sách cũ không được đưa lại thực thể đã pivot."""
    seen = []

    def planner(view):
        seen.append(view)
        if len(seen) == 1:
            return {"action": "hunt", "ttp_refs": [0, 1], "reason": "thử hai dấu vết"}
        if len(seen) == 2:
            assert ("may", "A") in {(p["loai"], p["gia_tri"]) for p in view["eligible_pivots"]}
            return {"action": "pivot", "pivot_targets": [{"loai": "may", "gia_tri": "A"}], "reason": "cùng máy"}
        assert ("may", "A") not in {(p["loai"], p["gia_tri"]) for p in view["eligible_pivots"]}
        assert all(p["pivot_depth"] == view["pivot_depth"] + 1 for p in view["eligible_pivots"])
        return {"action": "stop", "reason": "không còn thực thể chưa pivot"}

    tools = FixtureTools(con)
    config = {"configurable": {"thread_id": "fixture-TU-rejected-pivot"}}
    initial = {"report_id": "TU", "remaining_refs": [0, 1],
               "techniques": [{"ref": i, "technique_id": "T1047", "tactic": "Lateral Movement",
                               "behavior_description": f"Dấu vết {i}"} for i in (0, 1)], "observations": [],
               "eligible_pivots": [], "pivot_depth": 0, "queries_reserved": 0, "history": []}
    db = tmp_path / "checkpoint.sqlite"
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        graph.invoke(initial, config)
    _approve(tmp_path / "round_01")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        assert "__interrupt__" in graph.invoke(Command(resume=True), config)
    form_path = tmp_path / "round_02" / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "người vận hành"
    for h in form["gia_thuyet"]:
        h["quyet_dinh"], h["ly_do"] = "rejected", "fixture: từ chối cả vòng pivot"
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        done = graph.invoke(Command(resume=True), config)
    assert done["record"] == "record:3" and tools.executions == 1 and len(seen) == 3
    assert ("may", "A") in {(p["loai"], p["gia_tri"]) for p in done["eligible_pivots"]}  # state giữ nguyên


def test_planner_cannot_override_eligibility_or_caps():
    state = {"remaining_refs": [0], "eligible_pivots": [{"loai": "may", "gia_tri": "A", "pivot_depth": 1}],
             "pivot_depth": 0, "queries_reserved": 20, "history": []}
    with pytest.raises(AgentGuardError, match="ngoài danh sách"):
        _check_decision(Decision(action="hunt", ttp_refs=[9], reason="sai"), state, CFG)
    with pytest.raises(AgentGuardError, match="trần tổng"):
        _check_decision(Decision(action="pivot", pivot_targets=[{"loai": "may", "gia_tri": "A"}],
                                 reason="hết suất"), state, CFG)
    state["queries_reserved"] = 0
    with pytest.raises(AgentGuardError, match="không đủ điều kiện"):
        _check_decision(Decision(action="pivot", pivot_targets=[{"loai": "may", "gia_tri": "B"}],
                                 reason="ngoài danh sách"), state, CFG)
    state["pivot_depth"] = 2
    with pytest.raises(AgentGuardError, match="độ sâu"):
        _check_decision(Decision(action="pivot", pivot_targets=[{"loai": "may", "gia_tri": "A"}],
                                 reason="quá sâu"), state, CFG)


def test_llm_planner_uses_safe_context_with_mock(tmp_path):
    mock = MockClient(responses=[{"action": "stop", "ttp_refs": [], "pivot_targets": [], "reason": "đủ dấu vết"}])
    planner = LLMPlanner(mock, load_sections(ROOT / CFG["prompt_agent_plan"]), run_dir=tmp_path)
    decision = planner({"remaining_refs": [], "observations": []})
    assert decision["action"] == "stop" and "remaining_refs" in mock.calls[0][1]
    log = json.loads((tmp_path / "agent_plan_requests.jsonl").read_text(encoding="utf-8"))
    assert log["model"] == "mock" and log["response_raw"]["action"] == "stop"


def test_e2_e3_config_builds_distinct_planner_payload_without_api(tmp_path):
    planner = configured_planner(tmp_path)
    assert CFG["evaluation"]["independent_runs_per_report"] == 3
    assert load_cfg("llm")["effort"] == "high"  # khâu ② giữ cấu hình riêng
    assert load_cfg("llm")["model"] == "claude-opus-5-5"  # ② v1 đã chạy chính thức
    assert planner.llm.model_id == "claude-sonnet-5"      # E3 v2, 26/9
    payload = planner.llm.build_payload("system", "user", Decision.model_json_schema())
    assert payload["output_config"] == {"effort": "medium"}
    assert payload["tool_choice"] == {"type": "auto"}
    assert payload["tools"][0]["strict"] is True
    assert "temperature" not in payload
    assert planner.metadata()["llm_config_sha256"] == sha256_file(ROOT / "configs" / "agent_planner.yaml")


def test_planner_logs_failed_call_without_provider_error_body(tmp_path):
    class FailingClient:
        model_id = "fixture-model"

        def complete_json(self, system, user, json_schema, log=None):
            log({"lan": 1, "http": 400, "thu_lai": False, "loi": "secret from HTTP body"})
            raise ValueError("fixture failure")

    planner = LLMPlanner(FailingClient(), load_sections(ROOT / CFG["prompt_agent_plan"]), run_dir=tmp_path)
    with pytest.raises(ValueError, match="fixture failure"):
        planner({"remaining_refs": []})
    logged = (tmp_path / "agent_plan_requests.jsonl").read_text(encoding="utf-8")
    assert "secret from HTTP body" not in logged
    row = json.loads(logged)
    assert row["error_type"] == "ValueError" and row["api_events"] == [
        {"lan": 1, "http": 400, "thu_lai": False}]


def test_stage_tools_run_actual_stages_on_fixture(con, tmp_path):
    ca = ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", behavior_description=f"Dấu vết WMI {i}",
        source_span=SourceSpan(segment_id=f"TU-{i}", text="Mô tả tự soạn"), confidence=0.9)
        for i in range(2)])
    item = {"ttp_refs": [0], "scope": "mọi máy", "timeframe": "toàn bộ", "data_source": SYS,
            "event_ids": [1], "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}
    h4 = MockClient(responses=[{"items": [{**item, "behavior": "Dấu vết WMI thứ nhất"},
                                          {**item, "ttp_refs": [1], "behavior": "Dấu vết WMI thứ hai"}]},
                               {"items": [{**item, "behavior": "Tiến trình con sau pivot"}]}])
    rule = (ROOT / "hunts" / "sigma" / "H-03.yml").read_text(encoding="utf-8")
    h5 = MockClient(responses=[{"rule_yaml": rule} for _ in range(3)])
    tools = StageTools(
        ca, s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml"),
        duckdb_sigma.load_catalog(ROOT / "configs" / "logsource_catalog.yaml"), con, CFG, h4, h5,
        load_sections(ROOT / CFG["prompt_khau4"]), load_sections(ROOT / CFG["prompt_khau4_pivot"]),
        load_sections(ROOT / CFG["prompt_khau5"], ("SYSTEM", "USER", "REPAIR")), tmp_path,
        dataset_kind="fixture", dataset_id="TU-agent-v1")
    turns = []

    def planner(view):
        turns.append(view)
        if len(turns) == 1:
            return {"action": "hunt", "ttp_refs": [0, 1], "reason": "hai dấu vết trong CTI"}
        if len(turns) == 2:
            assert any(p["gia_tri"] == "A" for p in view["eligible_pivots"])
            assert view["rarity_summary"]["so_su_kien"] > 0
            return {"action": "pivot", "pivot_targets": [{"loai": "may", "gia_tri": "A"}],
                    "reason": "hai dấu vết trên A"}
        return {"action": "stop", "reason": "hết hướng có ích"}

    state = tools.initial_state()
    assert state["remaining_refs"] == [0, 1]
    config = {"configurable": {"thread_id": "stage-tools-TU"}}
    db = tmp_path / "checkpoint.sqlite"
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        first = graph.invoke(state, config)
    assert "__interrupt__" in first and h5.calls == []
    _approve(tmp_path / "round_01")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        second = graph.invoke(Command(resume=True), config)
    assert "__interrupt__" in second and len(h5.calls) == 2
    _approve(tmp_path / "round_02")
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        done = graph.invoke(Command(resume=True), config)
    assert len(h5.calls) == 3 and done["queries_reserved"] == 1
    assert done["record"].endswith("agent_dev_record.json")
    record = json.loads((tmp_path / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert record["kind"] == "development_only_unlabeled"
    assert "buoc" not in json.dumps(record)
    assert (tmp_path / "round_01" / "agent_execute.json").exists()
    assert (tmp_path / "round_02" / "hunts").exists()


def test_stage_tools_rejects_unidentified_dev_dataset(con, tmp_path):
    with pytest.raises(ValueError, match="SHA256"):
        StageTools(ContractA(report_id="TU"), {}, {}, con, CFG, MockClient(), MockClient(),
                   {}, {}, {}, tmp_path, dataset_kind="otrf_dev", dataset_id="otrf-technique")
    with pytest.raises(ValueError, match="E1"):
        StageTools(ContractA(report_id="TU"), {}, {}, con, CFG, MockClient(), MockClient(),
                   {}, {}, {}, tmp_path, dataset_kind="apt29_eval", dataset_id="day2")


def test_agent_can_choose_eligible_pivot_outside_pipeline_top_one():
    c = duckdb.connect()
    c.execute("""CREATE TABLE events (ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER,
              ev_rec INTEGER, ev_ts TIMESTAMP, Image VARCHAR, "User" VARCHAR)""")
    c.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", [
        (host, SYS, 1, i, "2020-01-01 00:00:00", "x.exe", "D\\alice")
        for i, host in enumerate(["A", "B", "C", "D"], start=1)])
    specs = [_spec("TU-H01", "TRUE"), _spec("TU-H02", "TRUE")]
    cfg = {**CFG, "triage": {**CFG["triage"], "max_pivots_per_round": 1}}
    tri = s8_triage.triage(c, specs, cfg)
    assert len(tri["pivot"]["de_xuat"]) == 1
    assert {p["gia_tri"] for p in tri["pivot"]["ung_vien_du_dieu_kien"] if p["loai"] == "may"} == {
        "A", "B", "C", "D"}
    state = {"remaining_refs": [], "eligible_pivots": tri["pivot"]["ung_vien_du_dieu_kien"],
             "pivot_depth": 0, "queries_reserved": 0, "history": []}
    _check_decision(Decision(action="pivot", pivot_targets=[{"loai": "may", "gia_tri": "D"}],
                             reason="chọn D"), state, cfg)
