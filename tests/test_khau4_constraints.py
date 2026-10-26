"""④ v5 → ◆ → ⑤ → truy vấn không nhãn → ⑨, chỉ văn bản và events tổng hợp."""
import re

import pytest
import yaml
from pydantic import ValidationError

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.agent.graph import Decision
from cti_hunt.agent.stage_tools import StageTools
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractA, ContractB, SourceSpan, TTP
from cti_hunt.data.store import connect
from cti_hunt.hunt.observe import unlabeled_result
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient, strict_schema
from cti_hunt.stages import execution_semantics as ES, s4_hypothesis as S4, s5_rule as S5, s8_pivot, s9_record

SYS = "microsoft-windows-sysmon/operational"
CFG = agent_config("v2")
P4 = load_sections(ROOT / CFG["prompt_khau4"])
PP = load_sections(ROOT / CFG["prompt_khau4_pivot"])
P5 = {"sections": {"SYSTEM": "s", "USER": "{hypothesis}\n{logsources}", "REPAIR": "{rule_yaml}{issues}{logsources}"}}
LS = A.load_catalog(ROOT / "configs/logsource_catalog.yaml")
TELEMETRY = {"T1059": {"status": "huntable", "sources": [
    {"channel": SYS, "event_ids": [1], "key_fields": ["Image", "ParentImage"]},
    {"channel": "security", "event_ids": [4688], "key_fields": ["NewProcessName"]}]}}
CA = ContractA(report_id="DEV", ttps=[TTP(tactic="Execution", technique_id="T1059",
    behavior_description="Tiến trình được mô tả trong văn bản phát triển tự soạn.",
    source_span=SourceSpan(segment_id="DEV-001", text="Văn bản tự soạn: ít nhất 2 tên tiến trình khác nhau cùng máy "
        "và tiến trình cha trong ±60 giây; sự kiện tạo tiến trình không có bản ghi nguồn kia trong 1 giây trước; "
        "tiến trình xuất hiện sau dấu vết neo, không quá 51 giây, cùng máy."))])
BASE = {"ttp_refs": [0], "behavior": "Tiến trình theo điều kiện nguồn", "scope": "mọi máy",
        "timeframe": "toàn bộ khoảng thời gian của log", "data_source": SYS, "event_ids": [1],
        "key_fields": ["Image", "ParentImage"], "extra_techniques": [], "priority": "cao", "rationale": "câu tự soạn"}
COUNT = {"dem_khac_nhau": {"truong": "Image", "theo": ["ev_host", "ParentImage"],
                          "cua_so_giay": 60, "toi_thieu": 2}}
ABSENCE = {"vang_mat": {"channel": SYS, "event_ids": [1],
                       "khop": [{"ung_vien": "ev_host", "nguon": "ev_host"}], "truoc_giay": 1}}
ANCHOR = {"moc_neo": {"gia_thuyet": "DEV-H00", "trong_vong_giay": 51, "cung": ["ev_host"]}}
ANCHOR_H = ContractB(hypothesis_id="DEV-H00", behavior="Tiến trình neo theo nguồn tự soạn", scope="mọi máy",
    timeframe="toàn bộ log", evidence={"data_source": SYS, "event_ids": [1], "key_fields": ["Image", "ParentImage"]},
    linked_ttps=["T1059"], source_spans=[CA.ttps[0].source_span], status="approved")
ANCHOR_SPEC = {"scope": {"channel": SYS, "event_ids": [1]}, "candidates": "ParentImage ILIKE '%wmiprvse.exe'", "filters": []}
EXE = """title: Fixture process
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
"""
SEC = """title: Fixture security process
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '.exe'
  condition: selection
"""


def generate(rb, *, anchors=(), item=None, cfg=CFG, directory=None):
    llm = MockClient(responses=[{"items": [{**BASE, "rang_buoc": rb, **(item or {})}]}])
    return S4.generate(CA, TELEMETRY, llm, P4, cfg, run_dir=directory, anchors=list(anchors)), llm


@pytest.mark.parametrize("rb,change,rule,keys,before,op", [
    (COUNT, {}, EXE, {("UTICA", 11), ("UTICA", 12)}, 5, "distinct_count"),
    (ABSENCE, {"data_source": "security", "event_ids": [4688], "key_fields": ["NewProcessName"]},
     SEC, {("UTICA", 20)}, 2, "absence"),
    (ANCHOR, {}, EXE, {("UTICA", 11)}, 5, "event_sequence"),
])
def test_generated_constraint_survives_review_execution_and_record(work, tmp_path, rb, change, rule, keys, before, op):
    res, llm = generate(rb, anchors=[ANCHOR_H], item={**change, "required_operations": [op]}, directory=tmp_path / "io")
    h = res["hypotheses"][0]
    assert h.rang_buoc.model_dump(exclude_none=True) == rb
    assert h.status == "pending_review" and h.source_spans == [CA.ttps[0].source_span]
    assert res["log"]["prompt_sha256"] == P4["sha256"] and len(llm.calls) == 1
    assert ES.issues(h) == []
    review = tmp_path / "review"
    path = approval.write_review([h], review)
    form = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert form["gia_thuyet"][0]["rang_buoc"] == rb
    with pytest.raises(approval.NotApprovedError):
        S5.generate_rule(h, MockClient(), P5, LS, 0)
    # Only the synthetic review form is approved in this test.
    form["nguoi_duyet"] = "Fixture reviewer"
    form["gia_thuyet"][0]["quyet_dinh"] = "approved"
    path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    approval.apply_review(review)
    approved = approval.load_hypotheses(review / approval.APPROVED_FILE)[0]
    assert approved.rang_buoc == h.rang_buoc
    con = connect(work)
    try:
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        built = S5.generate_rule(approved, MockClient(responses=[{"rule_yaml": rule}]), P5, LS, 0, cols, con,
                                anchors={"DEV-H00": ES.anchor_sql([ANCHOR_SPEC])})
        assert built["hop_le"], built
        spec = built["hunt_specs"][0]
        result = unlabeled_result(con, spec)
        rows = con.execute(f"SELECT ev_host, ev_rec FROM events WHERE ev_channel = ? AND ev_eid IN "
                           f"({','.join(map(str, spec['scope']['event_ids']))}) AND ({spec['candidates']})",
                           [spec["scope"]["channel"]]).fetchall()
        assert set(rows) == keys
        assert result["rang_buoc"]["ung_vien_truoc_rang_buoc"] == before
        assert result["rang_buoc"]["dieu_kien"] == rb
        record = s9_record.render(CA, TELEMETRY, [approved], [result])
        assert s9_record._constraint_text(rb) in record and "không có trong SPL" in record
    finally:
        con.close()


@pytest.mark.parametrize("rb,error", [
    ({"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "truong": "Bia"}}, "rang_buoc_truong_ngoai_danh_muc"),
    ({"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "theo": ["Image"]}}, "rang_buoc_thieu_may"),
    ({"vang_mat": {**ABSENCE["vang_mat"], "channel": "not_collected"}}, "rang_buoc_nguon_ngoai_danh_muc"),
    ({"vang_mat": {**ABSENCE["vang_mat"], "event_ids": [22]}}, "rang_buoc_nguon_ngoai_danh_muc"),
    ({"vang_mat": {**ABSENCE["vang_mat"], "khop": ABSENCE["vang_mat"]["khop"] + [
        {"ung_vien": "Image", "nguon": "NewProcessName"}]}}, "rang_buoc_truong_ngoai_danh_muc"),
    ({"vang_mat": {**ABSENCE["vang_mat"], "khop": [{"ung_vien": "Image", "nguon": "Image"}]}}, "rang_buoc_thieu_may"),
    (ANCHOR, "rang_buoc_moc_neo_chua_chay"),
    ({"moc_neo": {**ANCHOR["moc_neo"], "cung": ["Image"]}}, "rang_buoc_thieu_may"),
])
def test_invalid_constraint_rejects_hypothesis_with_reason(rb, error):
    result, _ = generate(rb)
    assert result["hypotheses"] == []
    assert result["log"]["ma_sua"] == {error: 1}


@pytest.mark.parametrize("rb", [
    {}, {"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "toi_thieu": 1}},
    {"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "cua_so_giay": 0}},
    {"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "truong": 'x" OR 1=1'}},
    {"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "sql": "TRUE"}},
    {"vang_mat": {**ABSENCE["vang_mat"], "khop": [{"ung_vien": "ev_host", "nguon": "ev_host", "op": "or"}]}},
])
def test_invalid_parameters_fail_schema_instead_of_losing_condition(rb):
    with pytest.raises(ValidationError):
        S4.LLMHypothesisBatchV2.model_validate({"items": [{**BASE, "rang_buoc": rb}]})
    result, _ = generate(rb)
    assert result["hypotheses"] == [] and result["log"]["ma_sua"] == {"dau_ra_sai_luoc_do": 1}


ALL_NULL = {"dem_khac_nhau": None, "moc_neo": None, "vang_mat": None}


def test_all_null_constraint_object_means_no_constraint_and_keeps_the_batch():
    # Dạng mô hình trả ở đánh giá v2 mới 08/10: object đủ ba khóa, cả ba null. Trước đây cả lô bị loại.
    item = S4.LLMHypothesisBatchV2.model_validate({"items": [{**BASE, "rang_buoc": ALL_NULL}]}).items[0]
    assert item.rang_buoc is None
    result, _ = generate(ALL_NULL)
    plain, _ = generate(None)
    assert "dau_ra_sai_luoc_do" not in result["log"]["ma_sua"]
    assert [h.model_dump(mode="json") for h in result["hypotheses"]] == [h.model_dump(mode="json") for h in plain["hypotheses"]]
    # Chỉ đúng dạng đủ ba khóa null mới quy về null; thêm khóa lạ vẫn bị từ chối, RangBuoc trực tiếp vẫn đòi một loại.
    with pytest.raises(ValidationError):
        S4.LLMHypothesisBatchV2.model_validate({"items": [{**BASE, "rang_buoc": {**ALL_NULL, "sql": None}}]})
    with pytest.raises(ValidationError):
        S4.RangBuoc.model_validate(ALL_NULL)


def test_pivot_batch_with_all_null_constraint_is_not_lost():
    selected = [{"loai": "may", "gia_tri": "HOST", "pivot_depth": 1, "tu_gia_thuyet": ["DEV-H00"]}]
    plan = {"selected": selected, "source_depth": 0, "triage": {"pivot": {"de_xuat": selected}}}
    llm = MockClient(responses=[{"items": [{**BASE, "rang_buoc": ALL_NULL}]}])
    result = s8_pivot.generate_round(CA, TELEMETRY, [ANCHOR_H], plan, llm, PP, CFG, anchors=[ANCHOR_H])
    assert len(result["hypotheses"]) == 1 and result["hypotheses"][0].rang_buoc is None
    assert "dau_ra_sai_luoc_do" not in result["log"]["chi_tiet"][0]["ma_sua"]


def test_constraint_dedup_does_not_erase_different_windows():
    items = [S4.LLMHypothesisV2(**BASE, rang_buoc=rb) for rb in [COUNT, COUNT,
        {"dem_khac_nhau": {**COUNT["dem_khac_nhau"], "cua_so_giay": 30}}]]
    hyps, log = S4.postprocess(items, S4.select_inputs(CA, TELEMETRY)[0], "DEV", 10)
    assert len(hyps) == 2 and log["trung_gia_thuyet"] == 1


def test_v1_schema_and_unconstrained_contract_remain_unchanged():
    assert "rang_buoc" not in S4.output_model(agent_config("v1")).model_json_schema()["$defs"]["LLMHypothesis"]["properties"]
    old = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [BASE]}]), P4, agent_config("v1"))["hypotheses"][0]
    new = generate(None)[0]["hypotheses"][0]
    assert old.model_dump(mode="json") == new.model_dump(mode="json")


def test_transport_schema_is_strict_and_bounds_stay_local():
    local = S4.LLMHypothesisBatchV2.model_json_schema()
    wire = strict_schema(local)
    assert local["$defs"]["DemKhacNhau"]["properties"]["toi_thieu"]["minimum"] == 2
    assert "minimum" not in wire["$defs"]["DemKhacNhau"]["properties"]["toi_thieu"]
    def check(node):
        if isinstance(node, dict):
            if "properties" in node:
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                check(value)
        elif isinstance(node, list):
            for value in node:
                check(value)
    check(wire)


def test_new_prompts_no_attck_ids_and_no_old_capability_claim():
    for prompt in (P4, PP):
        text = (ROOT / prompt["path"]).read_text(encoding="utf-8")
        assert not re.search(r"\bT\d{4}", text)
        assert "It does not implement distinct counts" not in text
        assert "All numeric values must be explicitly supported" in text
        assert '"toàn bộ khoảng thời gian của log"' in text
        assert "to?n" not in text and "Kh?u" not in text


def test_only_executed_approved_hypotheses_are_shown_as_anchors(tmp_path, work):
    cfg = {**CFG}
    cfg.pop("filter_policy_id")
    con = connect(work)
    try:
        llm = MockClient(responses=[{"items": [{**BASE, "rang_buoc": ANCHOR}]}])
        tools = StageTools(CA, TELEMETRY, LS, con, cfg, llm, MockClient(), P4, PP, P5,
                           tmp_path, dataset_kind="fixture", dataset_id="synthetic")
        review = tmp_path / "prior"
        approval.write_review([ANCHOR_H, ANCHOR_H.model_copy(update={"hypothesis_id": "DEV-H99"})], review)
        state = {"report_id": "DEV", "generated_ids": ["DEV-H00", "DEV-H99"],
                 "approved_files": [str(review / approval.HYP_FILE)],
                 "executed_specs": [{"hypothesis_id": "DEV-H00"}]}
        hyps = tools.propose(state, Decision(action="hunt", ttp_refs=[0], reason="fixture"), tmp_path / "new")
        assert hyps[0].rang_buoc.moc_neo.gia_thuyet == "DEV-H00"
        user = llm.calls[0][1]
        assert '"hypothesis_id": "DEV-H00"' in user and "DEV-H99" not in user
        assert "{executed_hypotheses}" not in user
    finally:
        con.close()


def test_pivot_keeps_constraint_and_checks_executed_anchor():
    selected = [{"loai": "may", "gia_tri": "HOST", "pivot_depth": 1, "tu_gia_thuyet": ["DEV-H00"]}]
    plan = {"selected": selected, "source_depth": 0, "triage": {"pivot": {"de_xuat": selected}}}
    for anchors, n in (([], 0), ([ANCHOR_H], 1)):
        llm = MockClient(responses=[{"items": [{**BASE, "rang_buoc": ANCHOR}]}])
        result = s8_pivot.generate_round(CA, TELEMETRY, [ANCHOR_H], plan, llm, PP, CFG, anchors=anchors)
        assert len(result["hypotheses"]) == n
        if n:
            h = result["hypotheses"][0]
            assert h.rang_buoc.moc_neo.gia_thuyet == "DEV-H00" and h.pivot_value == "HOST"
        else:
            assert result["log"]["chi_tiet"][0]["ma_sua"] == {"rang_buoc_moc_neo_chua_chay": 1}


def test_anchor_matching_field_must_exist_on_both_event_families():
    rb = {"moc_neo": {**ANCHOR["moc_neo"], "cung": ["ev_host", "NewProcessName"]}}
    result, _ = generate(rb, anchors=[ANCHOR_H], item={"data_source": "security", "event_ids": [4688],
                                                     "key_fields": ["NewProcessName"]})
    assert result["hypotheses"] == []
    assert result["log"]["ma_sua"] == {"rang_buoc_truong_ngoai_danh_muc": 1}


def test_unsupported_operation_is_still_blocked_when_an_unrelated_constraint_is_present():
    result, _ = generate(COUNT, item={"required_operations": ["distinct_count", "absence"]})
    assert [issue["operation"] for issue in ES.issues(result["hypotheses"][0])] == ["absence"]


def test_parameterised_count_window_does_not_require_an_unrelated_anchor():
    result, _ = generate(COUNT, item={"behavior": "Tiến trình có nhiều tên Image khác nhau trong 60 giây",
                                    "required_operations": ["distinct_count"]})
    h = result["hypotheses"][0]
    assert ES.issues(h) == []
    h.behavior += "; sau sự kiện neo trước đó"
    assert [issue["operation"] for issue in ES.issues(h)] == ["relative_time"]
