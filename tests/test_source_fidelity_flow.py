"""Self-authored CTI and synthetic events only; mock is not a model-quality measurement."""
import json
from datetime import datetime, timedelta

import duckdb
import pytest
import yaml

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma as adapter
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractA, ContractB, SourceSpan, TTP
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import execution_semantics as ES, s4_hypothesis as S4, s5_rule as S5

SYS = "microsoft-windows-sysmon/operational"
CFG = agent_config("v2")
P4 = load_sections(ROOT / CFG["prompt_khau4"])
P5 = load_sections(ROOT / CFG["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
LS = adapter.load_catalog(ROOT / "configs/logsource_catalog.yaml")
QUOTES = [
    "Self-authored: a process connects to at least two distinct destination IPs in the centered interval "
    "45 seconds before to 45 seconds after a connection, on the same host with the same process GUID.",
    "Self-authored: a connection has no collected DNS query for the same host and process GUID "
    "during the inclusive 30 seconds preceding it.",
    "Self-authored: a file is created strictly after the process starts, within at most 75 seconds, "
    "on the same host with the same process GUID.",
]
FIELDS = ["Image", "ProcessGuid", "DestinationIp", "DestinationPort", "QueryName", "TargetFilename"]
CA = ContractA(report_id="FIDELITY", ttps=[
    TTP(tactic="Command and Control", technique_id="T1105" if n == 2 else "T1071", behavior_description=q,
        source_span=SourceSpan(segment_id=f"SELF-{n}", text=q)) for n, q in enumerate(QUOTES)])
TELEMETRY = {tid: {"status": "huntable", "sources": [
    {"channel": SYS, "event_ids": [eid], "key_fields": FIELDS} for eid in [3, 22, 11]]}
    for tid in ["T1071", "T1105"]}
CONSTRAINTS = [
    {"dem_khac_nhau": {"truong": "DestinationIp", "theo": ["ev_host", "ProcessGuid"],
                      "cua_so_giay": 45, "toi_thieu": 2}},
    {"vang_mat": {"channel": SYS, "event_ids": [22], "truoc_giay": 30, "khop": [
        {"ung_vien": "ev_host", "nguon": "ev_host"},
        {"ung_vien": "ProcessGuid", "nguon": "ProcessGuid"}]}},
    {"moc_neo": {"gia_thuyet": "SELF-ANCHOR", "trong_vong_giay": 75, "cung": ["ev_host", "ProcessGuid"]}},
]
BEHAVIORS = [
    "Kết nối tới ít nhất 2 IP đích khác nhau trong cửa sổ ±45 giây, cùng máy và ProcessGuid.",
    "Kết nối không có bản ghi DNS cùng máy và ProcessGuid trong 30 giây liền trước sự kiện kết nối đó, gồm hai đầu.",
    "Tạo tệp sau sự kiện khởi tạo tiến trình, không quá 75 giây, cùng máy và ProcessGuid.",
]
OPS = ["distinct_count", "absence", "event_sequence"]
ANCHOR = ContractB(hypothesis_id="SELF-ANCHOR", behavior="Khởi tạo tiến trình tự soạn",
    scope="mọi máy", timeframe="toàn bộ khoảng thời gian của log", status="approved",
    linked_ttps=["T1059"], source_spans=[SourceSpan(text="Self-authored process start.")],
    evidence={"data_source": SYS, "event_ids": [1], "key_fields": ["ProcessGuid"]})


def proposal(n):
    return {"ttp_refs": [n], "behavior": BEHAVIORS[n], "scope": "mọi máy",
            "timeframe": "toàn bộ khoảng thời gian của log", "data_source": SYS,
            "event_ids": [11 if n == 2 else 3], "key_fields": FIELDS,
            "rationale": f"Căn cứ: {QUOTES[n]}. Dấu vết: nguồn và trường đã cho.",
            "required_operations": [OPS[n]], "rang_buoc": CONSTRAINTS[n]}


def rule(n):
    eid = 11 if n == 2 else 3
    category = "file_event" if n == 2 else "network_connection"
    return yaml.safe_dump({"title": "Self-authored primary trace", "status": "experimental",
                          "logsource": {"product": "windows", "category": category},
                          "detection": {"selection": {"EventID": eid}, "condition": "selection"},
                          "level": "medium"})


def approve_fixture(h, directory):
    # Only this test's temporary synthetic form is approved; no real user form is touched.
    path = approval.write_review([h], directory)
    form = yaml.safe_load(path.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "Synthetic fixture reviewer"
    form["gia_thuyet"][0]["quyet_dinh"] = "approved"
    path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    approval.apply_review(directory)
    return approval.load_hypotheses(directory / approval.APPROVED_FILE)[0]


def hypothesis_from_request(user):
    # Parse the actual JSON object embedded in the production prompt; do not compare strings only.
    return json.JSONDecoder().raw_decode(user[user.index('{'):])[0]


@pytest.fixture
def events():
    con = duckdb.connect()
    con.execute("CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, "
                "ev_ts TIMESTAMP, ProcessGuid VARCHAR, Image VARCHAR, DestinationIp VARCHAR, "
                "DestinationPort INTEGER, QueryName VARCHAR, TargetFilename VARCHAR, Initiated BOOLEAN, EventID INTEGER)")
    yield con
    con.close()


def add(con, rec, eid, seconds, guid, *, host="HOST-A", ip="10.0.0.1", initiated=False):
    con.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, 'fixture.exe', ?, 8443, NULL, 'fixture.bin', ?, ?)",
                [host, SYS, eid, rec, datetime(2020, 1, 1) + timedelta(seconds=seconds), guid, ip, initiated, eid])


def populate(con, n):
    if n == 0:
        # Private IPs and inbound connections are intentionally retained: the source restricts neither.
        for rec, sec, guid, ip in [(1, -45, 'g1', '10.0.0.1'), (2, 0, 'g1', '10.0.0.1'),
                                   (3, 45, 'g1', '10.0.0.2'), (4, 0, 'g2', '10.0.0.1'),
                                   (5, 46, 'g2', '10.0.0.2'), (7, 0, 'g3', '10.0.0.1'),
                                   (8, 1, 'g3', '10.0.0.1')]:
            add(con, rec, 3, sec, guid, ip=ip)
        add(con, 6, 3, 45, 'g2', host='HOST-B', ip='10.0.0.2')
        return {2, 3}, 8
    if n == 1:
        for rec in range(1, 9):
            add(con, rec, 3, 0, f'g{rec}' if rec != 8 else '')
        for rec, sec, guid in [(20, -30, 'g2'), (21, 0, 'g3'), (22, -31, 'g4'), (23, 1, 'g5')]:
            add(con, rec, 22, sec, guid)
        add(con, 24, 22, -15, 'g6', host='HOST-B')
        add(con, 25, 22, -15, 'other-guid')
        return {1, 4, 5, 6, 7}, 8
    add(con, 100, 1, 0, 'g1')
    for rec, sec, guid in [(1, 0, 'g1'), (2, 75, 'g1'), (3, 76, 'g1'),
                           (4, 1, 'g1'), (5, -1, 'g1'), (7, 1, 'g2')]:
        add(con, rec, 11, sec, guid)
    add(con, 6, 11, 1, 'g1', host='HOST-B')
    return {2, 4}, 7


@pytest.mark.parametrize("n", [0, 1, 2])
def test_faithful_mock_flows_through_review_repair_and_constraint_execution(n, events, tmp_path):
    expected, before = populate(events, n)
    llm4 = MockClient(responses=[{"items": [proposal(n)]}])
    res = S4.generate(CA, TELEMETRY, llm4, P4, CFG, anchors=[ANCHOR])
    h = res["hypotheses"][0]
    assert h.source_spans == [CA.ttps[n].source_span] and h.behavior == BEHAVIORS[n]
    assert h.rang_buoc.model_dump(exclude_none=True) == CONSTRAINTS[n]
    approved = approve_fixture(h, tmp_path / "review")
    cols = {r[0] for r in events.execute("DESCRIBE events").fetchall()}
    anchors = {ANCHOR.hypothesis_id: f"SELECT * FROM events WHERE ev_channel = '{SYS}' AND ev_eid = 1"}
    if n == 2:
        assert events.execute(anchors[ANCHOR.hypothesis_id]).fetchall()  # Execute the synthetic anchor first.
    llm5 = MockClient(responses=[{"rule_yaml": "invalid: ["}, {"rule_yaml": rule(n)}])
    result = S5.generate_rule(approved, llm5, P5, LS, 1, cols, events, anchors=anchors)
    assert result["hop_le"] and not result["hop_le_lan_dau"] and result["so_lan_sua"] == 1, result
    assert len(llm5.calls) == 2
    for _, user in llm5.calls:
        obj = hypothesis_from_request(user)
        assert obj["rang_buoc"] == approved.rang_buoc.model_dump(mode="json")
        assert obj["required_operations"] == [OPS[n]] and obj["behavior"] == BEHAVIORS[n]
        assert "source_spans" not in obj and QUOTES[n] not in user
        assert "{hypothesis}" not in user
    assert hypothesis_from_request(llm5.calls[0][1]) == hypothesis_from_request(llm5.calls[1][1])
    assert result["lan_thu"][0]["loi"][0]["kind"] == "yaml_loi"
    spec = result["hunt_specs"][0]
    assert spec["rang_buoc"]["dieu_kien"] == CONSTRAINTS[n]
    base_keys = events.execute(f"SELECT ev_rec FROM events WHERE ev_eid = {11 if n == 2 else 3} "
                              f"AND ({spec['rang_buoc']['candidates_goc']})").fetchall()
    assert len(base_keys) == before
    rows = events.execute(f"SELECT ev_rec FROM events WHERE ev_eid = {11 if n == 2 else 3} "
                          f"AND ({spec['candidates']})").fetchall()
    assert {r[0] for r in rows} == expected
    # Structured conditions are bound once by code, never written into the fixture's Sigma rule.
    assert yaml.safe_load(result["rule_yaml"])["detection"] == yaml.safe_load(rule(n))["detection"]
    assert approved.rang_buoc == h.rang_buoc and approved.behavior == h.behavior


@pytest.mark.parametrize("n", [0, 1, 2])
def test_unapproved_constraints_cannot_reach_rule_model(n):
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(n)]}]), P4, CFG, anchors=[ANCHOR])
    llm = MockClient()
    with pytest.raises(approval.NotApprovedError):
        S5.generate_rule(res["hypotheses"][0], llm, P5, LS, 1)
    assert llm.calls == []


def test_missing_executed_anchor_blocks_before_rule_model():
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(2)]}]), P4, CFG, anchors=[ANCHOR])
    h = res["hypotheses"][0].model_copy(update={"status": "approved"})
    llm = MockClient()
    result = S5.generate_rule(h, llm, P5, LS, 1)
    assert not result["hop_le"] and result["lan_thu"][0]["loi"][0]["kind"] == "thieu_moc_neo"
    assert llm.calls == []


def test_unconstrained_v1_request_is_unchanged():
    h = ANCHOR.model_copy(update={"status": "approved", "required_operations": []})
    cfg = agent_config("v1")
    old = load_sections(ROOT / cfg["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
    text = yaml.safe_dump({"title": "Fixture", "logsource": {"product": "windows", "category": "process_creation"},
                           "detection": {"selection": {"EventID": 1}, "condition": "selection"}})
    llm = MockClient(responses=[{"rule_yaml": text}])
    result = S5.generate_rule(h, llm, old, LS, 0)
    assert result["hop_le"]
    obj = hypothesis_from_request(llm.calls[0][1])
    assert obj == h.model_dump(include={"hypothesis_id", "behavior", "scope", "timeframe", "evidence", "linked_ttps"})
    assert "rang_buoc" not in obj and "required_operations" not in obj and "source_spans" not in obj


@pytest.mark.parametrize("suffix", ["; sau sự kiện neo trước đó", "; trong 30 giây sau", "; trong 31 giây trước"])
def test_absence_window_exemption_does_not_hide_other_relative_conditions(suffix):
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(1)]}]), P4, CFG)
    h = res["hypotheses"][0]
    assert ES.issues(h) == []
    h.behavior += suffix
    assert [i["operation"] for i in ES.issues(h)] == ["relative_time"]


@pytest.mark.parametrize("phrase", ["trong 30 giây trước", "trong 30 giây trước kết nối",
                                  "within 30 seconds before the connection event"])
def test_named_primary_absence_window_is_not_a_second_anchor(phrase):
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(1)]}]), P4, CFG)
    h = res["hypotheses"][0]
    h.behavior = "Không có bản ghi DNS cùng máy và ProcessGuid " + phrase + ", gồm hai đầu."
    assert ES.issues(h) == []


@pytest.mark.parametrize("phrase", ["trong 30 giây trước sự kiện khởi tạo tiến trình",
                                  "trong 31 giây trước sự kiện kết nối", "trong 30 giây sau sự kiện kết nối"])
def test_absence_cannot_exempt_a_different_event_direction_or_parameter(phrase):
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(1)]}]), P4, CFG)
    h = res["hypotheses"][0]
    h.behavior = "Không có bản ghi DNS cùng máy và ProcessGuid " + phrase + "."
    assert [i["operation"] for i in ES.issues(h)] == ["relative_time"]


def test_named_connection_exemption_requires_network_primary_evidence():
    res = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(1)]}]), P4, CFG)
    h = res["hypotheses"][0]
    h.evidence.event_ids = [11]
    assert [i["operation"] for i in ES.issues(h)] == ["relative_time"]


# 07/10: ④ v6 thật viết đúng nghĩa cửa sổ đếm ±45 giây; cổng không được coi đó là mốc neo thứ hai.
H01_V6 = ("Một tiến trình (cùng ProcessGuid, cùng host) kết nối tới ít nhất 2 địa chỉ IP đích khác nhau trong khoảng "
          "thời gian tập trung quanh một kết nối: từ 45 giây trước đến 45 giây sau. Sự kiện chính được xem xét là "
          "bản ghi kết nối mạng Sysmon EventID 3.")


def count_hypothesis(behavior):
    h = S4.generate(CA, TELEMETRY, MockClient(responses=[{"items": [proposal(0)]}]), P4, CFG)["hypotheses"][0]
    h.behavior = behavior
    return h


@pytest.mark.parametrize("behavior", [
    H01_V6,
    "Kết nối tới ít nhất 2 IP khác nhau từ 45 giây trước đến 45 giây sau, cùng máy và ProcessGuid.",
    "Kết nối tới ít nhất 2 IP khác nhau từ 45 giây trước đến 45 giây sau mỗi kết nối, cùng máy.",
    "Kết nối tới ít nhất 2 IP khác nhau trong vòng 45 giây trước và sau, cùng máy.",
    "Connects to at least two distinct IPs from 45 seconds before to 45 seconds after the connection event.",
])
def test_bound_centered_count_window_is_not_a_second_anchor(behavior):
    assert ES.issues(count_hypothesis(behavior)) == []


@pytest.mark.parametrize("behavior", [
    "Từ 45 giây trước đến 45 giây sau sự kiện khởi tạo tiến trình.",
    "Kết nối tới ít nhất 2 IP khác nhau từ 30 giây trước đến 30 giây sau, cùng máy.",
    "Từ 45 giây trước đến 45 giây sau; trong 60 giây sau sự kiện neo trước đó.",
    "Kết nối trong 45 giây sau sự kiện khởi tạo.",
])
def test_count_window_cannot_exempt_another_event_parameter_or_one_sided_window(behavior):
    assert [i["operation"] for i in ES.issues(count_hypothesis(behavior))] == ["relative_time"]


def test_count_window_exemption_requires_the_count_constraint_and_network_primary():
    h = count_hypothesis(H01_V6)
    named = "Kết nối tới ít nhất 2 IP khác nhau từ 45 giây trước đến 45 giây sau mỗi kết nối, cùng máy."
    h.behavior, h.evidence.event_ids = named, [11]
    assert [i["operation"] for i in ES.issues(h)] == ["relative_time"]
    h = count_hypothesis(H01_V6)
    h.rang_buoc, h.required_operations = None, []
    assert "relative_time" in [i["operation"] for i in ES.issues(h)]
