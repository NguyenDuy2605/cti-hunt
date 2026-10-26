"""Khâu ④ → ◆ → ⑤ → ⑨ trên văn bản TỰ SOẠN (câu ví dụ ở v3 §5.1), với mô hình giả lập.

Không dùng văn bản của 3 report đánh giá (cổng đóng băng).
"""
import json
import re

import pytest
import yaml

from cti_hunt import approval
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import ContractA, SourceSpan, TTP, TTPContext
from cti_hunt.hunt import runner
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s3_telemetry, s4_hypothesis as S4, s5_rule as S5, s9_record as S9

TELEMETRY = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
LS = A.load_catalog(ROOT / "configs" / "logsource_catalog.yaml")
CFG = load_cfg("agent")
P4 = load_sections(ROOT / CFG["prompt_khau4"])
P5 = load_sections(ROOT / CFG["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
SYSMON = "microsoft-windows-sysmon/operational"
QUOTE = "Sau khi có được quyền trên máy đầu tiên, nhóm tấn công sử dụng WMI để thực thi lệnh từ xa sang các máy khác."

CA = ContractA(report_id="TU", title="Văn bản tự soạn", ttps=[
    TTP(tactic="Lateral Movement", technique_id="T1047", technique_name="Windows Management Instrumentation",
        behavior_description="Thực thi lệnh từ xa qua WMI",
        context=TTPContext(tool="WMI", execution_path="remote", target_role="các máy khác trong mạng"),
        source_span=SourceSpan(section="đoạn", text=QUOTE, segment_id="TU-001"), confidence=0.9),
    TTP(tactic="Lateral Movement", technique_id="T1021.004", technique_name="SSH",
        source_span=SourceSpan(text="Nhóm tấn công dùng SSH.", segment_id="TU-002"), confidence=0.5),
])

GOOD = dict(ttp_refs=[0], behavior="Tiến trình con của tiến trình thực thi từ xa ngoài mẫu quản trị hợp lệ",
            scope="Mọi máy Windows trong log", timeframe="toàn bộ khoảng thời gian của log",
            data_source="Microsoft-Windows-Sysmon/Operational", event_ids=[1],
            key_fields=["ParentImage", "Image", "TruongBia"], extra_techniques=["T1021.006", "T1569.002", "TXXXX"],
            priority="cao", rationale="nhóm tiến trình cùng vai trò")

H03 = (ROOT / "hunts" / "sigma" / "H-03.yml").read_text(encoding="utf-8")


def hyp(status="approved", **kw):
    items = [S4.LLMHypothesis(**{**GOOD, **kw})]
    h = S4.postprocess(items, S4.select_inputs(CA, TELEMETRY)[0], "TU", 10)[0][0]
    return h.model_copy(update={"status": status})


# ---------- prompt ----------

PROMPT_FILES = {"prompt_khau2": load_cfg("llm")["prompt_file"],
                "prompt_khau4": CFG["prompt_khau4"],
                "prompt_khau4_pivot": CFG["prompt_khau4_pivot"],
                "prompt_agent_plan": CFG["prompt_agent_plan"],
                "prompt_khau5": CFG["prompt_khau5"]}


@pytest.mark.parametrize("key", list(PROMPT_FILES))
def test_new_prompts_contain_no_technique_ids(key):
    """Prompt không mồi mã kỹ thuật nào (D9): mã ví dụ cũ trùng cặp in-scope của bộ tham chiếu."""
    assert not re.search(r"\bT\d{4}", (ROOT / PROMPT_FILES[key]).read_text(encoding="utf-8"))


# ---------- khâu ④ ----------

def test_not_huntable_goes_to_gaps_not_to_model():
    inputs, gaps = S4.select_inputs(CA, TELEMETRY)
    assert [i["ref"] for i in inputs] == [0]
    assert gaps[0]["technique_id"] == "T1021.004"
    assert "T1021.004" not in S4.render_inputs(inputs)


def test_postprocess_validates_every_part_of_the_output():
    inputs = S4.select_inputs(CA, TELEMETRY)[0]
    items = [S4.LLMHypothesis(**x) for x in [
        GOOD,
        {**GOOD, "behavior": "  Tiến trình con của tiến trình   thực thi từ xa ngoài mẫu quản trị hợp lệ"},  # trùng
        {**GOOD, "data_source": "security"},                         # nguồn log không thuộc kỹ thuật được trỏ
        {**GOOD, "event_ids": [3]},                                  # mã sự kiện không thuộc nguồn đó
        {**GOOD, "ttp_refs": [1, 7]},                                # trỏ vào not_huntable và ref không tồn tại
        {**GOOD, "scope": " "},                                      # thiếu thành phần
        {**GOOD, "behavior": "khác", "key_fields": ["Bia1", "Bia2"]},  # không còn trường hợp lệ
    ]]
    hyps, log = S4.postprocess(items, inputs, "TU", 10)
    assert len(hyps) == 1
    h = hyps[0]
    assert (h.hypothesis_id, h.status, h.origin, h.pivot_depth) == ("TU-H01", "pending_review", "telemetry_mapping", 0)
    assert h.evidence.data_source == SYSMON and h.evidence.key_fields == ["ParentImage", "Image"]
    assert h.linked_ttps == ["T1021.006", "T1047", "T1569.002"]
    assert h.source_spans == [CA.ttps[0].source_span]           # do mã điền từ TTP, không do mô hình viết
    # sửa chỉ đếm trên giả thuyết được giữ; mỗi giả thuyết bị loại đếm đúng một lý do
    assert +log == {"truong_ngoai_danh_muc": 1, "mo_rong_ma_sai": 1, "mo_rong_ky_thuat": 2, "trung_gia_thuyet": 1,
                    "nguon_log_ngoai_danh_muc": 1, "ma_su_kien_ngoai_danh_muc": 1, "khong_neo_ttp": 1,
                    "thieu_thanh_phan": 1, "thieu_truong": 1}


def test_kept_hypothesis_counts_its_bad_refs():
    inputs = S4.select_inputs(CA, TELEMETRY)[0]
    _, log = S4.postprocess([S4.LLMHypothesis(**{**GOOD, "ttp_refs": [0, 1, 9]})], inputs, "TU", 10)
    assert log["ttp_ref_la"] == 2


def test_cap_per_round_and_pivot_depth():
    inputs = S4.select_inputs(CA, TELEMETRY)[0]
    items = [S4.LLMHypothesis(**GOOD), S4.LLMHypothesis(**{**GOOD, "behavior": "hành vi khác"})]
    hyps, log = S4.postprocess(items, inputs, "TU", max_items=1)
    assert len(hyps) == 1 and log["vuot_tran"] == 1
    with pytest.raises(S4.PivotLimitError):
        S4.generate(CA, TELEMETRY, MockClient(), P4, CFG, pivot_depth=CFG["max_pivot_depth"] + 1)


def test_generate_logs_raw_io(tmp_path):
    llm = MockClient(responses=[{"items": [GOOD]}])
    res = S4.generate(CA, TELEMETRY, llm, P4, CFG, run_dir=tmp_path)
    assert res["log"]["so_gia_thuyet"] == 1 and res["log"]["prompt_sha256"] == P4["sha256"]
    assert (tmp_path / "response_raw.json").exists() and QUOTE in llm.calls[0][1]


# ---------- điểm dừng phê duyệt ----------

def _fill(run_dir, reviewer="người vận hành", **decisions):
    p = run_dir / approval.REVIEW_FILE
    form = yaml.safe_load(p.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = reviewer
    for row in form["gia_thuyet"]:
        row["quyet_dinh"], row["ly_do"] = decisions.get(row["id"], ("", ""))
    p.write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")


def test_review_roundtrip(tmp_path):
    h1, h2 = hyp("pending_review"), hyp("pending_review").model_copy(update={"hypothesis_id": "TU-H02"})
    approval.write_review([h1, h2], tmp_path)
    form = yaml.safe_load((tmp_path / approval.REVIEW_FILE).read_text(encoding="utf-8"))
    assert form["quy_tac_duyet"] == approval.REVIEW_POLICY
    row = form["gia_thuyet"][0]
    assert row["thoi_gian"] == h1.timeframe
    assert row["nguon_chi_tiet"] == [s.model_dump() for s in h1.source_spans]
    assert row["nguon_chi_tiet"][0]["text"] == QUOTE  # đủ câu, kể cả khi có segment_id
    assert all(r["quyet_dinh"] == "" for r in form["gia_thuyet"])
    assert approval.apply_review(tmp_path)["dem"] == {"approved": 0, "rejected": 0, "pending_review": 2}
    _fill(tmp_path, **{"TU-H01": ("approved", ""), "TU-H02": ("rejected", "trùng H01")})
    log = approval.apply_review(tmp_path)
    assert log["dem"] == {"approved": 1, "rejected": 1, "pending_review": 0} and log["nguoi_duyet"] == "người vận hành"
    assert log["quy_tac_duyet"] == approval.REVIEW_POLICY
    out = approval.load_hypotheses(tmp_path / approval.APPROVED_FILE)
    assert [h.status for h in out] == ["approved", "rejected"]


@pytest.mark.parametrize("reviewer, decision, msg", [
    ("người vận hành", ("rejected", ""), "ly_do"),
    ("", ("approved", ""), "nguoi_duyet"),
    ("người vận hành", ("duyet", ""), "không hợp lệ"),
])
def test_review_rejects_bad_forms(tmp_path, reviewer, decision, msg):
    approval.write_review([hyp("pending_review")], tmp_path)
    _fill(tmp_path, reviewer, **{"TU-H01": decision})
    with pytest.raises(approval.ReviewError, match=msg):
        approval.apply_review(tmp_path)


def test_review_catches_yaml_boolean_and_changed_content(tmp_path):
    approval.write_review([hyp("pending_review")], tmp_path)
    p = tmp_path / approval.REVIEW_FILE
    p.write_text(p.read_text(encoding="utf-8").replace("quyet_dinh: ''", "quyet_dinh: yes")
                 .replace("nguoi_duyet: ''", "nguoi_duyet: người vận hành"), encoding="utf-8")
    with pytest.raises(approval.ReviewError, match="yes/no"):
        approval.apply_review(tmp_path)
    approval.write_review([hyp("pending_review")], tmp_path)
    hp = tmp_path / approval.HYP_FILE
    hp.write_text(hp.read_text(encoding="utf-8").replace("Mọi máy", "Chỉ server"), encoding="utf-8")
    with pytest.raises(approval.ReviewError, match="đã đổi"):
        approval.apply_review(tmp_path)


# ---------- khâu ⑤ ----------

BAD_MODIFIER = H03.replace("ParentImage|endswith", "ParentImage|endswithh")


@pytest.mark.parametrize("text, kind", [
    ("title: [", "yaml_loi"),
    ("- chỉ là một danh sách", "yaml_loi"),
    (H03.replace("detection:", "detection:\n  selection_dup: {}\n  selection_dup: {}", 1), "yaml_trung_khoa"),
    (BAD_MODIFIER, "sigma_loi"),
    (H03.replace("not filter_known_good", "not filter_khong_co"), "sigma_loi"),
    (H03.replace("category: process_creation", "category: driver_load"), "logsource_khong_co"),
    (H03.replace("category: process_creation", "category: ps_script"), "khac_nguon_gia_thuyet"),
])
def test_static_validation_layers(text, kind):
    issues, specs = S5.validate_rule(text, hyp(), LS)
    assert [i.kind for i in issues][:1] == [kind] and specs == []


def test_field_missing_from_data_is_reported():
    issues, _ = S5.validate_rule(H03, hyp(), LS, columns={"Image", "Hostname"})
    assert issues[0].kind == "truong_khong_co" and "ParentImage" in issues[0].message


def test_explain_catches_sql_error_without_running(con_labeled):
    con, _ = con_labeled
    text = H03.replace("Image|endswith:\n      - '\\WmiApSrv.exe'", "Hashes|contains:\n      - 'abc'")
    issues, _ = S5.validate_rule(text, hyp(), LS, columns=None, con=con)
    assert [i.kind for i in issues] == ["sql_loi"] and "S-01" in issues[0].message


def test_valid_rule_yields_spec_for_the_hypothesis_source_only():
    issues, specs = S5.validate_rule(H03, hyp(), LS)
    assert issues == [] and len(specs) == 1                 # security_4688 bỏ: khác nguồn log của giả thuyết
    s = specs[0]
    assert (s["scope"]["channel"], s["hypothesis_id"], [f["id"] for f in s["filters"]]) == (SYSMON, "TU-H01", ["S-01"])


def test_repair_loop_sees_only_validation_errors():
    llm = MockClient(responses=[{"rule_yaml": BAD_MODIFIER}, {"rule_yaml": H03, "note": "sửa modifier"}])
    r = S5.generate_rule(hyp(), llm, P5, LS, max_repair=2)
    assert (r["hop_le"], r["hop_le_lan_dau"], r["so_lan_sua"]) == (True, False, 1)
    first, repair = llm.calls[0][1], llm.calls[1][1]
    assert QUOTE not in first                               # không gửi câu trích report sang khâu ⑤
    assert "endswithh" in repair and "[sigma_loi]" in repair
    assert not re.search(r"\b(hits|kết quả truy vấn|buoc)\b", repair)


def test_repair_loop_stops_at_cap_and_counts():
    llm = MockClient(responses=[{"rule_yaml": BAD_MODIFIER}] * 3 + [{"rule_yaml": H03}])
    r = S5.generate_rule(hyp(), llm, P5, LS, max_repair=2)
    assert (r["hop_le"], r["so_lan_sua"], len(llm.calls), r["hunt_specs"]) == (False, 2, 3, [])
    ok = S5.generate_rule(hyp(), MockClient(responses=[{"rule_yaml": H03}]), P5, LS, max_repair=2)
    assert S5.summarize([r, ok]) == {"so_gia_thuyet": 2, "hop_le_lan_dau": 1, "hop_le_sau_sua": 1,
                                     "loi_lan_dau_theo_loai": {"sigma_loi": 1}}


class TokenClient:
    """Giả lập adapter thật: báo một lần thử lại (kèm thân lỗi) rồi số token của lời gọi."""
    model_id = "dem-token"

    def __init__(self, responses):
        self.responses = list(responses)

    def complete_json(self, system, user, json_schema, log=None):
        if log:
            log({"lan": 1, "http": 529, "thu_lai": True, "cho_giay": 2, "loi": "thân lỗi của nhà cung cấp"})
            log({"stop_reason": "tool_use", "input_tokens": 1200, "output_tokens": 300, "max_tokens": 32000})
        return self.responses.pop(0)


def test_token_usage_is_logged_for_khau4_and_khau5_without_error_bodies():
    """Chi phí là một chỉ số so sánh pipeline với agent (v3.2 §6.2): ④⑤ phải ghi token như khâu ② và planner."""
    r4 = S4.generate(CA, TELEMETRY, TokenClient([{"items": [GOOD]}]), P4, CFG)
    assert r4["log"]["token"] == {"input_tokens": 1200, "output_tokens": 300}
    assert all("loi" not in e for e in r4["log"]["api_events"])
    r5 = S5.generate_rule(hyp(), TokenClient([{"rule_yaml": BAD_MODIFIER}, {"rule_yaml": H03}]), P5, LS, max_repair=2)
    assert (r5["hop_le"], len(r5["lan_thu"])) == (True, 2)
    assert r5["token"] == {"input_tokens": 2400, "output_tokens": 600}     # cộng cả lần sinh lẫn lần sửa
    assert r5["lan_thu"][0]["api_events"][0] == {"lan": 1, "http": 529, "thu_lai": True, "cho_giay": 2}


def test_rules_only_for_approved_hypotheses():
    with pytest.raises(approval.NotApprovedError):
        S5.generate_rule(hyp("pending_review"), MockClient(), P5, LS, max_repair=0)


def test_same_sigma_rule_has_distinct_hunt_ids_for_two_hypotheses():
    h1 = hyp()
    h2 = h1.model_copy(update={"hypothesis_id": "TU-H02"})
    first = S5.validate_rule(H03, h1, LS)[1][0]
    second = S5.validate_rule(H03, h2, LS)[1][0]
    assert first["id"] != second["id"]
    assert first["id"].startswith("TU-H01__") and second["id"].startswith("TU-H02__")


def _hyp_on(channel, eids, fields, tid):
    from cti_hunt.contracts import ContractB, Evidence
    return ContractB(hypothesis_id="TU-H09", behavior="hành vi", scope="mọi máy", timeframe="toàn bộ",
                     linked_ttps=[tid], status="approved",
                     evidence=Evidence(data_source=channel, event_ids=eids, key_fields=fields))


SEC_RULE = """title: Tạo tài khoản cục bộ
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4720
  condition: selection
level: medium
"""
RUN_KEY_RULE = """title: Ghi khóa Run
status: experimental
logsource: {product: windows, category: registry_event}
detection:
  selection:
    TargetObject|contains: '\\CurrentVersion\\Run'
  condition: selection
level: medium
"""


def test_service_logsource_rule_is_scoped_to_the_hypothesis_event_ids():
    h = _hyp_on("security", [4720], ["TargetUserName"], "T1136.001")
    offered = S5.logsources_for(h, LS)
    assert [o["logsource"] for o in offered] == [{"product": "windows", "service": "security"}]
    issues, specs = S5.validate_rule(SEC_RULE, h, LS)
    assert issues == [] and len(specs) == 1
    assert specs[0]["scope"] == {"channel": "security", "event_ids": [4720]}    # mẫu số FPR = nguồn của giả thuyết


def test_broader_category_is_narrowed_to_the_hypothesis_event_ids():
    h = _hyp_on(SYSMON, [12, 13], ["TargetObject"], "T1547.001")
    issues, specs = S5.validate_rule(RUN_KEY_RULE, h, LS)
    assert issues == [] and specs[0]["scope"]["event_ids"] == [12, 13]
    narrower = RUN_KEY_RULE.replace("category: registry_event", "category: registry_set")   # chỉ EID 13
    assert [i.kind for i in S5.validate_rule(narrower, h, LS)[0]] == ["khac_nguon_gia_thuyet"]


def test_hypothesis_without_sigma_logsource_is_reported_without_calling_the_model():
    h = _hyp_on("microsoft-windows-terminalservices-remoteconnectionmanager/operational", [1149], ["Message"],
                "T1021.001")
    llm = MockClient(responses=[{"rule_yaml": H03}])
    r = S5.generate_rule(h, llm, P5, LS, max_repair=2)
    assert (r["hop_le"], r["so_lan_sua"], llm.calls) == (False, 0, [])
    assert S5.summarize([r])["loi_lan_dau_theo_loai"] == {"khong_co_logsource": 1}


# ---------- khâu ⑨ ----------

def _results(con):
    h1 = hyp()
    spec1 = S5.generate_rule(h1, MockClient(responses=[{"rule_yaml": H03}]), P5, LS, 0)["hunt_specs"][0]
    h2 = hyp(behavior="Mọi tiến trình .exe", priority="thap").model_copy(update={"hypothesis_id": "TU-H02"})
    spec2 = dict(spec1, id="TU-H02__sysmon_1", hypothesis_id="TU-H02", candidates="lower(Image) LIKE '%.exe'",
                 filters=[])
    return [h1, h2], [runner.run(con, s, [], []) for s in (spec1, spec2)]


def test_record_operational_has_no_ground_truth(con_labeled):
    con, _ = con_labeled
    hyps, results = _results(con)
    md = S9.render(CA, TELEMETRY, hyps, results)
    for leak in ("14.B", "16.D", "buoc", "FPR", "precision", "Precision", "recall", "tấn công |"):
        assert leak not in md, leak
    assert "### FINDING #01 · TU-H01 · ưu tiên cao" in md       # xếp theo ưu tiên
    assert "4 ứng viên → loại 1 → **3 cần xem xét**" in md
    assert "`TU-001`" in md and QUOTE in md                     # truy vết về câu gốc
    assert "| **T1021.004** | SSH | not_huntable |" in md         # khoảng trống quan sát (D13 bổ sung: bảng)
    assert "| máy | UTICA | 2 |" in md and "| máy | NEWYORK | 2 |" in md
    assert "| sau_S-01 | 3 | 1 |" in md and "sigma_rule" in md   # nhật ký lọc
    assert S9.MISSING_7 in md and S9.FEEDBACK in md


def test_record_coverage_notes_carry_no_step_ids(con_labeled):
    """Ghi chú khâu ③ hiện ở bảng độ phủ và khoảng trống quan sát của bản vận hành."""
    con, _ = con_labeled
    hyps, results = _results(con)
    extra = [TTP(tactic="Persistence", technique_id=t, source_span=SourceSpan(), confidence=0.5)
             for t in sorted(TELEMETRY)]
    md = S9.render(CA.model_copy(update={"ttps": CA.ttps + extra}), TELEMETRY, hyps, results)
    assert not s3_telemetry.STEP_ID.search(md)


# ---------- D13 bổ sung 25/9 ----------

COUNT = re.compile(r"=\s*\d|\d[\d.,]*\s+sự kiện")


def _table_rows(md: str, heading: str, prefix: str) -> list[list[str]]:
    body = md.split(heading, 1)[1].split("\n###", 1)[0]
    return [[c.strip() for c in line.strip("|").split(" | ")] for line in body.splitlines() if line.startswith(prefix)]


def test_every_hypothesis_has_a_source_column_in_any_state(con_labeled):
    """Kể cả giả thuyết không ra kết quả, bị từ chối, hoặc không có source_spans."""
    con, _ = con_labeled
    hyps, results = _results(con)
    no_result = hyps[0].model_copy(update={"hypothesis_id": "TU-H03", "status": "rejected"})
    no_span = hyps[0].model_copy(update={"hypothesis_id": "TU-H04", "status": "pending_review", "source_spans": []})
    md = S9.render(CA, TELEMETRY, hyps + [no_result, no_span], results)
    rows = {r[0]: r for r in _table_rows(md, "### Giả thuyết", "| TU-H")}
    assert sorted(rows) == ["TU-H01", "TU-H02", "TU-H03", "TU-H04"]
    assert all(len(r) == 8 and r[-1] for r in rows.values())          # cột "Nguồn CTI" không bao giờ trống
    assert rows["TU-H03"][-1].startswith("`TU-001` “Sau khi có được quyền") and rows["TU-H03"][-1].endswith("…”")
    assert rows["TU-H04"][-1] == S9.NO_SOURCE
    assert "TU-H03" not in md.split("### Phát hiện")[1]                # không ra kết quả nhưng vẫn có nguồn ở Learn


def test_keep_lists_partial_and_not_huntable_without_dataset_counts(con_labeled):
    con, _ = con_labeled
    hyps, results = _results(con)
    extra = [TTP(tactic="Persistence", technique_id=t, source_span=SourceSpan(), confidence=0.5)
             for t in sorted(TELEMETRY)]
    md = S9.render(CA.model_copy(update={"ttps": CA.ttps + extra}), TELEMETRY, hyps, results)
    keep = md.split("## Keep", 1)[1]
    statuses = {r[0].strip("*"): r[2] for r in _table_rows(keep, "### Khoảng trống quan sát", "| **T")}
    expected = {t: e["status"] for t, e in TELEMETRY.items() if e["status"] != "huntable"} | {"T1021.004": "not_huntable"}
    assert statuses == expected and {"partial", "not_huntable"} == set(statuses.values())
    assert not COUNT.search(keep)                                       # số sự kiện của APT29 không in ra
    assert not COUNT.search(md.split("### Bảng độ phủ", 1)[1].split("\n###", 1)[0])


def test_no_wording_suggests_the_model_writes_the_assessment(con_labeled):
    con, _ = con_labeled
    hyps, results = _results(con)
    md = S9.render(CA, TELEMETRY, hyps, results)
    assert "diễn giải bằng mô hình" not in md
    assert md.count("- **Nhận định:** chuyên viên ghi khi duyệt") == len([r for r in results if r["giai_doan"][-1]["hits"]])


@pytest.mark.parametrize("note, expected", [
    ("4697 = 18, không có System 7045. Sửa dịch vụ sẵn có không sinh 4697.",
     "Không có System 7045. Sửa dịch vụ sẵn có không sinh 4697."),
    ("Rất ít sự kiện (1149 = 1; 21/22 = 1/1). Đủ để viết truy vấn.", "Rất ít sự kiện. Đủ để viết truy vấn."),
    ("Phía đích qua wsmprovhost.exe; phía nguồn qua PS 4104 (716 sự kiện).",
     "Phía đích qua wsmprovhost.exe; phía nguồn qua PS 4104."),
    ("System 7045 KHÔNG có; 4697 chỉ 18 sự kiện.", "System 7045 KHÔNG có."),
    ("Sysmon 11 = 5.479, 3 = 2.186, BITS 306 = 2.", ""),
    ("Chỉ suy ra từ tiến trình con của mmc.exe, dllhost.exe, excel.exe.",
     "Chỉ suy ra từ tiến trình con của mmc.exe, dllhost.exe, excel.exe."),
])
def test_catalog_note_drops_only_dataset_counts(note, expected):
    assert S9.catalog_note(note) == expected


def test_record_d13_lock_sections_keep_existing_content_once(con_labeled):
    con, _ = con_labeled
    hyps, results = _results(con)
    md = S9.render(CA, TELEMETRY, hyps, results)
    assert re.findall(r"(?m)^## (.+)$", md) == ["Learn", "Observe", "Check", "Keep"]
    parts = re.split(r"(?m)^## (Learn|Observe|Check|Keep)$", md)
    sections = dict(zip(parts[1::2], parts[2::2]))
    for heading in ("Tóm tắt", "Bảng độ phủ", "Nguồn CTI theo phát hiện", "Giả thuyết"):
        assert sections["Learn"].count(f"### {heading}") == 1
    for heading in ("Kết quả chạy theo phát hiện", "Nhật ký lọc", "Truy vấn đã chạy"):
        assert sections["Observe"].count(f"### {heading}") == 1
    for heading in ("Phát hiện", "Bản đồ tương quan", "Nhật ký vòng lặp"):
        assert sections["Check"].count(f"### {heading}") == 1
    assert sections["Keep"].count("### Khoảng trống quan sát") == 1
    assert "- **Nguồn log:**" in sections["Observe"] and "- **Kết quả:**" in sections["Observe"]
    assert "- **Điểm độ hiếm:**" in sections["Check"]
    assert sections["Check"].splitlines().count("- **Verdict:**") == len(results)
    assert "`TU-001`" in sections["Learn"] and "**T1021.004**" in sections["Keep"]


def test_record_eval_mode_adds_ground_truth_section(con_labeled):
    con, _ = con_labeled
    hyps, results = _results(con)
    md = S9.render(CA, TELEMETRY, hyps, results, eval_mode=True)
    assert "## 9. Đánh giá theo ground truth" in md and "14.B×1" in md and "16.D×1" in md
    assert re.findall(r"(?m)^## (.+)$", md)[:4] == ["Learn", "Observe", "Check", "Keep"]
    assert md.index("## 9. Đánh giá theo ground truth") > md.index("## Keep")
