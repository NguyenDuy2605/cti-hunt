"""Rule cộng đồng SigmaHQ theo TTP (15/10): thư mục SigmaHQ tổng hợp, log fixture; không nhãn, không API."""
import json
import re

from cti_hunt import demo
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.data.store import connect
from cti_hunt.stages import community_rules as cr

# conftest tắt ưu tiên khoảng trống cho mọi module khác; module này tự trỏ cờ tới SigmaHQ tổng hợp.
BAT_KHOANG_TRONG = True

RULES = {
    "wmi_child.yml": r"""title: Synthetic WmiPrvSE child
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  filter_notepad:
    Image|endswith: '\notepad.exe'
  condition: selection and not filter_notepad
tags: [attack.execution, attack.t1047]
""",
    "experimental.yml": r"""title: Synthetic experimental rule
id: 22222222-2222-2222-2222-222222222222
status: experimental
level: high
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
tags: [attack.t1047]
""",
    "other_technique.yml": r"""title: Synthetic other technique
id: 33333333-3333-3333-3333-333333333333
status: stable
level: medium
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\notepad.exe'
  condition: selection
tags: [attack.t1021.006]
""",
    "parent_tag.yml": r"""title: Synthetic parent-technique tag
id: 44444444-4444-4444-4444-444444444444
status: stable
level: low
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\svchost.exe'
  condition: selection
tags: [attack.t1021]
""",
}


def _sigmahq(tmp_path):
    root = tmp_path / "sigmahq"
    d = root / "rules" / "windows"
    d.mkdir(parents=True)
    for name, text in RULES.items():
        (d / name).write_text(text, encoding="utf-8")
    return root


def _contract(*techs):
    return ContractA(report_id="TU", ttps=[TTP(tactic="Execution", technique_id=t, confidence=0.9,
                                               behavior_description="synthetic",
                                               source_span=SourceSpan(segment_id="TU-001", text="Synthetic."))
                                           for t in techs])


def test_select_takes_only_stable_or_test_rules_with_an_exact_technique_tag(tmp_path):
    root = _sigmahq(tmp_path)
    picked = cr.select(["t1047", "t1021.006"], root)
    assert sorted(m["relative_path"] for m in picked) == ["rules/windows/other_technique.yml",
                                                          "rules/windows/wmi_child.yml"]
    # tag kỹ thuật cha (t1021) không khớp TTP con (t1021.006): không mở rộng cha/con, như G0(c)
    assert all("parent_tag" not in m["relative_path"] for m in picked)


def test_run_compiles_keeps_rule_filters_and_counts_on_events(tmp_path, work):
    root = _sigmahq(tmp_path)
    res = cr.run(connect(work), _contract("T1047"), root)
    assert res["ttp"] == ["t1047"] and res["so_rule_chon"] == 1
    [row] = [r for r in res["rule"] if r["kenh"] == "microsoft-windows-sysmon/operational"]
    assert row["title"] == "Synthetic WmiPrvSE child" and row["level"] == "high"
    assert (row["pham_vi"], row["ung_vien"], row["cuoi"]) == (5, 1, 1)     # WmiPrvSE → powershell
    md = cr.render(res)
    assert "Rule cộng đồng SigmaHQ theo TTP" in md and "Synthetic WmiPrvSE child" in md


def test_report_without_matching_rules_selects_nothing(tmp_path, work):
    root = _sigmahq(tmp_path)
    res = cr.run(connect(work), _contract("T1566.001"), root)
    assert (res["so_rule_chon"], res["so_hunt"], res["co_ket_qua"]) == (0, 0, 0)


def test_ui_table_puts_rules_with_hits_first(tmp_path, work):
    root = _sigmahq(tmp_path)
    res = cr.run(connect(work), _contract("T1047", "T1021.006"), root)
    table = demo.community_table(res)
    assert table[0]["rule"] == "Synthetic WmiPrvSE child" or table[0]["giu"] >= table[-1]["giu"]
    assert {"rule", "muc", "ky_thuat", "nguon", "trong_pham_vi", "giu", "tep"} == set(table[0])


def test_coverage_marks_high_low_and_missing_from_metadata(tmp_path):
    root = _sigmahq(tmp_path)
    sysmon = {"microsoft-windows-sysmon/operational"}
    cov = cr.coverage(["T1047", "T1021.006", "T1566.001"], sysmon, root)
    assert cov["t1047"] == {"muc": "cao", "so_rule_cao": 1, "so_rule": 1}            # rule experimental không tính
    assert cov["t1021.006"]["muc"] == "thap" and cov["t1566.001"]["muc"] == "khong_co_rule"
    # log không có nguồn nào của rule (tạo tiến trình: Sysmon 1 hoặc Security 4688) thì rule không dùng được
    assert cr.coverage(["T1047"], {"microsoft-windows-powershell/operational"}, root)["t1047"]["muc"] == "khong_co_rule"
    md = cr.render_coverage(cov)
    assert md.index("T1566.001") < md.index("T1047") and "bật rule cộng đồng" in md


def test_gap_ttps_rank_first_only_when_coverage_is_given():
    from cti_hunt.config import ROOT
    from cti_hunt.stages import s3_telemetry, s4_hypothesis as S4
    telemetry = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
    ca = ContractA(report_id="TU", ttps=[
        TTP(tactic="Lateral Movement", technique_id="T1047", confidence=0.9, source_span=SourceSpan(segment_id="TU-1")),
        TTP(tactic="Persistence", technique_id="T1546.003", confidence=0.5, source_span=SourceSpan(segment_id="TU-2"))])
    plain, _ = S4.select_inputs(ca, telemetry)
    gap, _ = S4.select_inputs(ca, telemetry, {"t1047": {"muc": "cao"}, "t1546.003": {"muc": "khong_co_rule"}})
    assert [i["ttp"].technique_id for i in plain][0] == "T1047"      # cùng huntable: độ tin cậy cao hơn đứng trước
    assert [i["ttp"].technique_id for i in gap][0] == "T1546.003"    # khoảng trống được cộng 40 điểm
    assert gap[0]["score_components"]["community_coverage"] == "khong_co_rule"
    assert "community_coverage" not in plain[0]["score_components"]


class _Capture:
    """④ giả lập: ghi lại prompt, không sinh giả thuyết nào (chỉ kiểm thứ tự TTP gửi vào ④ và hunt record)."""
    model_id = 'mock'

    def __init__(self):
        self.users = []

    def describe(self):
        return {'model': 'mock', 'kieu_api': 'mock'}

    def complete_json(self, system, user, json_schema, log=None):
        assert json_schema['title'] == 'LLMHypothesisBatch'
        self.users.append(user)
        return {'items': []}


def _run_pipeline(tmp_path, work, monkeypatch, name, gap_on, gap_only=False):
    from cti_hunt import config as _config
    from cti_hunt.agent import session
    from cti_hunt.llm import providers
    root = _sigmahq(tmp_path / name)
    original = _config.agent_config

    def cfg(*args, **kwargs):
        c = original(*args, **kwargs)
        if gap_on:
            c['rule_cong_dong_root'] = str(root)
            c['chi_san_khoang_trong'] = gap_only
        else:
            c.pop('khoang_trong_rule_cong_dong', None)
            c.pop('rule_cong_dong_trong_luot', None)
        return c
    monkeypatch.setattr(_config, 'agent_config', cfg)
    client = _Capture()
    monkeypatch.setattr(providers, 'from_config', lambda c: client)
    ca = ContractA(report_id='TU', ttps=[
        TTP(tactic='Execution', technique_id='T1047', confidence=0.9, behavior_description='Synthetic WMI execution',
            source_span=SourceSpan(segment_id='TU-001', text='Synthetic WMI execution.')),
        TTP(tactic='Defense Evasion', technique_id='T1218.011', confidence=0.5,
            behavior_description='Synthetic rundll32 proxy execution',
            source_span=SourceSpan(segment_id='TU-002', text='Synthetic rundll32 execution.'))])
    path = tmp_path / f'{name}.json'
    path.write_text(ca.model_dump_json(), encoding='utf-8')
    run = tmp_path / f'run_{name}'
    out = session.start('pipeline', path, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    monkeypatch.setattr(_config, 'agent_config', original)
    order = re.findall(r'"technique_id": "(T[\d.]+)"', client.users[0])
    return out, run, order


def test_gap_priority_orders_khau4_input_and_lists_coverage_in_record(tmp_path, work, monkeypatch):
    out, run, order = _run_pipeline(tmp_path, work, monkeypatch, 'gap', gap_on=True)
    assert out['trang_thai'] == 'xong'
    assert order == ['T1218.011', 'T1047']            # không có rule cộng đồng → săn trước
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    cov = rec['khoang_trong_rule_cong_dong']
    assert cov['t1218.011']['muc'] == 'khong_co_rule' and cov['t1047']['muc'] == 'cao'
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    assert '### Rule cộng đồng và khoảng trống (ưu tiên khoảng trống)' in md.splitlines()
    assert [h for h in md.splitlines() if h.startswith('## ')] == ['## Learn', '## Observe', '## Check', '## Keep']


def test_without_gap_priority_order_and_record_are_unchanged(tmp_path, work, monkeypatch):
    out, run, order = _run_pipeline(tmp_path, work, monkeypatch, 'plain', gap_on=False)
    assert out['trang_thai'] == 'xong'
    assert order == ['T1047', 'T1218.011']            # độ tin cậy cao hơn đứng trước, như trước 15/10
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert rec['khoang_trong_rule_cong_dong'] is None
    assert 'Rule cộng đồng và khoảng trống' not in (run / 'hunt_record.md').read_text(encoding='utf-8')


def test_community_rules_run_inside_the_run_and_land_in_the_record(tmp_path, work, monkeypatch):
    out, run, order = _run_pipeline(tmp_path, work, monkeypatch, 'lai', gap_on=True)
    assert out['trang_thai'] == 'xong' and order == ['T1218.011', 'T1047']   # chế độ đầy đủ: cả hai TTP vẫn vào ④
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    com = rec['rule_cong_dong_trong_luot']
    assert com['muc'] == ['high', 'critical'] and rec['chi_san_khoang_trong'] is False
    # chỉ rule high stable/test có tag trùng: rule experimental và rule tag kỹ thuật cha không vào
    assert {r['title'] for r in com['rule']} == {'Synthetic WmiPrvSE child'}
    [sysmon] = [r for r in com['rule'] if r['kenh'] == 'microsoft-windows-sysmon/operational']
    assert (sysmon['pham_vi'], sysmon['cuoi']) == (5, 1)
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    assert '### Rule cộng đồng đã chạy trong lượt (SigmaHQ mức high/critical theo TTP)' in md.splitlines()
    assert 'Chế độ chỉ săn khoảng trống' not in md


def test_gap_only_mode_keeps_covered_ttps_out_of_khau4(tmp_path, work, monkeypatch):
    out, run, order = _run_pipeline(tmp_path, work, monkeypatch, 'chi_trong', gap_on=True, gap_only=True)
    assert out['trang_thai'] == 'xong'
    assert order == ['T1218.011']                       # T1047 đã có rule cộng đồng mức cao: rule cộng đồng lo
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert rec['chi_san_khoang_trong'] is True and rec['rule_cong_dong_trong_luot']['co_ket_qua'] >= 1
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    assert 'Chế độ chỉ săn khoảng trống: 1 TTP đã có rule cộng đồng mức cao không đưa vào ④ (T1047).' in md
    assert [h for h in md.splitlines() if h.startswith('## ')] == ['## Learn', '## Observe', '## Check', '## Keep']
