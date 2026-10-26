"""H6: cờ khởi chạy mã hóa trên trường nội dung script (lỗi tĩnh, policy v3) và chuỗi của giả thuyết không có trong rule
(chỉ để xem). Rule và giả thuyết tự soạn, client giả; không đọc tập đánh giá, không gọi API."""
import json

import pytest
import yaml
from sigma.collection import SigmaCollection

from cti_hunt import approval, demo, filter_approval as F
from cti_hunt.adapters import duckdb_sigma as adapter
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractB, SourceSpan
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import encoded_trace as E, rule_fidelity as RF, s5_rule as S5

LS = adapter.load_catalog(ROOT / 'configs/logsource_catalog.yaml')
PROMPT = load_sections(ROOT / agent_config('v2')['prompt_khau5'], ('SYSTEM', 'USER', 'REPAIR'))
PS, SYSMON = 'microsoft-windows-powershell/operational', 'microsoft-windows-sysmon/operational'
SCRIPT = dict(source=PS, eids=(4104,), fields=('ScriptBlockText',))
PROCESS = dict(source=SYSMON, eids=(1,), fields=('Image', 'ParentImage', 'CommandLine'))


def hyp(behavior='Nội dung script PowerShell được mã hóa base64.', *, source=PS, eids=(4104,),
        fields=('ScriptBlockText',), scope='mọi máy trong log'):
    return ContractB(hypothesis_id='SELF-H01', behavior=behavior, scope=scope, timeframe='toàn bộ log',
                     status='approved', linked_ttps=['T1059.001'],
                     source_spans=[SourceSpan(text='Self-authored sentence.')],
                     evidence={'data_source': source, 'event_ids': list(eids), 'key_fields': list(fields)})


def rule(detection, category='ps_script'):
    detection = detection if 'condition' in detection else {'selection': detection, 'condition': 'selection'}
    return yaml.safe_dump({'title': 'Self-authored', 'status': 'experimental',
                           'logsource': {'product': 'windows', 'category': category},
                           'detection': detection, 'level': 'medium'})


def kinds(text, h=None, policy=RF.SCRIPT_POLICY):
    errors, specs = S5.validate_rule(text, h or hyp(), LS, filter_policy=F.POLICY, candidate_regex_policy=policy)
    assert bool(errors) != bool(specs)
    return [e.kind for e in errors]


@pytest.mark.parametrize('selection', [
    {'ScriptBlock|re|i': r'-e\w*\s+[A-Za-z0-9+/=]+'},
    {'ScriptBlock|re|i': r'(^|\s)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]+'},
    {'ScriptBlock|re': r'-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]+'},
    {'ScriptBlock|contains': '-enc '},
    {'ScriptBlock|contains': '-e '},
    {'ScriptBlock|contains': ['-EncodedCommand', 'FromBase64String']},
])
def test_launch_switch_on_script_block_is_a_static_error(selection):
    assert kinds(rule(selection)) == [E.SCRIPT_ISSUE]
    for old in (RF.ENCODED_POLICY, RF.POLICY, ''):                 # spec/draft cũ giữ phép kiểm lúc chúng được tạo
        assert kinds(rule(selection), policy=old) == []


def test_switch_in_one_or_branch_is_still_reported_and_names_the_block():
    text = rule({'selection_switch': {'ScriptBlock|re|i': r'-e(nc)?\s+[A-Za-z0-9+/=]+'},
                 'selection_decode': {'ScriptBlock|re|i': E.DECODE}, 'condition': '1 of selection_*'})
    errors, _ = S5.validate_rule(text, hyp(), LS, filter_policy=F.POLICY, candidate_regex_policy=RF.SCRIPT_POLICY)
    assert [e.kind for e in errors] == [E.SCRIPT_ISSUE] and 'selection_switch.ScriptBlock' in errors[0].message
    assert 'selection_decode' not in errors[0].message


@pytest.mark.parametrize('selection', [
    {'ScriptBlock|re|i': E.DECODE},
    {'ScriptBlock|contains': 'FromBase64String'},
    {'ScriptBlock|contains': ['-nop', '-ErrorAction', '-eq']},      # cờ khác và toán tử của script
    {'ScriptBlock|contains': 'Invoke-Expression'},
    {'ScriptBlock|re|i': r'[A-Za-z0-9+/]+=?=?'},                    # khớp cả khi bỏ cờ: không phụ thuộc cờ
])
def test_script_content_conditions_without_the_switch_pass(selection):
    assert kinds(rule(selection)) == []


def test_module_payload_is_script_content_but_host_application_line_is_not():
    module = hyp(eids=(4103,), fields=('Payload', 'ContextInfo'))
    assert kinds(rule({'Payload|contains': '-enc '}, 'ps_module'), module) == [E.SCRIPT_ISSUE]
    assert kinds(rule({'ContextInfo|contains': '-enc '}, 'ps_module'), module) == []


def test_filter_blocks_are_left_to_the_filter_review():
    text = rule({'selection': {'ScriptBlock|contains': 'FromBase64String'},
                 'filter_known': {'ScriptBlock|contains': '-enc '}, 'condition': 'selection and not 1 of filter_*'})
    assert kinds(text) == []


def test_switch_written_in_the_approved_hypothesis_is_not_blocked():
    nested = hyp('Script gọi tiếp powershell.exe với -EncodedCommand để chạy lệnh con.')
    assert kinds(rule({'ScriptBlock|contains': '-EncodedCommand'}), nested) == []
    assert kinds(rule({'ScriptBlock|contains': '-EncodedCommand'}),
                 hyp('The PowerShell command is base64-encoded.')) == [E.SCRIPT_ISSUE]     # "-encoded" không phải cờ


def test_v3_keeps_the_v2_requirement_on_process_command_lines():
    process = hyp('PowerShell with a base64-encoded command', source='security', eids=(4688,),
                  fields=('NewProcessName', 'CommandLine'))
    good = {'Image|endswith': r'\powershell.exe', 'CommandLine|re|i': E.SWITCH}
    assert kinds(rule(good, 'process_creation'), process) == []
    assert kinds(rule({**good, 'CommandLine|re|i': '-enc'}, 'process_creation'), process) == [E.ISSUE]


def test_v2_config_pins_the_new_policy_through_a_new_prompt_and_keeps_v5():
    assert agent_config('v2')['prompt_khau5'] == 'prompts/khau5_sigma_v6.md'
    assert S5.candidate_policy(PROMPT) == RF.SCRIPT_POLICY
    v5 = load_sections(ROOT / 'prompts/khau5_sigma_v5.md', ('SYSTEM', 'USER', 'REPAIR'))
    assert S5.candidate_policy(v5) == RF.ENCODED_POLICY
    assert 'ScriptBlock' in PROMPT['sections']['SYSTEM'] and 'ScriptBlock' not in v5['sections']['SYSTEM']
    with pytest.raises(ValueError):
        RF.check_policy('candidate_regex_unknown')


def test_repair_loop_gets_only_the_static_message_and_keeps_the_decode_branch():
    bad = rule({'selection_switch': {'ScriptBlock|re|i': r'-e(nc)?\s+[A-Za-z0-9+/=]+'},
                'selection_decode': {'ScriptBlock|re|i': E.DECODE}, 'condition': '1 of selection_*'})
    good = rule({'ScriptBlock|re|i': E.DECODE})
    llm = MockClient(responses=[{'rule_yaml': bad, 'note': ''}, {'rule_yaml': good, 'note': 'removed'}])
    out = S5.generate_rule(hyp(), llm, PROMPT, LS, 2, filter_policy=F.POLICY)
    assert out['hop_le'] and not out['hop_le_lan_dau'] and out['so_lan_sua'] == 1 and out['rule_yaml'] == good
    assert [e['kind'] for e in out['lan_thu'][0]['loi']] == [E.SCRIPT_ISSUE]
    repair = llm.calls[1][1]
    assert f'[{E.SCRIPT_ISSUE}]' in repair and 'selection_switch.ScriptBlock' in repair
    assert out['hunt_specs'][0]['sigma_context']['candidate_regex_policy'] == RF.SCRIPT_POLICY


def missing(behavior, detection, **kw):
    return RF.missing_conditions(SigmaCollection.from_yaml(rule(detection, 'process_creation')).rules[0],
                                 hyp(behavior, **{**PROCESS, **kw}))


def test_hypothesis_literal_absent_from_every_candidate_value_is_listed():
    schtasks = {'Image|endswith': r'\schtasks.exe', 'CommandLine|contains': '/create'}
    assert missing('Tiến trình schtasks.exe chạy với /create và /tn.', schtasks) == [{'loai': 'co_lenh', 'gia_tri': '/tn'}]
    office = {'Image|endswith': r'\WINWORD.EXE'}
    assert missing('Ứng dụng Office (ví dụ WINWORD.EXE, EXCEL.EXE) tạo tiến trình con.', office) == \
        [{'loai': 'tep', 'gia_tri': 'EXCEL.EXE'}]
    assert missing('Kết nối tới cổng 443.', {'Initiated': 'true'}) == [{'loai': 'cong', 'gia_tri': '443'}]
    assert missing('Gọi Win32_Process qua Invoke-WmiMethod.', {'Image|endswith': r'\powershell.exe'}) == \
        [{'loai': 'lop_wmi', 'gia_tri': 'Win32_Process'}, {'loai': 'cmdlet', 'gia_tri': 'Invoke-WmiMethod'}]


@pytest.mark.parametrize('behavior, detection', [
    ('Tiến trình powershell.exe do WmiPrvSE.exe tạo.',
     {'Image|re|i': r'\\(powershell|pwsh)\.exe$', 'ParentImage|endswith': r'\WmiPrvSE.exe'}),   # tên bỏ đuôi trong regex
    (r'Tệp C:\Users\Public\a.dll được nạp.', {'ImageLoaded|endswith': r'\a.dll'}),               # đoạn cuối đường dẫn
    (r'Tệp C:\Users\Public\a.dll được nạp.', {'ImageLoaded|startswith': 'C:\\Users\\Public\\'}),  # thư mục đầu
    ('Dòng lệnh có -EncodedCommand.', {'CommandLine|re|i': E.SWITCH}),                           # tên cờ trong mẫu thư viện
    ('Kết nối tới cổng 443.', {'DestinationPort': 443}),
    ('Lệnh nltest /domain_trusts được chạy.', {'CommandLine|contains': 'domain_trusts'}),
    ('Một tiến trình được tạo trên máy.', {'Image|endswith': '.exe'}),                           # không có chuỗi để so
])
def test_literal_kept_by_the_rule_in_any_written_form_is_not_listed(behavior, detection):
    assert missing(behavior, detection) == []


def test_filter_value_and_bare_extension_do_not_count_as_keeping_a_literal():
    detection = {'selection': {'Image|endswith': '.exe'}, 'filter_known': {'Image|endswith': r'\certutil.exe'},
                 'condition': 'selection and not 1 of filter_*'}
    assert missing('Tiến trình certutil.exe chạy.', detection) == [{'loai': 'tep', 'gia_tri': 'certutil.exe'}]
    assert RF.missing_conditions(SigmaCollection.from_yaml(rule(detection)).rules[0], None) == []


def _round(tmp_path):
    h = hyp('Tiến trình schtasks.exe chạy với /create và /tn.', **PROCESS)
    (tmp_path / approval.APPROVED_FILE).write_text(json.dumps([h.model_dump(mode='json')]), encoding='utf-8')
    path = tmp_path / 'rules' / 'SELF-H01.yml'
    path.parent.mkdir()
    path.write_text(rule({'Image|endswith': r'\schtasks.exe', 'CommandLine|contains': '/create'}, 'process_creation'),
                    encoding='utf-8')
    return path


def test_saved_rule_view_and_script_report_the_missing_literal_without_touching_grounding(tmp_path):
    import importlib.util
    path = _round(tmp_path)
    before = path.read_bytes()
    assert demo.rule_missing(path) == [{'loai': 'co_lenh', 'gia_tri': '/tn'}]
    assert demo.rule_grounding(path) == []                         # phép đối chiếu cũ và mục băm ở cổng rule không đổi
    assert demo.rule_missing(tmp_path / 'rules' / 'KHAC.yml') is None
    spec = importlib.util.spec_from_file_location('doi_chieu_h6', ROOT / 'scripts/doi_chieu_dieu_kien_khau5.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert list(module.rows(tmp_path)) == [{'vong': '.', 'rule': 'rules/SELF-H01.yml', 'muc': [],
                                            'thieu': [{'loai': 'co_lenh', 'gia_tri': '/tn'}]}]
    assert path.read_bytes() == before


def test_ui_shows_missing_literals_as_a_view_only_note(tmp_path):
    from streamlit.testing.v1 import AppTest
    path = _round(tmp_path)
    app = tmp_path / 'note_app.py'
    app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import grounding_note\n"
                   f"grounding_note(Path({str(path)!r}))\n", encoding='utf-8')
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception and not at.error
    shown = [w.value for w in at.warning]
    assert len(shown) == 1 and '`/tn` (cờ lệnh)' in shown[0] and 'không chặn' in shown[0]
