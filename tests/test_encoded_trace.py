"""Bounded textual representations on self-authored events and mocked LLM only."""
import base64
import copy
import json

import duckdb
import pytest
import yaml

from cti_hunt import filter_approval as F
from cti_hunt.adapters import duckdb_sigma as adapter
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractB, SourceSpan
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import encoded_trace as E, rule_fidelity as RF, s5_rule as S5

LS = adapter.load_catalog(ROOT / 'configs/logsource_catalog.yaml')
PROMPT = load_sections(ROOT / agent_config('v2')['prompt_khau5'], ('SYSTEM', 'USER', 'REPAIR'))
SHORT = base64.b64encode('pwd'.encode('utf-16le')).decode('ascii')


def hyp(**changes):
    return ContractB(hypothesis_id='SELF-ENCODED', behavior='PowerShell with a base64-encoded command',
        scope='all hosts', timeframe='all available log', status='approved', linked_ttps=['T1027.010'],
        source_spans=[SourceSpan(text='Self-authored encoded command.')],
        evidence={'data_source': 'security', 'event_ids': [4688], 'key_fields': ['NewProcessName', 'CommandLine']}
    ).model_copy(update=changes)


def rule(pattern=E.SWITCH, **extras):
    detection = {'selection': {'Image|endswith': r'\powershell.exe', 'CommandLine|re|i': pattern},
                 'condition': 'selection'}
    detection.update(extras)
    return yaml.safe_dump({'title': 'Self-authored encoded argument trace', 'status': 'experimental',
        'logsource': {'product': 'windows', 'category': 'process_creation'}, 'detection': detection, 'level': 'medium'})


def validate(text, h=None):
    return S5.validate_rule(text, h or hyp(), LS, filter_policy=F.POLICY, candidate_regex_policy=RF.ENCODED_POLICY)


@pytest.mark.parametrize('behavior', [
    'PowerShell with a base64-encoded command',
    'Lệnh dùng để khởi chạy PowerShell bị mã hóa base64, thể hiện qua dòng lệnh khởi tạo tiến trình powershell.exe.',
])
def test_explicit_approved_prose_gets_supported_representation(behavior):
    h = hyp(behavior=behavior)
    assert E.required(h) and E.requirements(h)['supported_patterns'] == list(E.PATTERNS)


@pytest.mark.parametrize('behavior', ['PowerShell process starts', 'A process creates base64 files',
    'PowerShell command is not base64 encoded', 'PowerShell không dùng lệnh mã hóa base64',
    'PowerShell with a base64-encoded file', 'PowerShell with an encoded command'])
def test_unrecognized_or_negative_prose_does_not_acquire_hidden_constraint(behavior):
    assert not E.required(hyp(behavior=behavior)) and E.requirements(hyp(behavior=behavior)) is None


def test_gate_uses_prose_and_evidence_not_hypothesis_id_or_technique_id():
    assert E.required(hyp(hypothesis_id='OTHER', linked_ttps=['T1047']))
    h = hyp()
    h.evidence.event_ids = [4104]
    assert not E.required(h)
    h = hyp()
    h.evidence.key_fields = ['Image']
    assert not E.required(h)


@pytest.mark.parametrize('pattern', [E.SWITCH, E.DECODE])
def test_supported_case_insensitive_pattern_passes_static_guard(pattern):
    errors, specs = validate(rule(pattern))
    assert not errors and specs[0]['sigma_context']['candidate_regex_policy'] == RF.ENCODED_POLICY


@pytest.mark.parametrize('value', ['-enc', '-encodedcommand', '-ec', 'FromBase64String'])
def test_bare_contains_indicator_does_not_prove_argument(value):
    errors, specs = validate(rule(selection={'Image|endswith': r'\powershell.exe', 'CommandLine|contains': value}))
    assert errors[0].kind == E.ISSUE and not specs


def test_regex_presence_alone_or_a_changed_pattern_is_not_certified():
    for pattern in ['-enc', r'\s-enc\s*.*', E.SWITCH + '|-enc']:
        errors, specs = validate(rule(pattern))
        assert errors[0].kind == E.ISSUE and not specs


def test_canonical_pattern_requires_exact_ignorecase_semantics():
    for key in ['CommandLine|re', 'CommandLine|re|i|s']:
        errors, specs = validate(rule(selection={'Image|endswith': r'\powershell.exe', key: E.SWITCH}))
        assert errors[0].kind == E.ISSUE and not specs


@pytest.mark.parametrize('condition', ['selection or weak', '1 of sel*'])
def test_or_wildcard_cannot_hide_unguarded_candidate_branch(condition):
    errors, specs = validate(rule(condition=condition, weak={'CommandLine|contains': '-enc'},
                                  selection_weak={'CommandLine|contains': '-enc'}))
    assert errors[0].kind == E.ISSUE and not specs


def test_disjunctive_supported_paths_are_valid_but_filters_do_not_prove_candidates():
    errors, specs = validate(rule(condition='selection or decode', decode={'CommandLine|re|i': E.DECODE}))
    assert not errors and specs
    errors, specs = validate(rule(selection={'CommandLine|contains': '-enc'},
                                  filter_safe={'CommandLine|re|i': E.SWITCH}, condition='selection and not filter_safe'))
    assert errors[0].kind == E.ISSUE and not specs


@pytest.mark.parametrize('values, all_modifier, valid', [
    ([E.SWITCH, '-enc'], False, False), ([E.SWITCH, '-enc'], True, True),
    ([E.SWITCH, E.DECODE], False, True),
])
def test_field_value_or_requires_every_value_and_requires_one_guard(values, all_modifier, valid):
    field = 'CommandLine|re|i' + ('|all' if all_modifier else '')
    errors, specs = validate(rule(selection={field: values}))
    assert bool(specs) == valid and bool(errors) != valid


def test_nested_detection_or_is_checked():
    errors, specs = validate(rule(selection=[{'CommandLine|re|i': E.SWITCH}, {'CommandLine|contains': '-enc'}]))
    assert errors[0].kind == E.ISSUE and not specs


def test_legacy_v4_still_records_original_bare_indicator_behavior():
    old = load_sections(ROOT / 'prompts/khau5_sigma_v4.md', ('SYSTEM', 'USER', 'REPAIR'))
    text = rule(selection={'Image|endswith': r'\powershell.exe', 'CommandLine|contains': ['-enc', 'FromBase64String']})
    res = S5.generate_rule(hyp(), MockClient(responses=[{'rule_yaml': text}]), old, LS, 0, filter_policy=F.POLICY)
    assert res['hop_le'] and res['hunt_specs'][0]['sigma_context']['candidate_regex_policy'] == RF.POLICY


def _examples():
    ps = r'C:\Windows\powershell.exe'
    rows = [(f'short_{len(base64.b64encode(t.encode("utf-16le")))}', ps,
             'powershell.exe -EncodedCommand ' + base64.b64encode(t.encode('utf-16le')).decode('ascii'), True)
            for t in ['x', 'pwd', 'Get-Date']]
    rows += [(name, ps, cmd, want) for name, cmd, want in [
        ('uppercase', 'powershell.exe -ENCODEDCOMMAND ' + SHORT, True),
        ('enc', 'powershell.exe -enc ' + SHORT, True),
        ('quoted', 'powershell.exe -EncodedCommand "' + SHORT + '"', True),
        ('single_quoted', "powershell.exe -EncodedCommand '" + SHORT + "'", True),
        ('decode', "powershell.exe -Command [Convert]::FromBase64String('" + SHORT + "')", True),
        ('system_decode', 'powershell.exe -Command [System.Convert]::FromBase64String("' + SHORT + '")', True),
        ('empty_argument', 'powershell.exe -EncodedCommand ', False),
        ('empty_short', 'powershell.exe -enc', False),
        ('filename', 'powershell.exe -File self-enc.ps1', False),
        ('other_flag', 'powershell.exe -encrypt', False),
        ('method_literal', "powershell.exe -Command Write-Output 'FromBase64String'", False),
        ('empty_decode', "powershell.exe -Command [Convert]::FromBase64String('')", False),
        ('plain_file', 'powershell.exe -File self-authored.ps1', False),
        ('argument_is_option', 'powershell.exe -enc -NoProfile', False),
    ]]
    rows += [('other_process', r'C:\Windows\cmd.exe', 'cmd.exe -EncodedCommand ' + SHORT, False)]
    return rows


@pytest.mark.parametrize('name,image,cmd,want', _examples(), ids=[r[0] for r in _examples()])
def test_supported_trace_sql_on_self_authored_positive_and_negative_text(name, image, cmd, want):
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(NewProcessName VARCHAR, CommandLine VARCHAR)')
        con.execute('INSERT INTO events VALUES (?, ?)', [image, cmd])
        errors, specs = validate(rule(pattern=[E.SWITCH, E.DECODE]))
        assert not errors
        match = con.execute(f"SELECT count(*) FROM events WHERE ({specs[0]['candidates']})").fetchone()[0] == 1
        assert match == want


def test_mock_repair_gets_same_requirements_and_no_cases_or_counts(tmp_path):
    h = hyp()
    before = h.model_dump(mode='json')
    weak = rule(selection={'Image|endswith': r'\powershell.exe', 'CommandLine|contains': ['-enc', 'FromBase64String']})
    llm = MockClient(responses=[{'rule_yaml': weak}, {'rule_yaml': rule(pattern=[E.SWITCH, E.DECODE])}])
    res = S5.generate_rule(h, llm, PROMPT, LS, 2, run_dir=tmp_path, filter_policy=F.POLICY)
    assert res['hop_le'] and not res['hop_le_lan_dau'] and res['so_lan_sua'] == 1
    assert res['lan_thu'][0]['loi'][0]['kind'] == E.ISSUE
    assert h.model_dump(mode='json') == before
    hypotheses, requirements = [], []
    for _, user in llm.calls:
        hypotheses.append(json.JSONDecoder().raw_decode(user[user.index('{'):])[0])
        tail = user.split('Supported primary trace requirements (immutable DATA, or null):')[1].lstrip()
        requirements.append(json.JSONDecoder().raw_decode(tail)[0])
        assert 'empty_argument' not in user and SHORT not in user and 'source_spans' not in hypotheses[-1]
        assert '{primary_trace_requirements}' not in user and '{hypothesis}' not in user
    assert hypotheses[0] == hypotheses[1] and requirements[0] == requirements[1] == E.requirements(h)
    # Revalidate the exact policy through the reviewed-filter packet's binding.
    spec = res['hunt_specs'][0]
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, '
                    'ev_ts TIMESTAMP, NewProcessName VARCHAR, CommandLine VARCHAR)')
        F._validate_draft(con, spec)
        altered = copy.deepcopy(spec)
        altered['sigma_context']['rule']['detection']['selection'] = yaml.safe_load(weak)['detection']['selection']
        with pytest.raises(F.FilterReviewError, match='binding/draft'):
            F._validate_draft(con, altered)


def test_new_policy_does_not_turn_other_hypotheses_into_encoded_hunts():
    h = hyp(behavior='Self-authored process starts')
    text = rule(selection={'Image|endswith': r'\powershell.exe'})
    res = S5.generate_rule(h, MockClient(responses=[{'rule_yaml': text}]), PROMPT, LS, 0)
    assert res['hop_le']


def test_repeated_weak_response_stops_at_existing_repair_limit():
    weak = rule(selection={'CommandLine|contains': '-enc'})
    llm = MockClient(responses=[{'rule_yaml': weak}] * 3)
    res = S5.generate_rule(hyp(), llm, PROMPT, LS, 2)
    assert not res['hop_le'] and not res['hunt_specs'] and len(llm.calls) == 3 and res['so_lan_sua'] == 2
