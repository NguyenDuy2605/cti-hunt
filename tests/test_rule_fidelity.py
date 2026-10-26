"""Self-authored text/events and mocked LLM only; no campaign or detection-quality claim."""
import base64
import copy
import json

import duckdb
import pytest
import yaml

from cti_hunt import approval, filter_approval as F
from cti_hunt.adapters import duckdb_sigma as adapter
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractB, SourceSpan
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import rule_fidelity as RF, s5_rule as S5

SYS = 'microsoft-windows-sysmon/operational'
LS = adapter.load_catalog(ROOT / 'configs/logsource_catalog.yaml')
P4 = load_sections(ROOT / 'prompts/khau5_sigma_v4.md', ('SYSTEM', 'USER', 'REPAIR'))
SHORT = base64.b64encode('pwd'.encode('utf-16le')).decode('ascii')
LONG = base64.b64encode('Get-Date'.encode('utf-16le')).decode('ascii')
# This is a candidate trace, not a PowerShell syntax parser or proof of malicious intent.
PATTERN = r'\s-EncodedCommand\s+[A-Za-z0-9+/=]+'


def hypothesis(**changes):
    return ContractB(hypothesis_id='SELF-H05', behavior='PowerShell with a base64-encoded command',
        scope='all hosts', timeframe='all available log', status='approved', linked_ttps=['T1027.010'],
        source_spans=[SourceSpan(text='Self-authored: the command is base64-encoded.')],
        evidence={'data_source': SYS, 'event_ids': [1], 'key_fields': ['Image', 'CommandLine']}).model_copy(update=changes)


def rule(pattern=PATTERN, **extra):
    detection = {'selection': {'Image|endswith': r'\powershell.exe', 'CommandLine|re|i': pattern},
                 'condition': 'selection'}
    detection.update(extra)
    return yaml.safe_dump({'title': 'Synthetic encoded process', 'status': 'experimental',
        'logsource': {'product': 'windows', 'category': 'process_creation'},
        'detection': detection, 'level': 'medium'})


def validate(text, h=None, **kwargs):
    return S5.validate_rule(text, h or hypothesis(), LS, filter_policy=F.POLICY,
                            candidate_regex_policy=RF.POLICY, **kwargs)


@pytest.mark.parametrize('pattern, expected', [
    (r'[A-Za-z0-9+/=]{20,}', ['{20,}']), (r'.{2,8}', ['{2,8}']),
    (r'\w{64}', ['{64}']), (r'(ab){2}', ['{2}']), (r'.{0,20}', ['{0,20}']),
    (r'a{1,}', ['{1,}']), (r'a{20,}?b{20,}', ['{20,}']),
    (r'\{20,\}', []), (r'[{20,}]', []), (r'[]{}0-9,]+', []),
    (r'[^]{20,}]+', []), (r'\\{20,}', ['{20,}']),
    (r'\[{20,}', ['{20,}']), (r'[^a]{3}', ['{3}']),
    (r'[a\]{}0-9,]+', []), (r'[A-Za-z0-9+/]+=?=?', []),
])
def test_regex_lexing_ignores_literals_and_class_contents(pattern, expected):
    assert RF.numeric_repetitions(pattern) == expected


@pytest.mark.parametrize('suffix', ['{20,}', '{20}', '{2,20}', '{0,20}', '{1,}'])
def test_numeric_repetition_blocks_candidate_and_produces_no_spec(suffix):
    errors, specs = validate(rule(PATTERN[:-1] + suffix))
    assert [e.kind for e in errors] == [RF.ISSUE] and specs == []


def test_regression_encoded_command_alias_regex_is_blocked():
    # Exact regex syntax of the observed failure; a self-authored test hypothesis.
    pattern = r'(-enc(odedcommand)?\s|\s-e\s|\s-en\s|\s-enc\s)[A-Za-z0-9+/=]{20,}'
    errors, specs = validate(rule(pattern))
    assert [e.kind for e in errors] == [RF.ISSUE] and not specs


def test_numbers_elsewhere_do_not_authorize_regex_threshold():
    h = hypothesis(behavior='A process creates 20 connections within 20 seconds',
                   source_spans=[SourceSpan(text='Self-authored string with 20 in it.')])
    # Evidence metadata or prose numbers must not be used as heuristic permission.
    h.behavior = 'PowerShell base64 trace; unrelated number 20'
    errors, specs = validate(rule(PATTERN[:-1] + '{20,}'), h)
    assert errors[0].kind == RF.ISSUE and not specs


def test_explicit_length_condition_also_requires_supported_representation():
    h = hypothesis(behavior='PowerShell with an encoded argument at least 20 characters long')
    errors, specs = validate(rule(PATTERN[:-1] + '{20,}'), h)
    assert errors[0].kind == RF.ISSUE and not specs
    assert 'if an approved length requirement' in errors[0].message


@pytest.mark.parametrize('condition', ['selection or another', '1 of sel*', 'all of sel*'])
def test_active_or_and_wildcard_selectors_are_checked(condition):
    errors, specs = validate(rule(condition=condition,
        another={'Image|endswith': r'\powershell.exe', 'CommandLine|re': r'\w{20,}'},
        selection_extra={'CommandLine|re': [r'abc', r'[a-z]{7}']}))
    assert errors and all(e.kind == RF.ISSUE for e in errors) and not specs


def test_nested_detection_list_is_checked():
    errors, specs = validate(rule(selection=[{'Image|endswith': r'\powershell.exe'},
                                             {'CommandLine|re|i': r'[a-z]{20,}'}]))
    assert errors[0].kind == RF.ISSUE and not specs


def test_unreferenced_selectors_and_proposed_filters_are_not_candidates():
    errors, specs = validate(rule(condition='selection and not filter_fixture',
        unused={'CommandLine|re': r'.{20,}'}, filter_fixture={'CommandLine|re': r'.{20,}'}))
    assert not errors and specs
    assert specs[0]['sigma_context']['candidate_regex_policy'] == RF.POLICY
    assert len(specs[0]['filters']) == 1


def test_numeric_literal_is_not_mistaken_for_a_regex_quantifier():
    errors, specs = validate(rule(selection={'CommandLine|contains': '{20,}'}))
    assert not errors and specs


@pytest.mark.parametrize('version', ['v1', 'v2', 'v3'])
def test_old_prompt_validation_is_unchanged(version):
    old = load_sections(ROOT / f'prompts/khau5_sigma_{version}.md', ('SYSTEM', 'USER', 'REPAIR'))
    llm = MockClient(responses=[{'rule_yaml': rule(PATTERN[:-1] + '{20,}')}])
    res = S5.generate_rule(hypothesis(), llm, old, LS, 0, filter_policy=F.POLICY)
    assert res['hop_le'] and 'candidate_regex_policy' not in res['hunt_specs'][0]['sigma_context']
    assert len(llm.calls) == 1 and S5.candidate_policy(old) == ''


def test_policy_unknown_fails_before_model_call():
    prompt = copy.deepcopy(P4)
    prompt['sections']['STATIC_POLICY'] = 'unknown'
    llm = MockClient()
    with pytest.raises(ValueError, match='unknown candidate regex policy'):
        S5.generate_rule(hypothesis(), llm, prompt, LS, 1)
    assert not llm.calls


def test_v4_prompt_has_no_example_technique_ids_and_loads_policy_by_content():
    import re
    assert not re.search(r'\bT\d{4}', (ROOT / agent_config('v2')['prompt_khau5']).read_text(encoding='utf-8'))
    moved = copy.deepcopy(P4)
    moved['path'] = 'any/path/renamed.md'
    assert S5.candidate_policy(moved) == RF.POLICY


def test_unapproved_hypothesis_cannot_reach_new_rule_model():
    llm = MockClient()
    with pytest.raises(approval.NotApprovedError):
        S5.generate_rule(hypothesis(status='pending_review'), llm, P4, LS, 2)
    assert not llm.calls


def test_repair_limit_is_preserved_and_failed_rule_never_becomes_spec():
    text = rule(PATTERN[:-1] + '{20,}')
    llm = MockClient(responses=[{'rule_yaml': text}] * 3)
    res = S5.generate_rule(hypothesis(), llm, P4, LS, 2, filter_policy=F.POLICY)
    assert not res['hop_le'] and not res['hop_le_lan_dau']
    assert res['so_lan_sua'] == 2 and len(llm.calls) == 3
    assert res['rule_yaml'] is None and not res['hunt_specs']
    assert all(a['loi'][0]['kind'] == RF.ISSUE for a in res['lan_thu'])


@pytest.fixture
def events():
    con = duckdb.connect()
    con.execute('CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, '
                'ev_rec BIGINT, ev_ts TIMESTAMP, Image VARCHAR, CommandLine VARCHAR)')
    for rec, image, command in [
        (1, r'C:\Windows\powershell.exe', 'powershell.exe -EncodedCommand ' + SHORT),
        (2, r'C:\Windows\powershell.exe', 'powershell.exe -ENCODEDCOMMAND ' + LONG),
        (3, r'C:\Windows\powershell.exe', 'powershell.exe -EncodedCommand '),
        (4, r'C:\Windows\powershell.exe', 'powershell.exe -File self-authored.ps1'),
        (5, r'C:\Windows\cmd.exe', 'cmd.exe -EncodedCommand ' + SHORT),
    ]:
        con.execute("INSERT INTO events VALUES ('SELF-HOST', ?, 1, ?, TIMESTAMP '2020-01-01', ?, ?)",
                    [SYS, rec, image, command])
    yield con
    con.close()


def test_mock_repair_retains_short_encoded_trace_through_review_gate(events, tmp_path):
    h = hypothesis()
    before = h.model_dump(mode='json')
    cols = {r[0] for r in events.execute('DESCRIBE events').fetchall()}
    llm = MockClient(responses=[{'rule_yaml': rule(PATTERN[:-1] + '{20,}')}, {'rule_yaml': rule()}])
    res = S5.generate_rule(h, llm, P4, LS, 2, cols, events, tmp_path / 'requests', filter_policy=F.POLICY)
    assert res['hop_le'] and not res['hop_le_lan_dau'] and res['so_lan_sua'] == 1
    assert res['lan_thu'][0]['loi'][0]['kind'] == RF.ISSUE
    assert h.model_dump(mode='json') == before
    approved_fields = []
    for system, user in llm.calls:
        obj = json.JSONDecoder().raw_decode(user[user.index('{'):])[0]
        approved_fields.append(obj)
        assert obj['behavior'] == h.behavior and obj['evidence'] == h.evidence.model_dump()
        assert 'source_spans' not in obj and SHORT not in user and LONG not in user
        assert '{hypothesis}' not in user and RF.POLICY not in system
    assert approved_fields[0] == approved_fields[1]
    assert 'Do not invent a length threshold' in llm.calls[1][1]
    # Read only synthetic events after generation: no hit count was passed to the model.
    spec = res['hunt_specs'][0]
    keys = events.execute(f"SELECT ev_rec FROM events WHERE ({spec['candidates']}) ORDER BY ev_rec").fetchall()
    assert len(SHORT) == 8 and len(LONG) > 20 and keys == [(1,), (2,)]
    root = tmp_path / 'review-fixture'
    F.bind(events, root)
    rd = F.prepare(events, [spec], root, root / 'filter_review/r01')
    assert F.load_form(rd)['muc_loc'] == []  # No human decision is invented.
    paths = F.finalize(rd, con=events)
    effective = yaml.safe_load(paths[0].read_text(encoding='utf-8'))
    assert effective['sigma_context']['candidate_regex_policy'] == RF.POLICY
    assert effective['candidates'] == spec['candidates']


def test_filter_packet_revalidates_pinned_regex_policy(events):
    errors, specs = validate(rule(), columns={r[0] for r in events.execute('DESCRIBE events').fetchall()}, con=events)
    assert not errors
    altered = copy.deepcopy(specs[0])
    # Before a packet is hashed, an altered draft must still pass its pinned policy.
    altered['sigma_context']['rule']['detection']['selection']['CommandLine|re|i'] = PATTERN[:-1] + '{20,}'
    with pytest.raises(F.FilterReviewError, match='binding/draft'):
        F._validate_draft(events, altered)
