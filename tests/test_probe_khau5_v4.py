"""Isolated sources/decisions/ledger and fake HTTP only; never a real API call."""
import hashlib
import json
import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from cti_hunt import approval, config, integrity
from cti_hunt.agent import probe_khau5 as P
from cti_hunt.contracts import ContractA, ContractB, SourceSpan, TTP
from cti_hunt.llm import budget, providers
from cti_hunt.stages import s1_ingest

GOOD = r"""title: Self-authored encoded process trace
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|re|i: '\s-(EncodedCommand|enc)\s+[A-Za-z0-9+/=]+'
  condition: selection
level: medium
"""


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    for folder in ('src', 'configs', 'prompts'):
        shutil.copytree(config.ROOT / folder, root / folder)
    cfg_path = root / 'configs/agent_v2.yaml'
    cfg = yaml.safe_load(cfg_path.read_text(encoding='utf-8'))
    cfg['prompt_khau5'] = 'prompts/khau5_sigma_v4.md'  # Preserve the historical v4 protocol in this fixture.
    cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding='utf-8')
    (root / 'scripts').mkdir()
    shutil.copyfile(config.ROOT / 'scripts/probe_khau5_v4.py', root / 'scripts/probe_khau5_v4.py')
    bundle = root / 'data/dev/report_emotet_28-9/bundle'
    html = tmp_path / 'source.html'
    html.write_text('<html><body><article><p>Self-authored: PowerShell uses an encoded argument.</p></article></body></html>', encoding='utf-8')
    s1_ingest.ingest(str(html), 'SELF', bundle)
    _, segs, _ = s1_ingest.load_bundle(bundle)
    span = SourceSpan(segment_id=segs[0]['ma_doan'], text=segs[0]['van_ban'])
    extraction = root / 'data/dev/report_emotet_28-9/case/extraction'
    extraction.mkdir(parents=True)
    ca = ContractA(report_id='SELF', ttps=[TTP(tactic='Defense Evasion', technique_id='T1027.010',
        behavior_description='Self-authored encoded argument', source_span=span)])
    cp = extraction / 'contract_a.json'
    cp.write_text(ca.model_dump_json(), encoding='utf-8')
    P.write(extraction / 'meta.json', {'status': 'complete', 'bundle_manifest_sha256': integrity.sha256_file(bundle / 'manifest.json'),
                                    'contract_a_sha256': integrity.sha256_file(cp)})
    h = ContractB(hypothesis_id='SELF-H05', behavior='Self-authored PowerShell with an encoded argument',
        scope='all hosts', timeframe='toàn bộ khoảng thời gian của log', source_spans=[span],
        linked_ttps=['T1027.010'], evidence={'data_source': 'security', 'event_ids': [4688],
                                          'key_fields': ['NewProcessName', 'CommandLine']})
    rd = root / P.REVIEW_REL
    approval.write_review([h], rd)
    form_path = rd / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding='utf-8'))
    form['nguoi_duyet'] = 'Synthetic fixture reviewer'
    form['gia_thuyet'][0]['quyet_dinh'] = 'approved'
    form_path.write_text(yaml.safe_dump(form, allow_unicode=True), encoding='utf-8')
    approval.apply_review(rd)
    h = approval.load_hypotheses(rd / approval.APPROVED_FILE)[0]
    monkeypatch.setattr(P, 'HYPOTHESIS_ID', h.hypothesis_id)
    monkeypatch.setattr(P, 'HYPOTHESIS_HASH', hashlib.sha256(P.dump(h.model_dump(mode='json'))).hexdigest())
    monkeypatch.setattr(P, 'SOURCE_HASH', integrity.sha256_file(bundle / 'source.html'))
    monkeypatch.setattr(P, 'CONTRACT_HASH', integrity.sha256_file(cp))
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('1.042812')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    return root, root / P.OUT_REL, ledger


def transport(monkeypatch, *, raw=None, count=1000):
    calls = []
    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append((url, payload))
        if url.endswith('count_tokens'):
            return {'input_tokens': count}
        if isinstance(raw, BaseException):
            raise raw
        return raw if raw is not None else {'stop_reason': 'tool_use', 'usage': {'input_tokens': 100, 'output_tokens': 20},
            'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD, 'note': 'self-authored fixture'}}]}
    monkeypatch.setattr(providers, '_post', post)
    return calls


def send(case):
    root, out, _ = case
    return P.run(out, root=root, send=True, cap_usd='0.40')


def test_offline_prepares_pinned_payload_without_network_or_ledger_write(case, monkeypatch):
    root, out, ledger = case
    before = ledger.path.read_bytes()
    calls = transport(monkeypatch)
    result = P.run(out, root=root)
    assert result['mode'] == 'OFFLINE_NO_API' and result['api_authorization'] == 'pending_nguoi_van_hanh'
    assert result['synthetic_cases'] == 8 and calls == [] and ledger.path.read_bytes() == before
    payload = json.loads((out / 'payload.json').read_text(encoding='utf-8'))
    assert payload['max_tokens'] == 32000 and payload['output_config'] == {'effort': 'high'}
    user = payload['messages'][0]['content']
    assert 'expected_candidate' not in user and 'SELF-HOST' not in user and 'source_spans' not in user
    assert 'synthetic-test-key' not in json.dumps(payload) and not (out / 'attempt.json').exists()
    assert P.run(out, root=root) == result  # Same packet can be inspected offline, not rewritten.
    assert ledger.path.read_bytes() == before


def test_send_requires_explicit_separate_cap_and_does_not_send_by_default(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch)
    for cap in (None, '0.39', '0.41'):
        with pytest.raises(ValueError, match='trần riêng'):
            P.run(out, root=root, send=True, cap_usd=cap)
    assert calls == [] and not (out / 'attempt.json').exists()


def test_unprepared_send_does_not_create_packet(case, monkeypatch):
    _, out, _ = case
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='Chưa chuẩn bị'):
        send(case)
    assert calls == [] and not out.exists()


def test_success_is_one_generation_with_no_repairs_or_real_hunt(case, monkeypatch):
    root, out, ledger = case
    P.run(out, root=root)
    calls = transport(monkeypatch)
    result = send(case)
    assert len(calls) == 2 and calls[0][0].endswith('count_tokens') and calls[1][0].endswith('messages')
    assert result['state'] == 'received' and result['criteria_met'] and result['manual_review_required']
    assert result['filters_applied'] is False and not result['cost_exceeds_cap']
    assert ledger.status()['known_cost_usd'] == result['known_cost_usd'] == '0.000400'
    assert len(json.loads((out / 'rule_result.json').read_text(encoding='utf-8'))['lan_thu']) == 1
    assert not (out / 'hunt_record.md').exists() and not (out / 'duyet.yaml').exists()
    assert calls[1][1] == json.loads((out / 'payload.json').read_text(encoding='utf-8'))
    for flag in (False, True):
        with pytest.raises(ValueError, match='không gửi lại'):
            P.run(out, root=root, send=flag, cap_usd='0.40' if flag else None)
    assert len(calls) == 2


@pytest.mark.parametrize('file', ['payload.json', 'hypothesis.json', 'cases.json', 'criteria.json', 'protocol.json'])
def test_tampered_packet_is_never_overwritten_or_sent(file, case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    path = out / file
    path.write_text('{}', encoding='utf-8')
    calls = transport(monkeypatch)
    for do_send in (False, True):
        with pytest.raises(ValueError, match='đã đổi'):
            P.run(out, root=root, send=do_send, cap_usd='0.40' if do_send else None)
    assert calls == [] and path.read_text(encoding='utf-8') == '{}'


@pytest.mark.parametrize('name', ['configs/llm_hunt.yaml', 'src/cti_hunt/stages/s5_rule.py',
                                  'prompts/khau5_sigma_v4.md', 'scripts/probe_khau5_v4.py'])
def test_code_and_settings_drift_block_before_http(name, case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    with (root / name).open('a', encoding='utf-8') as f:
        f.write('\n# fixture drift\n')
    calls = transport(monkeypatch)
    with pytest.raises(ValueError):  # A changed policy may fail parsing before the hash comparison.
        send(case)
    assert calls == [] and not (out / 'attempt.json').exists()


def test_stale_actual_decision_is_rejected(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    path = root / P.REVIEW_REL / approval.REVIEW_FILE
    with path.open('a', encoding='utf-8') as f:
        f.write('\n# stale fixture review\n')
    calls = transport(monkeypatch)
    with pytest.raises(approval.ReviewError):
        send(case)
    assert calls == []


@pytest.mark.parametrize('invalid', ['data/dev/newprobe', 'tmp/thu_loi_emotet_6-10/newprobe', '../outside'])
def test_output_cannot_write_data_old_package_or_outside_root(invalid, case):
    root, _, _ = case
    with pytest.raises(ValueError, match='Đầu ra'):
        P.run(root / invalid, root=root)


@pytest.mark.parametrize('raw', [providers.TransportError('fixture network error'),
    {'stop_reason': 'refusal', 'usage': {'input_tokens': 100, 'output_tokens': 20}, 'content': []},
    {'stop_reason': 'max_tokens', 'usage': {'input_tokens': 100, 'output_tokens': 20},
     'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]},
    {'stop_reason': 'end_turn', 'usage': {'input_tokens': 100, 'output_tokens': 20},
     'content': [{'type': 'text', 'text': 'broken JSON'}]},
])
def test_failed_refused_truncated_or_malformed_replies_never_retry(raw, case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw=raw)
    result = send(case)
    assert not result['criteria_met'] and len(calls) == 2
    if not isinstance(raw, BaseException):
        assert (out / 'response_provider.json').exists()
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)


def test_missing_usage_leaves_pending_and_blocks_replay(case, monkeypatch):
    root, out, ledger = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]})
    result = send(case)
    assert result['state'] == 'failed_no_retry' and result['known_cost_usd'] is None
    assert ledger.status()['pending'] and len(calls) == 2
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)


def test_numeric_repetition_is_invalid_without_paid_repair(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100, 'output_tokens': 20},
        'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD.replace('[A-Za-z0-9+/=]+', '[A-Za-z0-9+/=]{20,}')}}]})
    result = send(case)
    assert not result['criteria_met'] and len(calls) == 2
    detail = json.loads((out / 'rule_result.json').read_text(encoding='utf-8'))
    assert not detail['hunt_specs'] and detail['lan_thu'][0]['loi'][0]['kind'] == 'regex_lap_so_khong_ho_tro'


def test_overly_broad_rule_fails_negative_cases(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    broad = yaml.safe_load(GOOD)
    del broad['detection']['selection']['CommandLine|re|i']
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100, 'output_tokens': 20},
        'content': [{'type': 'tool_use', 'input': {'rule_yaml': yaml.safe_dump(broad)}}]})
    result = send(case)
    assert result['checks']['static_valid_first_attempt'] and not result['criteria_met']
    assert not result['checks']['empty_argument'] and not result['checks']['plain_file'] and len(calls) == 2


def test_filters_remain_proposals_and_are_not_applied_to_candidate_cases(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    doc = yaml.safe_load(GOOD)
    doc['detection']['filter_fixture'] = {'Image|endswith': r'\powershell.exe'}
    doc['detection']['condition'] = 'selection and not filter_fixture'
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100, 'output_tokens': 20},
        'content': [{'type': 'tool_use', 'input': {'rule_yaml': yaml.safe_dump(doc)}}]})
    result = send(case)
    assert result['criteria_met'] and result['proposed_filter_count'] == 1 and not result['filters_applied']
    assert len(calls) == 2 and not (out / 'duyet_loc.yaml').exists()


def test_provider_usage_over_cap_is_reported_and_no_retry_occurs(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100000, 'output_tokens': 100000},
        'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]})
    result = send(case)
    assert result['state'] == 'cost_exceeds_cap_no_retry' and not result['criteria_met'] and result['cost_exceeds_cap']
    assert len(calls) == 2


def test_provider_echoed_key_is_redacted_in_saved_response_and_log(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100, 'output_tokens': 20},
        'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD, 'note': 'synthetic-test-key'}}]})
    assert send(case)['criteria_met']
    for name in ('response_provider.json', 'response_raw.json', 'rule_result.json', 'khau5_requests.jsonl'):
        assert 'synthetic-test-key' not in (out / name).read_text(encoding='utf-8')


def test_token_count_above_cap_never_sends_generation(case, monkeypatch):
    root, out, ledger = case
    P.run(out, root=root)
    calls = transport(monkeypatch, count=100000)
    result = send(case)
    assert not result['criteria_met'] and len(calls) == 1 and calls[0][0].endswith('count_tokens')
    assert ledger.status()['known_cost_usd'] == '0.000000' and not ledger.status()['pending']


@pytest.mark.parametrize('reason', ['pending', 'insufficient', 'missing_key'])
def test_preflight_failure_does_not_start_attempt(reason, case, monkeypatch):
    root, out, ledger = case
    P.run(out, root=root)
    if reason == 'pending':
        ledger.reserve('claude-sonnet-5', 100)
    elif reason == 'insufficient':
        ledger.set_limit('0.01')
    else:
        monkeypatch.delenv('LLM_API_KEY')
    calls = transport(monkeypatch)
    with pytest.raises((budget.BudgetError, providers.LLMError)):
        send(case)
    assert calls == [] and not (out / 'attempt.json').exists()


def test_concurrent_send_allows_only_one_generation(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch)
    def once(_):
        try:
            return send(case)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(once, range(2)))
    assert len(calls) == 2 and sum(r is not None for r in results) == 1


def test_hard_interrupt_marker_blocks_replay(case, monkeypatch):
    root, out, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        send(case)
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)
    assert len(calls) == 2 and (out / 'attempt.json').exists()
