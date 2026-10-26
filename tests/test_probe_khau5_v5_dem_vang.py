"""Isolated root/ledger, synthetic ◆ reviewer in a temp folder and fake HTTP only; never a real API call."""
import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from cti_hunt import approval, config, integrity
from cti_hunt.agent import probe_khau5_dem_vang as P
from cti_hunt.contracts import ContractB, SourceSpan
from cti_hunt.llm import budget, providers

SYS = P.SYS
TEXTS = ['Self-authored: a process connects to at least two distinct destination IPs in the centered interval '
         '45 seconds before to 45 seconds after a connection, on the same host with the same process GUID.',
         'Self-authored: a connection has no collected DNS query for the same host and process GUID during the '
         'inclusive 30 seconds preceding it.']
RB = [{'dem_khac_nhau': {'truong': 'DestinationIp', 'theo': ['ev_host', 'ProcessGuid'], 'cua_so_giay': 45, 'toi_thieu': 2}},
      {'vang_mat': {'channel': SYS, 'event_ids': [22], 'truoc_giay': 30, 'khop': [
          {'ung_vien': 'ProcessGuid', 'nguon': 'ProcessGuid'}, {'ung_vien': 'ev_host', 'nguon': 'ev_host'}]}}]
BEHAVIOR = ['Một tiến trình (cùng ProcessGuid, cùng host) kết nối tới ít nhất 2 địa chỉ IP đích khác nhau trong khoảng '
            'thời gian tập trung quanh một kết nối: từ 45 giây trước đến 45 giây sau.',
            'Một kết nối mạng (Sysmon EventID 3) không có truy vấn DNS nào được ghi nhận (Sysmon EventID 22) cho cùng '
            'host và cùng ProcessGuid trong khoảng 30 giây ngay trước đó (tính cả thời điểm biên).']


def rule(extra=None):
    selection = {'EventID': 3, **(extra or {})}
    return yaml.safe_dump({'title': 'Fixture network connection', 'status': 'experimental',
                           'logsource': {'product': 'windows', 'category': 'network_connection'},
                           'detection': {'selection': selection, 'condition': 'selection'}, 'level': 'low'})


GOOD = rule()


def hypotheses():
    return [ContractB(hypothesis_id=f'SELF-COUNT-ABSENCE-0610-H0{n + 1}', behavior=BEHAVIOR[n], scope='Toàn bộ host',
                      timeframe='toàn bộ khoảng thời gian của log', linked_ttps=['T1071'],
                      evidence={'data_source': SYS, 'event_ids': [3],
                                'key_fields': ['Image', 'ProcessGuid', 'DestinationIp', 'DestinationPort', 'EventID']},
                      source_spans=[SourceSpan(segment_id=f'SELF-MULTIEVENT-0{n + 1}-001', text=TEXTS[n])],
                      required_operations=['distinct_count' if n == 0 else 'absence'], rang_buoc=RB[n])
            for n in range(2)]


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    for folder in ('src', 'configs', 'prompts'):
        shutil.copytree(config.ROOT / folder, root / folder, ignore=shutil.ignore_patterns('__pycache__'))
    # Phép thử này ghim prompt ⑤ v5; từ 12/10 (H6) cấu hình v2 trỏ v6 nên fixture giữ v5 như lúc chuẩn bị gói.
    ac = root / 'configs/agent_v2.yaml'
    ac.write_text(re.sub(r'(?m)^prompt_khau5: \S+', 'prompt_khau5: prompts/khau5_sigma_v5.md',
                         ac.read_text(encoding='utf-8')), encoding='utf-8')
    (root / 'scripts').mkdir()
    shutil.copyfile(config.ROOT / 'scripts/probe_khau5_v5_dem_vang.py', root / 'scripts/probe_khau5_v5_dem_vang.py')
    src = root / P.SOURCE_REL
    src.mkdir(parents=True)
    P.write(src / 'hypotheses_pending.json', [h.model_dump(mode='json') for h in hypotheses()])
    P.write(src / 'result.json', {'state': 'received', 'fixture': True})
    P.write(src / 'attempt.json', {'state': 'attempt_started_no_retry', 'fixture': True})
    monkeypatch.setattr(P, 'SOURCE_SHA256', {n: integrity.sha256_file(src / n) for n in
                                             ('hypotheses_pending.json', 'result.json', 'attempt.json')})
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('0.999472')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    return root, root / P.OUT_REL, ledger


def review(out, decisions):
    # Only this test's synthetic form; no real ◆ form is touched.
    rd = out / P.ROUND
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    form['nguoi_duyet'] = 'Synthetic fixture reviewer'
    for row, d in zip(form['gia_thuyet'], decisions):
        row['quyet_dinh'], row['ly_do'] = d, 'fixture' if d == 'rejected' else ''
    (rd / approval.REVIEW_FILE).write_text(yaml.safe_dump(form, allow_unicode=True), encoding='utf-8')
    approval.apply_review(rd)


def prepared(case, decisions=('approved', 'approved')):
    root, out, _ = case
    assert P.run(out, root=root)['state'] == 'awaiting_duy_review'
    review(out, decisions)
    return P.run(out, root=root)


def transport(monkeypatch, replies=None, *, count=3000):
    calls, queue = [], list(replies or [])

    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append((url, payload))
        if url.endswith('count_tokens'):
            return {'input_tokens': count}
        r = queue.pop(0) if queue else {'rule_yaml': GOOD, 'note': 'fixture'}
        if isinstance(r, BaseException):
            raise r
        if isinstance(r, dict) and 'content' in r:
            return r
        return {'stop_reason': 'tool_use', 'usage': {'input_tokens': 3000, 'output_tokens': 500},
                'content': [{'type': 'tool_use', 'input': r}]}
    monkeypatch.setattr(providers, '_post', post)
    return calls


def generations(calls):
    return [c for c in calls if c[0].endswith('/v1/messages')]


def send(case):
    root, out, _ = case
    return P.run(out, root=root, send=True, cap_usd='0.40')


def test_first_prepare_only_creates_empty_review_form(case, monkeypatch):
    root, out, ledger = case
    before = ledger.path.read_bytes()
    calls = transport(monkeypatch)
    result = P.run(out, root=root)
    rd = out / P.ROUND
    assert result['state'] == 'awaiting_duy_review' and calls == [] and ledger.path.read_bytes() == before
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    assert form['nguoi_duyet'] == '' and [g['quyet_dinh'] for g in form['gia_thuyet']] == ['', '']
    # The fixed gate no longer reports the centered count window as a missing anchor.
    assert [g['loi_kha_nang_thuc_thi'] for g in form['gia_thuyet']] == [[], []]
    assert not (rd / approval.LOG_FILE).exists() and not (out / 'protocol.json').exists()
    assert P.run(out, root=root)['state'] == 'awaiting_duy_review'
    with pytest.raises(ValueError, match='chưa áp'):
        send(case)
    assert calls == []


def test_prepare_after_review_pins_requests_and_self_checks_harness(case, monkeypatch):
    root, out, ledger = case
    calls = transport(monkeypatch)
    result = prepared(case)
    assert result['mode'] == 'OFFLINE_NO_API' and result['harness_self_check'] and calls == []
    assert result['approved'] == ['SELF-COUNT-ABSENCE-0610-H01', 'SELF-COUNT-ABSENCE-0610-H02']
    protocol = json.loads((out / 'protocol.json').read_text(encoding='utf-8'))
    checks = protocol['harness_self_check']['hypotheses']
    assert checks['SELF-COUNT-ABSENCE-0610-H01']['kept_after_constraint'] == [2, 3]
    assert checks['SELF-COUNT-ABSENCE-0610-H02']['kept_after_constraint'] == [1, 4, 5, 6, 7]
    for hid in result['approved']:
        text = (out / f'payload_{hid}.json').read_text(encoding='utf-8')
        payload = json.loads(text)
        assert payload['max_tokens'] == 32000 and payload['output_config'] == {'effort': 'high'}
        # The model sees the approved hypothesis/logsource only: no quotes, fixture events or expected records.
        for word in ('Self-authored', '10.0.0.2', 'HOST-B', 'other-guid', 'expected', 'kept_after'):
            assert word not in text
    assert P.run(out, root=root) == result and ledger.status()['known_cost_usd'] == '0.000000'


def test_send_requires_separate_cap(case, monkeypatch):
    root, out, _ = case
    prepared(case)
    calls = transport(monkeypatch)
    for cap in (None, '0.39', '1.00'):
        with pytest.raises(ValueError, match='trần gói'):
            P.run(out, root=root, send=True, cap_usd=cap)
    with pytest.raises(ValueError, match='không nhận quyền chi'):
        P.run(out, root=root, cap_usd='0.40')
    assert calls == [] and not (out / 'attempt.json').exists()


def test_faithful_rules_meet_criteria_without_filters_or_record(case, monkeypatch):
    root, out, ledger = case
    prepared(case)
    calls = transport(monkeypatch)
    result = send(case)
    assert result['state'] == 'received' and result['criteria_met'] and result['generation_calls'] == 2
    assert len(generations(calls)) == 2 and result['filters_applied'] is False
    payloads = [json.loads((out / f'payload_{h}.json').read_text(encoding='utf-8')) for h in
                ('SELF-COUNT-ABSENCE-0610-H01', 'SELF-COUNT-ABSENCE-0610-H02')]
    assert [p for _, p in generations(calls)] == payloads
    assert result['known_cost_usd'] == ledger.status()['known_cost_usd'] == '0.022000'
    assert sorted(p.name for p in (out / 'api_calls').iterdir())[:2] == ['call_00_count.json', 'call_00_reply.json']
    assert not list(out.rglob('duyet_loc*')) and not list(out.rglob('hunt_record*'))
    for flag in (False, True):
        with pytest.raises(ValueError, match='không gửi lại'):
            P.run(out, root=root, send=flag, cap_usd='0.40' if flag else None)
    assert len(generations(calls)) == 2


@pytest.mark.parametrize('extra', [{'Initiated': 'true'}, {'DestinationPort': '443'},
                                   {'Image|endswith': '\\powershell.exe'}])
def test_rule_adding_unsupported_condition_fails_selection_check(extra, case, monkeypatch):
    prepared(case)
    transport(monkeypatch, [{'rule_yaml': rule(extra)}, {'rule_yaml': GOOD}])
    result = send(case)
    h01 = result['hypotheses']['SELF-COUNT-ABSENCE-0610-H01']
    assert result['state'] == 'received' and not result['criteria_met']
    assert h01['checks']['valid_rule'] and not h01['checks']['selection_keeps_every_primary_event']
    assert result['hypotheses']['SELF-COUNT-ABSENCE-0610-H02']['criteria_met']


def test_static_error_is_repaired_with_static_messages_only(case, monkeypatch):
    root, out, _ = case
    prepared(case)
    calls = transport(monkeypatch, [{'rule_yaml': 'title: [broken'}, {'rule_yaml': GOOD}, {'rule_yaml': GOOD}])
    result = send(case)
    h01 = result['hypotheses']['SELF-COUNT-ABSENCE-0610-H01']
    assert result['criteria_met'] and not h01['valid_first_attempt'] and h01['repairs'] == 1
    repair = generations(calls)[1][1]['messages'][0]['content']
    assert 'yaml_loi' in repair and '10.0.0' not in repair and 'kept_after' not in repair
    assert len(generations(calls)) == 3


def test_rejected_hypothesis_is_not_sent(case, monkeypatch):
    prepared(case, ('approved', 'rejected'))
    calls = transport(monkeypatch)
    result = send(case)
    assert list(result['hypotheses']) == ['SELF-COUNT-ABSENCE-0610-H01'] and len(generations(calls)) == 1


def test_nothing_approved_cannot_send(case, monkeypatch):
    result = prepared(case, ('rejected', 'rejected'))
    assert result['approved'] == []
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='Không có giả thuyết approved'):
        send(case)
    assert calls == []


def test_package_cap_stops_later_calls_without_sending(case, monkeypatch):
    prepared(case)
    big = {'stop_reason': 'tool_use', 'usage': {'input_tokens': 3000, 'output_tokens': 9000},
           'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]}
    calls = transport(monkeypatch, [big])
    result = send(case)
    h02 = result['hypotheses']['SELF-COUNT-ABSENCE-0610-H02']
    assert len(generations(calls)) == 1 and not h02['checks']['valid_rule'] and not result['criteria_met']
    detail = json.loads((case[1] / 'rule_result_SELF-COUNT-ABSENCE-0610-H02.json').read_text(encoding='utf-8'))
    assert detail['lan_thu'][0]['loi'][0]['kind'] == 'het_ngan_sach'


def test_reply_without_usage_is_kept_and_package_stops(case, monkeypatch):
    root, out, ledger = case
    prepared(case)
    calls = transport(monkeypatch, [{'stop_reason': 'tool_use', 'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]}])
    result = send(case)
    assert result['state'] == 'failed_no_retry' and result['failure']['error_type'] == 'BudgetError'
    assert (out / 'api_calls/call_00_reply.json').is_file() and ledger.status()['pending']
    assert len(generations(calls)) == 1
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)


@pytest.mark.parametrize('reply', [providers.TransportError('fixture network error'),
    {'stop_reason': 'max_tokens', 'usage': {'input_tokens': 100, 'output_tokens': 32000},
     'content': [{'type': 'tool_use', 'input': {'rule_yaml': GOOD}}]}])
def test_failed_call_stops_package_without_retry(reply, case, monkeypatch):
    prepared(case)
    calls = transport(monkeypatch, [reply])
    result = send(case)
    assert result['state'] == 'failed_no_retry' and not result['criteria_met'] and len(generations(calls)) == 1


def test_refusal_is_recorded_and_next_hypothesis_continues(case, monkeypatch):
    prepared(case)
    refusal = {'stop_reason': 'refusal', 'usage': {'input_tokens': 100, 'output_tokens': 10}, 'content': []}
    calls = transport(monkeypatch, [refusal, {'rule_yaml': GOOD}])
    result = send(case)
    assert result['state'] == 'received' and len(generations(calls)) == 2
    assert not result['hypotheses']['SELF-COUNT-ABSENCE-0610-H01']['criteria_met']
    assert result['hypotheses']['SELF-COUNT-ABSENCE-0610-H02']['criteria_met']


@pytest.mark.parametrize('name', ['src/cti_hunt/stages/s5_rule.py', 'prompts/khau5_sigma_v5.md',
                                  'configs/logsource_catalog.yaml', 'scripts/probe_khau5_v5_dem_vang.py',
                                  'tmp/thu_khau5_v5_dem_vang_7-10/round_01/duyet.yaml'])
def test_drift_after_preparation_blocks_before_http(name, case, monkeypatch):
    root, out, _ = case
    prepared(case)
    with (root / name).open('a', encoding='utf-8') as f:
        f.write('\n# fixture drift\n')
    calls = transport(monkeypatch)
    with pytest.raises(ValueError):
        send(case)
    assert calls == [] and not (out / 'attempt.json').exists()


def test_changed_source_trial_blocks_form_and_send(case, monkeypatch):
    root, out, _ = case
    prepared(case)
    (root / P.SOURCE_REL / 'result.json').write_text('{}', encoding='utf-8')
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='④ v6'):
        send(case)
    assert calls == []


@pytest.mark.parametrize('reason', ['pending', 'missing_key'])
def test_preflight_failure_does_not_start_attempt(reason, case, monkeypatch):
    root, out, ledger = case
    prepared(case)
    if reason == 'pending':
        ledger.reserve('claude-sonnet-5', 100)
    else:
        monkeypatch.delenv('LLM_API_KEY')
    calls = transport(monkeypatch)
    with pytest.raises((budget.BudgetError, providers.LLMError)):
        send(case)
    assert calls == [] and not (out / 'attempt.json').exists()


@pytest.mark.parametrize('invalid', ['data/dev/x', 'tmp/thu_khau4_v6_dem_vang_7-10', 'tmp/nested/x', '../outside'])
def test_output_cannot_be_data_old_trials_nested_or_outside(invalid, case):
    root, _, _ = case
    with pytest.raises(ValueError, match='Đầu ra'):
        P.run(root / invalid, root=root)


def test_concurrent_send_allows_one_package(case, monkeypatch):
    prepared(case)
    calls = transport(monkeypatch)

    def once(_):
        try:
            return send(case)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(once, range(2)))
    assert sum(r is not None for r in results) == 1 and len(generations(calls)) == 2


def test_hard_interrupt_marker_blocks_replay(case, monkeypatch):
    root, out, _ = case
    prepared(case)
    calls = transport(monkeypatch, [KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        send(case)
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)
    assert len(generations(calls)) == 1 and (out / 'attempt.json').exists()


def test_echoed_key_is_redacted(case, monkeypatch):
    root, out, _ = case
    prepared(case)
    transport(monkeypatch, [{'rule_yaml': GOOD, 'note': 'synthetic-test-key'}])
    send(case)
    for path in out.rglob('*'):
        if path.is_file() and path.suffix in ('.json', '.jsonl'):
            assert 'synthetic-test-key' not in path.read_text(encoding='utf-8')
