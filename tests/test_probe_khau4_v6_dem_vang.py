"""Isolated packet/config/ledger and fake HTTP only; never a real API call or the real shared ledger."""
import copy
import json
import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from cti_hunt import config, integrity
from cti_hunt.agent import probe_khau4_dem_vang as P
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import budget, providers
from cti_hunt.llm.prompting import fill, load_sections
from cti_hunt.stages import s4_hypothesis as S4

SYS = 'microsoft-windows-sysmon/operational'
TEXTS = ['Self-authored: a process connects to at least two distinct destination IPs in the centered interval '
         '45 seconds before to 45 seconds after a connection, on the same host with the same process GUID.',
         'Self-authored: a connection has no collected DNS query for the same host and process GUID during the '
         'inclusive 30 seconds preceding it.']
COUNT = {'truong': 'DestinationIp', 'theo': ['ev_host', 'ProcessGuid'], 'cua_so_giay': 45, 'toi_thieu': 2}
ABSENCE = {'channel': SYS, 'event_ids': [22], 'truoc_giay': 30,
           'khop': [{'ung_vien': 'ev_host', 'nguon': 'ev_host'}, {'ung_vien': 'ProcessGuid', 'nguon': 'ProcessGuid'}]}
REFERENCE = [({'dem_khac_nhau': COUNT, 'moc_neo': None, 'vang_mat': None}, ['distinct_count']),
             ({'dem_khac_nhau': None, 'moc_neo': None, 'vang_mat': ABSENCE}, ['absence'])]
TELEMETRY = {'T1071': {'status': 'huntable', 'sources': [
    {'channel': SYS, 'event_ids': [3], 'key_fields': ['Image', 'ProcessGuid', 'DestinationIp', 'DestinationPort', 'EventID']},
    {'channel': SYS, 'event_ids': [22], 'key_fields': ['Image', 'ProcessGuid', 'QueryName', 'EventID']}]}}
PINS = ['configs/agent_v2.yaml', 'configs/llm_hunt.yaml', 'prompts/khau4_gia_thuyet_v6.md',
        'src/cti_hunt/contracts.py', 'src/cti_hunt/config.py', 'src/cti_hunt/stages/s4_hypothesis.py',
        'src/cti_hunt/stages/s3_telemetry.py', 'src/cti_hunt/llm/providers.py', 'src/cti_hunt/llm/budget.py',
        'src/cti_hunt/llm/prompting.py', 'tmp/prepare_khau4_v6_dem_vang.py']
ALL_TRUE = {'schema_ok': True, 'parameter_criteria_met': True, 'manual_review_required': True,
            'prose_semantics_verified': False,
            'checks': {'two_independent_items': True, 'no_postprocess_correction': True, 'pending_only': True,
                       'ref_0_exact_parameters_source_keys_and_operations': True,
                       'ref_1_exact_parameters_source_keys_and_operations': True}}


def item(n):
    rb, ops = REFERENCE[n]
    return {'ttp_refs': [n], 'behavior': 'Hành vi theo câu nguồn tự soạn', 'scope': 'mọi máy có log',
            'timeframe': 'toàn bộ khoảng thời gian của log', 'data_source': SYS, 'event_ids': [3],
            'key_fields': ['ProcessGuid', 'DestinationIp'] if n == 0 else ['ProcessGuid'],
            'extra_techniques': [], 'priority': 'cao', 'rationale': 'Câu nguồn: ' + TEXTS[n],
            'required_operations': ops, 'rang_buoc': copy.deepcopy(rb)}


GOOD = {'items': [item(0), item(1)]}


def make_packet(root, monkeypatch, *, offline=None, criteria_edit=None, payload_edit=None):
    """Same structure as the 06/10 packet; the real packet is checked by preparing it in the repo."""
    packet = root / P.PACKET_REL
    packet.mkdir(parents=True)
    ca = ContractA(report_id='SELF-COUNT-ABSENCE-0610', title='Two independent self-authored cases; not real CTI',
                   ttps=[TTP(tactic='Command and Control', technique_id='T1071', behavior_description=t,
                             source_span=SourceSpan(segment_id=f'SELF-MULTIEVENT-0{i + 1}-001', text=t), confidence=0.5)
                         for i, t in enumerate(TEXTS)])
    cfg, lc = config.agent_config('v2', root), config.load('llm_hunt', root)
    prompt = load_sections(root / cfg['prompt_khau4'])
    inputs, _ = S4.select_inputs(ca, TELEMETRY)
    user = fill(prompt['sections']['USER'], report_id=ca.report_id, techniques=S4.render_inputs(inputs),
                max_items=str(cfg['max_hypotheses_per_round']), executed_hypotheses=S4.render_anchors([]))
    client = providers.from_config({**lc, 'budget_ledger': str(root / 'data/dev/api_budget.sqlite')})
    payload = client.build_payload(prompt['sections']['SYSTEM'], user, S4.output_model(cfg).model_json_schema())
    if payload_edit:
        payload_edit(payload)
    criteria = {'expected_independent_items': 2, 'anchors': [], 'manual_review_required': True, 'cases': [
        {'ref': n, 'source_span': ca.ttps[n].source_span.model_dump(), 'primary_channel': SYS,
         'primary_event_ids': [3], 'required_operations': ops, 'rang_buoc': rb, 'extra_techniques': []}
        for n, (rb, ops) in enumerate(copy.deepcopy(REFERENCE))]}
    if criteria_edit:
        criteria_edit(criteria)
    files = {'contract_a_self_authored.json': ca.model_dump(mode='json'), 'telemetry_self_authored.json': TELEMETRY,
             'request.json': {'system': prompt['sections']['SYSTEM'], 'user': user}, 'payload.json': payload,
             'criteria.json': criteria, 'fixture_mock_response_NOT_MODEL_OUTPUT.json': GOOD,
             'offline_checks.json': {'model_parameter_check': offline or ALL_TRUE, 'api_calls': 0}}
    for name, value in files.items():
        (packet / name).write_bytes(P.dump(value))
    (root / 'tmp/prepare_khau4_v6_dem_vang.py').write_text('# fixture placeholder\n', encoding='utf-8')
    manifest = {'files_sha256': {p: integrity.sha256_file(root / p) for p in PINS},
                'artifacts_sha256': {n: integrity.sha256_file(packet / n) for n in files}}
    (packet / 'manifest.json').write_bytes(P.dump(manifest))
    monkeypatch.setattr(P, 'PACKET_MANIFEST_SHA256', integrity.sha256_file(packet / 'manifest.json'))
    return packet


@pytest.fixture
def fixture_root(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    for folder in ('src', 'configs', 'prompts'):
        shutil.copytree(config.ROOT / folder, root / folder, ignore=shutil.ignore_patterns('__pycache__'))
    (root / 'scripts').mkdir()
    shutil.copyfile(config.ROOT / 'scripts/probe_khau4_v6_dem_vang.py', root / 'scripts/probe_khau4_v6_dem_vang.py')
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('1.029666')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    return root, ledger


@pytest.fixture
def case(fixture_root, monkeypatch):
    root, ledger = fixture_root
    packet = make_packet(root, monkeypatch)
    return root, root / P.OUT_REL, ledger, packet


def transport(monkeypatch, *, raw=None, count=5000):
    calls = []

    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append((url, payload))
        if url.endswith('count_tokens'):
            return {'input_tokens': count}
        if isinstance(raw, BaseException):
            raise raw
        return raw if raw is not None else {'stop_reason': 'tool_use', 'usage': {'input_tokens': 5000, 'output_tokens': 200},
                                            'content': [{'type': 'tool_use', 'input': copy.deepcopy(GOOD)}]}
    monkeypatch.setattr(providers, '_post', post)
    return calls


def reply(items):
    return {'stop_reason': 'tool_use', 'usage': {'input_tokens': 5000, 'output_tokens': 200},
            'content': [{'type': 'tool_use', 'input': {'items': items}}]}


def send(case):
    root, out, _, _ = case
    return P.run(out, root=root, send=True, cap_usd='0.40')


def snapshot(folder):
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(folder.rglob('*')) if p.is_file()}


def test_offline_prepare_rebuilds_packet_request_without_network_or_ledger_write(case, monkeypatch):
    root, out, ledger, packet = case
    before, packet_before = ledger.path.read_bytes(), snapshot(packet)
    calls = transport(monkeypatch)
    result = P.run(out, root=root)
    assert result['mode'] == 'OFFLINE_NO_API' and result['api_authorization'] == 'pending_nguoi_van_hanh'
    assert result['ttp_inputs'] == 2 and result['minimum_reservation_usd'] == '0.320512'
    assert calls == [] and ledger.path.read_bytes() == before and snapshot(packet) == packet_before
    protocol = json.loads((out / 'protocol.json').read_text(encoding='utf-8'))
    assert protocol['criteria']['fixture_self_check'] == ALL_TRUE and protocol['anchors'] == []
    assert protocol['model']['effort'] == 'high' and protocol['model']['max_output_tokens'] == 32000
    assert protocol['model']['timeout_giay'] == 600 and protocol['model']['budget_guard']['request_budget_usd'] == '0.40'
    assert 'src/cti_hunt/agent/probe_khau4_dem_vang.py' in protocol['files_sha256']
    assert not (out / 'attempt.json').exists()
    first = (out / 'protocol.json').read_bytes()
    assert P.run(out, root=root) == result and (out / 'protocol.json').read_bytes() == first


def test_payload_carries_no_criteria_reference_reply_or_key(case):
    _, _, _, packet = case
    text = (packet / 'payload.json').read_text(encoding='utf-8')
    for word in ('parameter_criteria_met', 'expected_independent_items', 'Câu nguồn:', 'pending_review',
                 'synthetic-test-key', 'NOT_MODEL_OUTPUT'):
        assert word not in text


def test_send_requires_explicit_separate_cap_and_prepare_takes_none(case, monkeypatch):
    root, out, _, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch)
    for cap in (None, '0.39', '0.41'):
        with pytest.raises(ValueError, match='trần riêng'):
            P.run(out, root=root, send=True, cap_usd=cap)
    with pytest.raises(ValueError, match='không nhận quyền chi'):
        P.run(out, root=root, cap_usd='0.40')
    assert calls == [] and not (out / 'attempt.json').exists()


def test_unprepared_send_does_not_create_output(case, monkeypatch):
    _, out, _, _ = case
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='Chưa chuẩn bị'):
        send(case)
    assert calls == [] and not out.exists()


def test_success_is_one_pinned_generation_without_review_form_or_stage5(case, monkeypatch):
    root, out, ledger, packet = case
    P.run(out, root=root)
    calls = transport(monkeypatch)
    result = send(case)
    assert [u.rsplit('/', 1)[-1] for u, _ in calls] == ['count_tokens', 'messages']
    assert calls[1][1] == json.loads((packet / 'payload.json').read_text(encoding='utf-8'))
    assert result['state'] == 'received' and result['parameter_criteria_met'] and result['manual_review_required']
    assert result['prose_semantics_verified'] is False and result['so_gia_thuyet'] == 2 and not result['ma_sua']
    assert result['known_cost_usd'] == ledger.status()['known_cost_usd'] == '0.012000'
    assert result['ledger_after']['pending'] == 0 and not result['cost_exceeds_cap']
    hyps = json.loads((out / 'hypotheses_pending.json').read_text(encoding='utf-8'))
    assert [h['status'] for h in hyps] == ['pending_review'] * 2
    assert [h['source_spans'][0]['text'] for h in hyps] == TEXTS
    for name in ('count_tokens.json', 'response_provider.json', 'response_raw.json', 'request.json', 'result.json'):
        assert (out / name).is_file()
    assert not list(out.glob('duyet*')) and not list(out.glob('*khau5*')) and not (out / 'hunt_record.md').exists()
    for flag in (False, True):
        with pytest.raises(ValueError, match='không gửi lại'):
            P.run(out, root=root, send=flag, cap_usd='0.40' if flag else None)
    assert len(calls) == 2


def test_prose_additions_are_not_judged_by_parameter_checks(case, monkeypatch):
    root, out, _, _ = case
    P.run(out, root=root)
    items = [item(0), item(1)]
    items[1]['behavior'] = 'Kết nối ra ngoài tới IP công cộng mà không truy vấn DNS'
    transport(monkeypatch, raw=reply(items))
    result = send(case)
    # Only the pre-registered parameters pass; the added meaning still needs người vận hành/manual review.
    assert result['parameter_criteria_met'] and result['prose_semantics_verified'] is False
    assert result['manual_review_required']


@pytest.mark.parametrize('name', ['contract_a_self_authored.json', 'telemetry_self_authored.json', 'request.json',
                                  'payload.json', 'criteria.json', 'fixture_mock_response_NOT_MODEL_OUTPUT.json',
                                  'offline_checks.json', 'manifest.json', 'extra.json'])
def test_changed_or_added_packet_file_blocks_before_network(name, case, monkeypatch):
    root, out, _, packet = case
    P.run(out, root=root)
    with (packet / name).open('a', encoding='utf-8') as f:
        f.write('\n')
    calls = transport(monkeypatch)
    for do_send in (False, True):
        with pytest.raises(ValueError, match='Gói chuẩn bị|Tệp trong gói'):
            P.run(out, root=root, send=do_send, cap_usd='0.40' if do_send else None)
    assert calls == [] and not (out / 'attempt.json').exists()


@pytest.mark.parametrize('edit, message', [
    ({'payload_edit': lambda p: p.update(max_tokens=16000)}, 'dựng lại'),
    ({'criteria_edit': lambda c: c['cases'][1]['source_span'].update(text='Edited quote')}, 'không khớp Contract A'),
    ({'criteria_edit': lambda c: c['cases'][0]['rang_buoc']['dem_khac_nhau'].update(toi_thieu=3)}, 'khác kiểm đã ghi'),
    ({'offline': {**ALL_TRUE, 'parameter_criteria_met': False}}, 'khác kiểm đã ghi'),
])
def test_consistent_but_different_packet_is_refused(edit, message, fixture_root, monkeypatch):
    root, _ = fixture_root
    make_packet(root, monkeypatch, **edit)
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match=message):
        P.run(root / P.OUT_REL, root=root)
    assert calls == []


@pytest.mark.parametrize('name', ['configs/llm_hunt.yaml', 'prompts/khau4_gia_thuyet_v6.md',
                                  'src/cti_hunt/stages/s4_hypothesis.py', 'src/cti_hunt/stages/s5_rule.py',
                                  'src/cti_hunt/agent/probe_khau4_dem_vang.py', 'scripts/probe_khau4_v6_dem_vang.py',
                                  'tmp/prepare_khau4_v6_dem_vang.py'])
def test_code_prompt_or_settings_drift_blocks_before_http(name, case, monkeypatch):
    root, out, _, _ = case
    P.run(out, root=root)
    with (root / name).open('a', encoding='utf-8') as f:
        f.write('\n# fixture drift\n')
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='đã đổi|khác bản đã kiểm'):
        send(case)
    assert calls == [] and not (out / 'attempt.json').exists()


@pytest.mark.parametrize('key, value', [('effort', 'medium'), ('max_output_tokens', 16000),
                                        ('request_timeout_giay', 300), ('model', 'claude-opus-5-5')])
def test_lowered_or_changed_model_settings_are_refused(key, value, fixture_root, monkeypatch):
    root, _ = fixture_root
    path = root / 'configs/llm_hunt.yaml'
    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    data[key] = value
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding='utf-8')
    make_packet(root, monkeypatch)  # Even a packet re-pinned to the changed settings is outside the protocol.
    calls = transport(monkeypatch)
    with pytest.raises(ValueError, match='Cấu hình'):
        P.run(root / P.OUT_REL, root=root)
    assert calls == []


@pytest.mark.parametrize('invalid', ['data/dev/newprobe', 'tmp/chuan_bi_khau4_v6_dem_vang_6-10',
                                     'tmp/thu_khau4_v5_6-10', 'tmp/nested/newprobe', '../outside'])
def test_output_cannot_be_data_old_packages_nested_or_outside(invalid, case):
    root, _, _, _ = case
    with pytest.raises(ValueError, match='Đầu ra'):
        P.run(root / invalid, root=root)


def test_unrelated_nonempty_tmp_folder_is_not_locked_or_written(case):
    root, _, _, _ = case
    other = root / 'tmp/other_package'
    other.mkdir()
    (other / 'keep.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='tệp không thuộc'):
        P.run(other, root=root)
    assert sorted(p.name for p in other.iterdir()) == ['keep.json']


@pytest.mark.parametrize('raw', [providers.TransportError('fixture network error'),
    {'stop_reason': 'refusal', 'usage': {'input_tokens': 100, 'output_tokens': 20}, 'content': []},
    {'stop_reason': 'max_tokens', 'usage': {'input_tokens': 100, 'output_tokens': 32000},
     'content': [{'type': 'tool_use', 'input': GOOD}]},
    {'stop_reason': 'end_turn', 'usage': {'input_tokens': 100, 'output_tokens': 20},
     'content': [{'type': 'text', 'text': 'broken JSON'}]},
])
def test_failed_refused_truncated_or_malformed_replies_never_retry(raw, case, monkeypatch):
    root, out, ledger, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw=raw)
    result = send(case)
    assert result['state'] == 'failed_no_retry' and not result['parameter_criteria_met'] and len(calls) == 2
    if isinstance(raw, BaseException):
        assert ledger.status()['pending'] and result['known_cost_usd'] is None
    else:
        assert (out / 'response_provider.json').is_file() and result['usage'] is not None
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)
    assert len(calls) == 2


def test_reply_without_usage_is_kept_although_settlement_fails(case, monkeypatch):
    root, out, ledger, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'content': [{'type': 'tool_use', 'input': GOOD}]})
    result = send(case)
    assert result['state'] == 'failed_no_retry' and result['known_cost_usd'] is None
    saved = json.loads((out / 'response_provider.json').read_text(encoding='utf-8'))
    assert saved['content'][0]['input'] == GOOD and ledger.status()['pending'] and len(calls) == 2
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)


def test_token_count_above_cap_never_sends_generation(case, monkeypatch):
    root, out, ledger, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, count=100000)
    result = send(case)
    assert result['state'] == 'failed_no_retry' and result['error_type'] == 'BudgetExhausted'
    assert len(calls) == 1 and calls[0][0].endswith('count_tokens') and (out / 'count_tokens.json').is_file()
    assert ledger.status()['known_cost_usd'] == '0.000000' and not ledger.status()['pending']
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)


def test_provider_usage_over_cap_is_reported_without_retry(case, monkeypatch):
    root, out, _, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw={'stop_reason': 'tool_use', 'usage': {'input_tokens': 100000, 'output_tokens': 100000},
                                        'content': [{'type': 'tool_use', 'input': GOOD}]})
    result = send(case)
    assert result['state'] == 'cost_exceeds_cap_no_retry' and result['cost_exceeds_cap'] and len(calls) == 2


def test_echoed_key_is_redacted_in_saved_files(case, monkeypatch):
    root, out, _, _ = case
    P.run(out, root=root)
    items = [item(0), item(1)]
    items[0]['scope'] = 'synthetic-test-key'
    transport(monkeypatch, raw=reply(items))
    send(case)
    for path in out.iterdir():
        if path.is_file() and path.suffix == '.json':
            assert 'synthetic-test-key' not in path.read_text(encoding='utf-8')


@pytest.mark.parametrize('reason', ['pending', 'insufficient', 'missing_key'])
def test_preflight_failure_does_not_start_attempt(reason, case, monkeypatch):
    root, out, ledger, _ = case
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
    root, out, _, _ = case
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
    root, out, _, _ = case
    P.run(out, root=root)
    calls = transport(monkeypatch, raw=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        send(case)
    with pytest.raises(ValueError, match='không gửi lại'):
        send(case)
    assert len(calls) == 2 and (out / 'attempt.json').exists()


def _ca():
    return ContractA(report_id='SELF-COUNT-ABSENCE-0610', ttps=[
        TTP(tactic='Command and Control', technique_id='T1071', behavior_description=t, confidence=0.5,
            source_span=SourceSpan(segment_id=f'SELF-MULTIEVENT-0{i + 1}-001', text=t)) for i, t in enumerate(TEXTS)])


def _criteria(ca):
    return {'expected_independent_items': 2, 'cases': [
        {'ref': n, 'source_span': ca.ttps[n].source_span.model_dump(), 'primary_channel': SYS, 'primary_event_ids': [3],
         'required_operations': ops, 'rang_buoc': rb, 'extra_techniques': []}
        for n, (rb, ops) in enumerate(copy.deepcopy(REFERENCE))]}


def _mutate(name):
    bad = copy.deepcopy(GOOD)
    a, b = bad['items']
    if name == 'missing_count': a['rang_buoc'] = None
    elif name == 'count_window_90': a['rang_buoc']['dem_khac_nhau']['cua_so_giay'] = 90
    elif name == 'count_threshold_3': a['rang_buoc']['dem_khac_nhau']['toi_thieu'] = 3
    elif name == 'count_missing_host': a['rang_buoc']['dem_khac_nhau']['theo'] = ['ProcessGuid']
    elif name == 'absence_window_31': b['rang_buoc']['vang_mat']['truoc_giay'] = 31
    elif name == 'absence_missing_guid': b['rang_buoc']['vang_mat']['khop'] = b['rang_buoc']['vang_mat']['khop'][:1]
    elif name == 'wrong_primary_eid': a['event_ids'] = [22]
    elif name == 'wrong_dns_eid': b['rang_buoc']['vang_mat']['event_ids'] = [3]
    elif name == 'merged_refs': a['ttp_refs'] = [0, 1]
    elif name == 'missing_case': bad['items'] = [a]
    elif name == 'unquoted_rationale': a['rationale'] = 'No source clause'
    elif name == 'unknown_parameter': a['rang_buoc']['dem_khac_nhau']['unsupported'] = 1
    elif name == 'extra_technique': a['extra_techniques'] = ['T1095']
    elif name == 'missing_operation': b['required_operations'] = []
    elif name == 'combined_constraint': a['rang_buoc']['vang_mat'] = copy.deepcopy(ABSENCE)
    elif name == 'third_item': bad['items'].append(copy.deepcopy(b) | {'behavior': 'Thêm mục không có nguồn riêng'})
    return bad


@pytest.mark.parametrize('name', ['missing_count', 'count_window_90', 'count_threshold_3', 'count_missing_host',
                                  'absence_window_31', 'absence_missing_guid', 'wrong_primary_eid', 'wrong_dns_eid',
                                  'merged_refs', 'missing_case', 'unquoted_rationale', 'unknown_parameter',
                                  'extra_technique', 'missing_operation', 'combined_constraint', 'third_item'])
def test_parameter_checks_reject_deliberate_errors(name):
    ca, cfg = _ca(), config.agent_config('v2')
    assert P.evaluate(GOOD, ca, TELEMETRY, cfg, _criteria(ca)) == ALL_TRUE
    assert not P.evaluate(_mutate(name), ca, TELEMETRY, cfg, _criteria(ca))['parameter_criteria_met']


def test_key_order_inside_constraints_does_not_matter():
    ca, cfg = _ca(), config.agent_config('v2')
    swapped = copy.deepcopy(GOOD)
    swapped['items'][0]['rang_buoc']['dem_khac_nhau']['theo'] = ['ProcessGuid', 'ev_host']
    swapped['items'][1]['rang_buoc']['vang_mat']['khop'].reverse()
    assert P.evaluate(swapped, ca, TELEMETRY, cfg, _criteria(ca))['parameter_criteria_met']
