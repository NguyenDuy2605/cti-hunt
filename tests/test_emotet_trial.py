"""All sources/events/ledger/network are isolated fixtures; never real API or real decisions."""
import hashlib
import json
import shutil
from pathlib import Path

import duckdb
import pytest
import yaml

from cti_hunt import approval, filter_approval as F, integrity
from cti_hunt.agent import emotet_trial as T, session
from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import budget, providers
from cti_hunt.stages import s1_ingest


@pytest.fixture(autouse=True)
def without_breadth_gate(monkeypatch):
    """Runner/script đã chạy xong, ghim hành vi cũ; cổng độ rộng/biến thể (phiếu rule v3, 15/10) kiểm ở test_duyet_rule_do_rong.py."""
    from cti_hunt import config as _config
    original = _config.agent_config
    def cfg_without(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_do_rong', None)
        return cfg
    monkeypatch.setattr(_config, 'agent_config', cfg_without)

RULE = r"""title: Synthetic WMI process
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  filter_fixture:
    Image|endswith: '\sppsvc.exe'
  condition: selection and not filter_fixture
"""
SYS = 'microsoft-windows-sysmon/operational'
ITEM = {'ttp_refs': [0], 'behavior': 'Tiến trình được WMI khởi tạo theo nguồn tự soạn', 'scope': 'mọi máy',
        'timeframe': 'toàn bộ khoảng thời gian của log', 'data_source': SYS, 'event_ids': [1],
        'key_fields': ['Image', 'ParentImage'], 'extra_techniques': [], 'priority': 'cao', 'rang_buoc': None}


@pytest.fixture
def case(tmp_path, work, monkeypatch):
    root = tmp_path / 'root'
    for d in ['configs', 'prompts', 'src']:
        shutil.copytree(ROOT / d, root / d)
    # This runner reproduces the approved v3 protocol, not the new default v4.
    agent_cfg = root / 'configs/agent_v2.yaml'
    old_cfg = yaml.safe_load(agent_cfg.read_text(encoding='utf-8'))
    old_cfg['prompt_khau5'] = 'prompts/khau5_sigma_v3.md'
    old_cfg.pop('duyet_rule_doi_chieu', None)   # gói chuẩn bị trước cổng giữ/bỏ rule (09/10)
    agent_cfg.write_text(yaml.safe_dump(old_cfg, allow_unicode=True), encoding='utf-8')
    # Only one self-authored technique in this fixture. Avoid 475 unrelated profile entries per test.
    cp = root / yaml.safe_load((root / 'configs/dataset.yaml').read_text(encoding='utf-8'))['telemetry_catalog_v2']
    catalog = yaml.safe_load(cp.read_text(encoding='utf-8'))
    catalog['techniques'] = {k: catalog['techniques'][k] for k in ['T1047', 'T1059.001']}
    cp.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding='utf-8')
    (root / 'scripts').mkdir()
    shutil.copyfile(ROOT / 'scripts/thu_loi_emotet.py', root / 'scripts/thu_loi_emotet.py')
    bundle = root / 'data/dev/report_emotet_28-9/bundle'
    html = tmp_path / 'source.html'
    html.write_text('<html><body><article><p>Self-authored other fixture paragraph.</p>'
                    '<p>Self-authored fixture: WMI starts a process.</p></article></body></html>', encoding='utf-8')
    s1_ingest.ingest(str(html), 'FIXTURE', bundle)
    _, segs, _ = s1_ingest.load_bundle(bundle)
    seg = next(s for s in segs if 'WMI starts' in s['van_ban'])
    other = next(s for s in segs if 'other fixture' in s['van_ban'])
    monkeypatch.setattr(T, 'SEGMENT', seg['ma_doan'])
    ttps = [TTP(tactic='Execution', technique_id='T1059.001' if i == 2 else 'T1047', confidence=i/10,
                behavior_description='Self-authored WMI action',
                source_span=SourceSpan(segment_id=seg['ma_doan'] if i >= 2 else other['ma_doan'],
                                       text=seg['van_ban'] if i >= 2 else other['van_ban']))
            for i in range(8)]
    extraction = root / 'data/dev/report_emotet_28-9/case/extraction'
    extraction.mkdir(parents=True)
    ca = extraction / 'contract_a.json'
    ca.write_text(ContractA(report_id='FIXTURE', ttps=ttps).model_dump_json(), encoding='utf-8')
    T.write(extraction / 'meta.json', {'status': 'complete', 'bundle_manifest_sha256': integrity.sha256_file(bundle / 'manifest.json'),
                                     'contract_a_sha256': integrity.sha256_file(ca)})
    monkeypatch.setattr(T, 'CONTRACT_HASH', integrity.sha256_file(ca))
    monkeypatch.setattr(T, 'SOURCE_HASH', integrity.sha256_file(bundle / 'source.html'))
    monkeypatch.setattr(T, 'DATA_HASH', 'a' * 64)
    events = root / 'data/dev/otrf-wmi-exec'
    events.mkdir(parents=True)
    con = duckdb.connect()
    con.execute(f"CREATE TABLE e AS SELECT * FROM read_parquet('{(work / 'events.parquet').as_posix()}')")
    con.execute("UPDATE e SET ev_host=ev_host || '-FIXTURE'")
    con.execute(f"COPY e TO '{(events / 'events.parquet').as_posix()}' (FORMAT PARQUET)")
    con.close()
    T.write(events / 'ingest_manifest.json', {'dataset_kind': 'otrf_dev', 'dataset_id': 'otrf-wmi-exec',
                                            'source_sha256': 'a' * 64, 'hosts': {'FIXTURE': 9}, 'rows': 9})
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('1.20')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    calls = []
    responses = [{'items': [ITEM]}, {'rule_yaml': RULE}]
    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append(url)
        if url.endswith('count_tokens'):
            return {'input_tokens': 100}
        data = responses.pop(0)
        if isinstance(data, BaseException):
            raise data
        if 'content' in data:
            return data
        return {'usage': {'input_tokens': 100, 'output_tokens': 20}, 'stop_reason': 'tool_use',
                'content': [{'type': 'tool_use', 'input': data}]}
    monkeypatch.setattr(providers, '_post', post)
    out = tmp_path / 'trial'
    return root, out, ledger, calls, responses


def prepare(case):
    root, out, _, _, _ = case
    T.prepare(out, root)
    return root, out


def human_hypothesis(out, decision='approved'):
    rd = out / 'round_01'
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    approval.save_decisions(rd, 'Fixture reviewer', {r['id']: {'quyet_dinh': decision, 'ly_do': 'Synthetic fixture decision'}
                                                  for r in form['gia_thuyet']}, integrity.sha256_file(rd / approval.REVIEW_FILE))


def human_filter(rd):
    form = F.load_form(rd)
    F.save_decisions(rd, 'Fixture reviewer', {r['id']: {'quyet_dinh': 'rejected', 'ly_do': 'Synthetic fixture decision'}
                                             for r in form['muc_loc']}, integrity.sha256_file(rd / F.FORM))


def test_prepare_and_status_never_call_network_or_change_ledger(case):
    root, out, ledger, calls, _ = case
    before = ledger.path.read_bytes()
    p = T.prepare(out, root)
    assert p['state'] == 'prepared_no_api' and p['cap_usd'] == '1.20'
    meta = T.read(out / 'run_meta.json')
    built = T.build(meta, out, root, paid=False)
    try:
        assert built[1].initial_state()['remaining_refs'] != list(range(6))
    finally:
        built[1].con.close()
    assert T.status(out, root)['state'] == 'prepared_no_api'
    assert calls == [] and ledger.path.read_bytes() == before
    assert not (out / session.CHECKPOINT_FILE).exists() and not (out / 'budget_baseline.json').exists()
    with pytest.raises(ValueError):
        T.prepare(out, root)


def test_both_gates_single_pass_and_repeat_commands_do_not_resend(case):
    root, out = prepare(case)
    _, _, ledger, calls, _ = case
    result = T.advance(out, root)
    assert result['state'] == 'awaiting_hypothesis_review'
    assert T.read(out / 'api_calls/call_00.json')['request'] == T.read(out / 'payload_khau4.json')
    assert len(calls) == 2 and ledger.status()['known_cost_usd'] == '0.000400'
    with pytest.raises(ValueError, match='chưa quyết định'):
        T.advance(out, root)
    assert len(calls) == 2
    human_hypothesis(out)
    result = T.advance(out, root)
    assert result['state'] == 'awaiting_filter_review' and len(calls) == 4
    rd = Path(result['review_dir'])
    with pytest.raises(F.PendingFilterReview):
        T.advance(out, root)
    assert len(calls) == 4
    human_filter(rd)
    assert T.advance(out, root)['state'] == 'completed'
    assert len(calls) == 4 and not (out / 'round_02').exists()
    record = T.read(out / 'agent_dev_record.json')
    assert len(record['executed_specs']) == 1
    assert all(h['decision']['action'] != 'pivot' for h in record['history'])
    assert T.status(out, root)['budget']['charged_delta_usd'] == '0.000800'
    with pytest.raises(ValueError, match='không gửi lại'):
        T.advance(out, root)
    assert len(calls) == 4


def test_all_rejected_no_rule_call_and_record_exists(case):
    root, out = prepare(case)
    T.advance(out, root)
    human_hypothesis(out, 'rejected')
    assert T.advance(out, root)['state'] == 'completed'
    assert len(case[3]) == 2 and (out / 'hunt_record.md').exists()
    assert not T.read(out / 'agent_dev_record.json')['executed_specs']


@pytest.mark.parametrize('kind', ['timeout', 'truncated', 'bad_json'])
def test_failed_paid_phase_is_never_replayed_even_after_pending_resolved(case, kind):
    root, out = prepare(case)
    _, _, ledger, calls, responses = case
    if kind == 'timeout':
        responses[0] = providers.TransportError('synthetic-test-key reflected by fake provider')
    else:
        responses[0] = {'usage': {'input_tokens': 100, 'output_tokens': 20},
                        'stop_reason': 'max_tokens' if kind == 'truncated' else 'end_turn',
                        'content': [{'type': 'tool_use', 'input': {'items': [ITEM]}}] if kind == 'truncated' else
                                   [{'type': 'text', 'text': 'broken json'}]}
    with pytest.raises(providers.LLMError):
        T.advance(out, root)
    assert T.status(out, root)['state'] == 'failed_no_retry'
    for pending in ledger.status()['pending']:
        ledger.resolve(pending['id'], '0.01', 'synthetic fixture reconciliation')
    with pytest.raises(ValueError, match='không gửi lại'):
        T.advance(out, root)
    assert len(calls) == 2 and (out / 'hunt_record.md').exists()
    assert 'synthetic-test-key' not in json.dumps(T.read(out / 'terminal.json'))


def test_budget_exhaustion_after_hypothesis_stops_without_rule_and_accounts_cumulatively(case):
    root, out = prepare(case)
    T.advance(out, root)
    ledger = case[2]
    # An unrelated settled request is conservatively included in this package's ledger delta.
    rid = ledger.reserve('claude-sonnet-5', budget.money('1.00'))
    ledger.settle(rid, 'claude-sonnet-5', {'input_tokens': 0, 'output_tokens': 100000})
    human_hypothesis(out)
    assert T.advance(out, root)['state'] == 'completed'
    assert len(case[3]) == 2
    result = T.read(out / 'round_01/agent_execute.json')
    assert 'het_ngan_sach' in json.dumps(result, ensure_ascii=False)


def test_shared_limit_not_enough_blocks_before_start_marker_or_http(case):
    root, out = prepare(case)
    case[2].set_limit('0.57')
    with pytest.raises(budget.BudgetError):
        T.advance(out, root)
    assert case[3] == [] and not (out / 'budget_baseline.json').exists()
    assert not list(out.glob('phase_*.json'))


def test_second_process_cannot_acquire_command_lock(case):
    root, out = prepare(case)
    with T.command_lock(out):
        with pytest.raises(ValueError, match='tiến trình khác'):
            T.advance(out, root)
    assert case[3] == []


@pytest.mark.parametrize('target', ['contract_a.json', 'payload_khau4.json', 'profile', 'script', 'source'])
def test_changed_inputs_are_blocked_before_network(case, target):
    root, out = prepare(case)
    paths = {'contract_a.json': out / 'contract_a.json', 'payload_khau4.json': out / 'payload_khau4.json',
             'profile': out / T.S3.PROFILE_FILE, 'script': root / 'scripts/thu_loi_emotet.py',
             'source': root / 'data/dev/report_emotet_28-9/bundle/source.html'}
    with paths[target].open('ab') as f:
        f.write(b' ')
    with pytest.raises((ValueError, session.SessionError)):
        T.advance(out, root)
    assert case[3] == []


def test_baseline_cannot_be_reset_when_resuming(case):
    root, out = prepare(case)
    T.advance(out, root)
    human_hypothesis(out)
    baseline = T.read(out / 'budget_baseline.json')
    baseline['known'] += 400
    T.write(out / 'budget_baseline.json', baseline)
    with pytest.raises(budget.BudgetError):
        T.advance(out, root)
    assert len(case[3]) == 2


def test_ordinary_resume_cannot_escape_one_pass_runner(case):
    root, out = prepare(case)
    T.advance(out, root)
    human_hypothesis(out)
    with pytest.raises(session.SessionError, match='runner riêng'):
        session.resume(out, root)
    assert len(case[3]) == 2


def test_crash_marker_blocks_even_with_no_checkpoint(case):
    root, out = prepare(case)
    T.write(out / 'phase_00.json', {'state': 'started_no_retry'})
    assert T.status(out, root)['state'] == 'interrupted_no_retry'
    with pytest.raises(ValueError, match='không gửi lại'):
        T.advance(out, root)
    assert case[3] == []


def test_missing_key_does_not_start_phase(case, monkeypatch):
    root, out = prepare(case)
    monkeypatch.delenv('LLM_API_KEY')
    with pytest.raises(providers.LLMError):
        T.advance(out, root)
    assert case[3] == [] and not list(out.glob('phase_*.json'))
    assert T.status(out, root)['state'] == 'prepared_no_api'


def test_no_hypotheses_means_rules_not_tested_not_a_detection_success(case):
    root, out = prepare(case)
    case[4][0] = {'items': []}
    assert T.advance(out, root)['state'] == 'completed'
    assert len(case[3]) == 2 and not T.read(out / 'agent_dev_record.json')['executed_specs']


def test_exact_token_count_can_block_package_before_generation(case):
    root, out = prepare(case)
    ledger, calls = case[2], case[3]
    T.advance(out, root)
    human_hypothesis(out)
    # Leave enough for minimum reserve but not the larger counted request.
    rid = ledger.reserve('claude-sonnet-5', budget.money('0.85'))
    ledger.settle(rid, 'claude-sonnet-5', {'input_tokens': 0, 'output_tokens': 85000})
    old_post = providers._post
    def larger_count(url, payload, headers, **kw):
        if url.endswith('count_tokens'):
            calls.append(url)
            return {'input_tokens': 20000}
        return old_post(url, payload, headers, **kw)
    from unittest.mock import patch
    with patch.object(providers, '_post', side_effect=larger_count):
        result = T.advance(out, root)
    assert result['state'] == 'completed' and len(calls) == 3 and calls[-1].endswith('count_tokens')
    assert ledger.status()['known_cost_usd'] == '0.850400'


def test_refusal_is_charged_and_not_retried(case):
    root, out = prepare(case)
    case[4][0] = {'usage': {'input_tokens': 100, 'output_tokens': 20}, 'stop_reason': 'refusal', 'content': []}
    result = T.advance(out, root)
    assert result['state'] == 'completed' and result['executed_hypotheses'] == 0
    assert case[2].status()['known_cost_usd'] == '0.000400' and len(case[3]) == 2


def test_static_repair_is_only_extra_paid_call(case):
    root, out = prepare(case)
    case[4][1:1] = [{'rule_yaml': 'broken: ['}]
    T.advance(out, root)
    human_hypothesis(out)
    result = T.advance(out, root)
    assert result['state'] == 'awaiting_filter_review' and len(case[3]) == 6
    assert len(list((out / 'api_calls').glob('call_*.json'))) == 3
    assert case[2].status()['known_cost_usd'] == '0.001200'


def test_pending_shared_request_blocks_before_start(case):
    root, out = prepare(case)
    case[2].reserve('claude-sonnet-5', budget.money('0.01'))
    with pytest.raises(budget.BudgetError):
        T.advance(out, root)
    assert case[3] == [] and not list(out.glob('phase_*.json'))


def test_all_rejected_can_close_without_api_key(case, monkeypatch):
    root, out = prepare(case)
    T.advance(out, root)
    human_hypothesis(out, 'rejected')
    monkeypatch.delenv('LLM_API_KEY')
    assert T.advance(out, root)['state'] == 'completed' and len(case[3]) == 2


def test_usage_exceeding_cap_is_terminal_not_more_api(case):
    root, out = prepare(case)
    case[4][0] = {'usage': {'input_tokens': 100, 'output_tokens': 130000}, 'stop_reason': 'tool_use',
                 'content': [{'type': 'tool_use', 'input': {'items': [ITEM]}}]}
    with pytest.raises(budget.BudgetError):
        T.advance(out, root)
    assert T.status(out, root)['state'] == 'failed_no_retry'
    assert case[2].status()['known_cost_usd'] == '1.300200' and len(case[3]) == 2


def test_wrapper_defaults_offline_and_never_displays_provider_exception(monkeypatch, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location('trial_wrapper', ROOT / 'scripts/thu_loi_emotet.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(T, 'prepare', lambda: {'state': 'prepared_no_api'})
    assert module.main([]) == 0
    monkeypatch.setattr(T, 'advance', lambda: (_ for _ in ()).throw(providers.TransportError('test-secret-key')))
    assert module.main(['--send']) == 1
    assert 'test-secret-key' not in capsys.readouterr().out
