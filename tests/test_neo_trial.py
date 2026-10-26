"""Isolated root/ledger/events, synthetic ◆ reviewer and fake HTTP only; never a real API call or real decision."""
import copy
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from cti_hunt import approval, integrity
from cti_hunt.agent import neo_trial as T, session
from cti_hunt.config import ROOT


@pytest.fixture(autouse=True)
def without_breadth_gate(monkeypatch):
    """Module này kiểm cơ chế khác; cổng độ rộng/biến thể (phiếu rule v3, 15/10) kiểm ở test_duyet_rule_do_rong.py."""
    from cti_hunt import config as _config
    original = _config.agent_config
    def cfg_without(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_do_rong', None)
        return cfg
    monkeypatch.setattr(_config, 'agent_config', cfg_without)
from cti_hunt.llm import budget, providers

SYS = T.SYS
ANCHOR = {'ttp_refs': [0], 'behavior': 'Khởi động tiến trình PowerShell trên máy.', 'scope': 'mọi máy',
          'timeframe': 'toàn bộ khoảng thời gian của log', 'data_source': SYS, 'event_ids': [1],
          'key_fields': ['Image', 'ProcessGuid'], 'extra_techniques': [], 'priority': 'trung_binh',
          'rationale': 'Căn cứ: "PowerShell starts on a host". Dấu vết: Sysmon 1.', 'required_operations': [],
          'rang_buoc': None}
DEPENDENT = {'ttp_refs': [0], 'behavior': 'Tạo tệp sau sự kiện khởi tạo tiến trình của neo, không quá 75 giây, '
             'cùng máy và ProcessGuid.', 'scope': 'mọi máy', 'timeframe': 'toàn bộ khoảng thời gian của log',
             'data_source': SYS, 'event_ids': [11], 'key_fields': ['TargetFilename', 'ProcessGuid'],
             'extra_techniques': [], 'priority': 'trung_binh', 'rationale': 'Căn cứ: "a file is created".',
             'required_operations': ['event_sequence'],
             'rang_buoc': {'moc_neo': {'gia_thuyet': 'SELF-NEO-0710-H01', 'trong_vong_giay': 75,
                                       'cung': ['ev_host', 'ProcessGuid']}}}


def rule(category, eid, extra=None):
    return yaml.safe_dump({'title': 'Fixture rule', 'status': 'experimental',
                           'logsource': {'product': 'windows', 'category': category},
                           'detection': {'selection': {'EventID': eid, **(extra or {})}, 'condition': 'selection'},
                           'level': 'low'})


def replies():
    return [{'items': [copy.deepcopy(ANCHOR)]},
            {'rule_yaml': rule('process_creation', 1, {'Image|endswith': r'\powershell.exe'})},
            {'items': [copy.deepcopy(DEPENDENT)]}, {'rule_yaml': rule('file_event', 11)}]


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    for d in ('configs', 'prompts', 'src'):
        shutil.copytree(ROOT / d, root / d, ignore=shutil.ignore_patterns('__pycache__'))
    # Gói này ghim danh mục v2.1; từ 09/10 con trỏ repo là v2.2 nên fixture đặt lại con trỏ như lúc chuẩn bị gói.
    # Gói này chuẩn bị trước cổng giữ/bỏ rule (09/10); fixture tắt cổng như lúc chuẩn bị gói.
    ac = root / 'configs/agent_v2.yaml'
    ac.write_text(re.sub(r'(?m)^duyet_rule_doi_chieu: .*\n', '', ac.read_text(encoding='utf-8')), encoding='utf-8')
    # Gói này ghim prompt ⑤ v5; từ 12/10 (H6) cấu hình v2 trỏ v6 nên fixture giữ v5 như lúc chuẩn bị gói.
    ac.write_text(re.sub(r'(?m)^prompt_khau5: \S+', 'prompt_khau5: prompts/khau5_sigma_v5.md',
                         ac.read_text(encoding='utf-8')), encoding='utf-8')
    ds = root / 'configs/dataset.yaml'
    ds.write_text(re.sub(r'(?m)^telemetry_catalog_v2: .*$', 'telemetry_catalog_v2: configs/telemetry_catalog_v2_1.yaml',
                         ds.read_text(encoding='utf-8')), encoding='utf-8')
    # Two techniques of the case only: avoid profiling 475 unrelated catalog entries per graph build.
    cp = root / yaml.safe_load((root / 'configs/dataset.yaml').read_text(encoding='utf-8'))['telemetry_catalog_v2']
    catalog = yaml.safe_load(cp.read_text(encoding='utf-8'))
    catalog['techniques'] = {k: catalog['techniques'][k] for k in ['T1059', 'T1105']}
    cp.write_text(yaml.safe_dump(catalog, allow_unicode=True, sort_keys=False), encoding='utf-8')
    (root / 'scripts').mkdir()
    shutil.copyfile(ROOT / 'scripts/thu_moc_neo.py', root / 'scripts/thu_moc_neo.py')
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('0.975016')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    calls, queue = [], replies()

    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append((url, payload))
        if url.endswith('count_tokens'):
            return {'input_tokens': 1000}
        data = queue.pop(0)
        if isinstance(data, BaseException):
            raise data
        if 'content' in data:
            return data
        return {'usage': {'input_tokens': 1000, 'output_tokens': 100}, 'stop_reason': 'tool_use',
                'content': [{'type': 'tool_use', 'input': data}]}
    monkeypatch.setattr(providers, '_post', post)
    return root, tmp_path / 'neo', ledger, calls, queue


def decide(rd, decision='approved'):
    rd = Path(rd)
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    approval.save_decisions(rd, 'Synthetic fixture reviewer',
                            {r['id']: {'quyet_dinh': decision, 'ly_do': 'Synthetic fixture decision'}
                             for r in form['gia_thuyet']}, integrity.sha256_file(rd / approval.REVIEW_FILE))


def generations(calls):
    return [p for u, p in calls if u.endswith('/v1/messages')]


def advance(case):
    root, out, *_ = case
    return T.advance(out, root, cap_usd='0.50')


def test_prepare_and_status_never_call_network_or_change_ledger(case):
    root, out, ledger, calls, _ = case
    before = ledger.path.read_bytes()
    p = T.prepare(out, root)
    assert p['state'] == 'prepared_no_api' and p['cap_usd'] == '0.50' and p['expected'] == T.EXPECTED
    assert T.status(out, root)['state'] == 'prepared_no_api'
    assert calls == [] and ledger.path.read_bytes() == before and not (out / session.CHECKPOINT_FILE).exists()
    payload = T.read(out / 'payload_khau4_round1.json')
    user = payload['messages'][0]['content']
    assert '"ProcessGuid"' in user and T.QUOTES[0][3] in user and T.QUOTES[1][3] not in user
    assert payload['max_tokens'] == 32000 and payload['output_config'] == {'effort': 'high'}
    with pytest.raises(ValueError):
        T.prepare(out, root)


def test_send_requires_the_package_cap(case):
    root, out, _, calls, _ = case
    T.prepare(out, root)
    for cap in (None, '0.40', '1.00'):
        with pytest.raises(ValueError, match='trần gói'):
            T.advance(out, root, cap_usd=cap)
    assert calls == []


def test_anchor_then_dependent_round_through_the_graph(case):
    root, out, ledger, calls, _ = case
    T.prepare(out, root)
    first = advance(case)
    assert first['state'] == 'awaiting_hypothesis_review' and len(generations(calls)) == 1
    assert T.read(out / 'api_calls/call_00.json')['request'] == T.read(out / 'payload_khau4_round1.json')
    with pytest.raises(ValueError, match='chưa quyết định'):
        advance(case)
    decide(first['review_dir'])
    second = advance(case)
    assert second['state'] == 'awaiting_hypothesis_review' and Path(second['review_dir']).name == 'round_02'
    # Round 2 ④ sees the anchor only because it was approved and executed in round 1 of this run.
    user = generations(calls)[2]['messages'][0]['content']
    anchors = json.JSONDecoder().raw_decode(user[user.index('(DATA; [] means none):') + 22:].lstrip())[0]
    assert [a['hypothesis_id'] for a in anchors] == ['SELF-NEO-0710-H01'] and T.QUOTES[1][3] in user
    decide(second['review_dir'])
    done = advance(case)
    assert done['state'] == 'completed' and (out / 'hunt_record.md').exists()
    ev = done['evaluation']
    assert ev['criteria_met'], ev['checks']
    assert ev['executed']['anchor']['SELF-NEO-0710-H01']['selected'] == [100]
    dep = ev['executed']['dependent']['SELF-NEO-0710-H02']
    assert dep['selected'] == [1, 2, 3, 4, 5, 6, 7] and dep['kept'] == [2, 4]
    assert len(generations(calls)) == 4 and done['budget']['charged_delta_usd'] == ledger.status()['known_cost_usd']
    with pytest.raises(ValueError, match='không gửi lại'):
        advance(case)
    assert len(generations(calls)) == 4


def test_rejected_anchor_stops_without_dependent_round(case):
    root, out, _, calls, _ = case
    T.prepare(out, root)
    decide(advance(case)['review_dir'], 'rejected')
    done = advance(case)
    assert done['state'] == 'completed' and len(generations(calls)) == 1 and not (out / 'round_02').exists()
    assert not done['evaluation']['checks']['anchor_executed_on_sysmon_1'] and not done['evaluation']['criteria_met']


@pytest.mark.parametrize('extra, selected', [(None, [100, 101, 102]), ({'Image|endswith': r'\other.exe'}, [101]),
                                             ({'Image|endswith': [r'\powershell.exe', r'\cmd.exe']}, [100, 102])])
def test_anchor_rule_not_matching_the_named_program_fails_selection_check(extra, selected, case):
    root, out, _, calls, queue = case
    queue[1] = {'rule_yaml': rule('process_creation', 1, extra)}
    T.prepare(out, root)
    decide(advance(case)['review_dir'])
    decide(advance(case)['review_dir'])
    ev = advance(case)['evaluation']
    assert ev['executed']['anchor']['SELF-NEO-0710-H01']['selected'] == selected
    assert not ev['checks']['anchor_selection_as_expected'] and not ev['criteria_met']


def test_dependent_without_executed_anchor_reference_is_rejected_by_code(case):
    root, out, _, calls, queue = case
    bad = copy.deepcopy(DEPENDENT)
    bad['rang_buoc']['moc_neo']['gia_thuyet'] = 'NOT-EXECUTED'
    queue[2] = {'items': [bad]}
    T.prepare(out, root)
    decide(advance(case)['review_dir'])
    done = advance(case)
    # ④ postprocess drops the hypothesis: no round-2 form, the run ends without the dependent hunt.
    assert done['state'] == 'completed' and len(generations(calls)) == 3
    assert not done['evaluation']['checks']['dependent_moc_neo_to_executed_anchor']


def test_failed_paid_phase_is_never_replayed(case):
    root, out, ledger, calls, queue = case
    queue[2] = providers.TransportError('synthetic-test-key reflected by fake provider')
    T.prepare(out, root)
    decide(advance(case)['review_dir'])
    with pytest.raises(providers.LLMError):
        advance(case)
    assert T.status(out, root)['state'] == 'failed_no_retry'
    for pending in ledger.status()['pending']:
        ledger.resolve(pending['id'], '0.01', 'synthetic fixture reconciliation')
    with pytest.raises(ValueError, match='không gửi lại'):
        advance(case)
    assert len(generations(calls)) == 3 and 'synthetic-test-key' not in json.dumps(T.read(out / 'terminal.json'))


def test_code_drift_after_preparation_blocks_before_http(case):
    root, out, _, calls, _ = case
    T.prepare(out, root)
    with (root / 'src/cti_hunt/stages/s5_rule.py').open('a', encoding='utf-8') as f:
        f.write('\n# fixture drift\n')
    with pytest.raises(ValueError):
        advance(case)
    assert calls == [] and not (out / 'budget_baseline.json').exists()


def test_preparation_refuses_catalog_without_process_guid(case):
    root, out, *_ = case
    ds = root / 'configs/dataset.yaml'
    ds.write_text(ds.read_text(encoding='utf-8').replace('telemetry_catalog_v2: configs/telemetry_catalog_v2_1.yaml',
                                                         'telemetry_catalog_v2: configs/telemetry_catalog_v2.yaml'),
                  encoding='utf-8')
    with pytest.raises(ValueError, match='danh mục'):
        T.prepare(out, root)
    assert not out.exists()
