"""Known semantic regressions, synthetic data and mocked models only."""
import json

import duckdb
import pytest
import yaml
from pydantic import ValidationError

from cti_hunt import approval
from cti_hunt.contracts import ContractA, ContractB, Evidence
from cti_hunt.agent.stage_tools import StageTools
from cti_hunt.config import load, ROOT
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import execution_semantics as sem, s5_rule
from cti_hunt.hunt.observe import run_unlabeled

SYS = 'microsoft-windows-sysmon/operational'
LS = {'process_creation': [{'name': 'sysmon_1', 'channel': SYS, 'event_ids': [1],
                            'field_map': {}, 'unavailable': []}]}
RULE = '''title: Synthetic process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\fixture.exe'
  condition: selection
'''


def hypothesis(**changes):
    return ContractB(**{'hypothesis_id': 'SYN-H01', 'behavior': 'Tiến trình tạo file', 'scope': 'máy fixture',
        'timeframe': 'toàn bộ log', 'evidence': Evidence(data_source=SYS, event_ids=[1], key_fields=['Image']),
        'linked_ttps': ['T1047'], 'status': 'approved', 'origin': 'pivot', 'pivot_depth': 1,
        'pivot_kind': 'may', 'pivot_value': 'A', **changes})


@pytest.mark.parametrize('change,operation', [
    ({'behavior': 'Cùng tiến trình kết nối nhiều địa chỉ IP trong thời gian ngắn, không qua phân giải tên miền'}, 'absence'),
    ({'timeframe': 'Trong vòng 30 phút sau sự kiện PowerShell trước đó'}, 'relative_time'),
    ({'behavior': 'Multiple destination IPs without DNS resolution'}, 'distinct_count'),
    ({'timeframe': 'within 30 minutes after the previous event'}, 'relative_time'),
    ({'required_operations': ['event_sequence']}, 'event_sequence'),
    ({'timeframe': 'từ mốc chưa xác định tới ngày mai'}, 'timeframe_unbound'),
])
def test_unsupported_hypothesis_blocked_before_any_rule_call(tmp_path, change, operation):
    h = hypothesis(**change)
    assert operation in {i['operation'] for i in sem.issues(h)}
    client = MockClient(responses=[])
    result = s5_rule.generate_rule(h, client, {}, LS, 2, run_dir=tmp_path)
    assert not result['hop_le'] and result['hunt_specs'] == [] and client.calls == []
    assert result['lan_thu'][0]['loai'] == 'bo_qua'
    assert result['token'] == {'input_tokens': 0, 'output_tokens': 0}
    # Direct validation (e.g. a UI path) must not bypass the guard.
    issues, specs = s5_rule.validate_rule(RULE, h, LS)
    assert issues[0].kind == 'ngu_nghia_chua_ho_tro' and not specs


def test_relative_window_not_resolved_by_inventing_absolute_times():
    h = hypothesis(timeframe='30 phút sau', execution_window={
        'start': '2020-01-01T00:00:00Z', 'end': '2020-01-01T00:30:00Z'})
    assert 'relative_time' in {i['operation'] for i in sem.issues(h)}


@pytest.mark.parametrize('window', [
    {'start': '2020-01-01T00:00:00', 'end': '2020-01-01T00:30:00'},
    {'start': '2020-01-01T00:30:00Z', 'end': '2020-01-01T00:00:00Z'},
    {'start': '2020-01-01T00:00:00Z', 'end': '2020-01-01T00:00:00Z'},
])
def test_invalid_absolute_windows_rejected(window):
    with pytest.raises(ValidationError):
        hypothesis(execution_window=window)


def test_reviewed_absolute_window_is_enforced_at_boundaries_and_host(tmp_path):
    h = hypothesis(timeframe='khoảng UTC được duyệt', execution_window={
        'start': '2020-01-01T07:00:00+07:00', 'end': '2020-01-01T07:30:00+07:00'})
    approval.write_review([h.model_copy(update={'status': 'pending_review'})], tmp_path)
    form = yaml.safe_load((tmp_path / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    assert form['gia_thuyet'][0]['cua_so_thuc_thi_utc']['start'] == '2020-01-01T00:00:00Z'
    assert form['gia_thuyet'][0]['loi_kha_nang_thuc_thi'] == []
    assert approval.load_hypotheses(tmp_path / approval.HYP_FILE)[0].execution_window == h.execution_window
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, '
                    'ev_rec INTEGER, ev_ts TIMESTAMP, Image VARCHAR)')
        for rec, host, ts in [(1, 'A', '2019-12-31 23:59:59'), (2, 'A', '2020-01-01 00:00:00'),
                              (3, 'A', '2020-01-01 00:29:59'), (4, 'A', '2020-01-01 00:30:00'),
                              (5, 'B', '2020-01-01 00:01:00')]:
            con.execute('INSERT INTO events VALUES (?,1,?,?,?,?)', [SYS, host, rec, ts, r'C:\fixture.exe'])
        columns = {r[0] for r in con.execute('DESCRIBE events').fetchall()}
        issues, specs = s5_rule.validate_rule(RULE, h, LS, columns, con)
        assert not issues and len(specs) == 1
        assert specs[0]['scope']['time_to'] == '2020-01-01 00:30:00'
        assert run_unlabeled(con, specs[0])['stages'][-1]['hits'] == 2


def test_blocked_rule_reason_reaches_final_record_without_zero_hit_claim(tmp_path):
    h = hypothesis(timeframe='30 phút sau')
    approval.write_review([h], tmp_path / 'round_01')
    # Synthetic approved artifact, not a real user form.
    approved = tmp_path / 'round_01' / approval.APPROVED_FILE
    approved.write_text(json.dumps([h.model_dump(mode='json')]), encoding='utf-8')
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, '
                    'ev_rec INTEGER, ev_ts TIMESTAMP, Image VARCHAR)')
        client = MockClient(responses=[])
        tools = StageTools(ContractA(report_id='SYN'), {}, LS, con, load('agent'), client, client,
                           {}, {}, {}, tmp_path, dataset_kind='fixture', dataset_id='synthetic')
        state = {'review_dir': str(approved.parent), 'approved_files': [str(approved)], 'history': [],
                 'executed_specs': []}
        output = tools.execute(state, [h])
        assert output['spec_files'] == [] and output['observations'] == []
        record = json.loads(open(tools.record(state), encoding='utf-8').read())
        assert record['execution_issues'][0]['hypothesis_id'] == 'SYN-H01'
        md = (tmp_path / 'hunt_record.md').read_text(encoding='utf-8')
        assert 'không phải kết quả 0 sự kiện' in md and 'SYN-H01' in md
        assert client.calls == []
