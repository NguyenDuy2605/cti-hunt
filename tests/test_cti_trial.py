"""Isolated root/ledger/events/extraction, synthetic ◆ reviewer and fake HTTP only; never a real API call."""
import copy
import json
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import duckdb
import pytest
import yaml

from cti_hunt import approval, integrity
from cti_hunt.agent import cti_trial as T
from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractA, SourceSpan, TTP, TTPContext
from cti_hunt.llm import budget, providers

SYS = 'microsoft-windows-sysmon/operational'
SEL = ['FIX-0001', 'FIX-0002']
TTPS = [('T1218.011', 'Stealth', 'FIX-0001', 'executing another DLL via rundll32.', 'rundll32.exe'),
        ('T1482', 'Discovery', 'FIX-0002', 'nltest /domain_trusts', 'nltest /domain_trusts'),
        ('T1082', 'Discovery', 'FIX-0002', 'systeminfo', 'systeminfo')]
EVENTS = [(1, r'C:\Windows\System32\rundll32.exe', 'rundll32.exe x.dll,Entry'),
          (2, r'C:\Windows\System32\nltest.exe', 'nltest /domain_trusts'),
          (3, r'C:\Windows\System32\systeminfo.exe', 'systeminfo'),
          (4, r'C:\Windows\System32\cmd.exe', 'cmd.exe /c whoami')]


def rule(image):
    return yaml.safe_dump({'title': 'Fixture', 'status': 'experimental',
                           'logsource': {'product': 'windows', 'category': 'process_creation'},
                           'detection': {'selection': {'Image|endswith': image}, 'condition': 'selection'},
                           'level': 'low'})


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
    cp = root / yaml.safe_load((root / 'configs/dataset.yaml').read_text(encoding='utf-8'))['telemetry_catalog_v2']
    catalog = yaml.safe_load(cp.read_text(encoding='utf-8'))
    catalog['techniques'] = {k: catalog['techniques'][k] for k in ['T1218.011', 'T1482', 'T1082']}
    cp.write_text(yaml.safe_dump(catalog, allow_unicode=True, sort_keys=False), encoding='utf-8')
    (root / 'scripts').mkdir()
    shutil.copyfile(ROOT / 'scripts/thu_cti_that.py', root / 'scripts/thu_cti_that.py')
    bundle, extraction = root / T.BUNDLE_REL, root / T.EXTRACTION_REL
    bundle.mkdir(parents=True)
    extraction.mkdir(parents=True)
    (bundle / 'source.html').write_text('<html>self-authored fixture</html>', encoding='utf-8')
    (bundle / 'manifest.json').write_text('{"report_id": "FIX"}', encoding='utf-8')
    ca = ContractA(report_id='FIX-CTI', title='Fixture CTI', ttps=[
        TTP(tactic=tactic, technique_id=tid, behavior_description=quote, confidence=0.8,
            context=TTPContext(command_example=cmd if tid != 'T1218.011' else '', tool=cmd.split()[0]),
            source_span=SourceSpan(segment_id=seg, text=quote)) for tid, tactic, seg, quote, cmd in TTPS])
    (extraction / 'contract_a.json').write_text(ca.model_dump_json(indent=2), encoding='utf-8')
    T.write(extraction / 'meta.json', {'status': 'complete', 'partial_extraction': True, 'selected_segments': SEL,
                                       'bundle_manifest_sha256': integrity.sha256_file(bundle / 'manifest.json')})
    events = root / T.EVENTS_REL
    events.mkdir(parents=True)
    con = duckdb.connect()
    con.execute('CREATE TABLE e(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, ev_ts TIMESTAMP, '
                'ev_ts_src VARCHAR, Hostname VARCHAR, EventID VARCHAR, Image VARCHAR, ParentImage VARCHAR, '
                'CommandLine VARCHAR, ProcessGuid VARCHAR, User VARCHAR, IntegrityLevel VARCHAR)')
    for rec, image, cmd in EVENTS:
        con.execute('INSERT INTO e VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    ['LAB-HOST', SYS, rec, datetime(2020, 1, 1) + timedelta(seconds=rec), 'UtcTime', 'lab-host',
                     '1', image, r'C:\Windows\explorer.exe', cmd, f'g{rec}', r'LAB\user', 'Medium'])
    con.execute(f"COPY e TO '{(events / 'events.parquet').as_posix()}' (FORMAT PARQUET)")
    con.close()
    T.write(events / 'ingest_manifest.json', {'dataset_kind': 'otrf_dev', 'dataset_id': T.DATASET_ID,
                                              'source_sha256': 'a' * 64, 'hosts': {'LAB-HOST': 4}, 'rows': 4})
    monkeypatch.setattr(T, 'SELECTED', SEL)
    monkeypatch.setattr(T, 'CONTRACT_SHA256', integrity.sha256_file(extraction / 'contract_a.json'))
    monkeypatch.setattr(T, 'BUNDLE_MANIFEST_SHA256', integrity.sha256_file(bundle / 'manifest.json'))
    monkeypatch.setattr(T, 'SOURCE_SHA256', integrity.sha256_file(bundle / 'source.html'))
    monkeypatch.setattr(T, 'DATA_SHA256', 'a' * 64)
    ledger = budget.Ledger(root / 'data/dev/api_budget.sqlite')
    ledger.init('0.648814')
    monkeypatch.setenv('LLM_API_KEY', 'synthetic-test-key')
    calls, queue = [], []

    def post(url, payload, headers, **kw):
        assert kw['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        calls.append((url, payload))
        if url.endswith('count_tokens'):
            return {'input_tokens': 1000}
        data = queue.pop(0)
        if isinstance(data, BaseException):
            raise data
        return {'usage': {'input_tokens': 1000, 'output_tokens': 100}, 'stop_reason': 'tool_use',
                'content': [{'type': 'tool_use', 'input': data}]}
    monkeypatch.setattr(providers, '_post', post)
    return root, root / T.OUT_REL, ledger, calls, queue


def plan(case, *, constraint=False, nltest_image=r'\nltest.exe'):
    """④ items keyed by the pinned payload's own ref order, then one ⑤ rule per hypothesis in that order."""
    root, out, _, _, queue = case
    T.prepare(out, root)
    user = T.read(out / 'payload_khau4_round1.json')['messages'][0]['content']
    rows = json.JSONDecoder().raw_decode(user[user.index('['):])[0]
    image = {'T1218.011': r'\rundll32.exe', 'T1482': nltest_image, 'T1082': r'\systeminfo.exe'}
    items, rules = [], []
    for r in rows:
        items.append({'ttp_refs': [r['ref']], 'behavior': f"Dấu vết {r['quote']}", 'scope': 'mọi máy',
                      'timeframe': 'toàn bộ khoảng thời gian của log', 'data_source': SYS, 'event_ids': [1],
                      'key_fields': ['Image', 'CommandLine', 'ProcessGuid'], 'extra_techniques': [],
                      'priority': 'trung_binh', 'rationale': f"Căn cứ: \"{r['quote']}\".", 'required_operations': [],
                      'rang_buoc': None})
        rules.append({'rule_yaml': rule(image[r['technique_id']])})
    if constraint:
        items[0]['required_operations'] = ['distinct_count']
        items[0]['rang_buoc'] = {'dem_khac_nhau': {'truong': 'CommandLine', 'theo': ['ev_host', 'ProcessGuid'],
                                                   'cua_so_giay': 120, 'toi_thieu': 2}}
    queue.extend([{'items': items}, *rules])


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
    return T.advance(out, root, cap_usd='0.60')


def test_prepare_and_status_are_offline(case):
    root, out, ledger, calls, _ = case
    before = ledger.path.read_bytes()
    p = T.prepare(out, root)
    assert p['state'] == 'prepared_no_api' and p['ttp_vao_khau4'] == 3 and p['cap_usd'] == '0.60'
    assert T.status(out, root)['state'] == 'prepared_no_api' and calls == [] and ledger.path.read_bytes() == before
    user = T.read(out / 'payload_khau4_round1.json')['messages'][0]['content']
    assert 'nltest /domain_trusts' in user and '"ProcessGuid"' in user
    with pytest.raises(ValueError):
        T.prepare(out, root)


def test_send_requires_cap_and_changed_contract_blocks(case):
    root, out, _, calls, _ = case
    T.prepare(out, root)
    with pytest.raises(ValueError, match='trần gói'):
        T.advance(out, root, cap_usd='0.50')
    (root / T.EXTRACTION_REL / 'contract_a.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='Nguồn/mã/script'):
        advance(case)
    assert calls == []


def test_one_round_end_to_end_meets_criteria(case):
    root, out, ledger, calls, _ = case
    plan(case)
    first = advance(case)
    assert first['state'] == 'awaiting_hypothesis_review' and len(generations(calls)) == 1
    assert T.read(out / 'api_calls/call_00.json')['request'] == T.read(out / 'payload_khau4_round1.json')
    decide(first['review_dir'])
    done = advance(case)
    assert done['state'] == 'completed' and len(generations(calls)) == 4, done
    ev = done['evaluation']
    assert ev['criteria_met'], ev['checks']
    hits = {tuple(r['linked_ttps']): r['stages'][0]['hits'] for r in ev['executed']}
    assert hits == {('T1218.011',): 1, ('T1482',): 1, ('T1082',): 1}
    assert done['budget']['charged_delta_usd'] == ledger.status()['known_cost_usd']
    with pytest.raises(ValueError, match='không gửi lại'):
        advance(case)


def test_invented_numeric_constraint_fails_the_criterion(case):
    plan(case, constraint=True)
    decide(advance(case)['review_dir'])
    ev = advance(case)['evaluation']
    assert not ev['checks']['no_numeric_constraint'] and not ev['criteria_met']


def test_rule_not_using_the_quoted_tool_fails_the_criterion(case):
    plan(case, nltest_image=r'\cmd.exe')
    decide(advance(case)['review_dir'])
    ev = advance(case)['evaluation']
    assert not ev['checks']['rule_uses_quoted_tool'] and not ev['criteria_met']


def test_rejected_hypotheses_are_not_counted_as_executed(case):
    root, out, _, calls, _ = case
    plan(case)
    decide(advance(case)['review_dir'], 'rejected')
    ev = advance(case)['evaluation']
    assert len(generations(calls)) == 1 and not ev['checks']['every_approved_executed'] and not ev['criteria_met']


def test_code_drift_after_preparation_blocks_before_http(case):
    root, out, _, calls, _ = case
    T.prepare(out, root)
    with (root / 'src/cti_hunt/stages/s5_rule.py').open('a', encoding='utf-8') as f:
        f.write('\n# fixture drift\n')
    with pytest.raises(ValueError):
        advance(case)
    assert calls == []
