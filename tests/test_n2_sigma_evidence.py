"""N2 bằng chứng SigmaHQ theo tiêu chí chặt: chỉ fixture tổng hợp, không API, không nhãn, không APT29."""
import hashlib
import json
import runpy

import duckdb
import pytest
import yaml

from cti_hunt.config import ROOT
from cti_hunt.stages.s3_telemetry import load_catalog

E = runpy.run_path(str(ROOT / 'scripts/n2_sigma_evidence.py'))
evaluate, field_counts, check_base, check_output = E['evaluate'], E['field_counts'], E['check_base'], E['check_output']
REASON = E['REASON_PARTIAL']
SYS = 'microsoft-windows-sysmon/operational'


def src(ch, eids, field):
    return {'channel': ch, 'event_ids': list(eids), 'key_fields': [field], 'truong_bat_buoc': [field]}


def partial(*sources, note=''):
    return {'status': 'partial', 'sources': list(sources), 'ly_do_partial': 'Sinh tự động.', 'ghi_chu': note}


BASE = {'phien_ban': 't', 'techniques': {
    'T1001': partial(src(SYS, [1], 'Image'), note='Ghi chú giữ nguyên.'),
    'T1002': partial(src(SYS, [3], 'Image')),
    'T1003': {'status': 'partial', 'sources': [src(SYS, [1], 'Image')], 'ly_do_partial': 'Lý do đã rà tay.'},
    'T1004': partial(src('security', [4688], 'NewProcessName')),
    'T1005': partial(src(SYS, [1], 'Image')),
    'T1006': {'status': 'not_huntable', 'sources': []},
    'T1007': partial(src(SYS, [1], 'Image')),
    'T1008': partial(src(SYS, [1], 'Image')),
    'T1009': partial(src('security', [4688], 'NewProcessName')),
    'T1010': partial(src('security', [4688], 'NewProcessName')),
}}
LOGSOURCES = {
    'process_creation': [{'name': 'sysmon_1', 'channel': SYS, 'event_ids': [1]}],
    'network_connection': [{'name': 'sysmon_3', 'channel': SYS, 'event_ids': [3]}],
    'service:security': [{'name': 'security_all', 'channel': 'security', 'event_ids': []}],
}


def rule(tag, detection, status='test', logsource='category: process_creation'):
    return (f'title: Rule {tag}\nstatus: {status}\ntags:\n  - attack.{tag}\n'
            f'logsource:\n  product: windows\n  {logsource}\ndetection:\n{detection}')


SEL_IMAGE = "  selection:\n    Image|endswith: '\\x.exe'\n  condition: selection\n"
RULES = [
    ('a/t1001.yml', rule('t1001', SEL_IMAGE)),
    ('a/t1002.yml', rule('t1002', "  selection:\n    DestinationIp: '10.0.0.1'\n  condition: selection\n",
                         logsource='category: network_connection')),
    ('a/t1003.yml', rule('t1003', SEL_IMAGE, status='stable')),
    ('a/t1004.yml', rule('t1004', SEL_IMAGE)),
    ('a/t9999.yml', rule('t9999', SEL_IMAGE)),
    ('a/t1007_exp.yml', rule('t1007', SEL_IMAGE, status='experimental')),
    ('a/t1007_kw.yml', rule('t1007', "  keywords:\n    - 'x.exe'\n  condition: keywords\n")),
    ('a/t1009.yml', rule('t1009', "  selection:\n    EventID: 4624\n    TargetUserName: 'a'\n  condition: selection\n",
                         logsource='service: security')),
    ('a/t1010.yml', rule('t1010', "  selection:\n    EventID: 4688\n    NewProcessName|endswith: '\\x.exe'\n"
                                  "  condition: selection\n", logsource='service: security')),
]


def events():
    con = duckdb.connect()
    con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, EventID VARCHAR, '
                'Image VARCHAR, DestinationIp VARCHAR, NewProcessName VARCHAR, CommandLine VARCHAR)')
    con.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)', [
        (SYS, 1, 'DEV', '1', 'C:\\bi-mat.exe', None, None, 'gia-tri-bi-mat'),
        (SYS, 3, 'DEV', '3', 'C:\\a.exe', ' ', None, None),
        ('security', 4688, 'DEV', '4688', None, None, 'C:\\b.exe', None)])
    return con


def run():
    with events() as con:
        return evaluate(BASE, {'T1003'}, RULES, LOGSOURCES, [('dev', con)], lambda t: {'T9999': 'T1005'}.get(t, t))


def test_only_rules_meeting_every_criterion_promote():
    out, audit = run()
    t = out['techniques']
    assert {k for k, v in t.items() if v['status'] == 'huntable'} == {'T1001', 'T1005', 'T1010'}
    assert 'ly_do_partial' not in t['T1001'] and t['T1001']['ghi_chu'] == 'Ghi chú giữ nguyên.'
    for tid in ('T1002', 'T1004', 'T1007', 'T1008', 'T1009'):
        assert t[tid]['status'] == 'partial' and t[tid]['ly_do_partial'] == REASON
    assert t['T1003'] == BASE['techniques']['T1003'] and t['T1006'] == BASE['techniques']['T1006']
    assert audit['not_promoted'] == {
        'T1002': {'truong_rong_hoac_thieu': 1}, 'T1004': {'khac_nguon_danh_muc': 1},
        'T1007': {'keyword_khong_ten_truong': 1, 'status_experimental': 1},
        'T1009': {'khac_nguon_danh_muc': 1}}
    assert audit['no_tagged_rule'] == ['T1008'] and audit['targets'] == 8
    ev = audit['promoted']['T1001'][0]
    assert (ev['dataset_id'], ev['channel'], ev['event_id'], ev['fields']) == ('dev', SYS, 1, ['Image'])
    assert audit['promoted']['T1005'][0]['rule'] == 'a/t9999.yml'          # mã thu hồi -> mã hiện hành
    assert audit['promoted']['T1010'][0]['event_id'] == 4688               # EID lấy từ detection của service
    assert 'bi-mat' not in json.dumps(audit, ensure_ascii=False)           # không xuất giá trị sự kiện


def test_output_passes_catalog_checks(tmp_path):
    out, _ = run()
    p = tmp_path / 'c.yaml'
    p.write_text(yaml.safe_dump(out, allow_unicode=True, sort_keys=False), encoding='utf-8')
    assert set(load_catalog(p)) == set(BASE['techniques'])


def test_label_columns_rejected():
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, buoc VARCHAR)')
        with pytest.raises(ValueError, match='nhãn'):
            field_counts(con)


def test_base_must_match_its_audit_hash(tmp_path):
    base = tmp_path / 'telemetry_candidate.yaml'
    base.write_text('techniques: {}\n', encoding='utf-8')
    audit = tmp_path / 'telemetry_candidate.audit.json'
    audit.write_text(json.dumps({'catalog_sha256': hashlib.sha256(base.read_bytes()).hexdigest()}), encoding='utf-8')
    assert check_base(base)[0] == {'techniques': {}}
    base.write_text('techniques: {T1: {status: huntable}}\n', encoding='utf-8')     # bị ghi đè sau khi sinh
    with pytest.raises(ValueError, match='ghi đè'):
        check_base(base)


def test_output_must_be_new_file_in_data_dev(tmp_path):
    root = tmp_path
    (root / 'data/dev/old').mkdir(parents=True)
    (root / 'data/dev/old/c.yaml').write_text('x', encoding='utf-8')
    with pytest.raises(ValueError, match='đã tồn tại'):
        check_output(root / 'data/dev/old/c.yaml', root, set())
    with pytest.raises(ValueError, match='data/dev'):
        check_output(root / 'configs/c.yaml', root, set())
    out, audit = check_output(root / 'data/dev/new/c.yaml', root, set())
    assert audit.name == 'c.audit.json' and out.name == 'c.yaml'
