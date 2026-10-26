"""Synthetic STIX only: validate N2 mappings without touching pinned datasets."""
import copy
import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractB, Evidence
from cti_hunt.stages.s3_telemetry import load_catalog
from cti_hunt.stages.s5_rule import logsources_for

B = runpy.run_path(str(ROOT / 'scripts/n2_catalog_builder.py'))
generate, parse_ids = B['generate_catalog'], B['event_ids']
CHANNEL = 'microsoft-windows-sysmon/operational'


def fixture():
    def tech(tid, **extra):
        return {'type': 'attack-pattern', 'id': tid, 'x_mitre_platforms': ['Windows'],
                'external_references': [{'source_name': 'mitre-attack', 'external_id': tid}], **extra}
    return dict(stix={'objects': [
        tech('T1001'), tech('T1002'), tech('T1003'),
        tech('T1004', x_mitre_platforms=['Linux']), tech('T1005', revoked=True),
        tech('T1006', x_mitre_deprecated=True),
        {'type': 'x-mitre-detection-strategy', 'id': 'ds', 'x_mitre_analytic_refs': ['a'],
         'external_references': [{'source_name': 'mitre-attack', 'external_id': 'DET0001'}]},
        {'type': 'x-mitre-analytic', 'id': 'a', 'x_mitre_platforms': ['Windows'],
         'x_mitre_log_source_references': [{'name': 'WinEventLog:Sysmon', 'channel': 'EventCode=3, 22'}]},
        *[{'type': 'relationship', 'id': 'r'+tid, 'relationship_type': 'detects',
           'source_ref': 'ds', 'target_ref': tid} for tid in ('T1001', 'T1002', 'T1004', 'T1005', 'T1006')]]},
        mapping={'WinEventLog:Sysmon': CHANNEL},
        fields={CHANNEL: {i: {'key_fields': ['Image'], 'truong_bat_buoc': ['Image']} for i in (3, 22)}},
        logsources={'network_connection': [{'name': 'sysmon3', 'channel': CHANNEL, 'event_ids': [3]}]},
        baseline={'techniques': {}})


@pytest.mark.parametrize('text,expected', [
    ('EventCode=3, 22', [3, 22]), ('EventCode=4778, EventCode=4779', [4778, 4779]),
    ('EventCode=5005 (WLAN), EventCode=302 (Bluetooth)', [302, 5005]),
    ('System bugcheck (Event ID 1001)', [1001]), ('eventcode = 3, 3, 22', [3, 22]),
    ('CommandLine=123, version 2026', []), ('EventCode=4103-4106', []),
])
def test_event_id_lists(text, expected):
    assert parse_ids(text) == expected


def test_windows_scope_one_to_many_and_unsupported_pair(tmp_path):
    args = fixture()
    cat, audit = generate(**args)
    assert set(cat['techniques']) == {'T1001', 'T1002', 'T1003'}
    for tid in ('T1001', 'T1002'):
        assert cat['techniques'][tid]['sources'][0]['event_ids'] == [3]
        assert audit['techniques'][tid]['gaps'][0]['reason'] == 'unsupported_stage5_pair'
        assert audit['techniques'][tid]['gaps'][0]['event_id'] == 22
        assert audit['techniques'][tid]['provenance'][0]['relationship'] == 'r'+tid
    assert cat['techniques']['T1003']['status'] == 'not_huntable'
    file = tmp_path / 'candidate.yaml'
    file.write_text(yaml.safe_dump(cat, allow_unicode=True), encoding='utf-8')
    loaded = load_catalog(file)
    for tid, entry in loaded.items():
        for s in entry['sources']:
            h = ContractB(hypothesis_id='SYN-H01', behavior='fixture', scope='fixture', timeframe='fixture',
                          evidence=Evidence(data_source=s['channel'], event_ids=s['event_ids'], key_fields=s['key_fields']),
                          linked_ttps=[tid])
            assert logsources_for(h, args['logsources'])


@pytest.mark.parametrize('obj_id', ['rT1001', 'ds', 'a'])
@pytest.mark.parametrize('flag', ['revoked', 'x_mitre_deprecated'])
def test_inactive_detection_chain_is_not_used(obj_id, flag):
    args = fixture()
    next(o for o in args['stix']['objects'] if o['id'] == obj_id)[flag] = True
    cat, _ = generate(**args)
    assert cat['techniques']['T1001']['status'] == 'not_huntable'


def test_service_wildcard_missing_schema_and_baseline_are_explicit():
    args = fixture()
    args['logsources']['network_connection'][0]['event_ids'] = []
    cat, _ = generate(**args)
    assert len(cat['techniques']['T1001']['sources']) == 2
    args['fields'][CHANNEL][22]['truong_bat_buoc'] = ['InventedField']
    base = {'status': 'huntable', 'sources': [{'channel': CHANNEL, 'event_ids': [99],
            'key_fields': ['Image'], 'truong_bat_buoc': ['Image']}], 'ghi_chu': 'Reviewed fixture'}
    args['baseline']['techniques']['T1002'] = base
    args['logsources']['network_connection'][0]['event_ids'] = [3, 22]
    before = copy.deepcopy(args)
    cat, audit = generate(**args)
    assert args == before
    assert audit['techniques']['T1001']['gaps'][0]['reason'] == 'missing_or_invalid_schema'
    assert cat['techniques']['T1002'] == base
    assert audit['techniques']['T1002']['baseline_unsupported_pairs'] == [{'channel': CHANNEL, 'event_id': 99}]
    assert audit['techniques']['T1002']['overridden']
    args['baseline']['techniques']['T1004'] = base
    with pytest.raises(ValueError, match='outside Windows'):
        generate(**args)
    args['baseline']['techniques']['T1004'] = {'status': 'not_huntable', 'sources': []}
    cat, audit = generate(**args)
    assert audit['techniques']['T1004']['baseline_outside_windows']
    assert cat['techniques']['T1004']['status'] == 'not_huntable'


def test_powershell_split_and_unmapped_ids():
    args = fixture()
    analytic = next(o for o in args['stix']['objects'] if o['id'] == 'a')
    analytic['x_mitre_log_source_references'] = [{'name': 'WinEventLog:PowerShell', 'channel': 'EventCode=400, 4103, 4104, 9999'}]
    args['mapping'] = {'WinEventLog:PowerShell': ['400,403: windows powershell', '4103-4106: microsoft-windows-powershell/operational']}
    pairs = B['mapped_pairs']('WinEventLog:PowerShell', [400, 4103, 4104], args['mapping'])
    assert pairs == {('windows powershell', 400), ('microsoft-windows-powershell/operational', 4103), ('microsoft-windows-powershell/operational', 4104)}
    _, audit = generate(**args)
    assert any(g.get('event_ids') == [9999] for g in audit['techniques']['T1001']['gaps'])


def test_generation_is_order_independent():
    args = fixture()
    first = generate(**args)
    args['stix']['objects'].reverse()
    assert generate(**args) == first


def test_cli_writes_candidate_and_audit_never_overwrites(tmp_path):
    args = fixture()
    cfg = tmp_path / 'configs'
    cfg.mkdir()
    files = {'mapping': 'attack_nguon_log', 'fields': 'truong_theo_su_kien',
             'logsources': 'logsource_catalog', 'baseline': 'telemetry_baseline'}
    for key, name in files.items():
        (cfg / (name+'.yaml')).write_text(yaml.safe_dump(args[key]), encoding='utf-8')
    stix = tmp_path / 'stix.json'
    stix.write_text(json.dumps(args['stix']), encoding='utf-8')
    reports = {'attack': {'version': '19.2', 'stix_path': 'stix.json',
                         'stix_sha256': hashlib.sha256(stix.read_bytes()).hexdigest()}}
    (cfg / 'reports.yaml').write_text(yaml.safe_dump(reports), encoding='utf-8')
    live = cfg / 'telemetry_catalog.yaml'
    live.write_text('PINNED', encoding='utf-8')
    out = tmp_path / 'candidate.yaml'
    cmd = [sys.executable, str(ROOT / 'scripts/generate_n2_catalog.py'), '--root', str(tmp_path), '--output', str(out)]
    subprocess.run(cmd, check=True, capture_output=True)
    audit = json.loads(out.with_suffix('.audit.json').read_text(encoding='utf-8'))
    assert audit['catalog_sha256'] == hashlib.sha256(out.read_bytes()).hexdigest()
    before = out.read_bytes()
    assert subprocess.run(cmd, capture_output=True).returncode != 0
    assert out.read_bytes() == before and live.read_text(encoding='utf-8') == 'PINNED'
    stix.write_text('{}', encoding='utf-8')
    cmd[-1] = str(tmp_path / 'bad.yaml')
    assert subprocess.run(cmd, capture_output=True).returncode != 0
    assert not (tmp_path / 'bad.yaml').exists()
