"""Schema regressions on synthetic events only, without API or real labels."""
import json
import runpy

import duckdb
import pytest
import yaml

from cti_hunt.config import ROOT
from cti_hunt.stages.s3_telemetry import build_profile, apply_profile

A = runpy.run_path(str(ROOT / 'scripts/audit_n2_schema.py'))
audit_fields, run_audit, main = A['audit_fields'], A['run_audit'], A['main']
CH = 'microsoft-windows-sysmon/operational'


def schema(*keys):
    return {'key_fields': list(keys), 'truong_bat_buoc': list(keys[:1])}


def test_fields_counted_by_channel_and_eid_not_union_columns():
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, Image VARCHAR, Name VARCHAR)')
        con.executemany('INSERT INTO events VALUES (?,?,?,?)', [
            (CH, 1, 'process.exe', None), (CH, 19, ' ', 'filter'), ('other', 19, 'other.exe', None)])
        fields = {CH: {19: schema('Image', 'Name'), 20: schema('Image')},
                  'absent': {19: schema('Image')}}
        out = audit_fields(con, fields)
        rows = {(s['channel'], s['event_id']): s for s in out['sources']}
        observed = rows[CH, 19]
        assert observed['events'] == 1
        assert observed['empty_fields'] == observed['missing_required'] == ['Image']
        assert observed['observed_fields'] == {'Name': 1}
        assert rows[CH, 20]['observation'] == 'no_events'
        assert rows[CH, 20]['field_counts'] is None
        assert rows[CH, 20]['missing_required'] == []
        assert rows['absent', 19]['observation'] == 'channel_absent'
        assert out['events'] == 3
        assert 'process.exe' not in json.dumps(out)


def test_missing_columns_and_quoted_identifiers():
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, "odd""field" VARCHAR)')
        con.execute("INSERT INTO events VALUES ('SECURITY', 1, 'value')")
        out = audit_fields(con, {'security': {1: schema('Odd"Field', 'Absent')}})
        row = out['sources'][0]
        assert row['field_counts'] == {'Odd"Field': 1, 'Absent': 0}
        assert row['missing_columns'] == ['Absent']
        assert row['missing_required'] == []


@pytest.mark.parametrize('label', ['buoc', 'labeled', 'attack_labels'])
def test_label_columns_rejected(label):
    with duckdb.connect() as con:
        con.execute(f'CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, {label} VARCHAR)')
        with pytest.raises(ValueError, match='Label columns'):
            audit_fields(con, {})


def synthetic_dev(tmp_path):
    cfg = tmp_path / 'configs'
    cfg.mkdir()
    (cfg / 'dataset.yaml').write_text(yaml.safe_dump({
        'work_dir': 'data/work', 'raw': {'path': 'data/raw/evaluation.zip',
                                      'sha256': 'a' * 64, 'hosts': ['EVAL']}}), encoding='utf-8')
    fields = cfg / 'fields.yaml'
    fields.write_text(yaml.safe_dump({CH: {19: schema('Name')}}), encoding='utf-8')
    d = tmp_path / 'data/dev/fixture'
    d.mkdir(parents=True)
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, Name VARCHAR)')
        con.execute('INSERT INTO events VALUES (?,19,?,?)', [CH, 'DEV', 'filter'])
        con.sql('SELECT * FROM events').write_parquet(str(d / 'events.parquet'))
    manifest = {'dataset_kind': 'otrf_dev', 'dataset_id': 'fixture', 'source_sha256': 'b' * 64,
                'source': 'fixture.zip', 'hosts': {'DEV': 1}, 'rows': 1}
    (d / 'ingest_manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return fields, d, manifest


def test_cli_repeatable_and_no_overwrite(tmp_path, capsys):
    fields, d, _ = synthetic_dev(tmp_path)
    output = tmp_path / 'data/dev/audit.json'
    args = ['--root', str(tmp_path), '--fields', str(fields), '--events', str(d), '--output', str(output)]
    main(args)
    before = output.read_bytes()
    result = json.loads(before)
    assert result['summary']['events'] == 1
    assert result['summary']['unique_sources_with_field_gaps'] == 0
    assert result == run_audit(tmp_path, fields, [d])
    with pytest.raises(SystemExit):
        main(args)
    assert before == output.read_bytes()
    with pytest.raises(ValueError, match='Duplicate development'):
        run_audit(tmp_path, fields, [d, d])
    with pytest.raises(ValueError, match='At least one'):
        run_audit(tmp_path, fields, [])


def test_reject_eval_path_before_reading_manifest(tmp_path):
    with pytest.raises(ValueError, match='inside data/dev'):
        A['checked_dataset'](tmp_path / 'data/work', tmp_path)


@pytest.mark.parametrize('kind', ['source_hash', 'member_hash', 'host', 'row_count', 'dataset_kind'])
def test_development_provenance_checks(tmp_path, kind):
    fields, d, manifest = synthetic_dev(tmp_path)
    if kind == 'source_hash':
        manifest['source_sha256'] = 'a' * 64
    elif kind == 'member_hash':
        manifest['members'] = [{'sha256': 'a' * 64}]
    elif kind == 'host':
        with duckdb.connect() as con:
            con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, Name VARCHAR)')
            con.execute('INSERT INTO events VALUES (?,19,?,?)', [CH, 'EVAL', 'filter'])
            con.sql('SELECT * FROM events').write_parquet(str(d / 'events.parquet'))
    elif kind == 'row_count':
        manifest['rows'] = 2
    else:
        manifest['dataset_kind'] = 'danh_gia'
    (d / 'ingest_manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    with pytest.raises(ValueError):
        run_audit(tmp_path, fields, [d])


def test_corrected_wmi_schema_keeps_objects_without_image():
    fields = yaml.safe_load((ROOT / 'configs/truong_theo_su_kien.yaml').read_text(encoding='utf-8'))
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, Image VARCHAR, '
                    'Name VARCHAR, EventNamespace VARCHAR, Query VARCHAR, Destination VARCHAR, '
                    'Consumer VARCHAR, Filter VARCHAR)')
        con.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', [
            (CH, 19, None, 'filter', 'namespace', 'SELECT * FROM fixture', None, None, None),
            (CH, 20, None, 'consumer', None, None, 'script', None, None),
            (CH, 21, None, None, None, None, None, 'consumer', 'filter')])
        sources = [{'channel': CH, 'event_ids': [eid], **fields[CH][eid]} for eid in (19, 20, 21)]
        cat = {'T0000': {'status': 'partial', 'sources': sources, 'ly_do_partial': 'synthetic'}}
        profile = build_profile(con, cat, 'synthetic')
        assert all(s['giu'] for s in profile['ky_thuat']['T0000']['nguon'])
        assert len(apply_profile(cat, profile)['T0000']['sources']) == 3
        broken = {'T0000': {'status': 'partial', 'sources': [
            {**s, **schema('Image')} for s in sources]}}
        assert build_profile(con, broken, 'synthetic')['ky_thuat']['T0000']['trang_thai'] == 'not_huntable'


@pytest.mark.parametrize('channel,eid,fields_in_event', [
    (CH, 22, {'Image': 'fixture.exe', 'QueryName': 'fixture.invalid'}),
    ('security', 4698, {'TaskName': 'fixture', 'TaskContent': '<Task/>'}),
])
def test_corrected_dns_and_task_fields_reach_hypothesis_input(channel, eid, fields_in_event):
    fields = yaml.safe_load((ROOT / 'configs/truong_theo_su_kien.yaml').read_text(encoding='utf-8'))
    with duckdb.connect() as con:
        cols = ', '.join(A['quote_ident'](f) + ' VARCHAR' for f in fields_in_event)
        con.execute('CREATE TABLE events(ev_channel VARCHAR, ev_eid INTEGER, ' + cols + ')')
        con.execute('INSERT INTO events VALUES (' + ','.join('?' for _ in range(2 + len(fields_in_event))) + ')',
                    [channel, eid, *fields_in_event.values()])
        source = {'channel': channel, 'event_ids': [eid], **fields[channel][eid]}
        cat = {'T0000': {'status': 'partial', 'sources': [source], 'ly_do_partial': 'synthetic'}}
        effective = apply_profile(cat, build_profile(con, cat, 'synthetic'))
        assert set(effective['T0000']['sources'][0]['key_fields']) == set(fields_in_event)
