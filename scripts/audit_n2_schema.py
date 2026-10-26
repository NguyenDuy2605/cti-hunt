"""Audit N2 field availability on explicit OTRF development datasets, without labels/API.

Counts describe collection only, not detection quality. Never change the catalog or
infer an invalid field from a source with zero events. Output contains no event values.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import duckdb
import yaml

from cti_hunt import config
from cti_hunt.agent.dev_data import check_manifest
from cti_hunt.agent.session import check_dataset


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def quote_ident(name):
    return '"' + name.replace('"', '""') + '"'


def audit_fields(con, fields):
    """Read only the `events` view; count each field on its channel AND EID."""
    columns = {r[0].lower(): r[0] for r in con.execute('DESCRIBE events').fetchall()}
    if not {'ev_channel', 'ev_eid'} <= columns.keys():
        raise ValueError('Expected normalized events with ev_channel and ev_eid')
    if {'buoc', 'labeled', 'attack_labels'} & columns.keys():
        raise ValueError('Label columns are forbidden for N2 schema development')
    data_columns = sorted(c for c in columns.values() if not c.lower().startswith('ev_'))
    aggregates = ''.join(
        f", count(NULLIF(trim(CAST({quote_ident(c)} AS VARCHAR)), ''))"
        for c in data_columns)
    counts = {}
    channel_counts = Counter()
    for row in con.execute('SELECT lower(ev_channel), ev_eid, count(*)' + aggregates
                           + ' FROM events GROUP BY lower(ev_channel), ev_eid').fetchall():
        ch, eid, n, *filled = row
        counts[ch, eid] = (int(n), dict(zip(data_columns, map(int, filled))))
        channel_counts[ch] += int(n)
    result = []
    for channel, schemas in sorted(fields.items()):
        for eid, schema in sorted(schemas.items()):
            if type(eid) is not int or not 0 <= eid <= 65535:
                raise ValueError('Event ID must be an integer in 0..65535')
            keys, required = schema['key_fields'], schema['truong_bat_buoc']
            if (not keys or not required or
                    not {f.lower() for f in required} <= {f.lower() for f in keys}):
                raise ValueError('Required fields must be nonempty and belong to key_fields')
            n, filled = counts.get((channel.lower(), eid), (0, {}))
            per_field = {f: filled.get(columns.get(f.lower()), 0) for f in keys}
            missing = [f for f in keys if f.lower() not in columns] if n else []
            empty = [f for f in keys if f.lower() in columns and not per_field[f]] if n else []
            lost = [f for f in required if not per_field[f]] if n else []
            result.append({
                'channel': channel.lower(), 'event_id': eid, 'events': n,
                'observation': 'observed' if n else (
                    'no_events' if channel_counts[channel.lower()] else 'channel_absent'),
                'field_counts': per_field if n else None,
                'missing_columns': missing, 'empty_fields': empty, 'missing_required': lost,
                'observed_fields': {f: v for f, v in filled.items() if v},
            })
    return {'events': sum(channel_counts.values()), 'sources': result}


def checked_dataset(directory, root):
    directory, root = Path(directory).resolve(), Path(root).resolve()
    if not directory.is_relative_to(root / 'data/dev'):
        raise ValueError('Only explicit datasets inside data/dev are allowed')
    for name in ('ingest_manifest.json', 'events.parquet'):
        if not (directory / name).resolve().is_relative_to(directory):
            raise ValueError('Dataset files must stay inside their development directory')
    manifest_path = directory / 'ingest_manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if not manifest.get('dataset_id') or not manifest.get('source_sha256'):
        raise ValueError('Development manifest must identify the dataset and its source hash')
    evaluation = config.load('dataset', root)['raw']
    eval_hash = str(evaluation['sha256']).lower()
    source_hashes = {str(manifest['source_sha256']).lower()}
    source_hashes.update(str(m.get('sha256', '')).lower() for m in manifest.get('members', []))
    if eval_hash in source_hashes:
        raise ValueError('E1: evaluation source hash in development manifest')
    check_dataset(directory, root)
    check_manifest(directory, manifest.get('dataset_id'), manifest.get('source_sha256'), root)
    return directory, manifest


def run_audit(root, field_path, directories):
    root, field_path = Path(root).resolve(), Path(field_path).resolve()
    if not directories:
        raise ValueError('At least one explicit development dataset is required')
    datasets = [checked_dataset(d, root) for d in directories]
    if len({d for d, _ in datasets}) != len(datasets):
        raise ValueError('Duplicate development dataset')
    if len({m['dataset_id'] for _, m in datasets}) != len(datasets):
        raise ValueError('Duplicate dataset ID')
    files = {field_path, Path(__file__).resolve(), root / 'configs/dataset.yaml'}
    for directory, _ in datasets:
        files.update(directory / name for name in ('ingest_manifest.json', 'events.parquet'))
    hashes = {str(p): sha256(p) for p in sorted(files)}
    fields = yaml.safe_load(field_path.read_text(encoding='utf-8'))
    eval_hosts = {str(h).upper() for h in config.load('dataset', root)['raw']['hosts']}
    results = []
    for directory, manifest in sorted(datasets):
        with duckdb.connect() as con:
            con.from_parquet(str(directory / 'events.parquet')).create_view('events')
            hosts = {str(r[0]).upper() for r in con.execute('SELECT DISTINCT ev_host FROM events').fetchall()}
            if hosts & eval_hosts:
                raise ValueError('E1: observed hosts overlap the evaluation dataset')
            result = audit_fields(con, fields)
            if result['events'] != manifest['rows']:
                raise ValueError('Dataset event count differs from ingest manifest')
        results.append({'dataset_id': manifest['dataset_id'], 'directory': str(directory), **result})
    if any(sha256(p) != digest for p, digest in hashes.items()):
        raise ValueError('Input changed during audit; rerun on stable inputs')
    observed = [s for d in results for s in d['sources'] if s['observation'] == 'observed']
    bad = [s for s in observed if s['missing_columns'] or s['empty_fields']]
    return {'version': 'n2_schema_audit_v1', 'duckdb_version': duckdb.__version__,
            'inputs_sha256': hashes, 'datasets': results,
            'summary': {'datasets': len(results), 'events': sum(d['events'] for d in results),
                        'observed_dataset_source_pairs': len(observed),
                        'dataset_source_pairs_with_field_gaps': len(bad),
                        'unique_sources_with_field_gaps': len({(s['channel'], s['event_id']) for s in bad}),
                        'dataset_source_pairs_missing_required': sum(bool(s['missing_required']) for s in observed)},
            'limitations': ['Counts measure field availability, not detection accuracy.',
                            'Zero events means unverified schema, not a missing field.',
                            'No automatic schema selection or catalog promotion.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=config.ROOT)
    parser.add_argument('--fields', type=Path, required=True)
    parser.add_argument('--events', type=Path, action='append', required=True,
                        help='Explicit OTRF development directory; repeat for each dataset')
    parser.add_argument('--output', type=Path, required=True, help='New JSON path inside data/dev')
    args = parser.parse_args(argv)
    output, root = args.output.resolve(), args.root.resolve()
    protected = {args.fields.resolve(), Path(__file__).resolve(), root / 'configs/dataset.yaml'}
    protected.update((d / name).resolve() for d in args.events
                     for name in ('ingest_manifest.json', 'events.parquet'))
    if not output.is_relative_to(root / 'data/dev') or output.suffix.lower() != '.json':
        parser.error('Output must be a new JSON file inside data/dev')
    if output.exists() or output in protected:
        parser.error('Output exists or overlaps an input; choose a new audit path')
    result = run_audit(root, args.fields, args.events)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'output': str(output), **result['summary']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
