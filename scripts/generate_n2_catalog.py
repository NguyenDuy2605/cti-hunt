"""Generate a NEW N2 candidate and audit; never overwrite an existing catalog."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml
from n2_catalog_builder import generate_catalog


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True, help='New candidate YAML path')
    args = parser.parse_args(argv)
    root, output = args.root.resolve(), args.output.resolve()
    audit_path = output.with_suffix('.audit.json')
    if output.suffix.lower() not in ('.yaml', '.yml'):
        parser.error('Output must be a YAML file')
    paths = {'mapping': root / 'configs/attack_nguon_log.yaml',
             'fields': root / 'configs/truong_theo_su_kien.yaml',
             'logsources': root / 'configs/logsource_catalog.yaml',
             'baseline': root / 'configs/telemetry_baseline.yaml',
             'reports': root / 'configs/reports.yaml'}
    reports = yaml.safe_load(paths['reports'].read_text(encoding='utf-8'))['attack']
    paths['stix'] = root / reports['stix_path']
    paths['generator'] = Path(__file__).resolve()
    paths['builder'] = Path(__file__).with_name('n2_catalog_builder.py').resolve()
    if output.exists() or audit_path.exists() or output in paths.values() or audit_path in paths.values():
        parser.error('Output already exists or overlaps an input; choose a new candidate path')
    hashes = {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in paths.items()}
    if reports['version'] != '19.2' or hashes['stix'] != reports['stix_sha256'].lower():
        raise ValueError('ATT&CK version/hash does not match pinned v19.2')
    docs = {key: yaml.safe_load(paths[key].read_text(encoding='utf-8'))
            for key in ('mapping', 'fields', 'logsources', 'baseline')}
    catalog, audit = generate_catalog(json.loads(paths['stix'].read_text(encoding='utf-8')), **docs)
    audit['inputs'] = {key: {'path': str(paths[key]), 'sha256': value} for key, value in hashes.items()}
    text = yaml.safe_dump(catalog, allow_unicode=True, sort_keys=False)
    audit['catalog_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as f:
        f.write(text)
    with audit_path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(audit, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'output': str(output), 'audit': str(audit_path),
                      'techniques': len(catalog['techniques']), 'status_counts': audit['status_counts']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
