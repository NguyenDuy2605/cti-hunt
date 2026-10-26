"""N2: nâng partial -> huntable chỉ khi có rule SigmaHQ đạt đủ tiêu chí.

Thay bước nâng hạng cũ (một rule gắn tag biên dịch được là đủ, ghi đè candidate). Một kỹ thuật sinh
tự động (không thuộc 18 mục baseline) chỉ được nâng khi có ít nhất một rule SigmaHQ thỏa MỌI điều kiện:

1. status `stable` hoặc `test` (cùng mức G0(c));
2. tag ATT&CK trùng đúng mã kỹ thuật; mã thu hồi đổi sang mã hiện hành theo v19.2; không suy cha/con;
3. không có mục keyword thiếu tên trường;
4. adapter DuckDB biên dịch được trên danh mục ⑤, và nguồn biên dịch trùng channel + ít nhất một EID
   với một nguồn của chính kỹ thuật đó trong candidate (thiết kế N2 §3.5);
5. mọi trường rule dùng (sau field_map) có giá trị khác rỗng trên đúng channel + EID đó, trong cùng
   một bộ OTRF phát triển;
6. SQL của selection và từng filter bind được trên bộ đó bằng LIMIT 0 — không đọc số kết quả khớp.

Không đọc nhãn, không đọc APT29 (E1). Bằng chứng chỉ nằm trong audit; `ghi_chu` giữ nguyên vì đi vào
prompt ④. Output luôn là tệp mới; candidate đầu vào phải khớp hash ghi trong audit của nó.
"""
from __future__ import annotations

import argparse
import copy
from collections import Counter, defaultdict
import hashlib
import importlib.metadata
import json
from pathlib import Path
import runpy
import subprocess

import duckdb
import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetectionItem

from cti_hunt import config
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.attack.catalog import AttackCatalog

VERSION = 'n2_sigma_evidence_v1'
ALLOWED_STATUS = ('stable', 'test')
REASON_PARTIAL = ('ATT&CK nêu nguồn log nhưng chưa có rule SigmaHQ stable/test gắn đúng kỹ thuật này '
                  'trên cùng nguồn, với mọi trường của rule đã kiểm có giá trị.')
CRITERIA = [
    'Rule SigmaHQ status stable hoặc test.',
    'Tag ATT&CK trùng đúng mã (mã thu hồi đổi sang mã hiện hành v19.2; không suy cha/con).',
    'Không có mục keyword thiếu tên trường.',
    'Adapter DuckDB biên dịch được; nguồn biên dịch trùng channel + ít nhất một EID với nguồn của kỹ thuật.',
    'Mọi trường rule dùng (sau field_map) có giá trị khác rỗng trên channel + EID đó trong cùng một bộ OTRF.',
    'SQL selection và filter bind được trên bộ đó (LIMIT 0, không đọc số kết quả khớp).',
]
LIMITATIONS = [
    'Rule có sẵn và trường có giá trị là bằng chứng nguồn quan sát được kỹ thuật, không phải độ chính xác phát hiện.',
    'Nguồn chưa có sự kiện trên OTRF phát triển thì chưa kiểm được trường nên không nâng.',
    'LIMIT 0 chỉ kiểm bind/plan; lỗi chỉ xuất hiện khi thực thi (vd regex) chưa được bắt.',
    'SigmaHQ là bản clone cục bộ cố định; rule mới hơn chưa được xét.',
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _items(detection):
    stack = list(detection.detection_items)
    while stack:
        item = stack.pop()
        if isinstance(item, SigmaDetectionItem):
            yield item
        else:
            stack.extend(item.detection_items)


def rule_facts(rule) -> dict:
    """EID lấy từ các detection không phải filter; keyword = mục không có tên trường."""
    keyword, eids = False, set()
    for name, det in rule.detection.detections.items():
        for item in _items(det):
            if not item.field:
                keyword = True
            elif item.field.lower() == 'eventid' and not name.lower().startswith('filter'):
                for v in item.value:
                    text = str(getattr(v, 'number', v))
                    if text.isdigit():
                        eids.add(int(text))
    return {'status': rule.status.name.lower() if rule.status else '', 'keyword': keyword,
            'event_ids': eids, 'fields': duckdb_sigma.rule_fields(rule),
            'techniques': duckdb_sigma.attack_techniques(rule),
            'logsource': duckdb_sigma._logsource_key(rule)}


def field_counts(con) -> dict[tuple[str, int], dict[str, int]]:
    """(channel, EID) -> {cột chữ thường: số giá trị khác rỗng}; chỉ giữ cột có giá trị. Không xuất giá trị."""
    cols = [r[0] for r in con.execute('DESCRIBE events').fetchall()]
    if {'buoc', 'labeled', 'attack_labels'} & {c.lower() for c in cols}:
        raise ValueError('Cột nhãn bị cấm ở N2')
    data = [c for c in cols if not c.lower().startswith('ev_')]
    agg = ''.join(f", count(NULLIF(trim(CAST({_q(c)} AS VARCHAR)), ''))" for c in data)
    out = {}
    for ch, eid, *filled in con.execute(f'SELECT lower(ev_channel), ev_eid{agg} FROM events '
                                        'WHERE ev_eid IS NOT NULL GROUP BY 1, 2').fetchall():
        out[ch, int(eid)] = {c.lower(): int(n) for c, n in zip(data, filled) if n}
    return out


def _sql_ok(con, pair: tuple[str, int], hunt) -> bool:
    base = f'SELECT 1 FROM events WHERE ev_channel = ? AND ev_eid = {int(pair[1])}'
    try:
        for where in [hunt.candidates, *(f['where'] for f in hunt.filters)]:
            con.execute(f'{base} AND ({where}) LIMIT 0', [pair[0]]).fetchall()
    except duckdb.Error:
        return False
    return True


def _verify(fields: list[str], pairs: set, hunt, datasets) -> tuple[dict | None, str]:
    seen, sql_error = False, False
    for ds_id, con, counts in datasets:
        for pair in sorted(pairs):
            filled = counts.get(pair)
            if filled is None:
                continue
            seen = True
            if all(filled.get(f.lower(), 0) for f in fields):
                if _sql_ok(con, pair, hunt):
                    return {'dataset_id': ds_id, 'channel': pair[0], 'event_id': pair[1]}, ''
                sql_error = True
    return None, ('sql_loi' if sql_error else 'truong_rong_hoac_thieu' if seen else 'nguon_chua_co_su_kien_otrf')


def evaluate(base: dict, baseline_ids: set[str], rules: list[tuple[str, str]], logsources: dict,
             datasets: list[tuple[str, object]], resolve) -> tuple[dict, dict]:
    """rules: [(đường dẫn tương đối, nội dung)]; datasets: [(mã bộ, kết nối có view events)];
    resolve: mã tag -> mã hiện hành hoặc None. Trả (candidate mới, audit)."""
    techniques = base['techniques']
    targets = {t for t, e in techniques.items() if e['status'] == 'partial' and t not in baseline_ids}
    counted = [(ds_id, con, field_counts(con)) for ds_id, con in datasets]
    evidence, rejected, excluded, tagged = defaultdict(list), defaultdict(Counter), Counter(), set()
    for rel, text in rules:
        try:
            parsed = SigmaCollection.from_yaml(text).rules
        except Exception:
            excluded['loi_phan_tich'] += 1
            continue
        if len(parsed) != 1:
            excluded['khong_dung_mot_rule_trong_tep'] += 1
            continue
        rule = parsed[0]
        facts = rule_facts(rule)
        hits = {r for r in map(resolve, facts['techniques']) if r} & targets
        if not hits:
            excluded['khong_gan_ky_thuat_dang_xet'] += 1
            continue
        tagged |= hits
        info = {'rule': rel, 'rule_sha256': sha256_bytes(text.encode('utf-8')), 'rule_id': str(rule.id or ''),
                'title': rule.title, 'status': facts['status'], 'logsource': facts['logsource']}

        def reject(reason):
            for t in hits:
                rejected[t][reason] += 1
        if facts['status'] not in ALLOWED_STATUS:
            reject('status_' + (facts['status'] or 'trong'))
            continue
        if facts['keyword']:
            reject('keyword_khong_ten_truong')
            continue
        try:
            hunts, _ = duckdb_sigma.compile_text(text, logsources)
        except Exception:
            reject('adapter_khong_bien_dich')
            continue
        if not hunts:
            reject('logsource_khong_dung_duoc')
            continue
        sources = {s['name']: s for s in logsources.get(facts['logsource'] or '') or []}
        for t in sorted(hits):
            found, reasons = None, Counter()
            for hunt in hunts:
                ch, scope_ids = hunt.scope['channel'].lower(), set(hunt.scope['event_ids'])
                if scope_ids and facts['event_ids']:
                    eff = scope_ids & facts['event_ids']
                    if not eff:
                        reasons['eid_rule_ngoai_nguon_bien_dich'] += 1
                        continue
                else:
                    eff = scope_ids or facts['event_ids'] or None
                pairs = {(ch, int(e)) for s in techniques[t].get('sources') or [] if s['channel'].lower() == ch
                         for e in s['event_ids'] if eff is None or e in eff}
                if not pairs:
                    reasons['khac_nguon_danh_muc'] += 1
                    continue
                fmap = sources[hunt.source].get('field_map') or {}
                fields = sorted({fmap.get(f, f) for f in facts['fields']})
                match, reason = _verify(fields, pairs, hunt, counted)
                if match:
                    found = {**info, 'source': hunt.source, **match, 'fields': fields}
                    break
                reasons[reason] += 1
            if found:
                evidence[t].append(found)
            else:
                rejected[t].update(reasons)
    out = copy.deepcopy(base)
    for t in sorted(targets):
        entry = out['techniques'][t]
        if evidence[t]:
            entry['status'] = 'huntable'
            entry.pop('ly_do_partial', None)
        else:
            entry['ly_do_partial'] = REASON_PARTIAL
    audit = {
        'version': VERSION, 'criteria': CRITERIA, 'limitations': LIMITATIONS,
        'status_counts': dict(sorted(Counter(e['status'] for e in out['techniques'].values()).items())),
        'targets': len(targets),
        'promoted': {t: evidence[t] for t in sorted(targets) if evidence[t]},
        'not_promoted': {t: dict(sorted(rejected[t].items())) for t in sorted(targets)
                         if not evidence[t] and t in tagged},
        'no_tagged_rule': sorted(targets - tagged),
        'rule_exclusions': dict(sorted(excluded.items())),
        'rules_scanned': len(rules),
    }
    return out, audit


def check_base(base_path: Path) -> tuple[dict, dict]:
    """Candidate đầu vào phải còn đúng hash trong audit của nó (chặn trường hợp bị ghi đè sau khi sinh)."""
    audit_path = base_path.with_suffix('.audit.json')
    audit = json.loads(audit_path.read_text(encoding='utf-8'))
    if sha256(base_path) != audit.get('catalog_sha256'):
        raise ValueError(f'{base_path} không khớp catalog_sha256 trong {audit_path.name}: có thể đã bị ghi đè')
    return yaml.safe_load(base_path.read_text(encoding='utf-8')), audit


def check_output(output: Path, root: Path, inputs: set[Path]) -> tuple[Path, Path]:
    output = output.resolve()
    audit_path = output.with_suffix('.audit.json')
    if not output.is_relative_to(root / 'data/dev') or output.suffix.lower() not in ('.yaml', '.yml'):
        raise ValueError('Output phải là tệp YAML mới trong data/dev')
    if output.exists() or audit_path.exists() or output in inputs or audit_path in inputs:
        raise ValueError('Output đã tồn tại hoặc trùng đầu vào; chọn đường dẫn mới')
    return output, audit_path


def _rules_tree(rules_dir: Path) -> tuple[list[tuple[str, str]], str, str]:
    rules = [(p.relative_to(rules_dir).as_posix(), p.read_text(encoding='utf-8'))
             for p in sorted(rules_dir.rglob('*.yml'))]
    tree = sha256_bytes(''.join(f'{rel}\t{sha256_bytes(t.encode("utf-8"))}\n' for rel, t in rules).encode('utf-8'))
    try:
        commit = subprocess.run(['git', '-C', str(rules_dir), 'rev-parse', 'HEAD'], capture_output=True,
                                text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = ''
    return rules, tree, commit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=config.ROOT)
    parser.add_argument('--base', type=Path, required=True, help='Candidate do generate_n2_catalog.py sinh (kèm .audit.json)')
    parser.add_argument('--rules', type=Path, default=Path('data/work/sigmahq/rules/windows'))
    parser.add_argument('--events', type=Path, action='append', required=True,
                        help='Thư mục OTRF phát triển; lặp lại cho từng bộ')
    parser.add_argument('--output', type=Path, required=True, help='Candidate YAML mới trong data/dev')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    base_path = (root / args.base).resolve() if not args.base.is_absolute() else args.base.resolve()
    rules_dir = (root / args.rules).resolve() if not args.rules.is_absolute() else args.rules.resolve()
    reports = config.load('reports', root)['attack']
    files = {'base': base_path, 'base_audit': base_path.with_suffix('.audit.json'),
             'logsources': root / 'configs/logsource_catalog.yaml',
             'baseline': root / 'configs/telemetry_baseline.yaml',
             'stix': config.resolve(reports['stix_path'], root), 'script': Path(__file__).resolve(),
             'adapter': Path(duckdb_sigma.__file__).resolve()}
    checked_dataset = runpy.run_path(str(root / 'scripts/audit_n2_schema.py'))['checked_dataset']
    datasets = [checked_dataset(d if d.is_absolute() else root / d, root) for d in args.events]
    if len({m['dataset_id'] for _, m in datasets}) != len(datasets):
        parser.error('Trùng bộ OTRF')
    for directory, m in datasets:
        files[f"{m['dataset_id']}/manifest"] = directory / 'ingest_manifest.json'
        files[f"{m['dataset_id']}/events"] = directory / 'events.parquet'
    output, audit_path = check_output(args.output if args.output.is_absolute() else root / args.output, root,
                                      {p.resolve() for p in files.values()})
    hashes = {k: sha256(p) for k, p in files.items()}
    if str(reports['version']) != '19.2' or hashes['stix'] != str(reports['stix_sha256']).lower():
        raise ValueError('ATT&CK không đúng bản v19.2 đã ghim')
    base, base_audit = check_base(base_path)
    baseline = yaml.safe_load(files['baseline'].read_text(encoding='utf-8'))['techniques']
    logsources = duckdb_sigma.load_catalog(files['logsources'])
    attack = AttackCatalog.from_stix(files['stix'])

    def resolve(tid):
        r = attack.resolve(tid)
        return r.final if r.status in ('ok', 'revoked') else None
    rules, tree, commit = _rules_tree(rules_dir)
    eval_hosts = {str(h).upper() for h in config.load('dataset', root)['raw']['hosts']}
    cons = []
    try:
        for directory, m in sorted(datasets, key=lambda x: x[1]['dataset_id']):
            con = duckdb.connect()
            cons.append(con)
            con.from_parquet(str(directory / 'events.parquet')).create_view('events')
            hosts = {str(r[0]).upper() for r in con.execute('SELECT DISTINCT ev_host FROM events').fetchall()}
            if hosts & eval_hosts:
                raise ValueError('E1: máy trùng tập đánh giá')
            if con.execute('SELECT count(*) FROM events').fetchone()[0] != m['rows']:
                raise ValueError(f"{m['dataset_id']}: số dòng khác manifest")
        catalog, audit = evaluate(base, set(baseline), rules, logsources,
                                  list(zip(sorted(m['dataset_id'] for _, m in datasets), cons)), resolve)
    finally:
        for con in cons:
            con.close()
    if any(sha256(p) != hashes[k] for k, p in files.items()):
        raise ValueError('Đầu vào đổi trong lúc chạy; chạy lại trên đầu vào ổn định')
    text = yaml.safe_dump(catalog, allow_unicode=True, sort_keys=False)
    audit.update({'catalog_sha256': sha256_bytes(text.encode('utf-8')),
                  'base_status_counts': base_audit.get('status_counts'),
                  'inputs': {k: {'path': str(files[k]), 'sha256': v} for k, v in hashes.items()},
                  'sigmahq': {'rules_dir': str(rules_dir), 'git_commit': commit, 'tree_sha256': tree},
                  'pysigma_version': importlib.metadata.version('pysigma'), 'duckdb_version': duckdb.__version__})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as f:
        f.write(text)
    with audit_path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(audit, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'output': str(output), 'status_counts': audit['status_counts'],
                      'promoted': len(audit['promoted']), 'targets': audit['targets'],
                      'no_tagged_rule': len(audit['no_tagged_rule'])}, ensure_ascii=False))


if __name__ == '__main__':
    main()
