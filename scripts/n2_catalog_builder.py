"""Pure N2 builder: no API, labels, dataset access or writes."""
import copy
import re
import json
from collections import Counter, defaultdict


def active(obj):
    return not (obj.get('revoked') or obj.get('x_mitre_deprecated'))


def external_id(obj):
    return next((r['external_id'] for r in obj.get('external_references', [])
                 if r.get('source_name') == 'mitre-attack' and r.get('external_id')), None)


def event_ids(text):
    """Explicit lists only; don't silently interpret one end of an EID range."""
    result = set()
    for m in re.finditer(r'\b(?:EventCode|Event\s+ID)\s*(?:=\s*)?(\d+(?:\s*,\s*\d+)*)', text, re.I):
        if re.match(r'\s*[-–/]\s*\d', text[m.end():]):
            continue
        result.update(int(n) for n in re.findall(r'\d+', m.group(1)))
    return sorted(result)


def mapped_pairs(name, eids, mapping):
    mapped = mapping.get(name)
    if not mapped and name.startswith('WinEventLog:Microsoft-Windows-'):
        mapped = name.removeprefix('WinEventLog:').lower()
    if isinstance(mapped, str):
        return {(mapped.lower(), eid) for eid in eids}
    pairs = set()
    for item in mapped or []:
        ranges, channel = item.split(': ', 1)
        allowed = set()
        for span in ranges.split(','):
            bounds = [int(n.strip()) for n in span.split('-')]
            if len(bounds) == 1:
                allowed.add(bounds[0])
            elif len(bounds) == 2 and 0 <= bounds[0] <= bounds[1] <= 65535:
                allowed.update(range(bounds[0], bounds[1] + 1))
            else:
                raise ValueError(f'Invalid EID mapping: {item}')
        pairs.update((channel.lower(), eid) for eid in set(eids) & allowed)
    return pairs


def supported(channel, eid, logsources):
    # Stage 5 semantics: an empty EID list covers the whole channel.
    return any(s['channel'].lower() == channel and
               (not s.get('event_ids') or eid in s['event_ids'])
               for sources in logsources.values() for s in sources)


def generate_catalog(stix, mapping, fields, logsources, baseline):
    objects = {o['id']: o for o in stix['objects']}
    techniques = {o['id']: o for o in objects.values()
                  if o['type'] == 'attack-pattern' and active(o)
                  and 'Windows' in o.get('x_mitre_platforms', []) and external_id(o)}
    chains = defaultdict(list)
    for rel in objects.values():
        if rel['type'] != 'relationship' or rel.get('relationship_type') != 'detects' or not active(rel):
            continue
        ds = objects.get(rel['source_ref'], {})
        if rel['target_ref'] not in techniques or ds.get('type') != 'x-mitre-detection-strategy' or not active(ds):
            continue
        for ref in ds.get('x_mitre_analytic_refs', []):
            analytic = objects.get(ref, {})
            if (analytic.get('type') == 'x-mitre-analytic' and active(analytic)
                    and 'Windows' in analytic.get('x_mitre_platforms', [])):
                chains[rel['target_ref']].append((rel, ds, analytic))

    entries, audit = {}, {}
    for obj_id, tech in sorted(techniques.items(), key=lambda pair: external_id(pair[1])):
        tid = external_id(tech)
        sources, provenance, gaps, strategies = {}, [], [], set()
        for rel, ds, analytic in chains[obj_id]:
            strategies.add(external_id(ds) or ds['id'])
            for src in analytic.get('x_mitre_log_source_references', []):
                name, description = src.get('name', ''), src.get('channel', '')
                context = {'relationship': rel['id'], 'strategy': ds['id'],
                           'analytic': analytic['id'], 'name': name, 'channel_text': description}
                eids = event_ids(description)
                pairs = mapped_pairs(name, eids, mapping)
                if not pairs:
                    gaps.append({**context, 'reason': 'unmapped_source_or_event_ids'})
                unmatched = set(eids) - {eid for _, eid in pairs}
                if pairs and unmatched:
                    gaps.append({**context, 'reason': 'unmapped_event_ids', 'event_ids': sorted(unmatched)})
                for channel, eid in sorted(pairs):
                    detail = {**context, 'channel': channel, 'event_id': eid}
                    schema = fields.get(channel, {}).get(eid, {})
                    keys, required = schema.get('key_fields', []), schema.get('truong_bat_buoc', [])
                    if not supported(channel, eid, logsources):
                        gaps.append({**detail, 'reason': 'unsupported_stage5_pair'})
                    elif not keys or not required or not {f.lower() for f in required} <= {f.lower() for f in keys}:
                        gaps.append({**detail, 'reason': 'missing_or_invalid_schema'})
                    else:
                        sources[channel, eid] = {'channel': channel, 'event_ids': [eid],
                                                'key_fields': copy.deepcopy(keys),
                                                'truong_bat_buoc': copy.deepcopy(required)}
                        provenance.append(detail)
        entry = {'status': 'partial' if sources else 'not_huntable',
                 'sources': [sources[key] for key in sorted(sources)]}
        if sources:
            entry['ly_do_partial'] = 'Sinh tự động từ ATT&CK (chưa đối chiếu rule phát hiện cụ thể).'
        # Raw source text stays in audit, outside the prompt-facing catalog.
        entry['ghi_chu'] = ('Chiến lược phát hiện ATT&CK: ' + ', '.join(sorted(strategies))) if strategies else 'Chưa có analytic Windows còn hiệu lực được ánh xạ.'
        if gaps:
            entry['ghi_chu'] += ' Có nguồn chưa ánh xạ, chưa có lược đồ trường hoặc chưa được khâu ⑤ hỗ trợ; xem audit N2.'
        if not sources:
            entry['ghi_chu'] += ' Không có nguồn log đủ điều kiện cho khâu ⑤.'
        entries[tid] = entry
        audit[tid] = {'technique_stix_id': obj_id, 'provenance': provenance, 'gaps': gaps,
                      'generated': copy.deepcopy(entry), 'overridden': False}

    for tid, entry in baseline.get('techniques', {}).items():
        if tid not in entries:
            # Reviewed baseline includes SSH, intentionally marked not_huntable.
            obj = next((o for o in objects.values() if o['type'] == 'attack-pattern'
                        and active(o) and external_id(o) == tid), None)
            if obj is None or entry.get('status') != 'not_huntable' or entry.get('sources'):
                raise ValueError(f'Baseline {tid} outside Windows must be active and not_huntable without sources')
            audit[tid] = {'technique_stix_id': obj['id'], 'provenance': [], 'gaps': [],
                          'generated': None, 'baseline_outside_windows': True}
        entries[tid] = copy.deepcopy(entry)
        audit[tid]['overridden'] = True
        # Preserve reviewed baseline exactly; report rather than hide its gaps.
        audit[tid]['baseline_unsupported_pairs'] = [
            {'channel': src['channel'], 'event_id': eid}
            for src in entry.get('sources', []) for eid in src['event_ids']
            if not supported(src['channel'].lower(), eid, logsources)]
    for row in audit.values():
        for key in ('provenance', 'gaps'):
            row[key] = sorted(row[key], key=lambda item: json.dumps(item, sort_keys=True))
    return {'phien_ban': '1.2', 'techniques': dict(sorted(entries.items()))}, {
        'status_counts': dict(sorted(Counter(e['status'] for e in entries.values()).items())),
        'techniques': audit}
