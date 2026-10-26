"""⑤ v5 on the two ④ v6 hypotheses người vận hành reviews at ◆ (count distinct IPs, absent DNS), 07/10.

Default is offline, 0 API: create the empty ◆ form from the sent ④ trial, then, after người vận hành applies his decisions with
`python -m cti_hunt approve`, pin the requests. Only the operator opts into `--send --cap-usd 0.40` (cumulative package cap).
Production ⑤: prompt v5, at most `max_repair_attempts` static repairs. Rules run only on self-authored synthetic
events with expected record IDs; never real logs, labels, applied filters, planner, pivot or a hunt record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from importlib.metadata import version
from pathlib import Path

import duckdb

from .. import approval, config, integrity
from ..adapters import duckdb_sigma as adapter
from ..contracts import ContractB
from ..hunt import runner
from ..llm import budget, providers
from ..llm.prompting import load_sections
from ..stages import s5_rule as S5
from .emotet_trial import command_lock, ledger_view

PROBE_ID = 'khau5-v5-dem-vang-0710'
PROPOSED_CAP = '0.40'
SOURCE_REL = 'tmp/thu_khau4_v6_dem_vang_7-10'
# The ④ v6 trial người vận hành sent once on 07/10; its files are read, never rewritten.
SOURCE_SHA256 = {'hypotheses_pending.json': '2320c483bd43bbdeb2db2e14fc5a5453730182e29a3e62f4948cd2564b2c4441',
                 'result.json': '0f5def03a1cec3dac365bcbe09f697f295e6844160946bfaf705a5c551a9eee3',
                 'attempt.json': '30e03afc4559f6618c3b84293d4c40559d025a01fefdd09d8bd9b78a1377807a'}
OUT_REL = 'tmp/thu_khau5_v5_dem_vang_7-10'
ROUND = 'round_01'
PROTECTED = {'chuan_bi_khau4_v6_dem_vang_6-10', 'chuan_bi_rang_buoc_4_5_6-10', 'chuan_bi_loi_emotet_6-10',
             'thu_khau4_v5_6-10', 'thu_khau4_v6_dem_vang_7-10', 'thu_khau5_v4_h05_6-10', 'thu_loi_emotet_6-10',
             'thu_loi_emotet_6-10_prepared_before_payload_fix'}
SYS = 'microsoft-windows-sysmon/operational'
# Source span of each self-authored case -> synthetic event set (same vectors as tests/test_source_fidelity_flow).
CASES = {'SELF-MULTIEVENT-01-001': 'dem_khac_nhau', 'SELF-MULTIEVENT-02-001': 'vang_mat'}
FIELDS = ['Hostname', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'Initiated',
          'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'DestinationIsIpv6', 'DestinationIp',
          'DestinationHostname', 'DestinationPort', 'QueryName', 'QueryStatus', 'QueryResults', 'RuleName', 'EventID']


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def dump(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')


def write(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.writing')
    tmp.write_bytes(dump(value))
    tmp.replace(path)


def fixture_rows(kind):
    """(rec, eid, seconds, guid, host, ip) rows and the expected kept primary records; no real event or label."""
    if kind == 'dem_khac_nhau':
        rows = [(1, 3, -45, 'g1', 'HOST-A', '10.0.0.1'), (2, 3, 0, 'g1', 'HOST-A', '10.0.0.1'),
                (3, 3, 45, 'g1', 'HOST-A', '10.0.0.2'), (4, 3, 0, 'g2', 'HOST-A', '10.0.0.1'),
                (5, 3, 46, 'g2', 'HOST-A', '10.0.0.2'), (6, 3, 45, 'g2', 'HOST-B', '10.0.0.2'),
                (7, 3, 0, 'g3', 'HOST-A', '10.0.0.1'), (8, 3, 1, 'g3', 'HOST-A', '10.0.0.1')]
        return rows, [2, 3]
    rows = [(rec, 3, 0, f'g{rec}' if rec != 8 else '', 'HOST-A', '10.0.0.1') for rec in range(1, 9)]
    rows += [(20, 22, -30, 'g2', 'HOST-A', None), (21, 22, 0, 'g3', 'HOST-A', None),
             (22, 22, -31, 'g4', 'HOST-A', None), (23, 22, 1, 'g5', 'HOST-A', None),
             (24, 22, -15, 'g6', 'HOST-B', None), (25, 22, -15, 'other-guid', 'HOST-A', None)]
    return rows, [1, 4, 5, 6, 7]


def fixture(kind):
    """Sysmon-like VARCHAR fields as in production events. Directions alternate and IPs are private on purpose:
    the source sentences restrict neither, so a rule adding such a condition loses primary events."""
    con = duckdb.connect()
    cols = ', '.join(f'"{f}" VARCHAR' for f in FIELDS)
    con.execute(f'CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, '
                f'ev_ts TIMESTAMP, {cols})')
    rows, expected = fixture_rows(kind)
    for rec, eid, sec, guid, host, ip in rows:
        ts = datetime(2020, 1, 1) + timedelta(seconds=sec)
        net = eid == 3
        values = {'Hostname': host.lower() + '.fixture.local', 'UtcTime': ts.isoformat(sep=' '), 'ProcessGuid': guid,
                  'ProcessId': '4242', 'Image': r'C:\Fixture\fixture.exe', 'User': r'FIXTURE\user',
                  'Protocol': 'tcp' if net else None, 'Initiated': ('true' if rec % 2 else 'false') if net else None,
                  'SourceIsIpv6': 'false' if net else None, 'SourceIp': '10.0.0.9' if net else None,
                  'SourceHostname': '' if net else None, 'SourcePort': '50000' if net else None,
                  'DestinationIsIpv6': 'false' if net else None, 'DestinationIp': ip,
                  'DestinationHostname': '' if net else None, 'DestinationPort': '8443' if net else None,
                  'QueryName': None if net else 'fixture.example', 'QueryStatus': None if net else '0',
                  'QueryResults': None if net else '', 'RuleName': '-', 'EventID': str(eid)}
        con.execute(f'INSERT INTO events VALUES (?, ?, ?, ?, ?{", ?" * len(FIELDS)})',
                    [host, SYS, eid, rec, ts, *(values[f] for f in FIELDS)])
    primary = sorted(r[0] for r in rows if r[1] == 3)
    return con, {'primary': primary, 'expected': expected}


def columns_of(con):
    return {r[0] for r in con.execute('DESCRIBE events').fetchall()}


def case_kind(h):
    kinds = {CASES.get(s.segment_id) for s in h.source_spans}
    kind = kinds.pop() if len(kinds) == 1 else None
    if kind is None or h.rang_buoc is None or getattr(h.rang_buoc, kind) is None:
        raise ValueError(f'{h.hypothesis_id} không thuộc đúng một ca tự soạn có ràng buộc tương ứng')
    return kind


def evaluate(results, approved):
    """Pre-registered checks on synthetic events; static validity is not semantic fidelity."""
    out, ok = {}, True
    for h in approved:
        kind, r = case_kind(h), results.get(h.hypothesis_id) or {}
        specs = r.get('hunt_specs') or []
        c = {'valid_rule': bool(r.get('hop_le')),
             'one_spec_on_primary_source': len(specs) == 1 and specs[0]['scope']['channel'] == SYS
             and specs[0]['scope']['event_ids'] == [3]}
        kept = before = None
        if c['one_spec_on_primary_source']:
            spec = specs[0]
            bound = (spec.get('rang_buoc') or {}).get('dieu_kien')
            c['constraint_bound_as_approved'] = bound == h.rang_buoc.model_dump(mode='json', exclude_none=True)
            con, want = fixture(kind)
            with con:
                where = runner._scope_where(spec['scope'])
                # Selection alone, then with the code-bound constraint; proposed filters are never applied here.
                before = sorted(x[0] for x in con.execute(
                    f"SELECT ev_rec FROM events WHERE {where} AND ({spec['rang_buoc']['candidates_goc']})").fetchall())
                kept = sorted(x[0] for x in con.execute(
                    f"SELECT ev_rec FROM events WHERE {where} AND ({spec['candidates']})").fetchall())
            c['selection_keeps_every_primary_event'] = before == want['primary']
            c['constrained_records_as_expected'] = kept == want['expected']
        else:
            c.update(constraint_bound_as_approved=False, selection_keeps_every_primary_event=False,
                     constrained_records_as_expected=False)
        ok &= all(c.values())
        out[h.hypothesis_id] = {'case': kind, 'checks': c, 'criteria_met': all(c.values()),
                                'selected_before_constraint': before, 'kept_after_constraint': kept,
                                'valid_first_attempt': bool(r.get('hop_le_lan_dau')), 'repairs': r.get('so_lan_sua'),
                                'proposed_filters': sum(len(s.get('filters') or []) for s in specs)}
    return {'hypotheses': out, 'criteria_met': bool(approved) and ok, 'filters_applied': False,
            'manual_review_required': True,
            'meaning': 'rule trên sự kiện tổng hợp tự soạn; không phải chất lượng săn trên log thật'}


def load_source(root):
    src = root / SOURCE_REL
    if any(not (src / n).is_file() or integrity.sha256_file(src / n) != h for n, h in SOURCE_SHA256.items()):
        raise ValueError('Đầu ra ④ v6 đã gửi thiếu hoặc đã đổi; chưa tạo phiếu/gửi')
    hyps = [ContractB.model_validate(x) for x in read(src / 'hypotheses_pending.json')]
    if [h.status for h in hyps] != ['pending_review'] * len(hyps) or sorted(map(case_kind, hyps)) != sorted(CASES.values()):
        raise ValueError('Đầu ra ④ không đúng hai giả thuyết pending của hai ca')
    return hyps


class CaptureRequest:
    def __init__(self, client):
        self.client, self.payload = client, None

    def complete_json(self, system, user, schema, log=None):
        if self.payload is not None:
            raise ValueError('Chỉ bắt lần sinh đầu')
        self.payload = self.client.build_payload(system, user, schema)
        return {'rule_yaml': '', 'note': 'Offline payload capture; no API'}


def _settings(root):
    cfg, lc = config.agent_config('v2', root), config.load('llm_hunt', root)
    if (cfg['prompt_khau5'] != 'prompts/khau5_sigma_v5.md' or int(cfg['max_repair_attempts']) != 2
            or cfg.get('dung_sua_khi_nguon_rong') is not True or lc.get('provider') != 'anthropic'
            or lc.get('model') != 'claude-sonnet-5' or lc.get('effort') != 'high'
            or lc.get('max_output_tokens') != 32000 or lc.get('request_timeout_giay') != 600
            or lc.get('base_url') not in ('', None, 'https://api.anthropic.com')):
        raise ValueError('Cấu hình/prompt khác phạm vi phép thử; chưa gửi')
    ledger = config.resolve(lc['budget_ledger'], root)
    if ledger.resolve() != (root / 'data/dev/api_budget.sqlite').resolve():
        raise ValueError('Phép thử phải dùng đúng sổ chung')
    return cfg, lc, ledger


def build(root, rd):
    """After người vận hành's applied ◆: pinned approved hypotheses, first ⑤ request each, self-check of the harness."""
    hyps = load_source(root)
    approval.verify_saved_review(rd)
    if [h.model_dump() for h in approval.load_hypotheses(rd / approval.HYP_FILE)] != [h.model_dump() for h in hyps]:
        raise ValueError('Phiếu ◆ không phát từ đúng đầu ra ④ đã gửi')
    approved = [h for h in approval.load_hypotheses(rd / approval.APPROVED_FILE) if h.status == 'approved']
    cfg, lc, ledger = _settings(root)
    client = providers.from_config({**lc, 'budget_ledger': str(ledger)})
    prompt = load_sections(root / cfg['prompt_khau5'], ('SYSTEM', 'USER', 'REPAIR'))
    catalog_path = config.resolve(config.load('dataset', root)['logsource_catalog'], root)
    catalog = adapter.load_catalog(catalog_path)
    payloads, self_check = {}, {}
    for h in approved:
        con, _ = fixture(case_kind(h))
        with con:
            capture = CaptureRequest(client)
            S5.generate_rule(h, capture, prompt, catalog, 0, columns_of(con), con,
                             filter_policy=cfg['filter_policy_id'])
            # Reference rule through the same production path proves the harness, not the model.
            mock = providers.MockClient(responses=[{'rule_yaml': REFERENCE_RULE, 'note': 'fixture reference'}])
            self_check[h.hypothesis_id] = S5.generate_rule(h, mock, prompt, catalog, 0, columns_of(con), con,
                                                           filter_policy=cfg['filter_policy_id'])
        if capture.payload is None:
            raise ValueError(f'{h.hypothesis_id}: ⑤ không dựng được yêu cầu (cổng ngữ nghĩa/logsource)')
        payloads[h.hypothesis_id] = capture.payload
    checked = evaluate(self_check, approved)
    if approved and not checked['criteria_met']:
        raise ValueError('Rule tham chiếu không cho đúng tập sự kiện kỳ vọng; bộ chấm sai, chưa gửi')
    watched = ['configs/agent_v2.yaml', 'configs/llm_hunt.yaml', 'configs/dataset.yaml', cfg['filter_policy'],
               cfg['prompt_khau5'], catalog_path.relative_to(root).as_posix(), 'scripts/probe_khau5_v5_dem_vang.py']
    watched += [p.relative_to(root).as_posix() for p in sorted((root / 'src/cti_hunt').rglob('*.py'))]
    review = {n: integrity.sha256_file(rd / n) for n in
              (approval.HYP_FILE, approval.REVIEW_FILE, approval.APPROVED_FILE, approval.LOG_FILE)}
    protocol = {'probe_id': PROBE_ID, 'proposed_cap_usd': PROPOSED_CAP, 'cap_kind': 'cumulative_ledger_delta',
                'api_authorization': 'pending_nguoi_van_hanh', 'source_trial': SOURCE_REL, 'source_sha256': SOURCE_SHA256,
                'review_sha256': review, 'approved': [h.hypothesis_id for h in approved],
                'model': client.describe(), 'rate_version': budget.RATE_VERSION,
                'max_repair_attempts': int(cfg['max_repair_attempts']), 'retries': 0,
                'payload_sha256': {k: hashlib.sha256(dump(v)).hexdigest() for k, v in payloads.items()},
                'fixture': {k: fixture_rows(k) for k in sorted(CASES.values())}, 'fixture_fields': FIELDS,
                'harness_self_check': checked, 'real_events_read': False, 'filters_applied': False,
                'packages': {n: version(n) for n in ('duckdb', 'pysigma', 'pysigma-backend-sqlite', 'pydantic')},
                'files_sha256': {p: integrity.sha256_file(root / p) for p in watched}}
    return {'cfg': cfg, 'client': client, 'prompt': prompt, 'catalog': catalog, 'approved': approved,
            'payloads': payloads, 'protocol': protocol}


REFERENCE_RULE = """title: Self-authored network connection selection
status: experimental
logsource: {product: windows, category: network_connection}
detection:
  selection:
    EventID: 3
  condition: selection
level: low
"""


def _redact(value, key):
    return json.loads(json.dumps(value).replace(key, '[REDACTED]')) if key else value


@contextmanager
def keep_replies(folder, index, key):
    """Save each HTTP reply on receipt, before ledger settlement or parsing can fail (shared transport unchanged)."""
    real = providers._post

    def post(url, payload, headers, **kwargs):
        data = real(url, payload, headers, **kwargs)
        kind = 'count' if url.endswith('/count_tokens') else 'reply'
        write(folder / f'call_{index:02d}_{kind}.json', _redact(data, key))
        return data
    providers._post = post
    try:
        yield
    finally:
        providers._post = real


class PackageClient:
    """One package-wide cap from the ledger delta since the attempt baseline (other spending counts too)."""

    def __init__(self, client, out, baseline, payloads):
        self.client, self.out, self.baseline, self.payloads = client, Path(out), baseline, payloads
        self.model_id, self.events, self.calls, self.current = client.model_id, [], 0, None
        self.first_seen = set()

    def remaining(self):
        now = ledger_view(self.client.budget_ledger)
        if any(now['rows'].get(k) != v for k, v in self.baseline['rows'].items()):
            raise budget.BudgetError('Sổ đã mất hoặc sửa dòng cũ; không thể kiểm trần gói')
        return now, budget.money(PROPOSED_CAP) - (now['known'] - self.baseline['known']) - now['held']

    def complete_json(self, system, user, schema, log=None):
        payload = self.client.build_payload(system, user, schema)
        pinned = self.payloads[self.current]
        if self.current not in self.first_seen:
            if payload != pinned:
                raise ValueError('Yêu cầu sinh đầu khác bản đã ghim')
            self.first_seen.add(self.current)
        elif {k: v for k, v in payload.items() if k != 'messages'} != {k: v for k, v in pinned.items() if k != 'messages'}:
            raise ValueError('Yêu cầu sửa đổi tham số mô hình/lược đồ')
        now, left = self.remaining()
        if now['pending']:
            raise budget.BudgetError('Có yêu cầu chưa rõ chi phí; giữ nguyên và đối soát Console')
        if left < budget.min_reserve(self.model_id, self.client.max_output_tokens):
            raise budget.BudgetExhausted(f'Không đủ dự phòng trong trần gói {PROPOSED_CAP} USD; chưa gửi')
        self.client.request_budget_usd = budget.usd(left)
        key = os.environ.get(self.client.api_key_env)
        if not key:
            raise providers.LLMError('Thiếu khóa API')
        index, self.calls = self.calls, self.calls + 1
        folder = self.out / 'api_calls'
        folder.mkdir(exist_ok=True)

        def record(event):
            item = {'call': index, 'hypothesis_id': self.current,
                    **{k: event[k] for k in providers.SAFE_EVENT_KEYS if k in event}}
            self.events.append(item)
            write(self.out / 'api_events.json', self.events)
            if log:
                log({k: event[k] for k in providers.SAFE_EVENT_KEYS if k in event})
        with keep_replies(folder, index, key):
            data = budget.guarded_request(self.client, payload, {'x-api-key': key, 'anthropic-version': '2023-06-01'},
                                          record)
        usage = data.get('usage') or {}
        record({'stop_reason': data.get('stop_reason'), 'input_tokens': usage.get('input_tokens'),
                'output_tokens': usage.get('output_tokens'), 'max_tokens': self.client.max_output_tokens})
        if data.get('stop_reason') == 'max_tokens':
            raise providers.BadOutputError('Output bị cắt; không gửi lại')
        return _redact(providers.read_response(data), key)


def _ledger_brief(path):
    try:
        s = ledger_view(path)
    except (OSError, sqlite3.Error, budget.BudgetError) as exc:
        return {'error_type': type(exc).__name__}
    return {'remaining_usd': budget.usd(s['limit'] - s['known'] - s['held']), 'pending': s['pending'],
            'known_cost_usd': budget.usd(s['known']), 'limit_usd': budget.usd(s['limit'])}


def _check_out(out, root):
    if out.parent != (root / 'tmp').resolve() or out.name in PROTECTED:
        raise ValueError('Đầu ra phải là thư mục mới ngay dưới tmp, ngoài các gói/phép thử cũ')
    if out.exists():
        names = {p.name for p in out.iterdir()} - {'command.lock'}
        if names and ROUND not in names:
            raise ValueError('Thư mục đầu ra có tệp không thuộc phép thử này; giữ nguyên, chưa gửi')


def run(out=None, *, root=config.ROOT, send=False, cap_usd=None):
    root = Path(root).resolve()
    out = Path(out or root / OUT_REL).resolve()
    _check_out(out, root)
    if send and (cap_usd is None or budget.money(cap_usd) != budget.money(PROPOSED_CAP)):
        raise ValueError('Chỉ người vận hành gửi sau khi chốt: cần trần gói --cap-usd 0.40')
    if not send and cap_usd is not None:
        raise ValueError('Chuẩn bị không nhận quyền chi tiền')
    if not out.exists():
        if send:
            raise ValueError('Chưa tạo phiếu/chuẩn bị ngoại tuyến; chưa gửi')
        out.mkdir()
    rd = out / ROUND
    with command_lock(out):
        if (out / 'attempt.json').exists():
            raise ValueError('Phép thử đã bắt đầu; không gửi lại/chuẩn bị đè')
        if not rd.exists():
            if send:
                raise ValueError('Chưa có phiếu ◆; chưa gửi')
            hyps = load_source(root)
            form = approval.write_review(hyps, rd)
            return {'state': 'awaiting_duy_review', 'form': str(form), 'api_calls': 0,
                    'next': f'người vận hành điền phiếu rồi chạy: python -m cti_hunt approve {rd}'}
        if not (rd / approval.LOG_FILE).exists():
            if send:
                raise ValueError('Phiếu ◆ chưa áp; chưa gửi')
            load_source(root)
            return {'state': 'awaiting_duy_review', 'form': str(rd / approval.REVIEW_FILE), 'api_calls': 0,
                    'next': f'người vận hành điền phiếu rồi chạy: python -m cti_hunt approve {rd}'}
        b = build(root, rd)
        client, protocol = b['client'], b['protocol']
        prepared = out / 'protocol.json'
        artifacts = {f'payload_{k}.json': v for k, v in b['payloads'].items()}
        if prepared.exists():
            if prepared.read_bytes() != dump(protocol) or any(
                    not (out / n).is_file() or (out / n).read_bytes() != dump(v) for n, v in artifacts.items()):
                raise ValueError('Mã/phiếu/cấu hình đã đổi so với bản chuẩn bị; không ghi đè hoặc gửi')
        elif send:
            raise ValueError('Chưa chuẩn bị ngoại tuyến sau phiếu ◆; chưa gửi')
        else:
            for name, value in artifacts.items():
                write(out / name, value)
            write(prepared, protocol)
        status = ledger_view(client.budget_ledger)
        minimum = budget.min_reserve(client.model_id, client.max_output_tokens)
        if not send:
            preflight = {'mode': 'OFFLINE_NO_API', 'probe_id': PROBE_ID, 'out': str(out),
                         'api_authorization': 'pending_nguoi_van_hanh', 'proposed_cap_usd': PROPOSED_CAP,
                         'approved': protocol['approved'], 'max_generation_calls': len(b['approved']) * 3,
                         'minimum_reservation_per_call_usd': budget.usd(minimum),
                         'ledger_remaining_usd': budget.usd(status['limit'] - status['known'] - status['held']),
                         'ledger_pending': status['pending'], 'harness_self_check': protocol['harness_self_check']['criteria_met']}
            write(out / 'preflight.json', preflight)
            return preflight
        if not b['approved']:
            raise ValueError('Không có giả thuyết approved; không có gì để gửi')
        if status['pending'] or status['limit'] - status['known'] - status['held'] < minimum:
            raise budget.BudgetError('Sổ chưa đối soát hoặc không đủ dự phòng; chưa gửi')
        if not os.environ.get(client.api_key_env):
            raise providers.LLMError('Thiếu khóa API; chưa gửi')
        baseline = {'known': status['known'], 'held': status['held'], 'rows': status['rows']}
        with (out / 'attempt.json').open('xb') as f:
            f.write(dump({'probe_id': PROBE_ID, 'state': 'attempt_started_no_retry', 'cap_usd': PROPOSED_CAP,
                          'protocol_sha256': integrity.sha256_file(prepared),
                          'ledger_baseline': {'known_usd': budget.usd(status['known']), 'requests': len(status['rows'])}}))
        observed = PackageClient(client, out, baseline, b['payloads'])
        results, failure = {}, None
        for h in b['approved']:
            observed.current = h.hypothesis_id
            con, _ = fixture(case_kind(h))
            try:
                with con:
                    results[h.hypothesis_id] = S5.generate_rule(
                        h, observed, b['prompt'], b['catalog'], int(b['cfg']['max_repair_attempts']),
                        columns_of(con), con, out / 'khau5', filter_policy=b['cfg']['filter_policy_id'],
                        stop_repair_on_empty_source=bool(b['cfg']['dung_sua_khi_nguon_rong']))
                write(out / f'rule_result_{h.hypothesis_id}.json', results[h.hypothesis_id])
            except (ValueError, OSError, duckdb.Error, providers.LLMError, budget.BudgetError) as exc:
                # Stop the whole package: no further call after an unknown or failed paid request.
                message = str(exc).replace(os.environ.get(client.api_key_env) or '\x00', '[REDACTED]')
                failure = {'hypothesis_id': h.hypothesis_id, 'error_type': type(exc).__name__, 'error': message[:1500]}
                break
        summary = {'state': 'failed_no_retry' if failure else 'received', 'failure': failure,
                   **evaluate(results, b['approved'])}
        if failure:
            summary['criteria_met'] = False
        usage = providers.token_totals(observed.events)
        ir, ore = budget.RATES[client.model_id]
        has_usage = any(type(e.get('input_tokens')) is int and type(e.get('output_tokens')) is int for e in observed.events)
        cost = usage['input_tokens'] * ir + usage['output_tokens'] * ore if has_usage else None
        summary.update(probe_id=PROBE_ID, out=str(out), generation_calls=observed.calls,
                       known_cost_usd=budget.usd(cost) if cost is not None else None,
                       usage=usage if has_usage else None, cap_usd=PROPOSED_CAP,
                       cost_exceeds_cap=cost > budget.money(PROPOSED_CAP) if cost is not None else None,
                       api_events=observed.events, ledger_after=_ledger_brief(client.budget_ledger),
                       filter_review_created=False, hunt_record_created=False)
        if summary['cost_exceeds_cap']:
            summary['state'] = 'cost_exceeds_cap_no_retry'
        write(out / 'result.json', summary)
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--send', action='store_true', help='Chỉ người vận hành, sau khi điền ◆ và chốt trần gói')
    parser.add_argument('--cap-usd', help='người vận hành xác nhận trần gói; phép thử chỉ nhận 0.40')
    args = parser.parse_args(argv)
    try:
        result = run(send=args.send, cap_usd=args.cap_usd)
    except (ValueError, OSError, sqlite3.Error, budget.BudgetError, providers.LLMError) as exc:
        print(f'[DỪNG] {exc}')
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get('mode') == 'OFFLINE_NO_API' or result.get('state') == 'awaiting_duy_review':
        return 0
    return 0 if result.get('state') == 'received' and result.get('criteria_met') else 1
