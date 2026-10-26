"""Offline H05/⑤ v4 probe; only người vận hành can opt into one capped generation request.

No new hypothesis decisions, real event queries, applied exclusions or hunt record.
The original completed Emotet package is read-only. Synthetic cases never enter
the model payload. A failed/interrupted attempt is never retried.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
from importlib.metadata import version
from pathlib import Path

import duckdb

from .. import approval, config, demo, integrity
from ..adapters import duckdb_sigma as adapter
from ..contracts import ContractA
from ..filter_approval import POLICY as FILTER_POLICY
from ..llm import budget, providers
from ..llm.prompting import load_sections
from ..stages import rule_fidelity, s5_rule as S5
from .emotet_trial import command_lock, ledger_view, SOURCE_HASH, CONTRACT_HASH

PROBE_ID = 'khau5-v4-emotet-h05-0610-one-request'
PROPOSED_CAP = '0.40'
OUT_REL = 'tmp/thu_khau5_v4_h05_6-10'
REVIEW_REL = 'tmp/thu_loi_emotet_6-10/round_01'
HYPOTHESIS_ID = 'DEV-EMOTET-2019-H05'
HYPOTHESIS_HASH = 'cd48756d299d2e4a2de228a04616f489a44d9bb2f78c7b7580b48f9e57f5bcc9'


def dump(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')


def write(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.writing')
    tmp.write_bytes(dump(value))
    tmp.replace(path)


def cases():
    """Text proxies for encoded process traces, not malicious/benign event labels."""
    enc = lambda text: base64.b64encode(text.encode('utf-16le')).decode('ascii')
    ps = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    rows = [(f'encoded_{len(enc(text))}', ps, 'powershell.exe -EncodedCommand ' + enc(text), True)
            for text in ('x', 'pwd', 'Get-Date')]
    rows += [('flag_uppercase', ps, 'powershell.exe -ENCODEDCOMMAND ' + enc('pwd'), True),
             ('flag_enc', ps, 'powershell.exe -enc ' + enc('pwd'), True),
             ('empty_argument', ps, 'powershell.exe -EncodedCommand ', False),
             ('plain_file', ps, 'powershell.exe -File self-authored.ps1', False),
             ('other_process', r'C:\Windows\cmd.exe', 'cmd.exe -EncodedCommand ' + enc('pwd'), False)]
    return [{'id': name, 'NewProcessName': image, 'CommandLine': cmd, 'expected_candidate': want}
            for name, image, cmd, want in rows]


def fixture(rows):
    con = duckdb.connect()
    con.execute('CREATE TABLE events(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, '
                'ev_rec BIGINT, ev_ts TIMESTAMP, EventID INTEGER, NewProcessName VARCHAR, CommandLine VARCHAR)')
    for i, row in enumerate(rows):
        con.execute("INSERT INTO events VALUES ('SELF-HOST', 'security', 4688, ?, TIMESTAMP '2020-01-01', 4688, ?, ?)",
                    [i, row['NewProcessName'], row['CommandLine']])
    return con


class CaptureRequest:
    def __init__(self, client):
        self.client, self.payload = client, None

    def complete_json(self, system, user, schema, log=None):
        if self.payload is not None:
            raise ValueError('Probe must have exactly one generation request')
        self.payload = self.client.build_payload(system, user, schema)
        return {'rule_yaml': '', 'note': 'Offline payload capture; no API'}


def build(root=config.ROOT):
    root = Path(root)
    rd = root / REVIEW_REL
    approval.verify_saved_review(rd)
    selected = [h for h in approval.load_hypotheses(rd / approval.APPROVED_FILE)
                if h.hypothesis_id == HYPOTHESIS_ID]
    if len(selected) != 1:
        raise ValueError('Cần đúng H05 trong phiếu đã duyệt')
    h = selected[0]
    approval.require_approved(h)
    if hashlib.sha256(dump(h.model_dump(mode='json'))).hexdigest() != HYPOTHESIS_HASH:
        raise ValueError('H05 khác nội dung đã chọn')
    bundle = root / 'data/dev/report_emotet_28-9/bundle'
    extraction = root / 'data/dev/report_emotet_28-9/case/extraction'
    ca_path = demo.verified_contract(bundle, extraction)
    if integrity.sha256_file(ca_path) != CONTRACT_HASH or integrity.sha256_file(bundle / 'source.html') != SOURCE_HASH:
        raise ValueError('CTI/Contract A khác nguồn đã chọn')
    ca = ContractA.model_validate_json(ca_path.read_text(encoding='utf-8'))
    if not all(any(t.source_span == span and t.technique_id in h.linked_ttps for t in ca.ttps)
               for span in h.source_spans) or not h.source_spans:
        raise ValueError('H05 không còn bám nguồn Contract A')
    cfg, lc = config.agent_config('v2', root), config.load('llm_hunt', root)
    if (cfg['prompt_khau5'] != 'prompts/khau5_sigma_v4.md' or lc.get('provider') != 'anthropic'
            or lc.get('model') != 'claude-sonnet-5' or lc.get('effort') != 'high'
            or lc.get('max_output_tokens') != 32000 or lc.get('request_timeout_giay') != 600
            or lc.get('base_url') not in ('', None, 'https://api.anthropic.com')):
        raise ValueError('Cấu hình/prompt khác phạm vi phép thử')
    ledger = config.resolve(lc['budget_ledger'], root)
    if ledger.resolve() != (root / 'data/dev/api_budget.sqlite').resolve():
        raise ValueError('Probe phải dùng đúng sổ chung')
    client = providers.from_config({**lc, 'budget_ledger': str(ledger)})
    client.request_budget_usd = PROPOSED_CAP
    prompt = load_sections(root / cfg['prompt_khau5'], ('SYSTEM', 'USER', 'REPAIR'))
    if S5.candidate_policy(prompt) != rule_fidelity.POLICY:
        raise ValueError('Thiếu policy regex đã chọn')
    cat_path = config.resolve(config.load('dataset', root)['logsource_catalog'], root)
    catalog = adapter.load_catalog(cat_path)
    capture = CaptureRequest(client)
    S5.generate_rule(h, capture, prompt, catalog, 0, filter_policy=FILTER_POLICY)
    payload = capture.payload
    if payload is None:
        raise ValueError('Không dựng được yêu cầu ⑤ cho H05')
    rows = cases()
    artifacts = {'hypothesis.json': h.model_dump(mode='json'), 'payload.json': payload,
                 'cases.json': rows, 'criteria.json': {
                     'static_valid_first_attempt': True, 'expected_source': {'channel': 'security', 'event_ids': [4688]},
                     'synthetic_candidates': {r['id']: r['expected_candidate'] for r in rows},
                     'filters_applied': False, 'manual_review_required': True,
                     'manual_items': ['Không thêm/bỏ điều kiện chính của H05',
                                      'Không thay ngưỡng số bằng điều kiện độ dài giấu trong regex',
                                      'Dấu vết dòng lệnh không chứng minh mọi cách mã hóa hay ý đồ độc hại'],
                     'meaning': 'Kiểm rule/ca văn bản tự soạn, không phải chất lượng săn Emotet'}}
    watched = [root / 'configs/agent_v2.yaml', root / 'configs/llm_hunt.yaml', root / 'configs/dataset.yaml',
               root / cfg['filter_policy'], root / cfg['prompt_khau5'], cat_path,
               root / 'scripts/probe_khau5_v4.py']
    watched += sorted((root / 'src/cti_hunt').rglob('*.py'))
    watched += [rd / name for name in (approval.HYP_FILE, approval.REVIEW_FILE, approval.APPROVED_FILE, approval.LOG_FILE)]
    watched += [bundle / name for name in ('source.html', 'manifest.json', 'segments.jsonl', 'provenance.json')]
    watched += [ca_path, extraction / 'meta.json']
    protocol = {'probe_id': PROBE_ID, 'proposed_cap_usd': PROPOSED_CAP, 'api_authorization': 'pending_nguoi_van_hanh',
                'model': client.describe(), 'rate_version': budget.RATE_VERSION, 'generation_attempts': 1,
                'automatic_repairs': 0, 'real_events_read': False,
                'packages': {name: version(name) for name in
                             ('duckdb', 'pysigma', 'pysigma-backend-sqlite', 'pydantic')},
                'files_sha256': {p.relative_to(root).as_posix(): integrity.sha256_file(p) for p in watched},
                'artifacts_sha256': {name: hashlib.sha256(dump(value)).hexdigest() for name, value in artifacts.items()}}
    return h, client, prompt, catalog, artifacts, protocol


def evaluate(result, rows, con):
    checks = {'static_valid_first_attempt': bool(result['hop_le_lan_dau']),
              'one_attempt_no_repair': len(result['lan_thu']) == 1 and result['so_lan_sua'] == 0}
    specs = result['hunt_specs']
    checks['correct_source'] = len(specs) == 1 and specs[0]['scope']['channel'] == 'security' \
        and specs[0]['scope']['event_ids'] == [4688]
    matched = set()
    if checks['correct_source']:
        # Diagnostic selection on synthetic text only. Never execute a draft on real logs,
        # never apply proposed filters or finalize a human review automatically.
        matched = {r[0] for r in con.execute(f"SELECT ev_rec FROM events WHERE ({specs[0]['candidates']})").fetchall()}
    checks.update({r['id']: (i in matched) == r['expected_candidate'] and bool(specs) for i, r in enumerate(rows)})
    return {'checks': checks, 'criteria_met': all(checks.values()), 'manual_review_required': True,
            'filters_applied': False, 'proposed_filter_count': sum(len(s.get('filters') or []) for s in specs),
            'meaning': 'Kiểm điều kiện ứng viên trên văn bản tự soạn; không phải chất lượng săn Emotet'}


class OneRequest:
    def __init__(self, client, payload, out):
        self.client, self.payload, self.out, self.events, self.calls = client, payload, Path(out), [], 0

    def complete_json(self, system, user, schema, log=None):
        self.calls += 1
        if self.calls != 1 or self.client.build_payload(system, user, schema) != self.payload:
            raise ValueError('Yêu cầu sinh khác bản đã ghim hoặc gọi lặp')
        key = os.environ.get(self.client.api_key_env)
        if not key:
            raise providers.LLMError('Thiếu khóa API')
        def record(event):
            item = {k: event[k] for k in providers.SAFE_EVENT_KEYS if k in event}
            self.events.append(item)
            write(self.out / 'api_events.json', self.events)
            if log:
                log(item)
        data = budget.guarded_request(self.client, self.payload,
            {'x-api-key': key, 'anthropic-version': '2023-06-01'}, record)
        safe_data = json.loads(json.dumps(data).replace(key, '[REDACTED]'))
        write(self.out / 'response_provider.json', safe_data)
        usage = data.get('usage') or {}
        record({'stop_reason': data.get('stop_reason'), 'input_tokens': usage.get('input_tokens'),
                'output_tokens': usage.get('output_tokens'), 'max_tokens': self.client.max_output_tokens})
        if data.get('stop_reason') == 'max_tokens':
            raise providers.BadOutputError('Output bị cắt; không gửi lại')
        raw = providers.read_response(safe_data)
        write(self.out / 'response_raw.json', raw)
        return raw


def run(out=None, *, root=config.ROOT, send=False, cap_usd=None):
    root = Path(root).resolve()
    out = Path(out or root / OUT_REL).resolve()
    if not out.is_relative_to(root / 'tmp') or out.is_relative_to(root / REVIEW_REL.split('/round_01')[0]):
        raise ValueError('Đầu ra phải là gói mới dưới tmp, ngoài gói Emotet cũ')
    if send and (cap_usd is None or budget.money(cap_usd) != budget.money(PROPOSED_CAP)):
        raise ValueError('Chỉ người vận hành gửi sau khi chốt: cần trần riêng --cap-usd 0.40')
    if not send and cap_usd is not None:
        raise ValueError('Chuẩn bị không nhận quyền chi tiền')
    if not out.exists():
        if send:
            raise ValueError('Chưa chuẩn bị ngoại tuyến')
        out.mkdir(parents=True)
    with command_lock(out):
        if (out / 'attempt.json').exists():
            raise ValueError('Phép thử đã bắt đầu; không gửi lại/chuẩn bị đè')
        h, client, prompt, catalog, artifacts, protocol = build(root)
        prepared = out / 'protocol.json'
        if prepared.exists():
            expected = {'protocol.json': protocol, **artifacts}
            if any(not (out / name).is_file() or (out / name).read_bytes() != dump(value)
                   for name, value in expected.items()):
                raise ValueError('Mã/nguồn/gói đã đổi; không ghi đè hoặc gửi')
        elif send or any(p.name != 'command.lock' for p in out.iterdir()):
            raise ValueError('Gói thiếu/dở hoặc có tệp khác; giữ nguyên, chưa gửi')
        else:
            for name, value in artifacts.items():
                write(out / name, value)
            write(prepared, protocol)  # Commit marker for the offline packet, written last.
        status = ledger_view(client.budget_ledger)
        if not send:
            preflight = {'mode': 'OFFLINE_NO_API', 'probe_id': PROBE_ID, 'out': str(out),
                         'api_authorization': 'pending_nguoi_van_hanh', 'proposed_cap_usd': PROPOSED_CAP,
                         'minimum_reservation_usd': budget.usd(budget.min_reserve(client.model_id, client.max_output_tokens)),
                         'exact_reservation': 'counted only when the operator sends; cap checked before generation',
                         'ledger_remaining_usd': budget.usd(status['limit'] - status['known'] - status['held']),
                         'ledger_pending': status['pending'], 'generation_attempts': 0,
                         'hypothesis_id': h.hypothesis_id, 'synthetic_cases': len(artifacts['cases.json'])}
            write(out / 'preflight.json', preflight)
            return preflight
        if status['pending'] or status['limit'] - status['known'] - status['held'] < budget.min_reserve(client.model_id, client.max_output_tokens):
            raise budget.BudgetError('Sổ chưa đối soát hoặc không đủ dự phòng; chưa gửi')
        if not os.environ.get(client.api_key_env):
            raise providers.LLMError('Thiếu khóa API; chưa gửi')
        with (out / 'attempt.json').open('xb') as f:
            f.write(dump({'probe_id': PROBE_ID, 'state': 'attempt_started_no_retry', 'cap_usd': cap_usd,
                          'protocol_sha256': integrity.sha256_file(prepared)}))
        observed = OneRequest(client, artifacts['payload.json'], out)
        with fixture(artifacts['cases.json']) as con:
            try:
                cols = {r[0] for r in con.execute('DESCRIBE events').fetchall()}
                result = S5.generate_rule(h, observed, prompt, catalog, 0, cols, con, out, filter_policy=FILTER_POLICY)
                write(out / 'rule_result.json', result)
                summary = {'state': 'received', **evaluate(result, artifacts['cases.json'], con)}
            except (ValueError, OSError, duckdb.Error, providers.LLMError, budget.BudgetError) as exc:
                message = str(exc).replace(os.environ.get(client.api_key_env) or '\x00', '[REDACTED]')
                summary = {'state': 'failed_no_retry', 'error_type': type(exc).__name__, 'error': message[:1500],
                           'criteria_met': False, 'manual_review_required': True}
        usage = providers.token_totals(observed.events)
        ir, ore = budget.RATES[client.model_id]
        has_usage = any(type(e.get('input_tokens')) is int and type(e.get('output_tokens')) is int for e in observed.events)
        cost = usage['input_tokens'] * ir + usage['output_tokens'] * ore if has_usage else None
        summary.update(probe_id=PROBE_ID, out=str(out), known_cost_usd=budget.usd(cost) if cost is not None else None,
                       usage=usage if has_usage else None, cap_usd=PROPOSED_CAP,
                       cost_exceeds_cap=cost > budget.money(PROPOSED_CAP) if cost is not None else None,
                       api_events=observed.events)
        if summary['cost_exceeds_cap']:
            summary.update(criteria_met=False, state='cost_exceeds_cap_no_retry')
        write(out / 'result.json', summary)
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--send', action='store_true', help='Chỉ người vận hành sau khi chốt một lần gọi API')
    parser.add_argument('--cap-usd', help='người vận hành xác nhận trần riêng; phép thử chỉ nhận 0.40')
    args = parser.parse_args(argv)
    try:
        result = run(send=args.send, cap_usd=args.cap_usd)
    except (ValueError, OSError, sqlite3.Error, budget.BudgetError, providers.LLMError) as exc:
        print(f'[DỪNG] {exc}')
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get('criteria_met') is False else 0
