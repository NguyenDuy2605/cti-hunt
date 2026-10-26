"""One ④ v6 request for two self-authored cases: distinct destination IPs, absent DNS (07/10).

Default is offline preparation, 0 API, from the checked packet `tmp/chuan_bi_khau4_v6_dem_vang_6-10`.
Only the operator opts into `--send --cap-usd 0.40` after approving the spend. No ◆ form, no ⑤, no log query,
no retry or repair. The source packet stays read-only; the attempt marker is never removed for a resend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path

from .. import config, integrity
from ..contracts import ContractA, RangBuoc
from ..llm import budget, providers
from ..llm.prompting import load_sections
from ..stages import s4_hypothesis as S4
from .emotet_trial import command_lock, ledger_view

PROBE_ID = 'khau4-v6-dem-vang-0710-one-request'
PROPOSED_CAP = '0.40'
PACKET_REL = 'tmp/chuan_bi_khau4_v6_dem_vang_6-10'
PACKET_MANIFEST_SHA256 = '4ecf9953b4bc9fc27be4667d00c6410ac62a06035b72de8f4035e9871631693d'
OUT_REL = 'tmp/thu_khau4_v6_dem_vang_7-10'
# Earlier packets and paid trials under tmp/; this runner never writes or locks inside them.
PROTECTED = {'chuan_bi_khau4_v6_dem_vang_6-10', 'chuan_bi_rang_buoc_4_5_6-10', 'chuan_bi_loi_emotet_6-10',
             'thu_khau4_v5_6-10', 'thu_khau5_v4_h05_6-10', 'thu_loi_emotet_6-10',
             'thu_loi_emotet_6-10_prepared_before_payload_fix'}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def dump(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')


def write(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.writing')
    tmp.write_bytes(dump(value))
    tmp.replace(path)


def load_packet(root):
    """The exact packet checked on 06/10: pinned manifest, no added/changed file, same code pins."""
    packet = root / PACKET_REL
    manifest_path = packet / 'manifest.json'
    if not manifest_path.is_file() or integrity.sha256_file(manifest_path) != PACKET_MANIFEST_SHA256:
        raise ValueError('Gói chuẩn bị hai ca thiếu hoặc đã đổi; chưa gửi')
    manifest = read(manifest_path)
    artifacts = manifest['artifacts_sha256']
    if ({p.name for p in packet.iterdir()} != set(artifacts) | {'manifest.json'}
            or any(integrity.sha256_file(packet / name) != h for name, h in artifacts.items())):
        raise ValueError('Tệp trong gói chuẩn bị đã đổi; chưa gửi')
    if any(not (root / p).is_file() or integrity.sha256_file(root / p) != h
           for p, h in manifest['files_sha256'].items()):
        raise ValueError('Mã/cấu hình/prompt khác bản đã kiểm khi dựng gói; chưa gửi')
    return packet, manifest


def canonical(value):
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value.lower() if isinstance(value, str) else value


def constraint_fields(rb: dict) -> set[str]:
    """Fields the constraint itself joins/counts on the primary source; ev_host is a derived column."""
    fields = set()
    if rb.get('dem_khac_nhau'):
        fields |= {rb['dem_khac_nhau']['truong'], *rb['dem_khac_nhau']['theo']}
    if rb.get('vang_mat'):
        fields |= {p['ung_vien'] for p in rb['vang_mat']['khop']}
    if rb.get('moc_neo'):
        fields |= set(rb['moc_neo']['cung'])
    return {f.lower() for f in fields} - {'ev_host'}


def evaluate(raw, ca, telemetry, cfg, criteria):
    """Pre-registered parameter checks from criteria.json (same as the packet's `check`).

    Never a proof that behavior/scope/timeframe/rationale preserve the source meaning: manual review always.
    """
    try:
        batch = S4.output_model(cfg).model_validate(raw)
    except ValueError:
        return {'parameter_criteria_met': False, 'schema_ok': False, 'manual_review_required': True}
    inputs, _ = S4.select_inputs(ca, telemetry)
    accepted, corrections = S4.postprocess(batch.items, inputs, ca.report_id,
                                           int(cfg['max_hypotheses_per_round']), anchors=[])
    expected = criteria['expected_independent_items']
    checks = {'two_independent_items': len(batch.items) == expected and len(accepted) == expected,
              'no_postprocess_correction': not any(corrections.values()),
              'pending_only': all(h.status == 'pending_review' for h in accepted)}
    for case in criteria['cases']:
        n = case['ref']
        span = ca.ttps[n].source_span
        want = RangBuoc.model_validate(case['rang_buoc']).model_dump(exclude_none=True)
        matched = [it for it in batch.items if it.ttp_refs == [n]]
        retained = [h for h in accepted if h.source_spans == [span]]
        checks[f'ref_{n}_exact_parameters_source_keys_and_operations'] = bool(
            len(matched) == len(retained) == 1
            and matched[0].rang_buoc is not None
            and canonical(matched[0].rang_buoc.model_dump(exclude_none=True)) == canonical(want)
            and canonical(retained[0].rang_buoc.model_dump(exclude_none=True)) == canonical(want)
            and matched[0].data_source.lower() == case['primary_channel']
            and matched[0].event_ids == case['primary_event_ids']
            and constraint_fields(want) <= {f.lower() for f in matched[0].key_fields}
            and matched[0].required_operations == case['required_operations']
            and matched[0].extra_techniques == case['extra_techniques']
            and span.text in matched[0].rationale)
    return {'schema_ok': True, 'checks': checks, 'parameter_criteria_met': all(checks.values()),
            'manual_review_required': True, 'prose_semantics_verified': False}


class CaptureRequest:
    """Runs the production ④ path offline and keeps the request instead of calling a model."""

    def __init__(self, client):
        self.client, self.request, self.payload = client, None, None

    def complete_json(self, system, user, schema, log=None):
        if self.payload is not None:
            raise ValueError('Phép thử chỉ có đúng một yêu cầu sinh')
        self.request = {'system': system, 'user': user}
        self.payload = self.client.build_payload(system, user, schema)
        return {'items': []}


def build(root=config.ROOT):
    root = Path(root)
    packet, manifest = load_packet(root)
    cfg, lc = config.agent_config('v2', root), config.load('llm_hunt', root)
    # Pin the existing model settings; never lower effort/tokens/timeout to fit the cap.
    if (cfg['prompt_khau4'] != 'prompts/khau4_gia_thuyet_v6.md' or not cfg.get('sinh_rang_buoc')
            or int(cfg['max_hypotheses_per_round']) != 10 or lc.get('provider') != 'anthropic'
            or lc.get('model') != 'claude-sonnet-5' or lc.get('effort') != 'high'
            or lc.get('max_output_tokens') != 32000 or lc.get('request_timeout_giay') != 600
            or lc.get('base_url') not in ('', None, 'https://api.anthropic.com')):
        raise ValueError('Cấu hình/prompt khác phạm vi phép thử; chưa gửi')
    ledger = config.resolve(lc['budget_ledger'], root)
    if ledger.resolve() != (root / 'data/dev/api_budget.sqlite').resolve():
        raise ValueError('Phép thử phải dùng đúng sổ chung')
    client = providers.from_config({**lc, 'budget_ledger': str(ledger)})
    client.request_budget_usd = PROPOSED_CAP
    prompt = load_sections(root / cfg['prompt_khau4'])
    ca = ContractA.model_validate(read(packet / 'contract_a_self_authored.json'))
    telemetry = read(packet / 'telemetry_self_authored.json')
    criteria = read(packet / 'criteria.json')
    if (criteria['anchors'] != [] or criteria['expected_independent_items'] != len(ca.ttps)
            or [c['ref'] for c in criteria['cases']] != list(range(len(ca.ttps)))
            or any(c['source_span'] != ca.ttps[c['ref']].source_span.model_dump() for c in criteria['cases'])):
        raise ValueError('Tiêu chí không khớp Contract A của gói; chưa gửi')
    capture = CaptureRequest(client)
    S4.generate(ca, telemetry, capture, prompt, cfg, anchors=[])
    # Same request as the packet, rebuilt by the current production ④ path, byte for byte.
    if (capture.payload is None or dump(capture.request) != (packet / 'request.json').read_bytes()
            or dump(capture.payload) != (packet / 'payload.json').read_bytes()):
        raise ValueError('Yêu cầu dựng lại từ mã hiện hành khác payload đã kiểm; chưa gửi')
    # The runner's criteria must reproduce the packet's recorded check on its fixture reply.
    self_check = evaluate(read(packet / 'fixture_mock_response_NOT_MODEL_OUTPUT.json'), ca, telemetry, cfg, criteria)
    if self_check != read(packet / 'offline_checks.json')['model_parameter_check']:
        raise ValueError('Tiêu chí của runner khác kiểm đã ghi trong gói; chưa gửi')
    watched = ['configs/agent_v2.yaml', 'configs/llm_hunt.yaml', cfg['filter_policy'], cfg['prompt_khau4'],
               'scripts/probe_khau4_v6_dem_vang.py']
    watched += [p.relative_to(root).as_posix() for p in sorted((root / 'src/cti_hunt').rglob('*.py'))]
    protocol = {'probe_id': PROBE_ID, 'proposed_cap_usd': PROPOSED_CAP, 'api_authorization': 'pending_nguoi_van_hanh',
                'scope': 'one stage-4 generation request for two self-authored cases; no review form, stage 5, '
                         'planner, pivot, log query, retry or repair',
                'source_packet': PACKET_REL, 'packet_manifest_sha256': PACKET_MANIFEST_SHA256,
                'packet_artifacts_sha256': manifest['artifacts_sha256'],
                'packet_files_sha256': manifest['files_sha256'],
                'model': client.describe(), 'rate_version': budget.RATE_VERSION, 'generation_attempts': 1,
                'automatic_repairs': 0, 'anchors': [], 'real_events_read': False,
                'payload_sha256': hashlib.sha256(dump(capture.payload)).hexdigest(),
                'criteria': {'file': 'criteria.json', 'function': 'cti_hunt.agent.probe_khau4_dem_vang:evaluate',
                             'fixture_self_check': self_check},
                'packages': {name: version(name) for name in ('pydantic',)},
                'files_sha256': {p: integrity.sha256_file(root / p) for p in watched}}
    return {'cfg': cfg, 'client': client, 'prompt': prompt, 'ca': ca, 'telemetry': telemetry,
            'criteria': criteria, 'payload': capture.payload, 'protocol': protocol}


def _redact(value, key):
    return json.loads(json.dumps(value).replace(key, '[REDACTED]')) if key else value


@contextmanager
def keep_replies(out, key):
    """Save each HTTP reply on receipt, before ledger settlement or tool_use parsing can fail.

    Wraps the shared transport for this one command only, so `budget.guarded_request` stays unchanged.
    """
    real = providers._post

    def post(url, payload, headers, **kwargs):
        data = real(url, payload, headers, **kwargs)
        name = 'count_tokens.json' if url.endswith('/count_tokens') else 'response_provider.json'
        write(out / name, _redact(data, key))
        return data
    providers._post = post
    try:
        yield
    finally:
        providers._post = real


class OneRequest:
    def __init__(self, client, payload, out):
        self.client, self.payload, self.out = client, payload, Path(out)
        self.events, self.calls, self.raw = [], 0, None
        self.model_id = client.model_id

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
        with keep_replies(self.out, key):
            data = budget.guarded_request(self.client, self.payload,
                                          {'x-api-key': key, 'anthropic-version': '2023-06-01'}, record)
        usage = data.get('usage') or {}
        record({'stop_reason': data.get('stop_reason'), 'input_tokens': usage.get('input_tokens'),
                'output_tokens': usage.get('output_tokens'), 'max_tokens': self.client.max_output_tokens})
        if data.get('stop_reason') == 'max_tokens':
            raise providers.BadOutputError('Output bị cắt; không gửi lại')
        self.raw = _redact(providers.read_response(data), key)
        return self.raw


def _ledger_brief(path):
    try:
        s = ledger_view(path)
    except (OSError, sqlite3.Error, budget.BudgetError) as exc:
        return {'error_type': type(exc).__name__}
    return {'remaining_usd': budget.usd(s['limit'] - s['known'] - s['held']), 'pending': s['pending'],
            'known_cost_usd': budget.usd(s['known']), 'limit_usd': budget.usd(s['limit'])}


def _check_out(out, root):
    tmp = (root / 'tmp').resolve()
    if out.parent != tmp or out.name in PROTECTED:
        raise ValueError('Đầu ra phải là thư mục mới ngay dưới tmp, ngoài các gói/phép thử cũ')
    if out.exists():
        names = {p.name for p in out.iterdir()} - {'command.lock'}
        if names and (not (out / 'protocol.json').is_file()
                      or read(out / 'protocol.json').get('probe_id') != PROBE_ID):
            raise ValueError('Thư mục đầu ra có tệp không thuộc phép thử này; giữ nguyên, chưa gửi')


def run(out=None, *, root=config.ROOT, send=False, cap_usd=None):
    root = Path(root).resolve()
    out = Path(out or root / OUT_REL).resolve()
    _check_out(out, root)
    if send and (cap_usd is None or budget.money(cap_usd) != budget.money(PROPOSED_CAP)):
        raise ValueError('Chỉ người vận hành gửi sau khi chốt: cần trần riêng --cap-usd 0.40')
    if not send and cap_usd is not None:
        raise ValueError('Chuẩn bị không nhận quyền chi tiền')
    if not out.exists():
        if send:
            raise ValueError('Chưa chuẩn bị ngoại tuyến; chưa gửi')
        out.mkdir()
    with command_lock(out):
        if (out / 'attempt.json').exists():
            raise ValueError('Phép thử đã bắt đầu; không gửi lại/chuẩn bị đè')
        b = build(root)
        client, protocol = b['client'], b['protocol']
        prepared = out / 'protocol.json'
        if prepared.exists():
            if prepared.read_bytes() != dump(protocol):
                raise ValueError('Mã/gói/cấu hình đã đổi so với bản chuẩn bị; không ghi đè hoặc gửi')
        elif send or any(p.name != 'command.lock' for p in out.iterdir()):
            raise ValueError('Gói thiếu/dở hoặc có tệp khác; giữ nguyên, chưa gửi')
        else:
            write(prepared, protocol)
        status = ledger_view(client.budget_ledger)
        minimum = budget.min_reserve(client.model_id, client.max_output_tokens)
        if not send:
            preflight = {'mode': 'OFFLINE_NO_API', 'probe_id': PROBE_ID, 'out': str(out),
                         'api_authorization': 'pending_nguoi_van_hanh', 'proposed_cap_usd': PROPOSED_CAP,
                         'minimum_reservation_usd': budget.usd(minimum),
                         'exact_reservation': 'counted only when the operator sends; cap checked before generation',
                         'ledger_remaining_usd': budget.usd(status['limit'] - status['known'] - status['held']),
                         'ledger_pending': status['pending'], 'generation_attempts': 0,
                         'ttp_inputs': len(b['ca'].ttps), 'payload_sha256': protocol['payload_sha256']}
            write(out / 'preflight.json', preflight)
            return preflight
        if status['pending'] or status['limit'] - status['known'] - status['held'] < minimum:
            raise budget.BudgetError('Sổ chưa đối soát hoặc không đủ dự phòng; chưa gửi')
        if not os.environ.get(client.api_key_env):
            raise providers.LLMError('Thiếu khóa API; chưa gửi')
        # Exclusive creation before any HTTP: a repeat, a concurrent run or a resend after interruption is refused.
        with (out / 'attempt.json').open('xb') as f:
            f.write(dump({'probe_id': PROBE_ID, 'state': 'attempt_started_no_retry', 'cap_usd': PROPOSED_CAP,
                          'protocol_sha256': integrity.sha256_file(prepared)}))
        observed = OneRequest(client, b['payload'], out)
        try:
            result = S4.generate(b['ca'], b['telemetry'], observed, b['prompt'], b['cfg'], run_dir=out, anchors=[])
            write(out / 'hypotheses_pending.json', [h.model_dump(mode='json') for h in result['hypotheses']])
            write(out / 'khau4_log.json', result['log'])
            summary = {'state': 'received', 'so_muc_tho': result['log']['so_muc_tho'],
                       'so_gia_thuyet': len(result['hypotheses']), 'ma_sua': result['log']['ma_sua'],
                       **evaluate(observed.raw, b['ca'], b['telemetry'], b['cfg'], b['criteria'])}
        except (ValueError, OSError, providers.LLMError, budget.BudgetError) as exc:
            message = str(exc).replace(os.environ.get(client.api_key_env) or '\x00', '[REDACTED]')
            summary = {'state': 'failed_no_retry', 'error_type': type(exc).__name__, 'error': message[:1500],
                       'parameter_criteria_met': False, 'manual_review_required': True}
        usage = providers.token_totals(observed.events)
        ir, ore = budget.RATES[client.model_id]
        has_usage = any(type(e.get('input_tokens')) is int and type(e.get('output_tokens')) is int
                        for e in observed.events)
        cost = usage['input_tokens'] * ir + usage['output_tokens'] * ore if has_usage else None
        summary.update(probe_id=PROBE_ID, out=str(out), known_cost_usd=budget.usd(cost) if cost is not None else None,
                       usage=usage if has_usage else None, cap_usd=PROPOSED_CAP,
                       cost_exceeds_cap=cost > budget.money(PROPOSED_CAP) if cost is not None else None,
                       api_events=observed.events, review_form_created=False, step5_called=False,
                       ledger_after=_ledger_brief(client.budget_ledger))
        if summary['cost_exceeds_cap']:
            summary['state'] = 'cost_exceeds_cap_no_retry'
        write(out / 'result.json', summary)
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--send', action='store_true', help='Chỉ người vận hành, sau khi chốt một lần gọi API')
    parser.add_argument('--cap-usd', help='người vận hành xác nhận trần riêng; phép thử chỉ nhận 0.40')
    args = parser.parse_args(argv)
    try:
        result = run(send=args.send, cap_usd=args.cap_usd)
    except (ValueError, OSError, sqlite3.Error, budget.BudgetError, providers.LLMError) as exc:
        print(f'[DỪNG] {exc}')
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get('mode') == 'OFFLINE_NO_API':
        return 0
    return 0 if result.get('state') == 'received' and result.get('parameter_criteria_met') else 1
