"""One source paragraph, one independent ④ batch, human gates, shared ledger, cumulative cap.

Only the operator sends. prepare/status never use HTTP or change the ledger. An interrupted paid phase is never replayed.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import yaml

from .. import approval, config, demo, integrity
from ..contracts import ContractA
from ..llm import budget, providers
from ..llm.prompting import fill, load_sections
from ..stages import s3_telemetry as S3, s4_hypothesis as S4
from . import session
from .graph import open_sqlite_graph

CAP = '1.20'
KIND = 'emotet_one_pass_0610_v1'
OUT = config.ROOT / 'tmp/thu_loi_emotet_6-10'
SEGMENT = 'DEV-EMOTET-2019-0007'
SOURCE_HASH = '962f1f92716e3db0cebeb847f4a85be1778b9d79c19a4b85e77ebda7defa1168'
CONTRACT_HASH = '14635e52a1ebe3e5d9baf61af63dbac658a398b38c17a657e21e6f3308e9b0b8'
DATA_HASH = '96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.writing')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    temp.replace(path)


def ledger_view(path):
    """Never init, resolve, set-limit, or use a writable DB connection here."""
    con = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        con.execute('BEGIN')
        limit, known, held, pending = budget.Ledger._state(con)
        rows = {r[0]: list(r[1:]) for r in con.execute('SELECT id, model, reserved, charged FROM requests')}
        return {'limit': limit, 'known': known, 'held': held, 'pending': len(pending), 'rows': rows}
    finally:
        con.close()


@contextmanager
def command_lock(out):
    # OS releases the lock after a killed process; phase markers survive and prohibit replay.
    path = Path(out) / 'command.lock'
    with path.open('a+b') as f:
        f.seek(0, 2)
        if not f.tell():
            f.write(b'0')
            f.flush()
        f.seek(0)
        if os.name == 'nt':
            import msvcrt
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as e:
                raise ValueError('Gói đang được xử lý ở tiến trình khác') from e
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                raise ValueError('Gói đang được xử lý ở tiến trình khác') from e
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


class OnePassPlanner:
    def metadata(self):
        return {'kind': KIND, 'model': 'deterministic', 'llm_called': False}

    def __call__(self, view):
        if view['prior_decisions']:
            return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [],
                    'reason': 'Đã kết thúc lô nguồn được chốt; không planner/pivot hay lô ④ tiếp theo.'}
        return {'action': 'hunt', 'ttp_refs': view['remaining_refs'], 'pivot_targets': [],
                'reason': 'Một lô cho toàn bộ 6 TTP nguyên vẹn trong đoạn nguồn đã chốt.'}


def spend(out):
    if integrity.sha256_file(Path(out) / 'budget_baseline.json') != read(Path(out) / 'start_pin.json')['baseline_sha256']:
        raise budget.BudgetError('Mốc chi phí gói đã đổi; không gửi')
    baseline = read(Path(out) / 'budget_baseline.json')
    now = ledger_view(baseline['ledger'])
    if any(now['rows'].get(k) != v for k, v in baseline['rows'].items()):
        raise budget.BudgetError('Sổ đã mất hoặc sửa chi phí cũ; không thể kiểm trần gói')
    used = now['known'] - baseline['known']
    if used < 0:
        raise budget.BudgetError('Chi phí trong sổ thấp hơn mốc ban đầu')
    return {'charged_delta': used, 'held': now['held'], 'pending': now['pending'],
            'remaining': budget.money(CAP) - used - now['held']}


class TrialClient:
    """Cap uses the ledger delta, including other clients conservatively; never a new ledger."""
    def __init__(self, client, out):
        self.client, self.out = client, Path(out)

    def __getattr__(self, name):
        return getattr(self.client, name)

    def describe(self):
        return {**self.client.describe(), 'trial_total_cap_usd': CAP}

    def complete_json(self, system, user, json_schema, log=None):
        current = spend(self.out)
        if current['pending']:
            raise budget.BudgetError('Có yêu cầu chưa rõ chi phí; giữ nguyên và đối soát Console')
        if current['remaining'] < budget.min_reserve(self.model_id, self.max_output_tokens):
            raise budget.BudgetExhausted('Không đủ dự phòng trong trần tổng 1,20 USD; chưa gửi')
        self.client.request_budget_usd = budget.usd(current['remaining'])
        key = os.environ.get(self.api_key_env)
        if not key:
            raise providers.LLMError('Thiếu biến khóa API; chưa gửi')
        payload = self.client.build_payload(system, user, json_schema)
        calls = self.out / 'api_calls'
        calls.mkdir(exist_ok=True)
        index = len(list(calls.glob('call_*.json')))
        path = calls / f'call_{index:02d}.json'
        with path.open('x', encoding='utf-8') as f:
            json.dump({'state': 'started_no_retry', 'request': payload}, f, ensure_ascii=False)
        safe = []
        def record(event):
            item = {k: event[k] for k in providers.SAFE_EVENT_KEYS if k in event}
            safe.append(item)
            if log:
                log(item)
        try:
            data = budget.guarded_request(self.client, payload,
                                         {'x-api-key': key, 'anthropic-version': '2023-06-01'}, record)
            usage = data.get('usage') or {}
            record({'stop_reason': data.get('stop_reason'), 'input_tokens': usage.get('input_tokens'),
                    'output_tokens': usage.get('output_tokens'), 'max_tokens': self.max_output_tokens})
            # Store the provider reply before parsing: refusals/malformed/truncated replies remain auditable.
            safe_data = json.loads(json.dumps(data, ensure_ascii=False).replace(key, '[REDACTED]'))
            write(path, {'state': 'received', 'request': payload, 'response': safe_data, 'api_events': safe})
            if spend(self.out)['remaining'] < 0:
                raise budget.BudgetError('Usage vượt trần gói; dừng, cần đối soát')
            if data.get('stop_reason') == 'max_tokens':
                raise providers.BadOutputError('Output bị cắt; không gửi lại pha này')
            return providers.read_response(data)
        except BaseException as e:
            saved = read(path)
            saved.update(error_type=type(e).__name__, api_events=safe)
            write(path, saved)
            raise


def prepare(out=OUT, root=config.ROOT):
    out, root = Path(out), Path(root)
    if out.exists():
        raise ValueError('Thư mục gói đã tồn tại; dùng status, không chuẩn bị đè')
    bundle = root / 'data/dev/report_emotet_28-9/bundle'
    extraction = root / 'data/dev/report_emotet_28-9/case/extraction'
    events = root / 'data/dev/otrf-wmi-exec'
    ca_path = demo.verified_contract(bundle, extraction)
    if integrity.sha256_file(ca_path) != CONTRACT_HASH or integrity.sha256_file(bundle / 'source.html') != SOURCE_HASH:
        raise ValueError('Nguồn/Contract A khác gói đã chốt')
    original = ContractA.model_validate_json(ca_path.read_text(encoding='utf-8'))
    chosen = [(i, t) for i, t in enumerate(original.ttps) if t.source_span.segment_id == SEGMENT]
    if len(chosen) != 6 or [i for i, _ in chosen] != list(range(2, 8)):
        raise ValueError('Đầu vào không khớp đúng 6 dòng nguồn đã chốt')
    ca = original.model_copy(update={'ttps': [t for _, t in chosen]})
    cfg = config.agent_config('v2', root)
    if (cfg['prompt_khau4'] != 'prompts/khau4_gia_thuyet_v6.md' or
        cfg['prompt_khau5'] != 'prompts/khau5_sigma_v3.md' or
        cfg['max_hypotheses_per_round'] != 10 or cfg['max_repair_attempts'] != 2 or not cfg.get('sinh_rang_buoc')):
        raise ValueError('Cấu hình gói đã đổi')
    llm_cfg = config.load('llm_hunt', root)
    if (llm_cfg['provider'] != 'anthropic' or llm_cfg['model'] != 'claude-sonnet-5' or
        llm_cfg['effort'] != 'high' or llm_cfg['max_output_tokens'] != 32000 or llm_cfg['request_timeout_giay'] != 600 or
        llm_cfg.get('base_url') not in ('', None, 'https://api.anthropic.com')):
        raise ValueError('Mô hình/tham số không khớp phạm vi đã chốt')
    m = read(events / 'ingest_manifest.json')
    if m['source_sha256'] != DATA_HASH:
        raise ValueError('Log khác gói đã chốt')
    from .dev_data import check_manifest
    check_manifest(events, m['dataset_id'], m['source_sha256'], root)
    session.check_dataset(events, root)
    paths = list(session.tracked_files(root, 'v2')) + ['scripts/thu_loi_emotet.py']
    external = [bundle / n for n in ('source.html', 'manifest.json', 'segments.jsonl', 'provenance.json')]
    external += [extraction / n for n in ('contract_a.json', 'meta.json')]
    external += [events / 'ingest_manifest.json']
    pins = {str(root / p): integrity.sha256_file(root / p) for p in paths}
    pins.update({str(p): integrity.sha256_file(p) for p in external})
    out.mkdir(parents=True)
    write(out / 'contract_a.json', ca.model_dump(mode='json'))
    dry = session.start('pipeline', out / 'contract_a.json', events, out / 'not_created',
                        dataset_kind='otrf_dev', dataset_id=m['dataset_id'], dataset_sha256=m['source_sha256'],
                        root=root, version='v2', dry_run=True)
    if dry['so_ttp_vao_khau4'] != 6:
        raise ValueError('Không đủ 6 TTP vào ④')
    write(out / 'dry_run.json', dry)
    ledger = root / llm_cfg['budget_ledger']
    lv = ledger_view(ledger)
    meta = {'runner': KIND, 'cap_usd': CAP, 'mode': 'pipeline', 'phien_ban': 'v2',
            'thread_id': KIND, 'contract_a': {'path': str((out / 'contract_a.json').resolve()),
                                          'sha256': integrity.sha256_file(out / 'contract_a.json')},
            'events': {'dir': str(events.resolve()), 'parquet_sha256': integrity.sha256_file(events / 'events.parquet')},
            'dataset': {'kind': 'otrf_dev', 'id': m['dataset_id'], 'sha256': m['source_sha256']},
            'tep': session.tracked_files(root, 'v2'), 'git': session.git_state(root), 'moc_co_dinh': None,
            'pins': pins, 'ledger': str(ledger.resolve())}
    write(out / 'run_meta.json', meta)
    built = build(meta, out, root, paid=False)
    try:
        # StageTools reindexes the selected TTP batch in the initial score order before calling ④.
        # Pin the payload that this graph will actually send, not the pre-selection ref numbering.
        refs = built[1].initial_state()['remaining_refs']
        batch_ca = ca.model_copy(update={'ttps': [ca.ttps[r] for r in refs]})
        inputs, _ = S4.select_inputs(batch_ca, built[1].telemetry)
        prompt = load_sections(root / cfg['prompt_khau4'])
        user = fill(prompt['sections']['USER'], report_id=ca.report_id, techniques=S4.render_inputs(inputs),
                    max_items='10', executed_hypotheses='[]')
        client = built[1].llm_hypotheses
        write(out / 'payload_khau4.json', client.build_payload(prompt['sections']['SYSTEM'], user, S4.output_model(cfg).model_json_schema()))
        _, sha = S3.write_profile(built[3], out)
        meta['ho_so'] = {'sha256': sha}
        meta['prepared_files'] = {n: integrity.sha256_file(out / n) for n in
                                 ('contract_a.json', 'dry_run.json', 'payload_khau4.json', S3.PROFILE_FILE)}
        write(out / 'run_meta.json', meta)
    finally:
        built[1].con.close()
    return {'state': 'prepared_no_api', 'out': str(out), 'cap_usd': CAP,
            'remaining_shared_usd': budget.usd(lv['limit'] - lv['known'] - lv['held']),
            'pending': lv['pending'], 'suggested_total_ledger_limit_usd': budget.usd(lv['known'] + budget.money(CAP))}


def verify(out, root):
    meta = read(out / 'run_meta.json')
    if meta.get('runner') != KIND or meta.get('cap_usd') != CAP:
        raise ValueError('Sai gói/trần đã chốt')
    if (out / 'start_pin.json').exists() and integrity.sha256_file(out / 'run_meta.json') != read(out / 'start_pin.json')['meta_sha256']:
        raise ValueError('Metadata lượt đã đổi sau khi bắt đầu')
    clean = {k: v for k, v in meta.items() if k != 'runner'}
    session._check_unchanged(clean, root)
    if any(integrity.sha256_file(Path(p)) != s for p, s in meta['pins'].items()):
        raise ValueError('Nguồn/mã/script đã đổi; không gửi')
    if any(integrity.sha256_file(out / p) != s for p, s in meta['prepared_files'].items()):
        raise ValueError('Tệp chuẩn bị đã đổi; không gửi')
    return meta


def build(meta, out, root, *, paid=True):
    clean = {k: v for k, v in meta.items() if k != 'runner'}
    built = session._build(clean, out, root)
    _, tools, cfg, profile = built
    if paid:
        tools.llm_hypotheses = TrialClient(tools.llm_hypotheses, out)
        tools.llm_rules = TrialClient(tools.llm_rules, out)
    return OnePassPlanner(), tools, cfg, profile


@contextmanager
def graph_context(meta, out, root):
    built = build(meta, out, root)
    try:
        session._check_profile(meta, out, built[3])
        with open_sqlite_graph(built[0], built[1], built[2], out, out / session.CHECKPOINT_FILE) as graph:
            yield graph, built[1]
    finally:
        built[1].con.close()


def status(out=OUT, root=config.ROOT):
    out = Path(out)
    meta = verify(out, root)
    if (out / 'terminal.json').exists():
        return read(out / 'terminal.json')
    phases = list(out.glob('phase_*.json'))
    if any(read(p)['state'] == 'started_no_retry' for p in phases):
        return {'state': 'interrupted_no_retry', 'meaning': 'Không resume/gửi lại pha bị ngắt; giữ log và đối soát Console'}
    if not (out / session.CHECKPOINT_FILE).exists():
        lv = ledger_view(meta['ledger'])
        return {'state': 'prepared_no_api', 'cap_usd': CAP, 'out': str(out),
                'remaining_shared_usd': budget.usd(lv['limit'] - lv['known'] - lv['held']),
                'pending': lv['pending'], 'suggested_total_ledger_limit_usd': budget.usd(lv['known'] + budget.money(CAP))}
    with graph_context(meta, out, root) as (graph, _):
        snap = graph.get_state(session._thread(meta))
        if snap.values.get('record'):
            return {'state': 'completed', 'hunt_record': str(out / 'hunt_record.md'),
                    'executed_hypotheses': len({s['hypothesis_id'] for s in snap.values.get('executed_specs') or []}),
                    'manual_review_required': True, 'meaning': 'Kiểm luồng phát triển; không phải chất lượng phát hiện Emotet.',
                    'budget': _spend_summary(out)}
        if 'review_filters' in snap.next:
            return {'state': 'awaiting_filter_review', 'review_dir': snap.values['filter_review_dir'], 'budget': _spend_summary(out)}
        if 'review' in snap.next:
            return {'state': 'awaiting_hypothesis_review', 'review_dir': snap.values['review_dir'], 'budget': _spend_summary(out)}
        raise ValueError('Checkpoint không ở điểm dừng an toàn; không gửi lại')


def _spend_summary(out):
    s = spend(out)
    return {'charged_delta_usd': budget.usd(s['charged_delta']), 'reserved_usd': budget.usd(s['held']),
            'remaining_package_usd': budget.usd(s['remaining']), 'pending': s['pending'],
            'meaning': 'delta sổ chung; chi ngoài gói trong thời gian thử cũng được tính bảo thủ vào trần'}


def advance(out=OUT, root=config.ROOT):
    """Explicit --send only. No phase replays after crashes, even if the shared ledger is later resolved."""
    from langgraph.types import Command
    from .. import filter_approval as filters
    out = Path(out)
    with command_lock(out):
        meta = verify(out, root)
        current = status(out, root)
        if current['state'] not in ('prepared_no_api', 'awaiting_hypothesis_review', 'awaiting_filter_review'):
            raise ValueError('Gói đã xong/bị ngắt; không gửi lại')
        first = current['state'] == 'prepared_no_api'
        if first:
            ledger = ledger_view(meta['ledger'])
            if ledger['pending'] or ledger['limit'] - ledger['known'] - ledger['held'] < budget.money(CAP):
                raise budget.BudgetError('Sổ cần không pending và ít nhất 1,20 USD còn được phép chi trước khi bắt đầu')
        # Do this before opening a fresh graph: missing credentials must leave preparation reusable.
        needs_key = first
        if current['state'] == 'awaiting_hypothesis_review':
            form = yaml.safe_load((Path(current['review_dir']) / approval.REVIEW_FILE).read_text(encoding='utf-8'))
            needs_key = any(g.get('quyet_dinh') == 'approved' for g in form['gia_thuyet'])
        if needs_key and not os.environ.get(config.load('llm_hunt', root)['api_key_env']):
            raise providers.LLMError('Thiếu biến khóa API; chưa bắt đầu pha')
        with graph_context(meta, out, root) as (graph, tools):
            if not first:
                snap = graph.get_state(session._thread(meta))
                if current['state'] == 'awaiting_hypothesis_review':
                    rd = Path(snap.values['review_dir'])
                    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
                    if any(not str(g.get('quyet_dinh') or '').strip() for g in form['gia_thuyet']):
                        raise ValueError('Phiếu ◆ còn mục chưa quyết định')
                    # Validate on a temporary copy so bad forms cannot start a paid phase or change saved decisions.
                    import tempfile, shutil
                    with tempfile.TemporaryDirectory() as temp:
                        copied = Path(temp) / 'review'
                        shutil.copytree(rd, copied)
                        approval.apply_review(copied)
                else:
                    rd = Path(snap.values['filter_review_dir'])
                    if (rd / filters.CANCEL).exists():
                        raise ValueError('Phiếu lọc đã hủy; không chạy tiếp')
                    filters.validate_form(rd, con=tools.con)
            # Key is needed only for phases that may invoke ④/⑤, not final execution after filter review.
            if needs_key and not os.environ.get(tools.llm_rules.api_key_env):
                raise providers.LLMError('Thiếu biến khóa API; chưa bắt đầu pha')
            if first:
                write(out / 'budget_baseline.json', {'ledger': meta['ledger'], 'known': ledger['known'], 'rows': ledger['rows']})
                write(out / 'start_pin.json', {'baseline_sha256': integrity.sha256_file(out / 'budget_baseline.json'),
                                             'meta_sha256': integrity.sha256_file(out / 'run_meta.json')})
            else:
                spend(out)  # Baseline integrity before any phase.
            phase = out / f"phase_{len(list(out.glob('phase_*.json'))):02d}.json"
            with phase.open('x', encoding='utf-8') as f:
                json.dump({'state': 'started_no_retry', 'from_state': current['state']}, f)
            try:
                graph.invoke(tools.initial_state() if first else Command(resume=True), session._thread(meta))
                write(phase, {'state': 'finished', 'from_state': current['state']})
            except BaseException as e:
                # Never record exception text (transport messages may contain reflected secrets).
                terminal = {'state': 'failed_no_retry', 'error_type': type(e).__name__, 'cap_usd': CAP,
                            'meaning': 'Pha bị ngắt; không tự gửi lại. Giữ checkpoint/API log và đối soát sổ.'}
                try:
                    terminal['budget'] = _spend_summary(out)
                except Exception:
                    terminal['budget'] = 'unknown_requires_manual_reconciliation'
                write(out / 'terminal.json', terminal)
                if not (out / 'hunt_record.md').exists():
                    (out / 'hunt_record.md').write_text(
                        '# Hunt record — gói phát triển bị ngắt\n\nPha gọi mô hình bị ngắt, không gửi lại.\n'
                        'Xem terminal.json, api_calls, checkpoint và các phiếu đã lưu.\n'
                        'Không kết luận không phát hiện; rule đang sinh dở chưa được thực thi.\n', encoding='utf-8')
                raise
    return status(out, root)
