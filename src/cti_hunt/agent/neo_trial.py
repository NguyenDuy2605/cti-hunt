"""Anchor (moc_neo) case through the real graph, 07/10: round 1 hunts the anchor TTP, round 2 the dependent TTP.

Self-authored sentences and synthetic Sysmon events with pre-registered expected records; catalog ③ v2.1 (ProcessGuid).
Round 2's ④ only sees the anchor after người vận hành approved it and the graph executed its rule (StageTools anchors).
Only the operator sends (`--send --cap-usd 0.50`); prepare/status never use HTTP or write the ledger. An interrupted paid phase
is never replayed. No planner model, no pivot, no real log, no labels.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import duckdb
import yaml

from .. import approval, config, filter_approval as filters, integrity
from ..contracts import ContractA, SourceSpan, TTP
from ..data.store import connect
from ..hunt import runner
from ..llm import budget, providers
from ..llm.prompting import fill, load_sections
from ..stages import s3_telemetry as S3, s4_hypothesis as S4
from . import session
from .emotet_trial import command_lock, ledger_view, read, write
from .graph import open_sqlite_graph

CAP = '0.50'
# Lượt 1 (07/10, tmp/thu_moc_neo_7-10) dùng câu neo "a process starts on a host…": ④ v6 trả 0 giả thuyết vì câu
# không nêu hành động cụ thể (quy tắc 3 của prompt). Lượt 2 (_lan2) dùng "the command interpreter fixture.exe…":
# ⑤ v5 không dùng tên riêng của report (v3 §3.5) nên neo rỗng. Lượt 3 dùng tên tiến trình hệ thống mức kỹ
# thuật (PowerShell), thứ ⑤ được phép săn; cmd.exe trong sự kiện bắt việc mở rộng sang "mọi trình thông dịch".
KIND = 'moc_neo_0710_v3'
OUT = config.ROOT / 'tmp/thu_moc_neo_7-10_lan3'
DATASET_ID = 'fixture-moc-neo-0710'
REPORT_ID = 'SELF-NEO-0710'
SYS = 'microsoft-windows-sysmon/operational'
ANCHOR_SEG, DEP_SEG = 'SELF-NEO-01-001', 'SELF-NEO-02-001'
QUOTES = [(ANCHOR_SEG, 'Execution', 'T1059',
           'Self-authored: PowerShell starts on a host.'),
          (DEP_SEG, 'Command and Control', 'T1105',
           'Self-authored: a file is created strictly after the process starts, within at most 75 seconds, '
           'on the same host with the same process GUID.')]
ANCHOR_REF, DEP_REF = 0, 1
FIELDS = ['Hostname', 'EventID', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ParentImage', 'ParentProcessGuid',
          'CommandLine', 'User', 'TargetFilename', 'CreationUtcTime', 'RuleName']
# (rec, eid, seconds, guid, host, image). Expected kept records are fixed before any model output.
PS = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
ROWS = [(100, 1, 0, 'g1', 'HOST-A', PS), (101, 1, 50, 'g2', 'HOST-A', r'C:\Fixture\other.exe'),
        (102, 1, 10, 'g3', 'HOST-A', r'C:\Windows\System32\cmd.exe'),
        (1, 11, 0, 'g1', 'HOST-A', PS), (2, 11, 75, 'g1', 'HOST-A', PS), (3, 11, 76, 'g1', 'HOST-A', PS),
        (4, 11, 1, 'g1', 'HOST-A', PS), (5, 11, -1, 'g1', 'HOST-A', PS), (6, 11, 1, 'g1', 'HOST-B', PS),
        (7, 11, 1, 'g2', 'HOST-A', r'C:\Fixture\other.exe')]
EXPECTED = {'anchor_selected': [100], 'dependent_selected': [1, 2, 3, 4, 5, 6, 7], 'dependent_kept': [2, 4]}


def contract() -> ContractA:
    return ContractA(report_id=REPORT_ID, title='Self-authored anchor case; not real CTI', ttps=[
        TTP(tactic=tactic, technique_id=tid, behavior_description=text, confidence=0.5,
            source_span=SourceSpan(segment_id=seg, text=text)) for seg, tactic, tid, text in QUOTES])


def write_events(path: Path) -> None:
    """Sysmon-only synthetic events, VARCHAR fields like production; no label column, no command encoding."""
    con = duckdb.connect()
    try:
        cols = ', '.join(f'"{f}" VARCHAR' for f in FIELDS)
        con.execute(f'CREATE TABLE e(ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec BIGINT, '
                    f'ev_ts TIMESTAMP, ev_ts_src VARCHAR, {cols})')
        for rec, eid, sec, guid, host, image in ROWS:
            ts = datetime(2020, 1, 1) + timedelta(seconds=sec)
            v = {'Hostname': host.lower() + '.fixture.local', 'EventID': str(eid), 'UtcTime': ts.isoformat(sep=' '),
                 'ProcessGuid': guid, 'ProcessId': '4242', 'Image': image, 'User': r'FIXTURE\user', 'RuleName': '-',
                 'ParentImage': r'C:\Fixture\parent.exe' if eid == 1 else None,
                 'ParentProcessGuid': 'g0' if eid == 1 else None,
                 'CommandLine': image.rsplit('\\', 1)[-1] + ' --self-authored' if eid == 1 else None,
                 'TargetFilename': rf'C:\Fixture\out\file{rec}.bin' if eid == 11 else None,
                 'CreationUtcTime': ts.isoformat(sep=' ') if eid == 11 else None}
            con.execute(f'INSERT INTO e VALUES (?, ?, ?, ?, ?, ?{", ?" * len(FIELDS)})',
                        [host, SYS, eid, rec, ts, 'UtcTime', *(v[f] for f in FIELDS)])
        con.execute(f"COPY (SELECT * FROM e ORDER BY ev_host, ev_rec) TO '{path.as_posix()}' (FORMAT PARQUET)")
    finally:
        con.close()


class AnchorPlanner:
    """Deterministic two rounds; the dependent TTP is hunted only after the anchor round executed a hunt."""

    def metadata(self):
        return {'kind': KIND, 'model': 'deterministic', 'llm_called': False,
                'anchor_ref': ANCHOR_REF, 'dependent_ref': DEP_REF}

    def __call__(self, view):
        prior = view['prior_decisions']
        if not prior:
            return {'action': 'hunt', 'ttp_refs': [ANCHOR_REF], 'pivot_targets': [],
                    'reason': 'Vòng 1: săn TTP neo (khởi động PowerShell) đã chốt.'}
        if len(prior) == 1 and view.get('last_round_executed') and DEP_REF in view['remaining_refs']:
            return {'action': 'hunt', 'ttp_refs': [DEP_REF], 'pivot_targets': [],
                    'reason': 'Vòng 2: TTP phụ thuộc; neo đã được duyệt và thực thi ở vòng 1 của lượt này.'}
        reason = ('Neo chưa có hunt được thực thi; không săn TTP phụ thuộc.' if len(prior) == 1 else
                  'Đã xong hai vòng đã chốt; không pivot.')
        return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [], 'reason': reason}


def spend(out, cap=CAP):
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
            'remaining': budget.money(cap) - used - now['held']}


class TrialClient:
    """Package cap from the shared-ledger delta (other spending counts too); request saved before the call."""

    def __init__(self, client, out, cap=CAP):
        self.client, self.out, self.cap = client, Path(out), cap

    def __getattr__(self, name):
        return getattr(self.client, name)

    def describe(self):
        return {**self.client.describe(), 'trial_total_cap_usd': self.cap}

    def complete_json(self, system, user, json_schema, log=None):
        current = spend(self.out, self.cap)
        if current['pending']:
            raise budget.BudgetError('Có yêu cầu chưa rõ chi phí; giữ nguyên và đối soát Console')
        if current['remaining'] < budget.min_reserve(self.model_id, self.max_output_tokens):
            raise budget.BudgetExhausted(f'Không đủ dự phòng trong trần gói {self.cap} USD; chưa gửi')
        self.client.request_budget_usd = budget.usd(current['remaining'])
        key = os.environ.get(self.api_key_env)
        if not key:
            raise providers.LLMError('Thiếu biến khóa API; chưa gửi')
        payload = self.client.build_payload(system, user, json_schema)
        calls = self.out / 'api_calls'
        calls.mkdir(exist_ok=True)
        index = len(list(calls.glob('call_*.json')))
        if index == 0 and payload != read(self.out / 'payload_khau4_round1.json'):
            raise ValueError('Yêu cầu ④ vòng 1 khác bản đã ghim; chưa gửi')
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
            if spend(self.out, self.cap)['remaining'] < 0:
                raise budget.BudgetError('Usage vượt trần gói; dừng, cần đối soát')
            if data.get('stop_reason') == 'max_tokens':
                raise providers.BadOutputError('Output bị cắt; không gửi lại pha này')
            return providers.read_response(data)
        except BaseException as e:
            saved = read(path)
            saved.update(error_type=type(e).__name__, api_events=safe)
            write(path, saved)
            raise


def _settings(root):
    cfg, lc = config.agent_config('v2', root), config.load('llm_hunt', root)
    if (cfg['prompt_khau4'] != 'prompts/khau4_gia_thuyet_v6.md' or cfg['prompt_khau5'] != 'prompts/khau5_sigma_v5.md'
            or cfg['max_hypotheses_per_round'] != 10 or cfg['max_repair_attempts'] != 2 or not cfg.get('sinh_rang_buoc')
            or config.telemetry_catalog('v2', root).name != 'telemetry_catalog_v2_1.yaml'):
        raise ValueError('Cấu hình/prompt/danh mục khác phạm vi đã chốt')
    if (lc['provider'] != 'anthropic' or lc['model'] != 'claude-sonnet-5' or lc['effort'] != 'high'
            or lc['max_output_tokens'] != 32000 or lc['request_timeout_giay'] != 600
            or lc.get('base_url') not in ('', None, 'https://api.anthropic.com')):
        raise ValueError('Mô hình/tham số không khớp phạm vi đã chốt')
    return cfg, lc


def prepare(out=OUT, root=config.ROOT):
    out, root = Path(out), Path(root)
    if out.exists():
        raise ValueError('Thư mục gói đã tồn tại; dùng --status, không chuẩn bị đè')
    cfg, lc = _settings(root)
    out.mkdir(parents=True)
    events = out / 'events'
    events.mkdir()
    write_events(events / 'events.parquet')
    ca = contract()
    write(out / 'contract_a.json', ca.model_dump(mode='json'))
    dry = session.start('pipeline', out / 'contract_a.json', events, out / 'not_created', dataset_kind='fixture',
                        dataset_id=DATASET_ID, root=root, version='v2', dry_run=True)
    if dry['so_ttp_vao_khau4'] != 2:
        raise ValueError('Không đủ 2 TTP vào ④')
    write(out / 'dry_run.json', dry)
    ledger = config.resolve(lc['budget_ledger'], root)
    paths = list(session.tracked_files(root, 'v2')) + ['scripts/thu_moc_neo.py']
    pins = {str(root / p): integrity.sha256_file(root / p) for p in paths}
    meta = {'runner': KIND, 'cap_usd': CAP, 'mode': 'pipeline', 'phien_ban': 'v2', 'thread_id': KIND,
            'contract_a': {'path': str((out / 'contract_a.json').resolve()),
                           'sha256': integrity.sha256_file(out / 'contract_a.json')},
            'events': {'dir': str(events.resolve()), 'parquet_sha256': integrity.sha256_file(events / 'events.parquet')},
            'dataset': {'kind': 'fixture', 'id': DATASET_ID, 'sha256': ''},
            'tep': session.tracked_files(root, 'v2'), 'git': session.git_state(root), 'moc_co_dinh': None,
            'pins': pins, 'ledger': str(ledger.resolve()), 'expected': EXPECTED}
    write(out / 'run_meta.json', meta)
    built = build(meta, out, root, paid=False)
    try:
        tools = built[1]
        if tools.initial_state()['remaining_refs'] != [ANCHOR_REF, DEP_REF]:
            raise ValueError('TTP vào ④ không đúng thứ tự/đủ hai ca')
        for ref, eid in ((ANCHOR_REF, 1), (DEP_REF, 11)):
            src = [s for s in S3.map_technique(ca.ttps[ref].technique_id, tools.telemetry).get('sources') or []
                   if s['channel'] == SYS and s['event_ids'] == [eid]]
            if len(src) != 1 or 'ProcessGuid' not in src[0]['key_fields']:
                raise ValueError('Danh mục hiệu lực thiếu ProcessGuid cho nguồn của ca neo')
        # Pin the round-1 request exactly as StageTools.propose builds it for the anchor TTP.
        subset = ca.model_copy(update={'ttps': [ca.ttps[ANCHOR_REF]]})
        inputs, _ = S4.select_inputs(subset, tools.telemetry)
        prompt = load_sections(root / cfg['prompt_khau4'])
        user = fill(prompt['sections']['USER'], report_id=ca.report_id, techniques=S4.render_inputs(inputs),
                    max_items=str(cfg['max_hypotheses_per_round']), executed_hypotheses=S4.render_anchors([]))
        write(out / 'payload_khau4_round1.json', tools.llm_hypotheses.build_payload(
            prompt['sections']['SYSTEM'], user, S4.output_model(cfg).model_json_schema()))
        _, sha = S3.write_profile(built[3], out)
        meta['ho_so'] = {'sha256': sha}
        meta['prepared_files'] = {n: integrity.sha256_file(out / n) for n in
                                  ('contract_a.json', 'dry_run.json', 'payload_khau4_round1.json', S3.PROFILE_FILE)}
        write(out / 'run_meta.json', meta)
    finally:
        built[1].con.close()
    lv = ledger_view(ledger)
    return {'state': 'prepared_no_api', 'out': str(out), 'cap_usd': CAP, 'expected': EXPECTED,
            'remaining_shared_usd': budget.usd(lv['limit'] - lv['known'] - lv['held']), 'pending': lv['pending']}


def verify(out, root):
    meta = read(out / 'run_meta.json')
    if meta.get('runner') != KIND or meta.get('cap_usd') != CAP:
        raise ValueError('Sai gói/trần đã chốt')
    if (out / 'start_pin.json').exists() and \
            integrity.sha256_file(out / 'run_meta.json') != read(out / 'start_pin.json')['meta_sha256']:
        raise ValueError('Metadata lượt đã đổi sau khi bắt đầu')
    session._check_unchanged({k: v for k, v in meta.items() if k != 'runner'}, root)
    if any(integrity.sha256_file(Path(p)) != s for p, s in meta['pins'].items()):
        raise ValueError('Mã/script đã đổi; không gửi')
    if any(integrity.sha256_file(out / p) != s for p, s in meta['prepared_files'].items()):
        raise ValueError('Tệp chuẩn bị đã đổi; không gửi')
    return meta


def build(meta, out, root, *, paid=True):
    _, tools, cfg, profile = session._build({k: v for k, v in meta.items() if k != 'runner'}, out, root)
    if paid:
        tools.llm_hypotheses = TrialClient(tools.llm_hypotheses, out)
        tools.llm_rules = TrialClient(tools.llm_rules, out)
    return AnchorPlanner(), tools, cfg, profile


@contextmanager
def graph_context(meta, out, root):
    built = build(meta, out, root)
    try:
        session._check_profile(meta, out, built[3])
        with open_sqlite_graph(built[0], built[1], built[2], out, out / session.CHECKPOINT_FILE) as graph:
            yield graph, built[1]
    finally:
        built[1].con.close()


def evaluate(meta, values) -> dict:
    """Pre-registered checks on the synthetic events, through the shared execution gate; no label exists here."""
    hyps = {h.hypothesis_id: h for p in values.get('approved_files') or [] for h in approval.load_hypotheses(Path(p))}
    seg = {hid: {s.segment_id for s in h.source_spans} for hid, h in hyps.items()}
    con = connect(Path(meta['events']['dir']))
    out = {'anchor': {}, 'dependent': {}}
    try:
        for f in values.get('executed_specs') or []:
            spec = runner.load_spec(Path(f['path']))
            filters.require_executable(spec, con=con)
            where = runner._scope_where(spec['scope'])
            kept = sorted(r[0] for r in con.execute(
                f"SELECT ev_rec FROM events WHERE {where} AND ({spec['candidates']})").fetchall())
            base = (spec.get('rang_buoc') or {}).get('candidates_goc', spec['candidates'])
            selected = sorted(r[0] for r in con.execute(
                f"SELECT ev_rec FROM events WHERE {where} AND ({base})").fetchall())
            h = hyps[f['hypothesis_id']]
            row = {'hypothesis_id': h.hypothesis_id, 'event_ids': spec['scope']['event_ids'],
                   'selected': selected, 'kept': kept, 'filters': len(spec.get('filters') or []),
                   'rang_buoc': h.rang_buoc.model_dump(mode='json', exclude_none=True) if h.rang_buoc else None}
            out['anchor' if ANCHOR_SEG in seg[h.hypothesis_id] else 'dependent'][h.hypothesis_id] = row
    finally:
        con.close()
    anchors = [r for r in out['anchor'].values() if r['event_ids'] == [1]]
    anchor_ids = {r['hypothesis_id'] for r in anchors}
    deps = [r for r in out['dependent'].values() if r['event_ids'] == [11]]
    neo = [r for r in deps if (r['rang_buoc'] or {}).get('moc_neo')]
    checks = {
        'anchor_executed_on_sysmon_1': bool(anchors),
        'anchor_selection_as_expected': bool(anchors) and all(
            r['selected'] == EXPECTED['anchor_selected'] for r in anchors),
        'dependent_moc_neo_to_executed_anchor': len(neo) == 1 and neo[0]['rang_buoc']['moc_neo']['gia_thuyet']
        in anchor_ids and neo[0]['rang_buoc']['moc_neo']['trong_vong_giay'] == 75
        and {f.lower() for f in neo[0]['rang_buoc']['moc_neo']['cung']} == {'ev_host', 'processguid'},
        'dependent_selection_keeps_every_file_event': len(neo) == 1 and neo[0]['selected'] == EXPECTED['dependent_selected'],
        'dependent_constrained_as_expected': len(neo) == 1 and neo[0]['kept'] == EXPECTED['dependent_kept'],
        'no_pivot': all(h['decision']['action'] in ('hunt', 'stop') for h in values.get('history') or []),
        'no_filter_applied': all(r['filters'] == 0 for part in out.values() for r in part.values())}
    return {'checks': checks, 'criteria_met': all(checks.values()), 'executed': out, 'expected': EXPECTED,
            'manual_review_required': True,
            'meaning': 'Kiểm chuỗi neo qua graph trên sự kiện tổng hợp tự soạn; không phải chất lượng săn trên log thật'}


def status(out=OUT, root=config.ROOT):
    out = Path(out)
    meta = verify(out, root)
    if (out / 'terminal.json').exists():
        return read(out / 'terminal.json')
    if any(read(p)['state'] == 'started_no_retry' for p in out.glob('phase_*.json')):
        return {'state': 'interrupted_no_retry', 'meaning': 'Không resume/gửi lại pha bị ngắt; giữ log và đối soát Console'}
    if not (out / session.CHECKPOINT_FILE).exists():
        lv = ledger_view(meta['ledger'])
        return {'state': 'prepared_no_api', 'cap_usd': CAP, 'out': str(out), 'expected': EXPECTED,
                'remaining_shared_usd': budget.usd(lv['limit'] - lv['known'] - lv['held']), 'pending': lv['pending']}
    with graph_context(meta, out, root) as (graph, _):
        snap = graph.get_state(session._thread(meta))
        if snap.values.get('record'):
            return {'state': 'completed', 'hunt_record': str(out / 'hunt_record.md'),
                    'evaluation': evaluate(meta, snap.values), 'budget': _spend_summary(out)}
        if 'review_filters' in snap.next:
            return {'state': 'awaiting_filter_review', 'review_dir': snap.values['filter_review_dir'],
                    'budget': _spend_summary(out)}
        if 'review' in snap.next:
            return {'state': 'awaiting_hypothesis_review', 'review_dir': snap.values['review_dir'],
                    'budget': _spend_summary(out)}
        raise ValueError('Checkpoint không ở điểm dừng an toàn; không gửi lại')


def _spend_summary(out, cap=CAP):
    s = spend(out, cap)
    return {'charged_delta_usd': budget.usd(s['charged_delta']), 'reserved_usd': budget.usd(s['held']),
            'remaining_package_usd': budget.usd(s['remaining']), 'pending': s['pending'],
            'meaning': 'delta sổ chung; chi ngoài gói trong thời gian thử cũng được tính bảo thủ vào trần'}


def advance(out=OUT, root=config.ROOT, *, cap_usd=None):
    """Explicit --send only. No phase replays after crashes, even if the shared ledger is later resolved."""
    from langgraph.types import Command
    import shutil
    import tempfile
    if cap_usd is None or budget.money(cap_usd) != budget.money(CAP):
        raise ValueError(f'Chỉ người vận hành gửi sau khi chốt: cần trần gói --cap-usd {CAP}')
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
                raise budget.BudgetError(f'Sổ cần không pending và ít nhất {CAP} USD còn được phép chi trước khi bắt đầu')
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
                    # Validate on a temporary copy so a bad form cannot start a paid phase or change saved decisions.
                    with tempfile.TemporaryDirectory() as temp:
                        copied = Path(temp) / 'review'
                        shutil.copytree(rd, copied)
                        approval.apply_review(copied)
                else:
                    rd = Path(snap.values['filter_review_dir'])
                    if (rd / filters.CANCEL).exists():
                        raise ValueError('Phiếu lọc đã hủy; không chạy tiếp')
                    filters.validate_form(rd, con=tools.con)
            if first:
                write(out / 'budget_baseline.json', {'ledger': meta['ledger'], 'known': ledger['known'],
                                                     'rows': ledger['rows']})
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
