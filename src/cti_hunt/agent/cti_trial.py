"""Real-CTI end-to-end run, 07/10: IcedID/ALPHV (The DFIR Report 2024) partial Contract A → ④ → ◆ → ⑤ → OTRF WMISUB.

One ④ batch for every TTP of the four extracted paragraphs, người vận hành reviews ◆ (and any filter form), executed on the
unlabeled OTRF development log; no pivot, no planner model, no labels. Only the operator sends (`--send --cap-usd 0.60`);
prepare/status never use HTTP or write the ledger. An interrupted paid phase is never replayed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml

from .. import approval, config, filter_approval as filters, integrity
from ..contracts import ContractA
from ..data.store import connect
from ..hunt import observe, runner
from ..llm import budget, providers
from ..llm.prompting import fill, load_sections
from ..stages import s3_telemetry as S3, s4_hypothesis as S4
from . import session
from .emotet_trial import command_lock, ledger_view, read, write
from .graph import open_sqlite_graph
from .neo_trial import TrialClient, _spend_summary, spend

CAP = '0.60'
KIND = 'cti_icedid_0710_v1'
OUT_REL = 'tmp/thu_cti_icedid_7-10/luot_graph'
EXTRACTION_REL = 'tmp/thu_cti_icedid_7-10/extract_4doan'
BUNDLE_REL = 'tmp/thu_cti_icedid_7-10/bundle2'
EVENTS_REL = 'data/dev/otrf-wmi-sub'
DATASET_ID = 'otrf-wmi-sub'
# Pinned inputs the operator produced on 07/10 (pha A, 0,099376 USD) and the source/log they came from.
CONTRACT_SHA256 = 'eb274964e33d9ce145e64b771cef713522c8b41cdd976a004e411fc708e97a0d'
BUNDLE_MANIFEST_SHA256 = '1cef04812f42f3defb092596955b29a9c11672a8f0df71cca8eae7a2d26e1455'
SOURCE_SHA256 = '86d59906864d114b9f1ab533c43d1ed5cd2a32752a0340cf8ebc2ad0f22aa715'
DATA_SHA256 = 'a507f2edd768b592e6b3157e974fd0468965eee00407387d88356ecb8fd20fea'
SELECTED = ['DEV-ICEDID-2024-0045', 'DEV-ICEDID-2024-0068', 'DEV-ICEDID-2024-0159', 'DEV-ICEDID-2024-0161']


class OnePassPlanner:
    def metadata(self):
        return {'kind': KIND, 'model': 'deterministic', 'llm_called': False}

    def __call__(self, view):
        if view['prior_decisions']:
            return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [],
                    'reason': 'Đã chạy một lô cho mọi TTP của bốn đoạn đã chọn; không pivot hay lô ④ tiếp theo.'}
        return {'action': 'hunt', 'ttp_refs': view['remaining_refs'], 'pivot_targets': [],
                'reason': 'Một lô cho toàn bộ TTP trích từ bốn đoạn CTI thật đã chọn.'}


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


def _check_sources(root):
    extraction, bundle = root / EXTRACTION_REL, root / BUNDLE_REL
    meta = read(extraction / 'meta.json')
    if (meta.get('status') != 'complete' or not meta.get('partial_extraction') or meta.get('selected_segments') != SELECTED
            or integrity.sha256_file(extraction / 'contract_a.json') != CONTRACT_SHA256
            or integrity.sha256_file(bundle / 'manifest.json') != BUNDLE_MANIFEST_SHA256
            or integrity.sha256_file(bundle / 'source.html') != SOURCE_SHA256
            or meta.get('bundle_manifest_sha256') != BUNDLE_MANIFEST_SHA256):
        raise ValueError('Contract A/bundle/nguồn khác bản đã chốt ở pha A')
    return extraction / 'contract_a.json'


def prepare(out=None, root=config.ROOT):
    root = Path(root)
    out = Path(out or root / OUT_REL)
    if out.exists():
        raise ValueError('Thư mục lượt đã tồn tại; dùng --status, không chuẩn bị đè')
    cfg, lc = _settings(root)
    source_ca = _check_sources(root)
    events = root / EVENTS_REL
    m = read(events / 'ingest_manifest.json')
    if m.get('dataset_id') != DATASET_ID or m.get('source_sha256') != DATA_SHA256:
        raise ValueError('Log khác bộ OTRF đã chốt')
    from .dev_data import check_manifest
    check_manifest(events, DATASET_ID, DATA_SHA256, root)
    session.check_dataset(events, root)
    out.mkdir(parents=True)
    shutil.copyfile(source_ca, out / 'contract_a.json')
    ca = ContractA.model_validate_json((out / 'contract_a.json').read_text(encoding='utf-8'))
    dry = session.start('pipeline', out / 'contract_a.json', events, out / 'not_created', dataset_kind='otrf_dev',
                        dataset_id=DATASET_ID, dataset_sha256=DATA_SHA256, root=root, version='v2', dry_run=True)
    write(out / 'dry_run.json', dry)
    ledger = config.resolve(lc['budget_ledger'], root)
    paths = list(session.tracked_files(root, 'v2')) + ['scripts/thu_cti_that.py']
    pins = {str(root / p): integrity.sha256_file(root / p) for p in paths}
    pins.update({str(p): integrity.sha256_file(p) for p in (
        root / EXTRACTION_REL / 'contract_a.json', root / EXTRACTION_REL / 'meta.json',
        root / BUNDLE_REL / 'manifest.json', root / BUNDLE_REL / 'source.html', events / 'ingest_manifest.json')})
    meta = {'runner': KIND, 'cap_usd': CAP, 'mode': 'pipeline', 'phien_ban': 'v2', 'thread_id': KIND,
            'contract_a': {'path': str((out / 'contract_a.json').resolve()),
                           'sha256': integrity.sha256_file(out / 'contract_a.json')},
            'events': {'dir': str(events.resolve()), 'parquet_sha256': integrity.sha256_file(events / 'events.parquet')},
            'dataset': {'kind': 'otrf_dev', 'id': DATASET_ID, 'sha256': DATA_SHA256},
            'tep': session.tracked_files(root, 'v2'), 'git': session.git_state(root), 'moc_co_dinh': None,
            'pins': pins, 'ledger': str(ledger.resolve()), 'selected_segments': SELECTED}
    write(out / 'run_meta.json', meta)
    built = build(meta, out, root, paid=False)
    try:
        tools = built[1]
        refs = tools.initial_state()['remaining_refs']
        if len(refs) != dry['so_ttp_vao_khau4'] or not refs:
            raise ValueError('Không có TTP nào vào ④')
        # Pin the single ④ request exactly as StageTools.propose builds it for this batch order.
        batch = ca.model_copy(update={'ttps': [ca.ttps[r] for r in refs]})
        inputs, _ = S4.select_inputs(batch, tools.telemetry)
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
    return {'state': 'prepared_no_api', 'out': str(out), 'cap_usd': CAP, 'ttp_vao_khau4': dry['so_ttp_vao_khau4'],
            'ttp_not_huntable': dry['so_ttp_not_huntable'],
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
        raise ValueError('Nguồn/mã/script đã đổi; không gửi')
    if any(integrity.sha256_file(out / p) != s for p, s in meta['prepared_files'].items()):
        raise ValueError('Tệp chuẩn bị đã đổi; không gửi')
    return meta


def build(meta, out, root, *, paid=True):
    _, tools, cfg, profile = session._build({k: v for k, v in meta.items() if k != 'runner'}, out, root)
    if paid:
        tools.llm_hypotheses = TrialClient(tools.llm_hypotheses, out, CAP)
        tools.llm_rules = TrialClient(tools.llm_rules, out, CAP)
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


def _tool(command_example: str) -> str:
    first = (command_example or '').strip().split()[0].lower() if (command_example or '').strip() else ''
    return first.rsplit('\\', 1)[-1].removesuffix('.exe')


def evaluate(meta, values, out) -> dict:
    """Pre-registered checks; hit counts describe an unlabeled lab log, never detection quality."""
    ca = ContractA.model_validate_json(Path(meta['contract_a']['path']).read_text(encoding='utf-8'))
    tools_by = {(t.technique_id, t.source_span.segment_id): _tool(t.context.command_example) for t in ca.ttps}
    generated = [h for d in sorted(Path(out).glob('round_*')) if (d / approval.HYP_FILE).exists()
                 for h in approval.load_hypotheses(d / approval.HYP_FILE)]
    approved = {h.hypothesis_id: h for p in values.get('approved_files') or []
                for h in approval.load_hypotheses(Path(p)) if h.status == 'approved'}
    con = connect(Path(meta['events']['dir']))
    rows, tool_ok = [], []
    try:
        for f in values.get('executed_specs') or []:
            spec = runner.load_spec(Path(f['path']))
            res = observe.unlabeled_result(con, spec, detail_limit=0)
            h = approved[f['hypothesis_id']]
            expected = sorted({tools_by.get((tid, s.segment_id), '') for tid in h.linked_ttps
                               for s in h.source_spans} - {''})
            cand = spec['candidates'].lower()
            found = {t: bool(re.search(rf'(?<![a-z0-9]){re.escape(t)}1?(?:\.exe)?(?![a-z0-9])', cand)) for t in expected}
            tool_ok.extend(found.values())
            rows.append({'hypothesis_id': h.hypothesis_id, 'linked_ttps': h.linked_ttps,
                         'source': res['hunt']['scope'], 'in_scope': res['pham_vi']['su_kien_trong_pham_vi'],
                         'stages': res['giai_doan'], 'filters_applied': len(spec.get('filters') or []),
                         'quoted_tools': found})
    finally:
        con.close()
    executed = {r['hypothesis_id'] for r in rows}
    checks = {'no_numeric_constraint': bool(generated) and all(h.rang_buoc is None for h in generated),
              'every_approved_executed': bool(approved) and set(approved) <= executed,
              'rule_uses_quoted_tool': all(tool_ok),
              'no_pivot': all(x['decision']['action'] in ('hunt', 'stop') for x in values.get('history') or [])}
    return {'checks': checks, 'criteria_met': all(checks.values()), 'generated': len(generated),
            'approved': sorted(approved), 'executed': rows, 'manual_review_required': True,
            'meaning': 'CTI thật trên log OTRF phát triển không nhãn; số trúng chỉ mô tả, không phải TP/FPR'}


def status(out=None, root=config.ROOT):
    root = Path(root)
    out = Path(out or root / OUT_REL)
    meta = verify(out, root)
    if (out / 'terminal.json').exists():
        return read(out / 'terminal.json')
    if any(read(p)['state'] == 'started_no_retry' for p in out.glob('phase_*.json')):
        return {'state': 'interrupted_no_retry', 'meaning': 'Không resume/gửi lại pha bị ngắt; giữ log và đối soát Console'}
    if not (out / session.CHECKPOINT_FILE).exists():
        lv = ledger_view(meta['ledger'])
        return {'state': 'prepared_no_api', 'cap_usd': CAP, 'out': str(out),
                'remaining_shared_usd': budget.usd(lv['limit'] - lv['known'] - lv['held']), 'pending': lv['pending']}
    with graph_context(meta, out, root) as (graph, _):
        snap = graph.get_state(session._thread(meta))
        if snap.values.get('record'):
            return {'state': 'completed', 'hunt_record': str(out / 'hunt_record.md'),
                    'evaluation': evaluate(meta, snap.values, out), 'budget': _spend_summary(out, CAP)}
        if 'review_filters' in snap.next:
            return {'state': 'awaiting_filter_review', 'review_dir': snap.values['filter_review_dir'],
                    'budget': _spend_summary(out, CAP)}
        if 'review' in snap.next:
            return {'state': 'awaiting_hypothesis_review', 'review_dir': snap.values['review_dir'],
                    'budget': _spend_summary(out, CAP)}
        raise ValueError('Checkpoint không ở điểm dừng an toàn; không gửi lại')


def advance(out=None, root=config.ROOT, *, cap_usd=None):
    """Explicit --send only. No phase replays after crashes, even if the shared ledger is later resolved."""
    from langgraph.types import Command
    if cap_usd is None or budget.money(cap_usd) != budget.money(CAP):
        raise ValueError(f'Chỉ người vận hành gửi sau khi chốt: cần trần gói --cap-usd {CAP}')
    root = Path(root)
    out = Path(out or root / OUT_REL)
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
                spend(out, CAP)  # Baseline integrity before any phase.
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
                    terminal['budget'] = _spend_summary(out, CAP)
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
