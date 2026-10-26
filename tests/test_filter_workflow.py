"""Two separate review gates on fixture logs; all model calls are mocked."""
from datetime import timedelta
from pathlib import Path
import json

import pytest
import yaml

from cti_hunt import approval, cli, config, filter_approval as F, integrity
from cti_hunt.agent import session
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.hunt import runner
from cti_hunt.llm import providers


@pytest.fixture(autouse=True)
def without_breadth_gate(monkeypatch):
    """Module này kiểm cơ chế khác; cổng độ rộng/biến thể (phiếu rule v3, 15/10) kiểm ở test_duyet_rule_do_rong.py."""
    from cti_hunt import config as _config
    original = _config.agent_config
    def cfg_without(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_do_rong', None)
        return cfg
    monkeypatch.setattr(_config, 'agent_config', cfg_without)

SYS = 'microsoft-windows-sysmon/operational'
RULE = r"""title: Synthetic reviewed process
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith:
      - '\WmiPrvSE.exe'
      - '\services.exe'
      - '\wsmprovhost.exe'
  filter_fixture:
    Image|endswith: '\sppsvc.exe'
  condition: selection and not filter_fixture
"""


class Scripted:
    model_id = 'mock'
    def __init__(self):
        self.calls = []
        self.rule = RULE
        self.views = []
    def describe(self):
        return {'model': 'mock', 'kieu_api': 'mock'}
    def complete_json(self, system, user, json_schema, log=None):
        title = json_schema['title']
        self.calls.append(title)
        if title == 'LLMRule':
            return {'rule_yaml': self.rule}
        if title == '_PlannerOutput':
            self.views.append(user)
            return {'action': 'hunt' if self.calls.count(title) == 1 else 'stop',
                    'ttp_refs': [0] if self.calls.count(title) == 1 else [],
                    'pivot_targets': [], 'reason': 'synthetic fixture plan'}
        assert title == 'LLMHypothesisBatch'
        return {'items': [{'ttp_refs': [0], 'behavior': 'Synthetic remote process spawned by WmiPrvSE.exe, services.exe or wsmprovhost.exe',
                          'scope': 'all hosts', 'timeframe': 'toàn bộ log', 'data_source': SYS, 'event_ids': [1],
                          'key_fields': ['ParentImage', 'Image'], 'extra_techniques': [], 'priority': 'cao'}]}


@pytest.fixture
def client(monkeypatch):
    scripted = Scripted()
    monkeypatch.setattr(providers, 'from_config', lambda cfg: scripted)
    return scripted


@pytest.fixture
def contract(tmp_path):
    ca = ContractA(report_id='TU', ttps=[TTP(tactic='Lateral Movement', technique_id='T1047', confidence=0.9,
        behavior_description='Synthetic remote process',
        source_span=SourceSpan(segment_id='TU-001', text='Synthetic WMI process execution.'))])
    path = tmp_path / 'contract.json'
    path.write_text(ca.model_dump_json(), encoding='utf-8')
    return path


def human_hypothesis(rd):
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    choices = {r['id']: {'quyet_dinh': 'approved', 'ly_do': 'synthetic fixture approval'} for r in form['gia_thuyet']}
    approval.save_decisions(rd, 'fixture reviewer', choices, integrity.sha256_file(rd / approval.REVIEW_FILE))


def human_filters(rd, decision):
    form = F.load_form(rd)
    choices = {r['id']: {'quyet_dinh': decision, 'ly_do': 'synthetic fixture decision',
                         'can_cu': 'fixture definition', 'nguoi_chiu_trach_nhiem': 'fixture reviewer',
                         'hieu_luc_den_utc': (F.utcnow() + timedelta(hours=1)).isoformat()} for r in form['muc_loc']}
    F.save_decisions(rd, 'fixture reviewer', choices, integrity.sha256_file(rd / F.FORM))


def start_review(tmp_path, work, contract, mode='pipeline'):
    run = tmp_path / 'run'
    out = session.start(mode, contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    assert out['review_kind'] == 'hypothesis'
    human_hypothesis(Path(out['review_dir']))
    out = session.resume(run)
    assert out['review_kind'] == 'filter'
    return run, Path(out['review_dir'])


@pytest.mark.parametrize('mode', ['pipeline', 'agent'])
@pytest.mark.parametrize('decision, hits', [('approved', 3), ('rejected', 4)])
def test_two_gates_resume_reuses_rule_and_executes_only_decided_filters(tmp_path, work, contract, client, mode, decision, hits):
    run, rd = start_review(tmp_path, work, contract, mode)
    before = list(client.calls)
    manifest_sha = integrity.sha256_file(rd / F.MANIFEST)
    assert not (rd / F.EFFECTIVE).exists()
    assert session.inspect(run)['review_kind'] == 'filter'
    with pytest.raises(F.PendingFilterReview):
        session.resume(run)
    assert client.calls == before and integrity.sha256_file(rd / F.MANIFEST) == manifest_sha
    assert not (run / 'round_01/agent_execute.json').exists()
    human_filters(rd, decision)
    out = session.resume(run)
    assert out['trang_thai'] == 'xong'
    assert client.calls.count('LLMRule') == 1
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert len(rec['executed_specs']) == 1 and len(rec['history']) == 2
    assert rec['observations'][0]['stages'][-1]['hits'] == hits
    spec = runner.load_spec(Path(rec['executed_specs'][0]['path']))
    assert spec['filter_phase'] == 'effective'
    assert len(spec['filters']) == (decision == 'approved')
    assert approval.load_hypotheses(run / 'round_01' / approval.APPROVED_FILE)[0].status == 'approved'
    assert F._read(rd / 'execution_receipt.json')['kind'] == 'completed_execution'
    assert all('preview_only_unlabeled' not in view and 'fixture definition' not in view for view in client.views)
    # Thiết kế §9: Observe in hash gói đã áp, trùng đúng byte các tệp của gói.
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    row = (f"| round_01/r01 | {manifest_sha} | {integrity.sha256_file(rd / F.FORM)} | "
           f"{integrity.sha256_file(rd / 'approval_log.json')} | {integrity.sha256_file(rd / F.EFFECTIVE)} |")
    assert md.count(row) == 1 and md.index(row) < md.index('## Check')


@pytest.mark.parametrize('target', ['preview.json', 'manifest.json', '../../rules_draft/TU-H01.yml',
                                   '../../hypotheses_da_duyet.json', '../../duyet.yaml'])
def test_stale_packet_resume_blocks_without_model_calls(tmp_path, work, contract, client, target):
    run, rd = start_review(tmp_path, work, contract)
    human_filters(rd, 'rejected')
    path = rd / target
    path.write_bytes(path.read_bytes() + b'\n')
    before = list(client.calls)
    with pytest.raises(F.FilterReviewError):
        session.resume(run)
    assert client.calls == before and not (rd / F.EFFECTIVE).exists()


def test_no_filter_skips_only_second_gate(tmp_path, work, contract, client):
    client.rule = RULE.replace('selection and not filter_fixture', 'selection')
    run = tmp_path / 'run'
    out = session.start('pipeline', contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    human_hypothesis(Path(out['review_dir']))
    assert session.resume(run)['trang_thai'] == 'xong'
    log = F._read(run / 'round_01/filter_review/r01/approval_log.json')
    assert log['kind'] == 'no_filters' and log['nguoi_duyet'] == ''
    assert client.calls.count('LLMRule') == 1


def test_cli_v2_displays_correct_form_and_rejected_can_resume(tmp_path, work, contract, client, capsys):
    run = tmp_path / 'run'
    assert cli.main(['agent', 'start', '--mode', 'pipeline', '--phien-ban', 'v2', '--contract-a', str(contract),
                     '--events', str(work), '--dataset-kind', 'fixture', '--dataset-id', 'synthetic', '--out', str(run)]) == 0
    human_hypothesis(run / 'round_01')
    assert cli.main(['agent', 'resume', str(run)]) == 0
    assert 'duyet_loc.yaml' in capsys.readouterr().out
    rd = run / 'round_01/filter_review/r01'
    assert cli.main(['filter-review', 'finalize', str(rd), '--events', str(work)]) == 1
    human_filters(rd, 'rejected')
    assert cli.main(['agent', 'resume', str(run)]) == 0


def test_cancel_leaves_packet_and_no_false_empty_execution(tmp_path, work, contract, client):
    run, rd = start_review(tmp_path, work, contract)
    before = list(client.calls)
    sha = integrity.sha256_file(rd / F.FORM)
    assert cli.main(['filter-review', 'cancel', str(rd), '--nguoi-xac-nhan', 'fixture reviewer', '--ly-do', 'fixture stop']) == 0
    assert session.inspect(run)['trang_thai'] == 'da_huy'
    assert session.resume(run)['trang_thai'] == 'da_huy'
    assert not (rd / F.EFFECTIVE).exists() and not (run / 'round_01/agent_execute.json').exists()
    assert integrity.sha256_file(rd / F.FORM) == sha and client.calls == before
    assert session.inspect(run)['trang_thai'] == 'da_huy'
    assert session.resume(run)['trang_thai'] == 'da_huy'


def test_pipeline_batches_and_pivots_each_use_a_fresh_filter_gate(tmp_path, work, contract, client):
    ca = ContractA.model_validate_json(contract.read_text(encoding='utf-8'))
    base = ca.ttps[0]
    ca = ca.model_copy(update={'ttps': [base.model_copy(update={
        'behavior_description': f'Synthetic behavior {i}',
        'source_span': SourceSpan(segment_id=f'TU-{i:03}', text=f'Synthetic source {i}')}) for i in range(11)]})
    contract.write_text(ca.model_dump_json(), encoding='utf-8')
    run = tmp_path / 'run'
    out = session.start('pipeline', contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    kinds = []
    for _ in range(10):
        if out['trang_thai'] == 'xong':
            break
        rd = Path(out['review_dir'])
        kinds.append(out['review_kind'])
        if out['review_kind'] == 'hypothesis':
            human_hypothesis(rd)
        else:
            human_filters(rd, 'rejected')
        out = session.resume(run)
    assert out['trang_thai'] == 'xong'
    assert kinds == ['hypothesis', 'filter'] * 3
    record = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert [h['decision']['action'] for h in record['history']] == ['hunt', 'hunt', 'pivot', 'stop']
    assert len(record['executed_specs']) == 4 and client.calls.count('LLMRule') == 4
    pivots = [runner.load_spec(Path(s['path'])) for s in record['executed_specs'] if s['pivot_depth'] == 1]
    assert {s['scope']['hosts'][0] for s in pivots} == {'UTICA', 'NEWYORK'}
    assert all(s['sigma_context']['binding']['origin'] == 'pivot' for s in pivots)


def test_budget_exhausted_after_one_rule_keeps_draft_until_review(tmp_path, work, contract, client):
    from copy import deepcopy
    from cti_hunt.llm.budget import BudgetExhausted
    original = client.complete_json
    def limited(system, user, json_schema, log=None):
        if json_schema['title'] == 'LLMRule' and client.calls.count('LLMRule') == 1:
            client.calls.append('LLMRule')
            raise BudgetExhausted('synthetic budget cap before send')
        data = original(system, user, json_schema, log)
        if json_schema['title'] == 'LLMHypothesisBatch':
            second = deepcopy(data['items'][0])
            second['behavior'] = 'Second synthetic behavior'
            data['items'].append(second)
        return data
    client.complete_json = limited
    run, rd = start_review(tmp_path, work, contract)
    assert not (rd / F.EFFECTIVE).exists()
    packet = F.verify_packet(rd)
    assert len(packet['specs']) == 1 and packet['context']['budget_exhausted']
    human_filters(rd, 'rejected')
    assert session.resume(run)['trang_thai'] == 'xong'
    assert client.calls.count('LLMRule') == 2
    record = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert len(record['executed_specs']) == 1
    assert any(i['issues'][0]['kind'] == 'het_ngan_sach' for i in record['execution_issues'])


def test_stored_rule_prepare_finalize_and_execution_cli_never_builds_a_model(tmp_path, work, contract, client, monkeypatch):
    run, rd = start_review(tmp_path, work, contract)
    def forbidden(*args, **kwargs):
        pytest.fail('local filter operations must not instantiate an LLM')
    monkeypatch.setattr(providers, 'from_config', forbidden)
    out = tmp_path / 'stored_rule_run'
    assert cli.main(['filter-review', 'prepare', '--rule', str(run / 'round_01/rules_draft/TU-H01.yml'),
                     '--hypothesis-dir', str(run / 'round_01'), '--hypothesis-id', 'TU-H01',
                     '--events', str(work), '--out', str(out)]) == 0
    stored = out / 'filter_review/r01'
    assert cli.main(['filter-review', 'inspect', str(stored), '--events', str(work)]) == 0
    assert cli.main(['filter-review', 'execute', str(stored), '--events', str(work), '--out', str(tmp_path / 'pending.json')]) == 1
    assert not (tmp_path / 'pending.json').exists()
    human_filters(stored, 'rejected')
    assert cli.main(['filter-review', 'finalize', str(stored), '--events', str(work)]) == 0
    executed = tmp_path / 'executed.json'
    assert cli.main(['filter-review', 'execute', str(stored), '--events', str(work), '--out', str(executed)]) == 0
    assert json.loads(executed.read_text(encoding='utf-8'))['api_called'] is False


@pytest.mark.skipif(not (config.ROOT / "data" / "work" / "events.parquet").exists(), reason="chưa có data/work/events.parquet")
def test_v2_requires_its_own_milestone(work, contract, tmp_path, client, monkeypatch):
    from cti_hunt.agent import moc
    # Không dựa vào trạng thái mốc thật của repo (người vận hành đã khóa mốc v2 ngày 05/10): trỏ thư mục mốc sang chỗ trống.
    monkeypatch.setattr(moc, 'MOC_DIR', str(tmp_path / 'chua_co_moc'))
    assert moc.latest('pipeline', version='v2')[1] is None
    with pytest.raises(moc.MilestoneError, match='chưa có mốc'):
        session.start('pipeline', contract, config.resolve(config.load('dataset')['work_dir']), tmp_path / 'eval',
                      dataset_kind='danh_gia', version='v2', dry_run=True)


def test_v2_run_pins_and_uses_route_b_catalog(tmp_path, work, contract, client):
    # 02/10: lượt v2 dùng danh mục ③ tuyến B qua con trỏ telemetry_catalog_v2; tuyến A giữ danh mục 18 mục.
    from cti_hunt.stages import s3_telemetry
    run, _ = start_review(tmp_path, work, contract)
    meta = json.loads((run / 'run_meta.json').read_text(encoding='utf-8'))
    # 07/10: v2 trỏ sang v2.1 (thêm ProcessGuid); 09/10: sang v2.2 (B4). Các tệp đã dùng API giữ nguyên.
    assert 'configs/telemetry_catalog_v2_2.yaml' in meta['tep'] and 'configs/telemetry_catalog.yaml' not in meta['tep']
    profile = json.loads((run / 'ho_so_du_lieu.json').read_text(encoding='utf-8'))
    v1, v2 = (s3_telemetry.load_catalog(config.telemetry_catalog(v)) for v in ('v1', 'v2'))
    assert set(profile['ky_thuat']) == set(v2) and len(v2) > len(v1)
    assert 'configs/telemetry_catalog.yaml' in session.tracked_files() and \
        'configs/telemetry_catalog_v2_2.yaml' not in session.tracked_files()


@pytest.mark.parametrize('version, prompt', [('v1', 'prompts/agent_plan_v2.md'), ('v2', 'prompts/agent_plan_v4.md')])
def test_planner_stop_is_annotated_and_v2_prompt_leaves_budget_stops_to_code(tmp_path, work, contract, monkeypatch,
                                                                            version, prompt):
    # N5 (02/10): planner tự dừng khi bộ chặn bằng mã chưa kích hoạt thì nhật ký ghi phần còn lại.
    assert config.agent_config(version)['prompt_agent_plan'] == prompt

    class StopAtOnce:
        model_id = 'mock'
        def __init__(self):
            self.systems = []
        def describe(self):
            return {'model': 'mock', 'kieu_api': 'mock'}
        def complete_json(self, system, user, json_schema, log=None):
            assert json_schema['title'] == '_PlannerOutput'
            self.systems.append(system)
            return {'action': 'stop', 'ttp_refs': [], 'pivot_targets': [], 'reason': 'synthetic early stop'}

    scripted = StopAtOnce()
    monkeypatch.setattr(providers, 'from_config', lambda cfg: scripted)
    run = tmp_path / 'run'
    out = session.start('agent', contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version=version)
    assert out['trang_thai'] == 'xong'
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert rec['history'][0]['dung_do_planner'] == {'ttp_con_lai': 1, 'pivot_du_dieu_kien': 0,
                                                   'bo_chan_ngan_sach_kich_hoat': False}
    assert 'planner chọn dừng khi còn 1 TTP chưa săn' in (run / 'hunt_record.md').read_text(encoding='utf-8')
    assert rec['chi_phi_api_luot']['loi_goi'] == 0 and rec['chi_phi_api_luot']['nguon'] == 'nhat_ky_api_cua_luot'
    assert ('Never choose stop because of api_budget' in scripted.systems[0]) is (version == 'v2')
