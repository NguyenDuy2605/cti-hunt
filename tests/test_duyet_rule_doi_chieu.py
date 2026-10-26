"""Cổng giữ/bỏ rule có mục đối chiếu (09/10): fixture tổng hợp, mọi lời gọi mô hình là giả lập, không API."""
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
NO_FILTER = RULE.replace('selection and not filter_fixture', 'selection')
# Giả thuyết nêu đủ ba giá trị của khối ứng viên → không có mục đối chiếu; câu chung → ba mục.
GROUNDED = 'Synthetic remote process spawned by WmiPrvSE.exe, services.exe or wsmprovhost.exe'
UNGROUNDED = 'Synthetic remote process hypothesis'


class Scripted:
    model_id = 'mock'
    def __init__(self, behaviors):
        self.calls, self.rule, self.behaviors = [], RULE, behaviors
        self.rules = []                                  # rule riêng theo thứ tự lời gọi ⑤; hết thì dùng self.rule
    def describe(self):
        return {'model': 'mock', 'kieu_api': 'mock'}
    def complete_json(self, system, user, json_schema, log=None):
        title = json_schema['title']
        self.calls.append(title)
        if title == 'LLMRule':
            return {'rule_yaml': self.rules.pop(0) if self.rules else self.rule}
        if title == '_PlannerOutput':
            first = self.calls.count(title) == 1
            return {'action': 'hunt' if first else 'stop', 'ttp_refs': [0] if first else [],
                    'pivot_targets': [], 'reason': 'synthetic fixture plan'}
        assert title == 'LLMHypothesisBatch'
        return {'items': [{'ttp_refs': [0], 'behavior': b, 'scope': 'all hosts', 'timeframe': 'toàn bộ log',
                           'data_source': SYS, 'event_ids': [1], 'key_fields': ['ParentImage', 'Image'],
                           'extra_techniques': [], 'priority': 'cao'} for b in self.behaviors]}


@pytest.fixture(autouse=True)
def without_breadth_gate(monkeypatch):
    """Module này kiểm phiếu v2 (mục đối chiếu); cổng độ rộng (phiếu v3, 15/10) kiểm ở test_duyet_rule_do_rong.py."""
    original = config.agent_config
    def cfg_v2(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_do_rong', None)
        return cfg
    monkeypatch.setattr(config, 'agent_config', cfg_v2)


@pytest.fixture
def scripted(monkeypatch):
    def make(*behaviors, rule=RULE):
        client = Scripted(list(behaviors))
        client.rule = rule
        monkeypatch.setattr(providers, 'from_config', lambda cfg: client)
        return client
    return make


@pytest.fixture
def contract(tmp_path):
    ca = ContractA(report_id='TU', ttps=[TTP(tactic='Lateral Movement', technique_id='T1047', confidence=0.9,
        behavior_description='Synthetic remote process',
        source_span=SourceSpan(segment_id='TU-001', text='Synthetic WMI process execution.'))])
    path = tmp_path / 'contract.json'
    path.write_text(ca.model_dump_json(), encoding='utf-8')
    return path


def approve_hypotheses(rd):
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    choices = {r['id']: {'quyet_dinh': 'approved', 'ly_do': 'synthetic fixture approval'} for r in form['gia_thuyet']}
    approval.save_decisions(rd, 'fixture reviewer', choices, integrity.sha256_file(rd / approval.REVIEW_FILE))


def reject_filters(rd):
    form = F.load_form(rd)
    choices = {r['id']: {'quyet_dinh': 'rejected', 'ly_do': 'synthetic fixture decision',
                         'can_cu': 'fixture definition', 'nguoi_chiu_trach_nhiem': 'fixture reviewer',
                         'hieu_luc_den_utc': (F.utcnow() + timedelta(hours=1)).isoformat()} for r in form['muc_loc']}
    F.save_decisions(rd, 'fixture reviewer', choices, integrity.sha256_file(rd / F.FORM))


def decide_rules(rd, decisions, reviewer='fixture reviewer'):
    F.save_rule_decisions(rd, reviewer, decisions, integrity.sha256_file(rd / F.RULE_FORM))


def start(tmp_path, work, contract, mode='pipeline'):
    run = tmp_path / 'run'
    out = session.start(mode, contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    assert out['review_kind'] == 'hypothesis'
    approve_hypotheses(Path(out['review_dir']))
    return run, session.resume(run)


def to_filter_gate(tmp_path, work, contract, mode='pipeline'):
    run, out = start(tmp_path, work, contract, mode)
    assert out['review_kind'] == 'filter'
    return run, Path(out['review_dir'])


def spec_ids(rd):
    return {s['hypothesis_id']: s['id'] for s in F.verify_packet(rd)['specs']}


def test_rule_with_added_values_is_listed_and_holds_whole_batch(tmp_path, work, contract, scripted):
    client = scripted(GROUNDED, UNGROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract, 'agent')
    ids = spec_ids(rd)
    h01, h02 = sorted(ids)
    form = F.load_rule_form(rd)
    assert form['quy_tac_duyet'] == F.RULE_POLICY and form['nguoi_duyet'] == ''
    assert form['manifest_sha256'] == integrity.sha256_file(rd / F.MANIFEST)
    assert [r['id'] for r in form['rule']] == [ids[h02]]          # giả thuyết nêu đủ giá trị thì không vào phiếu
    row = form['rule'][0]
    assert row['hypothesis_id'] == h02 and row['quyet_dinh'] == '' and row['ly_do'] == ''
    assert all(i['truong'] == 'ParentImage' and i['khoi'] == 'selection' for i in row['doi_chieu'])
    assert len(row['doi_chieu']) == 3 and 'filter_fixture' not in json.dumps(row)
    assert F.verify_packet(rd)['doi_chieu_rule'][0]['doi_chieu'] == row['doi_chieu']
    reject_filters(rd)
    before = list(client.calls)
    with pytest.raises(F.PendingFilterReview, match='rule'):
        session.resume(run)
    assert client.calls == before and not (run / 'round_01/agent_execute.json').exists()
    assert not (rd / F.EFFECTIVE).exists() and session.inspect(run)['review_kind'] == 'filter'


def test_rule_form_accepts_only_keep_or_drop_with_reason(tmp_path, work, contract, scripted):
    scripted(UNGROUNDED)
    _, rd = to_filter_gate(tmp_path, work, contract)
    rid = F.load_rule_form(rd)['rule'][0]['id']
    original = (rd / F.RULE_FORM).read_bytes()
    for choice, match in (({'quyet_dinh': 'bo', 'ly_do': ' '}, 'lý do'),
                          ({'quyet_dinh': 'approved', 'ly_do': ''}, 'giu, bo hoặc rut_gon'),
                          ({'quyet_dinh': 'giu', 'doi_chieu': []}, 'trường người điền')):
        with pytest.raises(F.FilterReviewError, match=match):
            decide_rules(rd, {rid: choice})
    with pytest.raises(F.FilterReviewError, match='nguoi_duyet'):
        decide_rules(rd, {rid: {'quyet_dinh': 'giu', 'ly_do': ''}}, reviewer=' ')
    with pytest.raises(F.FilterReviewError, match='đã đổi'):
        F.save_rule_decisions(rd, 'fixture reviewer', {rid: {'quyet_dinh': 'giu'}}, 'a' * 64)
    assert (rd / F.RULE_FORM).read_bytes() == original
    form = F.load_rule_form(rd)
    form['rule'][0]['doi_chieu'] = []
    (rd / F.RULE_FORM).write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding='utf-8')
    with pytest.raises(F.FilterReviewError, match='bất biến'):
        F.validate_form(rd, complete=False)


@pytest.mark.parametrize('decision', ['giu', 'bo'])
def test_keep_or_drop_decides_what_runs_and_is_logged(tmp_path, work, contract, scripted, decision):
    scripted(GROUNDED, UNGROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract, 'agent')
    ids = spec_ids(rd)
    h01, h02 = sorted(ids)
    reject_filters(rd)
    reason = 'synthetic: điều kiện không có trong giả thuyết' if decision == 'bo' else ''
    decide_rules(rd, {ids[h02]: {'quyet_dinh': decision, 'ly_do': reason}})
    assert session.resume(run)['trang_thai'] == 'xong'
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    executed = [s['hypothesis_id'] for s in rec['executed_specs']]
    assert sorted(executed) == ([h01, h02] if decision == 'giu' else [h01])
    ex = json.loads((run / 'round_01/agent_execute.json').read_text(encoding='utf-8'))
    dropped = [i for i in rec['execution_issues'] if i['issues'][0]['kind'] == 'nguoi_duyet_bo_rule']
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    if decision == 'bo':
        assert ex['rule_bi_bo'] == [{'hunt_id': ids[h02], 'hypothesis_id': h02, 'ly_do': reason}]
        assert [i['hypothesis_id'] for i in dropped] == [h02]
        assert '## Giả thuyết bị chặn trước thực thi' in md and f'{h02}: người duyệt bỏ rule' in md and reason in md
    else:
        assert 'rule_bi_bo' not in ex and dropped == []
    log = F._read(rd / 'approval_log.json')
    form = F.load_rule_form(rd)
    assert log['phieu_rule_sha256'] == integrity.sha256_file(rd / F.RULE_FORM)
    assert log['quyet_dinh_rule'] == form['rule'] and log['nguoi_duyet_rule'] == 'fixture reviewer'
    assert F._read(rd / 'execution_receipt.json')['kind'] == 'completed_execution'
    files = F.finalize(rd)                                        # gọi lại: đọc gói đã xuất, không xuất lại
    assert [str(p) for p in files] == [s['path'] for s in rec['executed_specs']]
    spec = runner.load_spec(files[0])
    F.require_executable(spec)
    form['rule'][0]['ly_do'] = 'sửa sau khi đã thực thi'
    (rd / F.RULE_FORM).write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding='utf-8')
    with pytest.raises(F.FilterReviewError):
        F.finalize(rd)
    with pytest.raises(F.FilterReviewError, match='rule'):
        F.require_executable(spec)


def test_all_rules_dropped_runs_nothing_and_says_so(tmp_path, work, contract, scripted):
    scripted(UNGROUNDED, rule=NO_FILTER)
    run, rd = to_filter_gate(tmp_path, work, contract)
    assert F.load_form(rd)['muc_loc'] == []                       # không có mục lọc vẫn dừng vì phiếu rule
    rid = F.load_rule_form(rd)['rule'][0]['id']
    decide_rules(rd, {rid: {'quyet_dinh': 'bo', 'ly_do': 'synthetic drop'}})
    assert session.resume(run)['trang_thai'] == 'xong'
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert rec['executed_specs'] == [] and rec['observations'] == []
    assert F._read(rd / 'execution_receipt.json')['kind'] == 'no_executable_rules'
    assert F._read(rd / F.EFFECTIVE)['files'] == {}
    assert [i['issues'][0]['kind'] for i in rec['execution_issues']] == ['nguoi_duyet_bo_rule']
    assert F.finalize(rd) == []
    form = F.load_rule_form(rd)
    form['rule'][0]['quyet_dinh'] = 'giu'
    (rd / F.RULE_FORM).write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding='utf-8')
    with pytest.raises(F.FilterReviewError):
        F.finalize(rd)


def test_grounded_rule_without_filters_skips_the_gate(tmp_path, work, contract, scripted):
    scripted(GROUNDED, rule=NO_FILTER)
    run, out = start(tmp_path, work, contract)
    assert out['trang_thai'] == 'xong'
    rd = run / 'round_01/filter_review/r01'
    assert F.verify_packet(rd)['doi_chieu_rule'] == [] and not (rd / F.RULE_FORM).exists()
    F.validate_form(rd)


def test_flag_off_keeps_old_packet_and_refuses_a_stray_rule_form(tmp_path, work, contract, scripted, monkeypatch):
    original = config.agent_config
    def without_gate(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop('duyet_rule_doi_chieu', None)
        return cfg
    monkeypatch.setattr(config, 'agent_config', without_gate)
    scripted(UNGROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract)
    assert 'doi_chieu_rule' not in F.verify_packet(rd) and not (rd / F.RULE_FORM).exists()
    reject_filters(rd)
    (rd / F.RULE_FORM).write_text('rule: []\n', encoding='utf-8')
    with pytest.raises(F.FilterReviewError, match='không thuộc gói'):
        session.resume(run)
    (rd / F.RULE_FORM).unlink()
    assert session.resume(run)['trang_thai'] == 'xong'
    assert 'phieu_rule_sha256' not in F._read(rd / 'approval_log.json')


def test_cli_points_to_rule_form_and_inspect_shows_it(tmp_path, work, contract, scripted, capsys):
    scripted(UNGROUNDED)
    run = tmp_path / 'run'
    assert cli.main(['agent', 'start', '--mode', 'pipeline', '--phien-ban', 'v2', '--contract-a', str(contract),
                     '--events', str(work), '--dataset-kind', 'fixture', '--dataset-id', 'synthetic', '--out', str(run)]) == 0
    approve_hypotheses(run / 'round_01')
    capsys.readouterr()
    assert cli.main(['agent', 'resume', str(run)]) == 0
    rd = run / 'round_01/filter_review/r01'
    assert str(rd / F.RULE_FORM) in capsys.readouterr().out
    assert cli.main(['filter-review', 'inspect', str(rd)]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown['rule_form'] == F.load_rule_form(rd)


def test_ui_rule_form_saves_only_the_human_fields(tmp_path, work, contract, scripted):
    from streamlit.testing.v1 import AppTest
    scripted(UNGROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract)
    rid = F.load_rule_form(rd)['rule'][0]['id']
    keep = {p.name: p.read_bytes() for p in rd.iterdir() if p.is_file() and p.name != F.RULE_FORM}
    app = tmp_path / 'rule_app.py'
    app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import filter_form\n"
                   f"filter_form(Path({str(rd)!r}), Path({str(run)!r}))\n", encoding='utf-8')
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception and not at.error
    assert [x.value for x in at.selectbox if x.label == 'Giữ/bỏ rule'] == ['']
    next(x for x in at.text_input if x.label == 'Người duyệt rule').set_value('synthetic UI tester')
    next(x for x in at.selectbox if x.label == 'Giữ/bỏ rule').set_value('bo')
    next(x for x in at.text_input if x.label == 'Lý do (bắt buộc khi bỏ, rút gọn, giữ rule rộng hoặc chọn biến thể)').set_value('synthetic UI drop')
    next(x for x in at.button if x.label == 'Lưu quyết định rule').click().run()
    assert not at.exception and not at.error
    row = F.load_rule_form(rd)['rule'][0]
    assert (row['id'], row['quyet_dinh'], row['ly_do']) == (rid, 'bo', 'synthetic UI drop')
    assert F.load_rule_form(rd)['nguoi_duyet'] == 'synthetic UI tester'
    assert keep == {p.name: p.read_bytes() for p in rd.iterdir() if p.is_file() and p.name != F.RULE_FORM}


def _check_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location('kiem_cong_rule_test', config.ROOT / 'scripts/kiem_cong_rule.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_read_only_check_script_confirms_and_catches_a_missing_record_line(tmp_path, work, contract, scripted):
    script = _check_script()
    scripted(GROUNDED, UNGROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract, 'agent')
    ids = spec_ids(rd)
    h02 = sorted(ids)[1]
    reject_filters(rd)
    decide_rules(rd, {ids[h02]: {'quyet_dinh': 'bo', 'ly_do': 'synthetic drop'}})
    assert session.resume(run)['trang_thai'] == 'xong'
    before = {p: p.read_bytes() for p in run.rglob('*') if p.is_file()}
    result = script.check(run)
    assert result['dat'] and result['kich_hoat'] and (result['so_rule_co_muc'], result['so_giu'], result['so_bo']) == (1, 0, 1)
    packet, = result['goi']
    assert all(packet['kiem'].values()) and packet['quyet_dinh'][0]['hypothesis_id'] == h02
    assert before == {p: p.read_bytes() for p in run.rglob('*') if p.is_file()}     # chỉ đọc
    md = run / 'hunt_record.md'
    md.write_text(md.read_text(encoding='utf-8').replace(f'{h02}: người duyệt bỏ rule', f'{h02}: '), encoding='utf-8')
    result = script.check(run)
    assert not result['dat'] and not result['goi'][0]['kiem']['record_ghi_rule_bo']
    assert script.main([str(run)]) == 1


def test_read_only_check_script_marks_a_run_without_items_as_not_triggered(tmp_path, work, contract, scripted):
    script = _check_script()
    scripted(GROUNDED)
    run, rd = to_filter_gate(tmp_path, work, contract)
    reject_filters(rd)
    assert session.resume(run)['trang_thai'] == 'xong'
    result = script.check(run)
    assert result['dat'] and not result['kich_hoat'] and result['so_rule_co_muc'] == 0


def test_stored_rows_recompute_exactly_for_a_multi_block_rule(tmp_path, work, contract, scripted):
    # 10/10 (G1): khối/trường của rule không theo thứ tự chữ cái; manifest lưu JSON sắp khóa. Tính lại phải trùng byte.
    multi = r"""title: Synthetic multi block
logsource: {product: windows, category: process_creation}
detection:
  selection_z:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith: '\cmd.exe'
  selection_a:
    Image|endswith: '\fixture-tool.exe'
  condition: 1 of selection_*
"""
    scripted(UNGROUNDED, rule=multi)
    run, rd = to_filter_gate(tmp_path, work, contract)
    m = F._read(rd / F.MANIFEST)
    rows = m['doi_chieu_rule']
    assert len(rows) == 1 and {i['khoi'] for i in rows[0]['doi_chieu']} == {'selection_a', 'selection_z'}
    assert F._grounding_rows(m['specs']) == rows
    rid = rows[0]['id']
    decide_rules(rd, {rid: {'quyet_dinh': 'giu', 'ly_do': ''}})
    assert session.resume(run)['trang_thai'] == 'xong'
    packet, = _check_script().check(run)['goi']
    assert packet['kiem']['tinh_lai_khop'] and all(packet['kiem'].values())


# 10/10: rút gọn rule — bỏ đúng các mục chọn, phát bản sửa của gói để duyệt lại rồi mới chạy.
SHORTEN = r"""title: Synthetic shorten
logsource: {product: windows, category: process_creation}
detection:
  selection_tool:
    Image|endswith: '\fixture-tool.exe'
  selection_parent:
    ParentImage|endswith: '\WmiPrvSE.exe'
  condition: 1 of selection_*
"""


def _item(rd, value):
    row, = F.load_rule_form(rd)['rule']
    return row['id'], next(n for n, i in enumerate(row['doi_chieu']) if i['gia_tri'] == value)


def test_shorten_issues_a_revision_that_is_reviewed_again_before_it_runs(tmp_path, work, contract, scripted):
    client = scripted(UNGROUNDED, rule=SHORTEN)
    run, r01 = to_filter_gate(tmp_path, work, contract)
    assert F.load_rule_form(r01)['quy_tac_duyet'] == F.RULE_POLICY == 'duyet_rule_khau5_v2'
    rid, n = _item(r01, 'fixture-tool.exe')
    for bad, match in (({'quyet_dinh': 'rut_gon', 'ly_do': 'x', 'bo_muc': []}, 'bo_muc'),
                       ({'quyet_dinh': 'giu', 'ly_do': '', 'bo_muc': [n]}, 'bo_muc'),
                       ({'quyet_dinh': 'rut_gon', 'ly_do': 'x', 'bo_muc': [9]}, 'bo_muc'),
                       ({'quyet_dinh': 'rut_gon', 'ly_do': 'x', 'bo_muc': [n, n]}, 'bo_muc'),
                       ({'quyet_dinh': 'rut_gon', 'ly_do': ' ', 'bo_muc': [n]}, 'lý do')):
        with pytest.raises(F.FilterReviewError, match=match):
            decide_rules(r01, {rid: bad})
    reason = 'synthetic: tên công cụ giả thuyết không nêu'
    decide_rules(r01, {rid: {'quyet_dinh': 'rut_gon', 'ly_do': reason, 'bo_muc': [n]}})
    with pytest.raises(F.FilterReviewError, match='rút gọn'):
        F.finalize(r01)                                                       # chưa phát bản sửa thì không chạy
    calls = list(client.calls)
    out = session.resume(run)
    r02 = r01.parent / 'r02'
    assert (out['trang_thai'], out['review_kind'], Path(out['review_dir'])) == ('cho_duyet', 'filter', r02.resolve())
    assert client.calls == calls                                              # bản sửa không gọi mô hình
    assert (r01 / F.REVISION).exists() and not (r01 / F.EFFECTIVE).exists()
    with pytest.raises(F.FilterReviewError, match='bản sửa'):
        F.finalize(r01)                                                       # gói cũ bị khóa
    m2 = F.verify_packet(r02)
    prov = m2['context']['ban_sua_cua']
    assert prov['goi'] == 'r01' and prov['manifest_sha256'] == integrity.sha256_file(r01 / F.MANIFEST)
    assert [(c['id'], c['ly_do'], [i['gia_tri'] for i in c['bo_muc']]) for c in prov['rut_gon']] == \
           [(rid, reason, ['fixture-tool.exe'])]
    spec, = m2['specs']
    assert spec['sigma_context']['rule']['detection'] == {'selection_parent': {'ParentImage|endswith': '\\WmiPrvSE.exe'},
                                                          'condition': 'selection_parent'}
    row, = F.load_rule_form(r02)['rule']                                     # mục còn lại phải được quyết lại
    assert [i['gia_tri'] for i in row['doi_chieu']] == ['wmiprvse.exe'] and row['quyet_dinh'] == ''
    with pytest.raises(F.PendingFilterReview):
        session.resume(run)
    decide_rules(r02, {row['id']: {'quyet_dinh': 'giu', 'ly_do': '', 'bo_muc': []}})
    assert session.resume(run)['trang_thai'] == 'xong'
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    executed, = rec['executed_specs']
    assert 'selection_tool' not in runner.load_spec(Path(executed['path']))['sigma_context']['rule']['detection']
    assert rec['observations'][0]['stages'][-1]['hits'] == 1
    ex = json.loads((run / 'round_01/agent_execute.json').read_text(encoding='utf-8'))
    assert [(c['goi'], c['id']) for c in ex['rule_rut_gon']] == [('r01', rid)]
    md = (run / 'hunt_record.md').read_text(encoding='utf-8')
    assert '## Rule người duyệt rút gọn trước thực thi' in md and 'Image = fixture-tool.exe' in md and reason in md
    result = _check_script().check(run)
    assert result['dat'] and result['kich_hoat'], result
    form = F.load_rule_form(r01)                                              # sửa phiếu gói cũ: bản sửa hết hợp lệ
    form['rule'][0]['ly_do'] = 'sửa sau khi đã có bản sửa'
    (r01 / F.RULE_FORM).write_text(yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding='utf-8')
    with pytest.raises(F.FilterReviewError):
        F.verify_packet(r02)


def test_shortening_every_candidate_condition_is_refused_and_the_gate_stays(tmp_path, work, contract, scripted):
    scripted(UNGROUNDED, rule=NO_FILTER)                                    # một khối, ba giá trị ParentImage
    run, r01 = to_filter_gate(tmp_path, work, contract)
    row, = F.load_rule_form(r01)['rule']
    decide_rules(r01, {row['id']: {'quyet_dinh': 'rut_gon', 'ly_do': 'synthetic',
                                   'bo_muc': list(range(len(row['doi_chieu'])))}})
    with pytest.raises(F.FilterReviewError, match='không còn'):
        session.resume(run)
    assert not (r01.parent / 'r02').exists() and not (r01 / F.REVISION).exists()
    info = session.inspect(run)
    assert info.get('review_kind') == 'filter', info                         # lượt vẫn ở cổng, đổi quyết định được
    decide_rules(r01, {row['id']: {'quyet_dinh': 'bo', 'ly_do': 'synthetic drop', 'bo_muc': []}})
    assert session.resume(run)['trang_thai'] == 'xong'


def test_v1_rule_form_of_an_old_packet_still_validates_without_shortening(tmp_path):
    rd = tmp_path / 'r01'
    rd.mkdir()
    item = {'kind': 'gia_tri_khong_co_trong_gia_thuyet', 'khoi': 'selection', 'truong': 'Image', 'gia_tri': 'x.exe'}
    m = {'doi_chieu_rule': [{'id': 'TU-H01__x', 'hypothesis_id': 'TU-H01', 'doi_chieu': [item], 'content_sha256': '0'}]}
    (rd / F.MANIFEST).write_text(json.dumps(m), encoding='utf-8')            # gói trước 10/10: không có chính sách
    def form(decision, policy=F.RULE_POLICY_V1, **extra):
        row = {**m['doi_chieu_rule'][0], 'quyet_dinh': decision, 'ly_do': 'synthetic', **extra}
        return {'manifest_sha256': integrity.sha256_file(rd / F.MANIFEST), 'quy_tac_duyet': policy,
                'nguoi_duyet': 'fixture reviewer', 'rule': [row]}
    assert F.validate_rule_form(rd, m, proposed=form('bo'))['rule'][0]['quyet_dinh'] == 'bo'
    for bad, match in ((form('rut_gon'), 'giu hoặc bo'), (form('bo', bo_muc=[]), 'bất biến'),
                       (form('bo', policy=F.RULE_POLICY), 'header')):
        with pytest.raises(F.FilterReviewError, match=match):
            F.validate_rule_form(rd, m, proposed=bad)
    (rd / F.RULE_FORM).write_text(yaml.safe_dump(form('bo'), allow_unicode=True), encoding='utf-8')
    assert F.shortened(rd) == [] and F.blocked_rules(rd) == {'TU-H01__x': {'hypothesis_id': 'TU-H01', 'ly_do': 'synthetic'}}


def test_ui_shorten_choice_then_revision_is_shown_and_listed(tmp_path, work, contract, scripted):
    from streamlit.testing.v1 import AppTest
    from cti_hunt import demo
    scripted(UNGROUNDED, rule=SHORTEN)
    run, r01 = to_filter_gate(tmp_path, work, contract)
    rid, n = _item(r01, 'fixture-tool.exe')
    app = tmp_path / 'rule_app.py'
    def page(rd):
        app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import filter_form\n"
                       f"filter_form(Path({str(rd)!r}), Path({str(run)!r}))\n", encoding='utf-8')
        return AppTest.from_file(str(app), default_timeout=30).run()
    at = page(r01)
    assert not at.exception and not at.error and not at.info                   # gói gốc: chưa có thông báo bản sửa
    next(x for x in at.text_input if x.label == 'Người duyệt rule').set_value('synthetic UI tester')
    next(x for x in at.selectbox if x.label == 'Giữ/bỏ rule').set_value('rut_gon')
    next(x for x in at.multiselect if x.label == 'Mục bỏ khi rút gọn').set_value([n])
    next(x for x in at.text_input if x.label == 'Lý do (bắt buộc khi bỏ, rút gọn, giữ rule rộng hoặc chọn biến thể)').set_value('synthetic UI cut')
    next(x for x in at.button if x.label == 'Lưu quyết định rule').click().run()
    assert not at.exception and not at.error
    row, = F.load_rule_form(r01)['rule']
    assert (row['quyet_dinh'], row['bo_muc'], row['ly_do']) == ('rut_gon', [n], 'synthetic UI cut')
    assert session.resume(run)['review_dir'] == str((r01.parent / 'r02').resolve())
    at = page(r01.parent / 'r02')
    assert not at.exception and not at.error
    assert any('fixture-tool.exe' in i.value and 'bản sửa' in i.value for i in at.info)
    (label, text, removed), = demo.shortened_rules(run)
    assert label == f'round_01/filter_review/r02/{rid}' and 'fixture-tool' not in text
    assert [i['gia_tri'] for i in removed] == ['fixture-tool.exe']


# Kiểm thật 10/10 (lượt kẹt): rule giữ nguyên có nhiều trường không theo thứ tự chữ cái; manifest JSON sắp khóa làm đảo
# thứ tự khi đọc lại, dựng lại ra SQL cùng nghĩa khác chữ.
KEPT = r"""title: Synthetic kept multi field
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith: '\powershell.exe'
  condition: selection
"""
KEPT_BEHAVIOR = 'Synthetic powershell.exe spawned by WmiPrvSE.exe'


def _two_rule_gate(tmp_path, work, contract, scripted):
    client = scripted(UNGROUNDED, KEPT_BEHAVIOR)
    client.rules = [SHORTEN, KEPT]
    run, r01 = to_filter_gate(tmp_path, work, contract, 'agent')
    rid, n = _item(r01, 'fixture-tool.exe')                                  # rule giữ nguyên không có mục
    decide_rules(r01, {rid: {'quyet_dinh': 'rut_gon', 'ly_do': 'synthetic cut', 'bo_muc': [n]}})
    return client, run, r01


def test_revision_carries_an_unchanged_multi_field_draft_as_is(tmp_path, work, contract, scripted):
    client, run, r01 = _two_rule_gate(tmp_path, work, contract, scripted)
    kept, = [s for s in F.verify_packet(r01)['specs'] if s['hypothesis_id'].endswith('H02')]
    assert list(kept['sigma_context']['rule']['detection']['selection']) == ['Image|endswith', 'ParentImage|endswith']
    out = session.resume(run)                                                # trước khi sửa: draft khác rule gốc
    r02 = r01.parent / 'r02'
    assert Path(out['review_dir']) == r02.resolve()
    m2 = F.verify_packet(r02)
    assert [s for s in m2['specs'] if s['id'] == kept['id']] == [kept]       # mang nguyên draft, không dựng lại
    row, = F.load_rule_form(r02)['rule']
    decide_rules(r02, {row['id']: {'quyet_dinh': 'giu', 'ly_do': '', 'bo_muc': []}})
    assert session.resume(run)['trang_thai'] == 'xong'
    assert _check_script().check(run)['dat']
    from cti_hunt.data.store import connect
    con = connect(work)
    try:
        plan = F.revision_specs(con, r01)                                     # gói cũ đã khóa nhưng vẫn đọc được
        F._check_drafts(con, plan['specs'], plan['context'], plan['new_dir'])
        tampered = [{**s, 'candidates': s['candidates'] + ' OR TRUE'} if s['id'] == kept['id'] else s
                    for s in plan['specs']]
        with pytest.raises(F.FilterReviewError, match='chỉ được đổi'):
            F._check_drafts(con, tampered, plan['context'], plan['new_dir'])
        with pytest.raises(F.FilterReviewError, match='giữ đúng các hunt'):
            F._check_drafts(con, plan['specs'][:1], plan['context'], plan['new_dir'])
    finally:
        con.close()


def test_error_inside_the_gate_node_keeps_the_run_at_the_gate(tmp_path, work, contract, scripted, monkeypatch):
    from cti_hunt.agent import stage_tools
    client, run, r01 = _two_rule_gate(tmp_path, work, contract, scripted)
    original = stage_tools.StageTools.revise_rules
    def fail(self, state):
        raise F.FilterReviewError('synthetic failure inside the gate node')
    monkeypatch.setattr(stage_tools.StageTools, 'revise_rules', fail)
    with pytest.raises(F.FilterReviewError, match='synthetic failure'):
        session.resume(run)
    info = session.inspect(run)
    assert (info['trang_thai'], info.get('review_kind'), Path(info['review_dir'])) == ('cho_duyet', 'filter', r01.resolve())
    monkeypatch.setattr(stage_tools.StageTools, 'revise_rules', original)
    out = session.resume(run)
    assert Path(out['review_dir']) == (r01.parent / 'r02').resolve()
