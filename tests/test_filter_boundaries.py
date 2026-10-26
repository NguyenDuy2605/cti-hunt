"""Provenance across replay, reconstructed results, and SPL on synthetic events."""
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import duckdb
import pytest
import yaml

from cti_hunt import cli, filter_approval as F, integrity
from cti_hunt.adapters.splunk_sigma import convert_effective, convert_rule
from cti_hunt.eval import splunk_compare
from cti_hunt.hunt import runner
from cti_hunt.hunt.observe import run_unlabeled, unlabeled_result
from cti_hunt.replay import effective_packet
from cti_hunt.stages import s8_triage

RULE = r"""title: Fixture reviewed filters
logsource: {product: windows, category: network_connection}
detection:
  selection:
    Image|endswith: '\powershell.exe'
  filter_internal:
    DestinationIp|startswith: '10.'
  filter_port:
    DestinationPort: '5985'
  condition: selection and not 1 of filter_*
"""
CAT = {'network_connection': [{'name': 'fixture_sysmon3', 'channel': 'sysmon', 'event_ids': [3]}]}


@pytest.fixture
def events():
    con = duckdb.connect()
    con.execute("SET default_collation='nocase'")
    con.execute("""CREATE TABLE events AS SELECT * FROM (VALUES
      ('LAB-A', 'sysmon', 1, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '10.0.0.8', '443'),
      ('LAB-A', 'sysmon', 2, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '198.51.100.8', '5985'),
      ('LAB-A', 'sysmon', 3, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '203.0.113.8', '443'),
      ('LAB-A', 'sysmon', 4, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', NULL, NULL)
      ) t(ev_host, ev_channel, ev_rec, ev_eid, ev_ts, Image, DestinationIp, DestinationPort)""")
    yield con
    con.close()


def draft(condition=None):
    from cti_hunt.adapters import duckdb_sigma as A
    text = RULE if condition is None else RULE.replace('selection and not 1 of filter_*', condition)
    return A.compile_text(text, CAT, filter_policy=F.POLICY)[0][0].to_hunt_spec()


def packet(tmp_path, events, condition=None):
    root = tmp_path / 'run'
    F.bind(events, root)
    rd = root / 'round_01/filter_review/r01'
    F.prepare(events, [draft(condition)], root, rd)
    return rd


def choose(rd, decision='approved'):
    choices = {row['id']: {'quyet_dinh': decision, 'ly_do': 'synthetic fixture decision',
                          'can_cu': 'fixture test definition', 'nguoi_chiu_trach_nhiem': 'tester',
                          'hieu_luc_den_utc': (F.utcnow() + timedelta(hours=1)).isoformat()}
               for row in F.load_form(rd)['muc_loc']}
    F.save_decisions(rd, 'tester', choices, integrity.sha256_file(rd / F.FORM))


def test_filter_modifiers_cannot_hide_nested_negation():
    from cti_hunt.adapters import duckdb_sigma as A
    from cti_hunt.adapters.filter_structure import FilterStructureError
    text = RULE.replace("DestinationPort: '5985'", "DestinationPort|neq: '5985'")
    with pytest.raises(FilterStructureError, match='modifier'):
        A.compile_text(text, CAT, filter_policy=F.POLICY)


def test_exists_false_cannot_hide_negation():
    from cti_hunt.adapters import duckdb_sigma as A
    from cti_hunt.adapters.filter_structure import FilterStructureError
    text = RULE.replace("Image|endswith: '\\powershell.exe'", "Image|exists: false")
    with pytest.raises(FilterStructureError, match='exists:false'):
        A.compile_text(text, CAT, filter_policy=F.POLICY)


def test_each_source_has_a_separate_review_id_and_preserves_field_mapping(tmp_path, events):
    from cti_hunt.adapters import duckdb_sigma as A
    catalog = {'network_connection': [CAT['network_connection'][0],
        {'name': 'fixture_mapped', 'channel': 'mapped', 'event_ids': [3], 'field_map': {'Image': 'OtherImage'}}]}
    events.execute('ALTER TABLE events ADD COLUMN OtherImage VARCHAR')
    events.execute('UPDATE events SET OtherImage=Image')
    events.execute("INSERT INTO events SELECT ev_host, 'mapped', ev_rec, ev_eid, ev_ts, Image, DestinationIp, DestinationPort, OtherImage FROM events")
    specs = [h.to_hunt_spec() for h in A.compile_text(RULE, catalog, filter_policy=F.POLICY)[0]]
    root = tmp_path / 'run'
    F.bind(events, root)
    rd = F.prepare(events, specs, root, root / 'filter_review/r01')
    rows = F.load_form(rd)['muc_loc']
    assert len(rows) == 2 and len({r['id'] for r in rows}) == 2
    assert all(r['id'].endswith('__S-01') for r in rows)
    assert [p['candidates'] for p in F._read(rd / 'preview.json')] == [4, 4]
    choices = {r['id']: {'quyet_dinh': 'rejected', 'ly_do': 'Synthetic source decision'} for r in rows}
    F.save_decisions(rd, 'fixture reviewer', choices, integrity.sha256_file(rd / F.FORM))
    files = F.finalize(rd, con=events)
    assert 'OtherImage' in runner.load_spec(files[1])['candidates']
    assert [run_unlabeled(events, runner.load_spec(p))['stages'][-1]['hits'] for p in files] == [4, 4]


def test_account_pivot_binding_kept_in_preview_sql_and_spl(tmp_path, work):
    pytest.importorskip('sigma.backends.splunk')
    from cti_hunt.data.store import connect
    from cti_hunt.config import ROOT
    from cti_hunt.stages import s5_rule
    from cti_hunt.contracts import ContractB, Evidence
    from cti_hunt.adapters import duckdb_sigma as A
    con = connect(work)
    try:
        con.execute('CREATE TEMP TABLE synthetic_events AS SELECT *, CAST(NULL AS VARCHAR) AS User FROM events')
        con.execute("UPDATE synthetic_events SET User='LAB\\fixture_user' WHERE ev_rec IN (10, 11)")
        con.execute('CREATE OR REPLACE VIEW events AS SELECT * FROM synthetic_events')
        h = ContractB(hypothesis_id='FIXTURE-H01', behavior='Synthetic remote process hypothesis',
                      scope='Mọi máy Windows trong log', timeframe='toàn bộ log',
                      evidence=Evidence(data_source='microsoft-windows-sysmon/operational', event_ids=[1],
                                        key_fields=['ParentImage', 'Image', 'User']),
                      linked_ttps=['T1047'], status='approved', origin='pivot', pivot_kind='tai_khoan',
                      pivot_value='fixture_user', pivot_depth=1)
        process_rule = r"""title: Synthetic reviewed process
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
        catalog = A.load_catalog(ROOT / 'configs/logsource_catalog.yaml')
        columns = {r[0] for r in con.execute('DESCRIBE events').fetchall()}
        errors, specs = s5_rule.validate_rule(process_rule, h, catalog, columns, con, filter_policy=F.POLICY)
        assert errors == []
        # Use a memory fingerprint for this modified synthetic table.
        F._connections.pop(con)
        root = tmp_path / 'run'
        F.bind(con, root)
        rd = F.prepare(con, specs, root, root / 'filter_review/r01')
        choose(rd, 'rejected')
        spec = runner.load_spec(F.finalize(rd, con=con)[0])
        assert 'coalesce("User"' in spec['candidates']
        exported = convert_effective(spec, 'fixture_index')
        assert '| where (' in exported['stages'][0]['spl'] and 'coalesce(User' in exported['stages'][0]['spl']
        assert 'fixture_user' in exported['stages'][0]['spl']
        assert run_unlabeled(con, spec)['stages'][-1]['hits'] == 3
    finally:
        con.close()


@pytest.mark.parametrize('condition, expected', [
    ('selection and not 1 of filter_*', [4, 2]),
    ('selection and not all of filter_*', [4, 4]),
    ('(selection and not filter_internal) and not filter_port', [4, 3, 2])])
def test_spl_uses_positive_group_and_exact_null_safe_sql(tmp_path, events, condition, expected):
    pytest.importorskip('sigma.backends.splunk')
    rd = packet(tmp_path, events, condition)
    choose(rd)
    spec = runner.load_spec(F.finalize(rd, con=events)[0])
    export = convert_effective(spec, 'fixture_index')
    assert [events.execute(s['sql']).fetchall().__len__() for s in export['stages']] == expected
    assert export['filter_review'] == spec['filter_review']
    assert export['executed_on_splunk'] is False
    assert all('ev_channel="sysmon"' in s['spl'] and 'ev_eid=3' in s['spl'] for s in export['stages'])
    assert export['stages'][-1]['spl'].count(' NOT (') == len(spec['filters'])
    assert all('IS NOT TRUE' in s['sql'] for s in export['stages'][1:])


def test_rejected_group_cannot_return_through_raw_spl_or_cli(tmp_path, events):
    pytest.importorskip('sigma.backends.splunk')
    rd = packet(tmp_path, events)
    choose(rd, 'rejected')
    spec = runner.load_spec(F.finalize(rd, con=events)[0])
    exported = convert_effective(spec, 'fixture_index')
    assert len(exported['stages']) == 1 and ' NOT (' not in exported['stages'][0]['spl']
    rule = Path(F.verify_packet(rd)['run_root']) / 'rules_draft/raw.yml'
    rule.parent.mkdir()
    rule.write_text(RULE, encoding='utf-8')
    with pytest.raises(F.FilterReviewError):
        convert_rule(rule)
    with pytest.raises(F.FilterReviewError):
        splunk_compare.plans(rule, CAT, set(), 'fixture_index', '2025-01-01Z', '2027-01-01Z')
    assert cli.main(['sigma', str(rule), '--run']) == 1  # blocks before dataset/labels attachment


def test_result_to_triage_preserves_and_revalidates_exact_contract(tmp_path, events):
    rd = packet(tmp_path, events)
    choose(rd)
    spec = runner.load_spec(F.finalize(rd, con=events)[0])
    result = unlabeled_result(events, spec)
    restored = s8_triage.spec_from_result(result)
    assert run_unlabeled(events, restored)['stages'][-1]['hits'] == 2
    changed = deepcopy(result)
    changed['truy_van']['filters'] = []
    with pytest.raises(F.FilterReviewError):
        s8_triage.spec_from_result(changed)
    changed = deepcopy(result)
    changed.pop('filter_contract')
    with pytest.raises(F.FilterReviewError):
        s8_triage.spec_from_result(changed)


def test_expired_authorization_only_replays_completed_original_packet(tmp_path, events, monkeypatch):
    rd = packet(tmp_path, events)
    choose(rd)
    first = effective_packet(rd, events, tmp_path / 'executed.json')
    spec = runner.load_spec(Path(next(iter(F._read(rd / F.EFFECTIVE)['files']))))
    expired_now = F.utcnow() + timedelta(days=2)
    monkeypatch.setattr(F, 'utcnow', lambda: expired_now)
    with pytest.raises(F.FilterReviewError, match='hết hạn'):
        run_unlabeled(events, spec)
    before = integrity.sha256_file(rd / F.EFFECTIVE)
    audited = effective_packet(rd, events, tmp_path / 'audited.json', audit=True)
    assert audited['kind'] == 'audit_replay_only'
    assert audited['results'][0]['giai_doan'] == first['results'][0]['giai_doan']
    assert audited['api_called'] is False and audited['new_authorization'] is False
    assert integrity.sha256_file(rd / F.EFFECTIVE) == before
    with pytest.raises(F.FilterReviewError):
        F.require_executable(spec, con=events, audit_at='2000-01-01T00:00:00Z')
    rec = F._read(rd / 'execution_receipt.json')
    rec['effective_manifest_sha256'] = '0' * 64
    F._write(rd / 'execution_receipt.json', rec)
    with pytest.raises(F.FilterReviewError):
        effective_packet(rd, events, tmp_path / 'corrupt_audit.json', audit=True)


def test_audit_cannot_invent_execution_for_a_finalized_unexecuted_packet(tmp_path, events):
    rd = packet(tmp_path, events)
    choose(rd)
    F.finalize(rd, con=events)
    with pytest.raises(F.FilterReviewError):
        effective_packet(rd, events, tmp_path / 'audit.json', audit=True)


def test_preparation_recompiles_draft_instead_of_trusting_policy_marker(tmp_path, events):
    root = tmp_path / 'run'
    F.bind(events, root)
    spec = draft()
    spec['candidates'] += ' AND NOT (DestinationIp IS NULL)'
    with pytest.raises(F.FilterReviewError, match='draft khác'):
        F.prepare(events, [spec], root, root / 'filter_review/r01')
    assert not (root / 'filter_review/r01' / F.FORM).exists()


ESCAPED = r"""title: Fixture escaped backslash
logsource: {product: windows, category: network_connection}
detection:
  selection:
    Image|contains: 'sc.exe \\\\'
  filter_internal:
    DestinationIp|startswith: '10.'
  condition: selection and not filter_internal
"""


def test_escaped_backslash_value_passes_draft_recompile(tmp_path, events):
    # 05/10 (SY_01 vòng 5): pySigma to_dict() bỏ dấu thoát, giá trị đổi 4 → 2 → 1 dấu '\' qua mỗi lần ghi lại rule
    # dù SQL không đổi; cổng lọc từng báo "draft khác" và chặn cả lượt.
    from cti_hunt.adapters import duckdb_sigma as A
    spec = A.compile_text(ESCAPED, CAT, filter_policy=F.POLICY)[0][0].to_hunt_spec()
    F._validate_draft(events, spec)
    again = A.compile_text(yaml.safe_dump(spec['sigma_context']['rule'], allow_unicode=True, sort_keys=False),
                           CAT, filter_policy=F.POLICY)[0][0].to_hunt_spec()
    assert again['sigma_context']['rule'] == spec['sigma_context']['rule']          # rule lưu đã ổn định
    plain = A.compile_text(ESCAPED, CAT)[0][0].to_hunt_spec()
    assert spec['candidates'] == plain['candidates']                                 # SQL không đổi so với v1
    root = tmp_path / 'run'
    F.bind(events, root)
    F.prepare(events, [spec], root, root / 'filter_review/r01')
    assert (root / 'filter_review/r01' / F.FORM).exists()


def test_decision_preview_counts_overlap_as_a_union(tmp_path, events):
    events.execute("UPDATE events SET DestinationPort='5985' WHERE ev_rec=1")
    rd = packet(tmp_path, events, 'selection and not filter_internal and not filter_port')
    choose(rd)
    stages = F.decision_preview(rd, events)[0]['stages']
    assert [s['hits'] for s in stages] == [4, 3, 2]
    assert not (rd / F.EFFECTIVE).exists()


def test_partial_effective_write_is_unusable_and_not_silently_overwritten(tmp_path, events, monkeypatch):
    rd = packet(tmp_path, events)
    choose(rd)
    write = F._write
    def fail_manifest(path, value, **kw):
        if path.name == F.EFFECTIVE:
            raise OSError('synthetic interrupted write')
        return write(path, value, **kw)
    monkeypatch.setattr(F, '_write', fail_manifest)
    with pytest.raises(OSError):
        F.finalize(rd, con=events)
    artifact = next(rd.parent.parent.glob('hunts_effective/r01/*.yaml'))
    with pytest.raises(F.FilterReviewError):
        runner.load_spec(artifact)
    monkeypatch.setattr(F, '_write', write)
    with pytest.raises(F.FilterReviewError, match='xuất dở'):
        F.finalize(rd, con=events)
    assert not (rd / F.EFFECTIVE).exists()


def test_changed_events_view_cannot_reuse_unchanged_parquet_hash(tmp_path, work):
    from cti_hunt.data.store import connect
    con = connect(work)
    try:
        F.bind(con, tmp_path / 'run')
        before = F._fingerprint(con)
        con.execute('CREATE TEMP TABLE synthetic_empty AS SELECT * FROM events WHERE FALSE')
        con.execute('CREATE OR REPLACE VIEW events AS SELECT * FROM synthetic_empty')
        assert integrity.sha256_file(work / 'events.parquet') == before['sha256']
        with pytest.raises(F.FilterReviewError, match='view events'):
            F._fingerprint(con)
    finally:
        con.close()


def test_effective_spl_plan_mutation_blocks_before_engine_queries(tmp_path, events):
    pytest.importorskip('sigma.backends.splunk')
    rd = packet(tmp_path, events)
    choose(rd)
    spec = runner.load_spec(F.finalize(rd, con=events)[0])
    plan = splunk_compare.plans_effective(spec, events, 'fixture_index', '2025-01-01T00:00:00Z', '2027-01-01T00:00:00Z')
    splunk_compare._check_effective_plan(events, plan)
    class Forbidden:
        def search(self, *args, **kw):
            pytest.fail('changed plan must not query Splunk')
    plan['stages'][-1]['sql'] = 'SELECT * FROM events'
    with pytest.raises(F.FilterReviewError):
        splunk_compare._engines(events, Forbidden(), plan)
    plan.pop('filter_contract')
    with pytest.raises(F.FilterReviewError):
        splunk_compare._engines(events, Forbidden(), plan)


@pytest.mark.parametrize('decision', ['approved', 'rejected'])
def test_multiline_approved_filter_blocks_effective_spl_only_when_applied(tmp_path, events, decision):
    # Splunk không khớp giá trị có CRLF như DuckDB (kiểm 1/10); chỉ mục approved mới vào SPL.
    pytest.importorskip('sigma.backends.splunk')
    from cti_hunt.adapters import duckdb_sigma as A
    text = RULE.replace("DestinationPort: '5985'", 'DestinationPort|contains: "59\\r\\n85"')
    assert '\r' in yaml.safe_load(text)['detection']['filter_port']['DestinationPort|contains']
    root = tmp_path / 'run'
    F.bind(events, root)
    rd = F.prepare(events, [A.compile_text(text, CAT, filter_policy=F.POLICY)[0][0].to_hunt_spec()],
                   root, root / 'round_01/filter_review/r01')
    choose(rd, decision)
    spec = runner.load_spec(F.finalize(rd, con=events)[0])
    if decision == 'approved':
        with pytest.raises(ValueError, match='xuống dòng'):
            convert_effective(spec, 'fixture_index')
    else:
        assert spec['filters'] == [] and len(convert_effective(spec, 'fixture_index')['stages']) == 1
