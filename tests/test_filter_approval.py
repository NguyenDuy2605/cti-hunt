"""The v2 exclusion boundary on synthetic, unlabeled events; no real API/dataset."""
from copy import deepcopy
from datetime import timedelta
import json

import duckdb
import pytest
import yaml

from cti_hunt import filter_approval as F, integrity
from cti_hunt.adapters import duckdb_sigma as A
from cti_hunt.adapters.filter_structure import FilterStructureError
from cti_hunt.hunt import runner
from cti_hunt.hunt.observe import run_unlabeled
from cti_hunt.eval.exec_accuracy import result_keys
from cti_hunt.stages import s7_rarity, s8_triage

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
    c = duckdb.connect()
    c.execute("SET default_collation='nocase'")
    c.execute("""CREATE TABLE events AS SELECT * FROM (VALUES
      ('LAB-A', 'sysmon', 1, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '10.0.0.8', '443'),
      ('LAB-A', 'sysmon', 2, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '198.51.100.8', '5985'),
      ('LAB-A', 'sysmon', 3, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', '203.0.113.8', '443'),
      ('LAB-A', 'sysmon', 4, 3, TIMESTAMP '2026-01-01', 'C:\\powershell.exe', NULL, NULL)
      ) t(ev_host, ev_channel, ev_rec, ev_eid, ev_ts, Image, DestinationIp, DestinationPort)""")
    yield c
    c.close()


def draft(condition=None):
    text = RULE if condition is None else RULE.replace('selection and not 1 of filter_*', condition)
    return A.compile_text(text, CAT, filter_policy=F.POLICY)[0][0].to_hunt_spec()


def packet(tmp_path, events, condition=None):
    root = tmp_path / 'run'
    F.bind(events, root)
    rd = root / 'round_01/filter_review/r01'
    F.prepare(events, [draft(condition)], root, rd)
    return rd


def choose(rd, decision='approved'):
    p = rd / F.FORM
    form = F.load_form(rd)
    choices = {r['id']: {'quyet_dinh': decision, 'ly_do': 'synthetic fixture decision',
                         'can_cu': 'fixture test definition', 'nguoi_chiu_trach_nhiem': 'tester',
                         'hieu_luc_den_utc': (F.utcnow() + timedelta(hours=1)).isoformat()}
               for r in form['muc_loc']}
    F.save_decisions(rd, 'tester', choices, integrity.sha256_file(p))


@pytest.mark.parametrize('condition', ['selection or selection and not filter_internal',
    'not filter_internal', 'selection and not selection', 'selection and filter_internal',
    'selection and not (filter_internal and not filter_port)', '1 of them'])
def test_strict_structure_blocks_hidden_exclusions(condition):
    with pytest.raises(FilterStructureError):
        draft(condition)


@pytest.mark.parametrize('condition, groups', [
    ('selection', 0), ('selection and not 1 of filter_*', 1),
    ('selection and not all of filter_*', 1),
    ('selection and not filter_internal and not filter_port', 2),
    ('selection and not (filter_internal and filter_port)', 1)])
def test_groups_keep_boolean_structure(condition, groups):
    s = draft(condition)
    assert len(s['filters']) == groups
    runner.validate(s, for_execution=False)
    with pytest.raises(F.FilterReviewError):
        runner.validate(s)


def test_neq_modifier_cannot_hide_exclusion():
    text = RULE.replace('Image|endswith:', 'Image|neq:')
    with pytest.raises(FilterStructureError, match='modifier'):
        A.compile_text(text, CAT, filter_policy=F.POLICY)


def test_preview_is_full_count_with_nulls_and_limited_sample(tmp_path, events):
    rd = packet(tmp_path, events)
    preview = json.loads((rd / 'preview.json').read_text())
    p = preview[0]
    assert (p['scope'], p['candidates'], p['union_removed']) == (4, 4, 2)
    assert [s['ev_rec'] for s in p['filters'][0]['sample']] == [1, 2]
    form = F.load_form(rd)
    assert len(form['muc_loc']) == 1
    assert form['nguoi_duyet'] == '' and form['muc_loc'][0]['quyet_dinh'] == ''
    with pytest.raises(F.PendingFilterReview):
        F.finalize(rd, con=events)
    assert not (rd / F.EFFECTIVE).exists()


def test_preview_counts_all_rows_beyond_five_event_sample(tmp_path, events):
    events.execute("""INSERT INTO events SELECT ev_host, ev_channel, n, ev_eid, ev_ts, Image, DestinationIp, DestinationPort
                      FROM events, range(5, 15) t(n) WHERE ev_rec=1""")
    rd = packet(tmp_path, events)
    preview = F._read(rd / 'preview.json')[0]
    assert preview['candidates'] == 14 and preview['union_removed'] == 12
    assert len(preview['filters'][0]['sample']) == 5
    assert [r['ev_rec'] for r in preview['filters'][0]['sample']] == [1, 2, 5, 6, 7]


@pytest.mark.parametrize('decision, expected', [('approved', 2), ('rejected', 4)])
def test_decision_effect_and_null_semantics(tmp_path, events, decision, expected):
    rd = packet(tmp_path, events)
    choose(rd, decision)
    files = F.finalize(rd, con=events)
    spec = runner.load_spec(files[0])
    assert run_unlabeled(events, spec)['stages'][-1]['hits'] == expected
    assert ('LAB-A', 'sysmon', 4) in result_keys(events, spec)['cuoi']
    assert F.finalize(rd, con=events) == files       # no regeneration or changed decisions


def test_no_filters_needs_no_fabricated_reviewer(tmp_path, events):
    rd = packet(tmp_path, events, 'selection')
    files = F.finalize(rd, con=events)
    log = json.loads((rd / 'approval_log.json').read_text())
    assert log['kind'] == 'no_filters' and log['nguoi_duyet'] == ''
    assert run_unlabeled(events, runner.load_spec(files[0]))['stages'][-1]['hits'] == 4


def test_all_pending_and_partly_decided_keep_entire_batch(tmp_path, events):
    rd = packet(tmp_path, events, 'selection and not filter_internal and not filter_port')
    form = F.load_form(rd)
    F.save_decisions(rd, 'tester', {form['muc_loc'][0]['id']: {'quyet_dinh': 'rejected', 'ly_do': 'not verified'}},
                     integrity.sha256_file(rd / F.FORM))
    with pytest.raises(F.PendingFilterReview):
        F.finalize(rd, con=events)
    assert not (rd / F.EFFECTIVE).exists()


@pytest.mark.parametrize('which', ['draft', 'candidates', 'scope', 'where', 'marker'])
def test_query_gate_blocks_changed_in_memory_spec(tmp_path, events, which):
    rd = packet(tmp_path, events)
    choose(rd)
    s = runner.load_spec(F.finalize(rd, con=events)[0])
    if which == 'draft':
        s['filter_phase'] = 'draft'
    elif which == 'marker':
        s.pop('filter_policy')
    elif which == 'where':
        s['filters'][0]['where'] = 'TRUE'
    elif which == 'scope':
        s['scope']['hosts'] = ['LAB-B']
    else:
        s['candidates'] = 'TRUE'
    with pytest.raises(F.FilterReviewError):
        run_unlabeled(events, s)
    with pytest.raises(F.FilterReviewError):
        result_keys(events, s)
    with pytest.raises(F.FilterReviewError):
        s8_triage.final_rows(events, s, set())


@pytest.mark.parametrize('target', ['preview.json', 'manifest.json', F.FORM, 'approval_log.json'])
def test_changed_files_invalidate_packet(tmp_path, events, target):
    rd = packet(tmp_path, events)
    choose(rd)
    s = runner.load_spec(F.finalize(rd, con=events)[0])
    path = rd / target
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(F.FilterReviewError):
        run_unlabeled(events, s)


def test_changed_data_invalidates_approval(tmp_path, events):
    rd = packet(tmp_path, events)
    choose(rd)
    s = runner.load_spec(F.finalize(rd, con=events)[0])
    events.execute("UPDATE events SET DestinationIp = '10.1.1.1' WHERE ev_rec = 3")
    with pytest.raises(F.FilterReviewError, match='events'):
        run_unlabeled(events, s)


@pytest.mark.parametrize('change', ['duplicate', 'missing', 'boolean', 'scope', 'owner', 'expiry', 'reason', 'evidence'])
def test_invalid_form_never_materializes(tmp_path, events, change):
    rd = packet(tmp_path, events)
    choose(rd)
    form = F.load_form(rd)
    r = form['muc_loc'][0]
    if change == 'duplicate':
        form['muc_loc'].append(deepcopy(r))
    elif change == 'missing':
        form['muc_loc'] = []
    elif change == 'boolean':
        r['quyet_dinh'] = True
    elif change == 'scope':
        r['scope']['hosts'] = ['OTHER']
    elif change == 'owner':
        r['nguoi_chiu_trach_nhiem'] = 'he_thong'
    elif change == 'expiry':
        r['hieu_luc_den_utc'] = '2020-01-01T00:00:00Z'
    elif change == 'reason':
        r['ly_do'] = ''
    else:
        r['can_cu'] = ''
    (rd / F.FORM).write_text(yaml.safe_dump(form), encoding='utf-8')
    with pytest.raises(F.FilterReviewError):
        F.finalize(rd, con=events)
    assert not (rd / F.EFFECTIVE).exists()


def test_stale_ui_is_read_only_on_failure(tmp_path, events):
    rd = packet(tmp_path, events)
    old = integrity.sha256_file(rd / F.FORM)
    choose(rd, 'rejected')
    before = (rd / F.FORM).read_bytes()
    with pytest.raises(F.FilterReviewError):
        F.save_decisions(rd, 'tester', {}, old)
    assert (rd / F.FORM).read_bytes() == before
