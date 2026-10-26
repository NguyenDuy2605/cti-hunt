"""Cổng độ rộng của rule (15/10, phiếu rule v3): fixture tổng hợp, mọi lời gọi mô hình là giả lập, không API."""
from pathlib import Path
import json

import duckdb
import pytest
import yaml

from cti_hunt import approval, filter_approval as F, integrity
from cti_hunt.agent import session
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import providers

SYS = 'microsoft-windows-sysmon/operational'
# Fixture `work` có 5 sự kiện Sysmon 1; rule dưới giữ 4/5 (80%) → rộng; chỉ WmiPrvSE giữ 1/5 (20%) → không.
BROAD = r"""title: Synthetic broad process rule
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith:
      - '\WmiPrvSE.exe'
      - '\services.exe'
      - '\wsmprovhost.exe'
  condition: selection
"""
NARROW = r"""title: Synthetic narrow process rule
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  condition: selection
"""
GROUNDED = 'Synthetic remote process spawned by WmiPrvSE.exe, services.exe or wsmprovhost.exe'
# Không có tiến trình cha → không có biến thể; 1/5 sự kiện → không rộng.
NOTEPAD = r"""title: Synthetic notepad rule
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\notepad.exe'
  condition: selection
"""
# Bám thủ tục kiểu Raindrop: WmiPrvSE sinh rundll32. Fixture có WmiPrvSE sinh powershell → gốc 0, biến thể 1.
RUNDLL = r"""title: Synthetic rundll32 spawned by WmiPrvSE
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith: '\rundll32.exe'
  condition: selection
"""
EXPLORER = r"""title: Synthetic explorer child rule
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\explorer.exe'
  condition: selection
"""


class Scripted:
    model_id = 'mock'
    def __init__(self, rule, behavior=GROUNDED):
        self.calls, self.rule, self.behavior = [], rule, behavior
    def describe(self):
        return {'model': 'mock', 'kieu_api': 'mock'}
    def complete_json(self, system, user, json_schema, log=None):
        title = json_schema['title']
        self.calls.append(title)
        if title == 'LLMRule':
            return {'rule_yaml': self.rule}
        if title == '_PlannerOutput':
            first = self.calls.count(title) == 1
            return {'action': 'hunt' if first else 'stop', 'ttp_refs': [0] if first else [],
                    'pivot_targets': [], 'reason': 'synthetic fixture plan'}
        assert title == 'LLMHypothesisBatch'
        return {'items': [{'ttp_refs': [0], 'behavior': self.behavior, 'scope': 'all hosts', 'timeframe': 'toàn bộ log',
                           'data_source': SYS, 'event_ids': [1], 'key_fields': ['ParentImage', 'Image'],
                           'extra_techniques': [], 'priority': 'cao'}]}


@pytest.fixture
def contract(tmp_path):
    ca = ContractA(report_id='TU', ttps=[TTP(tactic='Lateral Movement', technique_id='T1047', confidence=0.9,
        behavior_description='Synthetic remote process',
        source_span=SourceSpan(segment_id='TU-001', text='Synthetic WMI process execution.'))])
    path = tmp_path / 'contract.json'
    path.write_text(ca.model_dump_json(), encoding='utf-8')
    return path


def start(tmp_path, work, contract, rule, monkeypatch, behavior=GROUNDED):
    client = Scripted(rule, behavior)
    monkeypatch.setattr(providers, 'from_config', lambda cfg: client)
    run = tmp_path / 'run'
    out = session.start('pipeline', contract, work, run, dataset_kind='fixture', dataset_id='synthetic', version='v2')
    rd = Path(out['review_dir'])
    form = yaml.safe_load((rd / approval.REVIEW_FILE).read_text(encoding='utf-8'))
    approval.save_decisions(rd, 'fixture reviewer',
                            {r['id']: {'quyet_dinh': 'approved', 'ly_do': 'synthetic'} for r in form['gia_thuyet']},
                            integrity.sha256_file(rd / approval.REVIEW_FILE))
    return run, session.resume(run)


def decide(rd, decision, reason=''):
    rid = F.load_rule_form(rd)['rule'][0]['id']
    F.save_rule_decisions(rd, 'fixture reviewer', {rid: {'quyet_dinh': decision, 'ly_do': reason}},
                          integrity.sha256_file(rd / F.RULE_FORM))
    return rid


def test_broad_rule_on_high_volume_source_holds_the_batch(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, BROAD, monkeypatch)
    assert out['review_kind'] == 'filter'
    rd = Path(out['review_dir'])
    form = F.load_rule_form(rd)
    assert form['quy_tac_duyet'] == F.RULE_POLICY_V3
    [row] = form['rule']
    assert row['doi_chieu'] == []                        # giả thuyết nêu đủ giá trị: chỉ vì độ rộng
    assert row['do_rong'] == {'giu': 4, 'pham_vi': 5, 'ty_le': 0.8, 'nguong': 0.5, 'version': F.BREADTH_VERSION}
    assert F.verify_packet(rd)['doi_chieu_rule'][0]['do_rong'] == row['do_rong']
    with pytest.raises(F.PendingFilterReview, match='rule'):
        session.resume(run)


def test_keeping_a_broad_rule_needs_a_reason(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, BROAD, monkeypatch)
    rd = Path(out['review_dir'])
    with pytest.raises(F.FilterReviewError, match='rule rộng'):
        decide(rd, 'giu')
    decide(rd, 'giu', 'synthetic: fixture has only five process events')
    assert session.resume(run)['trang_thai'] == 'xong'
    obs = json.loads((run / 'round_01/agent_execute.json').read_text(encoding='utf-8'))['observations']
    assert [o['stages'][1]['hits'] for o in obs] == [4]      # rule được giữ thì chạy: 4 ứng viên
    # 15/10: v2 bật ưu tiên khoảng trống; có bản SigmaHQ cục bộ thì record ghi độ phủ, không có thì None
    rec = json.loads((run / 'agent_dev_record.json').read_text(encoding='utf-8'))
    assert 'khoang_trong_rule_cong_dong' in rec


def test_dropping_a_broad_rule_runs_nothing(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, BROAD, monkeypatch)
    rd = Path(out['review_dir'])
    rid = decide(rd, 'bo', 'synthetic: keeps most process events')
    assert session.resume(run)['trang_thai'] == 'xong'
    assert rid in F.blocked_rules(rd)
    assert 'synthetic: keeps most process events' in (run / 'hunt_record.md').read_text(encoding='utf-8')


def test_narrow_grounded_rule_without_variant_skips_the_gate(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, NOTEPAD, monkeypatch, behavior='Synthetic process notepad.exe starts')
    assert out['trang_thai'] == 'xong'
    rd = run / 'round_01/filter_review/r01'
    m = F.verify_packet(rd)
    assert m['doi_chieu_rule'] == [] and m['doi_chieu_rule_policy'] == F.RULE_POLICY_V3
    assert not (rd / F.RULE_FORM).exists()


def _events(rows):
    con = duckdb.connect()
    con.execute("CREATE TABLE events (ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, DestinationPort VARCHAR, "
                "Name VARCHAR)")
    con.executemany("INSERT INTO events VALUES (?, ?, 'W1', ?, ?)", rows)
    return con


def _spec(sid, channel, eids, candidates):
    return {'id': sid, 'scope': {'channel': channel, 'event_ids': eids}, 'candidates': candidates}


def test_breadth_only_counts_high_volume_sources():
    con = _events([(SYS, 3, '443', None)] * 6 + [(SYS, 3, '80', None)] * 4 + [(SYS, 20, None, 'Updater')])
    wide = F._breadth(con, [_spec('net443', SYS, [3], "DestinationPort = '443'"),
                            _spec('net80', SYS, [3], "DestinationPort = '80'"),
                            _spec('wmi', SYS, [20], "Name = 'Updater'")])
    assert set(wide) == {'net443'}                       # 6/10 ≥ 50%; 4/10 dưới; Sysmon 20 là nguồn hiếm
    assert wide['net443']['ty_le'] == 0.6


def test_breadth_config_is_versioned_and_lists_rare_sources_out():
    from cti_hunt import config
    cfg = yaml.safe_load(config.resolve(F.BREADTH_CONFIG).read_text(encoding='utf-8'))
    assert cfg['version'] == F.BREADTH_VERSION and 0 < cfg['nguong'] <= 1
    sysmon = set(cfg['nguon_khoi_luong_lon'][SYS])
    assert {1, 3}.issubset(sysmon) and not {19, 20, 21}.intersection(sysmon)


def test_reviewer_can_run_the_technique_level_variant(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, RUNDLL, monkeypatch,
                     behavior='Synthetic rundll32.exe spawned by WmiPrvSE.exe')
    rd = Path(out['review_dir'])
    [row] = F.load_rule_form(rd)['rule']
    var = row['bien_the']
    assert row['do_rong'] is None and row['doi_chieu'] == []
    assert (var['goc_giu'], var['bien_the_giu'], var['pham_vi']) == (0, 1, 5)
    assert 'wmiprvse.exe' in var['mo_ta'] and 'powershell' in var['candidates'].lower()
    with pytest.raises(F.FilterReviewError, match='biến thể thay rule gốc cần lý do'):
        decide(rd, 'bien_the')
    rid = decide(rd, 'bien_the', 'synthetic: payload in report is procedure-specific')
    assert session.resume(run)['trang_thai'] == 'xong'
    obs = json.loads((run / 'round_01/agent_execute.json').read_text(encoding='utf-8'))['observations']
    assert [o['stages'][1]['hits'] for o in obs] == [1]
    spec = yaml.safe_load(next((run / 'round_01/hunts_effective').rglob('*.yaml')).read_text(encoding='utf-8'))
    assert spec['id'] == rid and spec['candidates'] == var['candidates'] and spec['filters'] == []
    assert spec['bien_the']['candidates_goc'] != spec['candidates']
    assert 'Rule chạy bằng biến thể mức kỹ thuật' in (run / 'hunt_record.md').read_text(encoding='utf-8')


def test_variant_choice_needs_a_variant(tmp_path, work, contract, monkeypatch):
    run, out = start(tmp_path, work, contract, EXPLORER, monkeypatch)
    rd = Path(out['review_dir'])
    [row] = F.load_rule_form(rd)['rule']
    assert row['bien_the'] is None and row['doi_chieu']            # explorer.exe không có trong giả thuyết
    with pytest.raises(F.FilterReviewError, match='không có biến thể'):
        decide(rd, 'bien_the', 'synthetic')
