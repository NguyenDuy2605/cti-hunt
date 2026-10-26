"""Bằng chứng Security trong báo cáo cục bộ, độc lập với mẫu gửi planner."""
import json

import duckdb
import pytest

from cti_hunt.contracts import ContractA
from cti_hunt.hunt.observe import run_unlabeled, unlabeled_result
from cti_hunt.stages import s9_record


@pytest.mark.parametrize("eid,content_field", [(4698, "TaskContent"), (4702, "TaskContentNew")])
def test_security_evidence_reaches_record_without_expanding_planner_sample(eid, content_field):
    with duckdb.connect() as con:
        con.execute('''CREATE TABLE events (
            ev_host VARCHAR, ev_channel VARCHAR, ev_rec INTEGER, ev_eid INTEGER, ev_ts TIMESTAMP,
            ParentImage VARCHAR, Image VARCHAR, CommandLine VARCHAR, "User" VARCHAR, TargetUserName VARCHAR,
            SubjectUserName VARCHAR, TaskName VARCHAR, TaskContent VARCHAR, TaskContentNew VARCHAR,
            buoc VARCHAR, labeled VARCHAR, attack_labels VARCHAR)''')
        xml = '<Task>\r\n<Command>demo.exe</Command>\n<Arguments>a | b &amp; c</Arguments>\r</Task>'
        for rec in (1, 2):
            con.execute('INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        ['LAB', 'security', rec, eid, '2020-01-01 01:00:00', None, None, None, None, None,
                         'alice', r'\Demo', xml if eid == 4698 else None, xml if eid == 4702 else None,
                         'CANARY_LABEL', 'CANARY_LABEL', 'CANARY_LABEL'])
        spec = {"id": "TU", "scope": {"channel": "security", "event_ids": [eid]}, "candidates": "TRUE",
                "filters": [{"id": "fixture", "where": "ev_rec = 2", "ly_do": "fixture",
                             "nguoi_chiu_trach_nhiem": "test", "het_han": "end"}]}
        planner = run_unlabeled(con, spec)
        record = unlabeled_result(con, spec)
    assert [s["hits"] for s in planner["stages"]] == [2, 2, 1]
    assert [(s["hits"], s["removed"]) for s in record["giai_doan"]] == [(2, 0), (1, 1)]
    row, = record["ket_qua_cuoi"]
    assert row["ev_rec"] == 1 and row["SubjectUserName"] == 'alice' and row["TaskName"] == r'\Demo'
    assert row[content_field] == xml
    assert set(planner["sample"][0]) == {
        "ev_host", "ev_channel", "ev_rec", "ev_ts", "ParentImage", "Image", "CommandLine", "User", "TargetUserName"}
    md = s9_record.render(ContractA(report_id="TU"), {}, [], [record])
    assert '| SubjectUserName | TaskName | ' + content_field + ' |' in md
    assert 'ParentImage' not in md and '| User |' not in md
    assert 'alice' in md and r'\Demo' in md and '2 ứng viên → loại 1 → **1 cần xem xét**' in md
    assert '&lt;Task&gt;' in md and r'a \| b &amp;amp; c' in md and '<Task>' not in md
    assert '\r' not in md
    assert 'CANARY_LABEL' not in md + json.dumps(record) + json.dumps(planner)
    assert '- **Verdict:**\n' in md


def test_record_without_security_columns_still_works_and_honors_detail_limit():
    with duckdb.connect() as con:
        con.execute("""CREATE TABLE events AS SELECT 'LAB' AS ev_host, 'system' AS ev_channel,
            1 AS ev_rec, 1 AS ev_eid, TIMESTAMP '2020-01-01' AS ev_ts""")
        spec = {"id": "TU", "scope": {"channel": "system", "event_ids": [1]}, "candidates": "TRUE"}
        res = unlabeled_result(con, spec, detail_limit=0)
        assert res["ket_qua_cuoi"] == [] and res["giai_doan"][0]["hits"] == 1
        with pytest.raises(ValueError, match="0–20"):
            unlabeled_result(con, spec, detail_limit=21)


def test_record_sample_keeps_zero_false_and_fields_present_only_in_later_rows():
    res = {"ket_qua_cuoi": [{"ev_rec": 1, "empty": " ", "zero": 0, "flag": False, "buoc": "CANARY"},
                           {"ev_rec": 2, "empty": None, "TaskName": r'\Demo'}]}
    cols, rows = s9_record._finding_rows(res, 5)
    assert cols == ["ev_rec", "zero", "flag", "TaskName"]
    assert rows[0] == ['1', '0', 'False', ''] and rows[1][-1] == r'\Demo'
