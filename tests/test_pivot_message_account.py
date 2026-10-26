"""H7: pivot theo tài khoản trên kênh ghi tài khoản trong Message (WMI-Activity). Sự kiện tự soạn, không nhãn, không API."""
import inspect

import duckdb
import pytest

from cti_hunt.adapters import splunk_sigma
from cti_hunt.contracts import ContractB
from cti_hunt.stages import s8_pivot, s8_triage

WMI, SYS = "microsoft-windows-wmi-activity/operational", "microsoft-windows-sysmon/operational"
ROWS = [  # (rec, kênh, eid, User, AccountName, Message)
    (1, WMI, 5858, None, "SYSTEM", r"Id = {1}; ClientMachine = A; User = CORP\alice; ClientProcessId = 7; Operation = Start"),
    (2, WMI, 5858, None, "SYSTEM", r"Id = {2}; ClientMachine = A; User = NT AUTHORITY\SYSTEM; ClientProcessId = 8"),
    (3, WMI, 5860, None, "SYSTEM", r"Namespace = ROOT\CIMV2; NotificationQuery = SELECT 1; UserName = corp\ALICE; ClientProcessID = 9, ClientMachine = A"),
    (4, WMI, 5857, None, "NETWORK SERVICE", r"Provider started. HostProcess = wmiprvse.exe; ProcessID = 5; ProviderPath = x.dll"),
    (5, WMI, 5861, None, "SYSTEM", r"Namespace = //./root/subscription; NameOfUserSIDProperty = alice; Query = SELECT alice"),
    (6, WMI, 5858, None, "SYSTEM", r"Id = {6}; User = CORP\alice2; ClientProcessId = 1"),
    (7, WMI, 5858, None, "SYSTEM", r"Id = {7}; User = CORP\malice; ClientProcessId = 1"),
    (8, WMI, 5858, None, "SYSTEM", r"Id = {8}; User = alice@corp.local; ClientProcessId = 1"),
    (9, WMI, 5858, None, "SYSTEM", r"Id = {9}; ClientMachine = A; User = CORP\alice"),          # tài khoản ở cuối bản tin
    (10, SYS, 1, r"CORP\alice", "SYSTEM", r"Process Create: User = CORP\bob; note"),
    (11, SYS, 1, r"CORP\bob", "SYSTEM", r"Process Create: User = CORP\alice; note"),
]


@pytest.fixture
def con():
    c = duckdb.connect()
    c.execute('CREATE TABLE events (ev_host VARCHAR, ev_channel VARCHAR, ev_rec INTEGER, ev_eid INTEGER, ev_ts TIMESTAMP, '
              '"User" VARCHAR, AccountName VARCHAR, Message VARCHAR)')
    c.executemany("INSERT INTO events VALUES ('A', ?, ?, ?, '2020-01-01 00:00:00', ?, ?, ?)",
                  [(ch, rec, eid, user, account, message) for rec, ch, eid, user, account, message in ROWS])
    return c


def hyp(channel, eids, account="alice"):
    return ContractB(hypothesis_id="SELF-H01", behavior="Dấu vết của tài khoản", scope="máy A", timeframe="toàn bộ",
                     evidence={"data_source": channel, "event_ids": eids, "key_fields": ["Message"]},
                     linked_ttps=["T1047"], origin="pivot", pivot_depth=1, pivot_kind="tai_khoan", pivot_value=account)


def bound(con, channel, eids, account="alice"):
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    spec = {"id": "P", "scope": {"channel": channel, "event_ids": eids}, "candidates": "TRUE", "filters": []}
    out = s8_pivot.bind_spec(spec, hyp(channel, eids, account), cols)
    assert spec["candidates"] == "TRUE"                                       # không sửa spec gốc
    return out, {r["ev_rec"] for r in s8_triage.final_rows(con, out, cols)}


def test_wmi_activity_account_is_matched_in_message_with_exact_key_and_name(con):
    out, recs = bound(con, WMI, [5857, 5858, 5860, 5861])
    # 1: MIỀN\tên; 3: khóa UserName, khác hoa thường; 8: dạng tên@miền; 9: cuối bản tin.
    # Không khớp: tài khoản dịch vụ (2), bản tin không có tài khoản (4), khóa khác tên (5), tên dài hơn hay chỉ chứa (6, 7).
    assert recs == {1, 3, 8, 9}
    assert "regexp_matches" in out["candidates"] and '"Message"' in out["candidates"]
    assert bound(con, WMI, [5858], "bob")[1] == set()


def test_other_channels_keep_the_column_only_binding(con):
    out, recs = bound(con, SYS, [1])
    assert recs == {10}                                                       # theo cột User, không theo Message
    assert "regexp_matches" not in out["candidates"] and "Message" not in out["candidates"]
    assert out["candidates"] == (
        "(TRUE) AND (lower(trim(split_part(split_part(coalesce(\"User\", ''), chr(92), -1), '@', 1))) = 'alice' OR "
        "lower(trim(split_part(split_part(coalesce(\"AccountName\", ''), chr(92), -1), '@', 1))) = 'alice')")


def test_account_name_is_escaped_for_sql_and_regex(con):
    for name in ("a.ice", "al'ice", "alic(e"):
        _, recs = bound(con, WMI, [5858], name)
        assert recs == set()                                                  # không lỗi SQL/regex, không khớp "alice"


def test_splunk_export_refuses_a_message_account_binding_instead_of_dropping_it():
    source = inspect.getsource(splunk_sigma.convert_effective)
    refusal = source.index('binding.get("message_keys")')
    assert "raise ValueError" in source[refusal:refusal + 300] and refusal < source.index('fields = binding["fields"]')
    assert set(s8_pivot.MESSAGE_ACCOUNT_KEYS) == {WMI}
