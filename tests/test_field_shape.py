"""Kiểm hình dạng trường (`stages/field_shape.py`, hinh_dang_truong_v1): đọc điều kiện SQL của adapter, gắn cờ điều kiện trái
hình dạng giá trị thật của trường; dữ liệu tổng hợp, không nhãn."""
import duckdb
import pytest

from cti_hunt.stages import field_shape as fs

SYS = "microsoft-windows-sysmon/operational"


@pytest.fixture
def checker():
    con = duckdb.connect()
    con.execute("""CREATE TABLE events (ev_channel VARCHAR, ev_eid INTEGER, Image VARCHAR, CommandLine VARCHAR,
                   Type VARCHAR, EventID VARCHAR, TargetObject VARCHAR, Rong VARCHAR)""")
    rows = []
    for i in range(60):        # như log thật: Image, CommandLine có hơn DONG_MAX giá trị khác nhau (tập mở)
        rows.append((SYS, 1, rf"C:\Windows\System32\prog{i}.exe", f'"C:\\Windows\\prog{i}.exe" /c x', None, "1",
                     None, None))
        rows.append(("security", 4688, None, f"cmd.exe /c y{i}", None, "4688", None, None))
    for t in ("Command Line", "Script", "Event Log") * 4:
        rows.append((SYS, 20, None, None, t, "20", None, None))
    for i in range(12):
        rows.append((SYS, 13, None, None, None, "13", rf"HKLM\Software\k{i}", None))
    con.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return fs.Checker([con])


def _spec(channel, eids, candidates):
    return {"scope": {"channel": channel, "event_ids": eids}, "candidates": candidates}


def _ly_do(checker, channel, eids, sql):
    return sorted({r for x in checker.check(_spec(channel, eids, sql)) for r in x["ly_do"]})


def test_doc_dieu_kien_sql_cua_adapter():
    a = fs.atoms(r"""(Image ILIKE '%\\rundll32.exe' ESCAPE '\' OR Image ILIKE 'C:\\Windows\\x.exe' ESCAPE '\')"""
                 r""" AND regexp_matches(CommandLine, '(?i)^\s*/c(\s|$)') AND Type IN ('a', 'b''c') AND ev_channel = 'x'""")
    assert [(x.kind, x.field, x.value, x.anchored, x.first) for x in a] == [
        ("ilike", "Image", r"%\rundll32.exe", False, None),
        ("bang", "Image", r"C:\Windows\x.exe", True, "C"),
        ("regex", "CommandLine", r"(?i)^\s*/c(\s|$)", True, "/"),
        ("bang", "Type", "a", True, "a"), ("bang", "Type", "b'c", True, "b")]       # ev_* bỏ qua


def test_gan_co_cac_loi_da_thay(checker):
    assert _ly_do(checker, SYS, [1], "Image='netsh.exe'") == ["khong_phai_duong_dan", "ky_tu_dau"]
    assert _ly_do(checker, SYS, [20], "Type='CommandLineEventConsumer'") == ["ngoai_tap_gia_tri"]
    assert _ly_do(checker, "security", [4688], r"regexp_matches(CommandLine, '(?i)^\s*/c(\s|$)')") == ["ky_tu_dau"]
    assert _ly_do(checker, "security", [4688], r"CommandLine ILIKE '/C%' ESCAPE '\'") == ["ky_tu_dau"]
    assert "khong_phai_so" in _ly_do(checker, SYS, [13], "EventID='12,13,14'")
    assert _ly_do(checker, SYS, [13], r"TargetObject ILIKE 're:i|.%\\.%\\.%$|i' ESCAPE '\'") == ["ky_tu_dau", "regex_trong_mau"]
    assert _ly_do(checker, SYS, [1], "Rong='x'") == ["truong_rong"]


def test_khong_gan_co_dieu_kien_hop_le(checker):
    for ch, eids, sql in [
        (SYS, [1], r"Image ILIKE '%\\cmd.exe' ESCAPE '\'"),
        (SYS, [1], r"Image ILIKE 'C:\\Windows\\System32\\cmd.exe' ESCAPE '\'"),
        (SYS, [20], "Type='Command Line'"),
        (SYS, [20], "Type IN ('script', 'Event Log')"),
        ("security", [4688], r"regexp_matches(CommandLine, '(?i)(^|\s)/c(\s|$)')"),
        ("security", [4688], r"CommandLine ILIKE '%\\\\.\\pipe\\%' ESCAPE '\'"),     # \\.\pipe\ không phải regex
        (SYS, [1], "EventID=1"),
        (SYS, [7], "Image='x'"),                     # nguồn không có sự kiện: không đủ dữ liệu để kết luận
    ]:
        assert checker.check(_spec(ch, eids, sql)) == [], sql
