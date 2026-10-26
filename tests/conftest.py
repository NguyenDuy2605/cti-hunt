"""Fixture tổng hợp nhỏ, mô phỏng đúng các chỗ khó của dataset thật (v3 §3.4)."""
import csv
import json
from pathlib import Path

import pytest

from cti_hunt.data.ingest import ingest
from cti_hunt.data.store import connect

SYSMON = "Microsoft-Windows-Sysmon/Operational"
TIME_CFG = {"sysmon_field": "UtcTime", "other_field": "EventTime", "other_offset_hours": 4}
KEY = ["ev_host", "ev_channel", "ev_rec"]


def ev(host, channel, eid, rec, event_time, **fields):
    return {"Hostname": host, "Channel": channel, "EventID": eid, "RecordNumber": rec,
            "EventTime": event_time, **fields}


EVENTS = [
    # Sysmon EID 1: 3 con của services/WmiPrvSE/wsmprovhost, 1 con của explorer
    ev("UTICA.dmevals.local", SYSMON, 1, 10, "2020-05-02 03:59:09", UtcTime="2020-05-02 07:59:09.928",
       ParentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ev("UTICA.dmevals.local", SYSMON, 1, 11, "2020-05-02 04:00:00", UtcTime="2020-05-02 08:00:00.100",
       ParentImage=r"C:\Windows\system32\services.exe", Image=r"C:\Windows\System32\svchost.exe"),
    ev("UTICA.dmevals.local", SYSMON, 1, 12, "2020-05-02 04:00:01", UtcTime="2020-05-02 08:00:01.200",
       ParentImage=r"C:\Windows\system32\services.exe", Image=r"C:\Windows\System32\sppsvc.exe"),
    ev("NEWYORK.dmevals.local", SYSMON, 1, 10, "2020-05-02 04:04:25", UtcTime="2020-05-02 08:04:25.616",
       ParentImage=r"C:\Windows\System32\wsmprovhost.exe", Image=r"C:\Users\mscott\m.exe"),
    ev("NEWYORK.dmevals.local", SYSMON, 1, 11, "2020-05-02 04:05:00", UtcTime="2020-05-02 08:05:00.000",
       ParentImage=r"C:\Windows\explorer.exe", Image=r"C:\Windows\System32\notepad.exe"),
    # System EID 1 không phải tạo tiến trình (v3 §3.4)
    ev("UTICA.dmevals.local", "System", 1, 10, "2020-05-02 04:01:00"),
    # Security viết hai kiểu; cùng RecordNumber 10 với Sysmon trên UTICA (chỉ duy nhất trong cặp máy+channel)
    ev("UTICA.dmevals.local", "Security", 4688, 20, "2020-05-02 04:00:00", NewProcessName=r"C:\x.exe"),
    ev("UTICA.dmevals.local", "security", 4688, 21, "2020-05-02 04:00:02", NewProcessName=r"C:\y.exe",
       IpAddress="10.0.0.1", Ipaddress="10.0.0.2"),
    # PowerShell 4104: không có UtcTime -> EventTime + 4h
    ev("UTICA.dmevals.local", "Microsoft-Windows-PowerShell/Operational", 4104, 10, "2020-05-02 04:02:03",
       ScriptBlockText="Invoke-Command -ComputerName NEWYORK", **{"@timestamp": "2020-05-02T08:05:00Z"}),
]


@pytest.fixture(autouse=True)
def without_community_gap_priority(request, monkeypatch):
    """15/10: ưu tiên khoảng trống đọc bản SigmaHQ ghim trên máy (`data/work/sigmahq`), máy khác có thể không có. Test cơ
    chế khác tắt cờ để thứ tự TTP không phụ thuộc máy; module đặt `BAT_KHOANG_TRONG = True` tự trỏ tới SigmaHQ tổng hợp."""
    if getattr(request.module, "BAT_KHOANG_TRONG", False):
        return
    from cti_hunt import config as _config
    original = _config.agent_config

    def cfg_without(*args, **kwargs):
        cfg = original(*args, **kwargs)
        cfg.pop("khoang_trong_rule_cong_dong", None)
        cfg.pop("rule_cong_dong_trong_luot", None)
        cfg.pop("chi_san_khoang_trong", None)
        return cfg
    monkeypatch.setattr(_config, "agent_config", cfg_without)


@pytest.fixture
def raw_json(tmp_path) -> Path:
    p = tmp_path / "raw.json"
    p.write_text("\n".join(json.dumps(e) for e in EVENTS) + "\n", encoding="utf-8")
    return p


@pytest.fixture
def work(tmp_path, raw_json) -> Path:
    w = tmp_path / "work"
    ingest(raw_json, w, sysmon_channel=SYSMON.lower(), time_cfg=TIME_CFG, event_key=KEY, expected_rows=len(EVENTS))
    return w


def write_labels(path: Path, rows: list[tuple]) -> Path:
    """rows: (may, channel, record_number, buoc) — đúng header và BOM của nhãn v1."""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow("utc,may,channel,event_id,record_number,process_guid,image,chi_tiet,ly_do,buoc".split(","))
        for may, ch, rec, buoc in rows:
            w.writerow(["", may, ch, "", rec, "", "", "", "", buoc])
    return path


LABEL_KEYS = {"ev_host": "may", "ev_channel": "channel", "ev_rec": "record_number"}


@pytest.fixture
def con_labeled(work, tmp_path):
    from cti_hunt.labels import events
    con = connect(work)
    csv_path = write_labels(tmp_path / "su_kien_tan_cong.csv", [
        ("utica", SYSMON, 10, "14.B"),       # WmiPrvSE -> powershell
        ("newyork", SYSMON, 10, "16.D"),     # wsmprovhost -> m.exe
        ("utica", "Microsoft-Windows-PowerShell/Operational", 10, "16.C"),
    ])
    summary = events.attach(con, csv_path, LABEL_KEYS, "buoc", expected_rows=3)
    return con, summary
