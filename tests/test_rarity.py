"""Khâu ⑦ trên dữ liệu tự tạo; kết nối không có view/bảng nhãn."""
import json

import duckdb

from cti_hunt.stages import s7_rarity


SYS = "microsoft-windows-sysmon/operational"


def _con():
    con = duckdb.connect()
    con.execute("""CREATE TABLE events (
        ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec INTEGER, ev_ts TIMESTAMP,
        ParentImage VARCHAR, Image VARCHAR, CommandLine VARCHAR, "User" VARCHAR)""")
    rows = [
        ("A", SYS, 1, 1, "2020-01-01 00:00:00", "C:\\services.exe", "C:\\wmi.exe", "whoami", "D\\alice"),
        ("A", SYS, 1, 2, "2020-01-01 00:00:02", "C:\\services.exe", "C:\\wmi.exe", "net.exe user", "D\\alice"),
        ("A", SYS, 1, 3, "2020-01-01 00:00:03", "C:\\services.exe", "C:\\svchost.exe", "", "SYSTEM"),
        ("B", SYS, 1, 4, "2020-01-01 00:00:04", "C:\\services.exe", "C:\\wmi.exe",
         "powershell -enc QWxhZGRpbjpPcGVuU2VzYW1lMzIxMDEyMzQ=", "D\\bob"),
        ("B", SYS, 1, 5, "2020-01-01 00:00:05", "C:\\services.exe", "C:\\wmi.exe", "", "D\\bob"),
        ("C", SYS, 1, 6, "2020-01-01 00:00:06", "C:\\services.exe", "C:\\wmi.exe", "", "D\\carol"),
    ]
    con.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return con


def test_rarity_uses_full_baseline_approved_filters_and_no_labels():
    con = _con()
    specs = [
        {"id": "H1", "hypothesis_id": "T1", "scope": {"channel": SYS, "event_ids": [1], "hosts": ["A"]},
         "candidates": "TRUE", "filters": [{"id": "F-01", "where": "Image ILIKE '%svchost.exe'",
                                      "ly_do": "hợp lệ", "nguoi_chiu_trach_nhiem": "người vận hành", "het_han": "cuoi_de_tai"}]},
        {"id": "H2", "hypothesis_id": "T2", "scope": {"channel": SYS, "event_ids": [1], "hosts": ["A"]},
         "candidates": "CommandLine ILIKE '%whoami%'", "filters": []},
        {"id": "H3", "hypothesis_id": "T3", "scope": {"channel": SYS, "event_ids": [1], "hosts": ["B"]},
         "candidates": "TRUE", "filters": []},
    ]
    result = s7_rarity.score(con, specs)
    assert result["so_su_kien"] == 5
    assert result["nhat_ky_loc"][0]["giai_doan"] == [
        {"stage": "ung_vien", "hits": 3, "removed": 0},
        {"stage": "sau_F-01", "id": "F-01", "hits": 2, "removed": 1,
         "ly_do": "hợp lệ", "nguoi_chiu_trach_nhiem": "người vận hành", "het_han": "cuoi_de_tai"},
    ]
    assert not any(x["ev_rec"] == 3 for x in result["su_kien"])
    assert result["de_xuat_loai_tru"] == []
    row1 = next(x for x in result["su_kien"] if x["hunt_id"] == "H1" and x["ev_rec"] == 1)
    row2 = next(x for x in result["su_kien"] if x["hunt_id"] == "H1" and x["ev_rec"] == 2)
    encoded = next(x for x in result["su_kien"] if x["hunt_id"] == "H3" and x["ev_rec"] == 4)
    assert row1["bang_chung"]["parent_image_host_count"] == 2
    assert row1["bang_chung"]["parent_image_global_count"] == 5  # cả B, C ngoài scope
    assert result["tham_so"]["version"] == "khau7_v1"
    assert row1["bang_chung"]["recon_commands_in_window"] == 1
    assert row2["bang_chung"]["recon_commands_in_window"] == 2
    assert row1["thanh_phan"]["trinh_sat_day"] == 0
    assert row2["thanh_phan"]["trinh_sat_day"] == 1
    assert row1["thanh_phan"]["tai_khoan_lan_dau"] == 1
    assert row2["thanh_phan"]["tai_khoan_lan_dau"] == 0
    assert row1["bang_chung"]["account_hypotheses"] == 2
    assert encoded["thanh_phan"]["base64_hoac_entropy_cao"] == 1
    assert "buoc" not in json.dumps(result)


def test_recon_density_uses_past_five_seconds_and_one_account():
    con = _con()
    con.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        ("A", SYS, 1, 7, "2020-01-01 00:00:01", "C:\\services.exe", "C:\\wmi.exe", "whoami", "D\\bob"),
        ("A", SYS, 1, 8, "2020-01-01 00:00:01", "C:\\services.exe", "C:\\wmi.exe", "whoami", None),
        ("A", SYS, 1, 9, "2020-01-01 00:00:08", "C:\\services.exe", "C:\\wmi.exe", "whoami", "D\\alice"),
    ])
    spec = {"id": "T", "scope": {"channel": SYS, "event_ids": [1], "hosts": ["A"]},
            "candidates": "ev_rec IN (1, 2, 7, 8, 9)", "filters": []}
    rows = {r["ev_rec"]: r for r in s7_rarity.score(con, [spec])["su_kien"]}
    assert rows[1]["bang_chung"]["recon_commands_in_window"] == 1  # lệnh tương lai không tính
    assert rows[2]["bang_chung"]["recon_commands_in_window"] == 2
    assert rows[7]["bang_chung"]["recon_commands_in_window"] == 1  # tài khoản khác không gộp
    assert rows[8]["bang_chung"]["recon_commands_in_window"] == 0  # thiếu tài khoản không cộng
    assert rows[9]["bang_chung"]["recon_commands_in_window"] == 1  # lệnh cách 6 giây không tính


def test_rarity_rejects_label_query():
    con = _con()
    spec = {"id": "bad", "scope": {"channel": SYS, "event_ids": [1]},
            "candidates": "buoc IS NOT NULL", "filters": []}
    try:
        s7_rarity.score(con, [spec])
    except ValueError as exc:
        assert "nhãn" in str(exc)
    else:
        raise AssertionError("truy vấn nhãn phải bị từ chối")


def test_exclusion_proposal_requires_narrow_sample_and_stays_pending():
    sample = {"Image": "C:\\Tools\\o'brien.exe", "CommandLine": "o'brien.exe /safe",
              "User": "D\\alice", "ev_host": "A"}
    proposal = s7_rarity.propose_exclusion(sample, reason="đã xác nhận là tác vụ bảo trì", owner="người vận hành",
                                           expires="2026-10-31")
    assert proposal["status"] == "pending_review"
    assert "o''brien.exe" in proposal["where"]
    assert '"ev_host" = \'A\'' in proposal["where"]
    assert proposal["nguon"] == "phan_hoi_chuyen_vien"
    no_args = s7_rarity.propose_exclusion({**sample, "CommandLine": ""}, reason="x", owner="người vận hành",
                                          expires="2026-10-31")
    assert 'COALESCE("CommandLine", \'\') = \'\'' in no_args["where"]
    try:
        s7_rarity.propose_exclusion({k: v for k, v in sample.items() if k != "CommandLine"},
                                    reason="x", owner="người vận hành", expires="2026-10-31")
    except ValueError as exc:
        assert "CommandLine" in str(exc)
    else:
        raise AssertionError("mẫu thiếu dòng lệnh không được đề xuất")
