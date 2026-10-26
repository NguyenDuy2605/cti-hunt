"""Không nhãn, không API (15/10): đợt 2 của phép kiểm IOC trên report chưa thấy — 8 report, mã đóng băng là bản sau sửa
(`s2_ioc_sweep.NOT_FILE_HASH`). Giao thức: `docs/METHODOLOGY.md` §6.

Bài Sekoia và ThreatDown liệt kê IOC bằng thẻ `<br>`, bộ đọc nối các dòng lại (lỗi bộ đọc, ghi nhận, không sửa trong phép
kiểm). Đáp án hai bài này lấy từ HTML gốc (mỗi `<br>` là một dòng), chép nguyên văn dưới đây; bộ rút vẫn chạy trên đầu ra của bộ
đọc như khi hệ thống chạy thật.

    .venv/Scripts/python.exe -X utf8 scripts/do_ioc_report_chua_thay_dot2.py --out <thư mục ra>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import do_ioc_tac_gia as T  # noqa: E402

NGOAI = "../workspace/ioc_15-10/report_moi"
T.REPORTS = {
    "Gopher Strike (Zscaler ThreatLabz)": (f"{NGOAI}/IOC-CT-04", "IOC-CT-04-0122", "IOC-CT-04-0154"),
    "FormBook (Fortinet FortiGuard Labs)": (f"{NGOAI}/IOC-CT-05", "IOC-CT-05-0283", "IOC-CT-05-0286"),
    "Chrysalis backdoor (Rapid7)": (f"{NGOAI}/IOC-CT-06", "IOC-CT-06-0203", "IOC-CT-06-0229"),
    "Trial, Error & Typos (Huntress)": (f"{NGOAI}/IOC-CT-07", "IOC-CT-07-0085", None),
    "PolarEdge (Sekoia)": (f"{NGOAI}/IOC-CT-08", "IOC-CT-08-0161", None),
    "Malvertiser copies PC news site (ThreatDown)": (f"{NGOAI}/IOC-CT-09", "IOC-CT-09-0039", "IOC-CT-09-0048"),
    "Zoom-themed malware (Cyble)": (f"{NGOAI}/IOC-CT-10", "IOC-CT-10-0069", None),
    "CORNFLAKE.V3 (Google Threat Intelligence)": (f"{NGOAI}/IOC-CT-11", "IOC-CT-11-0174", "IOC-CT-11-0190"),
}
# Chuỗi regex lấy đáp án đọc nhầm thành tên miền nhưng không phải IOC (xem từng chuỗi), bỏ tay như cách làm 14/10:
T.EXCLUDE = {
    "Gopher Strike (Zscaler ThreatLabz)": {"afwho.pdf": "tên tệp PDF mồi nhử ở cột tên tệp"},
    "Chrysalis backdoor (Rapid7)": {"nsis.nsi": "tên tệp [NSIS.nsi] ở cột tên tệp"},
    "Malvertiser copies PC news site (ThreatDown)": {
        "citrix-x64.msix": "tên tệp trong URL tải (tác giả ghi không có giao thức)", "cpu-z-x86.msix": "tên tệp trong URL tải",
        "realvnc-x64.msix": "tên tệp trong URL tải", "hdr.jpg": "tên tệp trong URL tải", "team.tar.gpg": "tên tệp trong URL tải"},
    "CORNFLAKE.V3 (Google Threat Intelligence)": {
        "78g0zrqi.png": "tên tệp trong đường dẫn máy", "ckw8ua56.log": "tên tệp trong đường dẫn máy",
        "config.cfg": "tên tệp trong đường dẫn máy", "windytwist.sea": "tên họ mã độc WINDYTWIST.SEA, không phải tên miền"},
}

# Đáp án từ HTML gốc cho hai bài bộ đọc nối dòng; ký tự rác "µ" trước một mã băm của Sekoia đã bỏ.
GOLD_SEKOIA = """Webshell - sha256
1ca7262f91d517853a0551b14abb0306c4e3567e41b1e82a018f0aac718e499e
PolarEdge botnet - sha256
eda7cc5e1781c681afe99bf513fcaf5ae86afbf1d84dfd23aa563b1a043cbba8
13cd040a7f488e937b1b234d71a0126b7bc74367bf6538b6961c476f5d620d13
464f29d5f496b4acffc455330f00adb34ab920c66ca1908eee262339d6946bcd
932b2545bd6e3ad74b82ca2199944edecf9c92ad3f75fce0d07e04ab084824d5
121969d72f8e6f09ad93cf17500c479c452e230e27e7b157d5c9336dff15b6ef
PolarEdge botnet - Delivery infrastructure
119.8.186[.]227
longlog[.]cc
landim[.]cc
hitchil[.]cc
Logchim[.]cc
ssofhoseuegsgrfnu[.]ru
PolarEdge botnet - Reporting infrastructure
aipricadd[.]top
firebasesafer[.]top
largeroofs[.]top
siotherlentsearsitech[.]shop
asustordownload[.]com
gardensc[.]cc
headached[.]cc
durianlink[.]cc
nternetd[.]cc
suiteiol[.]cc
centrequ[.]cc
icecreand[.]cc
159.138.119[.]99
43.129.205[.]244
122.8.183[.]181
195.123.212[.]54
"""
GOLD_THREATDOWN = """Ad domains
argenferia[.]com
realvnc[.]pro
corporatecomf[.]online
cilrix-corp[.]pro
thecoopmodel[.]com
winscp-apps[.]online
wireshark-app[.]online
cilrix-corporate[.]online
workspace-app[.]online
Payload URLs
thecoopmodel[.]com/CPU-Z-x86.msix
kaotickontracting[.]info/account/hdr.jpg
ivcgroup[.]in/temp/Citrix-x64.msix
robo-claim[.]site/order/team.tar.gpg
argenferia[.]com/RealVNC-x64.msix
Payloads
55d3ed51c3d8f56ab305a40936b446f761021abfc55e5cc8234c98a2c93e99e1
9acbf1a5cd040c6dcecbe4e8e65044b380b7432f46c5fbf2ecdc97549487ca88
419e06194c01ca930ed5d7484222e6827fd24520e72bfe6892cfde95573ffa16
cf9589665615375d1ad22d3b84e97bb686616157f2092e2047adb1a7b378cc95
C2s
11234jkhfkujhs[.]site
11234jkhfkujhs[.]top
94.131.111[.]240
81.177.136[.]179
"""
_gold = T.gold_from_section


def gold_from_section(text: str):
    if "PolarEdge botnet - Delivery infrastructure" in text:
        return _gold(GOLD_SEKOIA)
    if "11234jkhfkujhs" in text and "Ad domains" in text:
        return _gold(GOLD_THREATDOWN)
    return _gold(text)


T.gold_from_section = gold_from_section

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--khong-quet-log" not in args:
        args.append("--khong-quet-log")
    sys.exit(T.main(args))
