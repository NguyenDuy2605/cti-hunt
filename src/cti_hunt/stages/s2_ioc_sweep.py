"""Khâu quét IOC (thêm 14/10): phân loại IOC của Contract A thành mạnh/yếu rồi quét đúng trường trên log.

Xử lý xác định, không gọi mô hình, không đọc nhãn. Quét IOC là bước rẻ và chính xác khi hạ tầng hay mẫu của chiến dịch còn
được dùng lại; khi không khớp (kẻ tấn công đổi hạ tầng, hay lab dựng lại hành vi bằng hạ tầng riêng), săn theo hành vi ở
các khâu ③–⑨ mới là phần chính. Vì vậy khâu này chạy trước, không thay các khâu sau.

Mức IOC:
- ``manh``: mã băm tệp, IP/tên miền công khai không thuộc dịch vụ phổ biến, URL có tên máy như vậy, đường dẫn đầy đủ,
  khóa registry, named pipe. Quét mặc định.
- ``yeu``: khớp cả hoạt động hợp lệ nên chỉ quét khi người dùng yêu cầu — IP nội bộ/dải đặc biệt/DNS công cộng, tên miền
  dịch vụ phổ biến, tên tệp không kèm đường dẫn, imphash/JA3 (dấu vân tay dùng chung giữa nhiều chương trình).
- ``bo``: không phải chỉ dấu của chiến dịch — link của nhà xuất bản hay tài liệu tham khảo, ảnh minh họa.

Mỗi loại IOC chỉ so với các trường có thể chứa nó (mã băm với ``Hashes``, IP với trường địa chỉ…), không quét mọi trường:
quét mọi trường làm một mã băm lẫn trong dòng lệnh hay một tên tệp trong call trace thành "khớp".
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import duckdb

from ..contracts import IOC, ContractA
from . import s2_ioc
from .s8_triage import ACCOUNT_COLUMNS, norm_account

VERSION = "ioc_sweep_v1"
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.220.220", "208.67.222.222",
              "84.200.69.80", "84.200.70.40", "4.2.2.2"}
# Dịch vụ phổ biến: kẻ tấn công có dùng (đẩy dữ liệu lên OneDrive, tải công cụ từ GitHub) nhưng người dùng hợp lệ cũng dùng,
# nên tên miền đứng một mình không phải chỉ dấu.
COMMON_SERVICES = ("microsoft.com", "microsoftonline.com", "live.com", "live.net", "windows.net", "windows.com", "office.com",
                   "office365.com", "sharepoint.com", "onedrive.com", "azure.com", "azureedge.net", "msft.net", "aka.ms",
                   "github.com", "githubusercontent.com", "google.com", "googleapis.com", "gstatic.com", "cloudflare.com",
                   "amazonaws.com", "akamai.net", "akamaiedge.net", "dropbox.com", "apple.com", "mozilla.org",
                   "wikipedia.org", "twitter.com", "x.com", "youtube.com", "linkedin.com", "socket.io")
# Không gồm nền tảng cho thuê tên miền con (workers.dev, azurewebsites.net…): mỗi tên miền con do một người tự đặt.
# Nhà xuất bản CTI, kho tài liệu tham khảo: link tới đây là trích dẫn, không phải chỉ dấu.
REFERENCE_HOSTS = ("thedfirreport.com", "securelist.com", "kaspersky.com", "welivesecurity.com", "eset.com", "elastic.co",
                   "mandiant.com", "fireeye.com", "paloaltonetworks.com", "proofpoint.com", "symantec.com", "broadcom.com",
                   "security.com", "crowdstrike.com", "sentinelone.com", "talosintelligence.com", "cisa.gov",
                   "attack.mitre.org", "mitre.org", "medium.com", "sigmasearchengine.com", "detection.fyi", "threatview.io",
                   "compass-security.com", "falconforce.nl", "virustotal.com", "learn.microsoft.com", "docs.microsoft.com")
# Dải đặc biệt của IANA mà ipaddress vẫn coi là "global" (AS112, AMT, 6to4 relay, 192.0.0.9/10).
SPECIAL_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.0.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                                         "192.88.99.0/24", "192.175.48.0/24"))
# Dải công bố của Cloudflare: kẻ tấn công núp sau CDN, nhưng nhiều trang hợp lệ dùng chung địa chỉ.
CDN_NETS = tuple(ipaddress.ip_network(n) for n in ("104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "173.245.48.0/20",
                                                     "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
                                                     "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                                                     "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "131.0.72.0/22"))
NAME_SERVER = re.compile(r"^ns\d*\.")
# Tên khóa registry chung của Windows: khóa IOC kết thúc ở đây là vị trí, không phải dấu vết riêng của kẻ tấn công.
COMMON_KEYS = {"software", "system", "microsoft", "windows", "windows nt", "currentversion", "run", "runonce", "services",
               "control", "currentcontrolset", "controlset001", "policies", "explorer", "winlogon", "environment", "classes",
               "wow6432node", ".default", "internet", "internet settings", "terminal", "terminal server", "session manager"}
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")
FINGERPRINT = re.compile(r"(imphash|ja3s?|ssdeep|tlsh)\W{0,4}$", re.I)
# 15/10 (thấy trên report chưa từng dùng): chuỗi hex 40/64 ký tự đứng ngay sau các từ này là mã đối tượng git, khóa mã hóa hay
# dấu vân tay khóa, không phải mã băm của một tệp; quét trên trường Hashes không bao giờ khớp.
NOT_FILE_HASH = re.compile(r"\b(tree|parent|commit|object|key|nonce|salt|iv|value\s*\d*|fingerprint)\W{0,4}$", re.I)
# 15/10 (thấy trên report chưa từng dùng: `C:\Windows\System32\arp.exe` của CORNFLAKE.V3 khớp 132 sự kiện bình thường): chương
# trình (.exe/.com/.msc) nằm thẳng trong thư mục hệ thống của Windows phần lớn là công cụ có sẵn mà kẻ tấn công dùng lại. DLL và
# tệp dữ liệu ở đó giữ mạnh (ToddyCat thả `libvlc.dll`, `update.bin` vào System32). Đánh đổi: mã độc thả vào System32 dưới dạng
# .exe thành IOC yếu (vẫn hiện trong danh sách, không quét mặc định). Quy tắc viết sau khi xem đường dẫn của 19 report.
SYSTEM_FILE = re.compile(r"^(?:[a-z]:\\windows|%systemroot%|%windir%)\\(?:(?:system32|syswow64|sysnative)\\"
                         r"(?:wbem\\|windowspowershell\\v1\.0\\)?)?[^\\]+\.(?:exe|com|msc)$")

# loại IOC → [(trường, cách so)]; "bang": bằng · "chua": chứa · "chua_tu": chứa đứng riêng (không liền chữ, số, dấu chấm, gạch,
# gạch chéo ngược hai bên — 15/10: `microsoft.net` từng khớp mọi dòng lệnh có `Microsoft.NET\Framework`, `1.2.3.4` khớp
# `11.2.3.45`) · "ten_mien": bằng hoặc là tên miền con · "duoi": đuôi đường dẫn
FIELDS: dict[str, list[tuple[str, str]]] = {
    "hash": [("Hashes", "chua"), ("Hash", "chua"), ("MD5", "bang"), ("SHA1", "bang"), ("SHA256", "bang")],
    "ip": [("DestinationIp", "bang"), ("SourceIp", "bang"), ("IpAddress", "bang"), ("SourceAddress", "bang"),
           ("DestAddress", "bang"), ("ClientAddress", "bang"), ("QueryResults", "chua_tu"), ("CommandLine", "chua_tu"),
           ("ScriptBlockText", "chua_tu"), ("Payload", "chua_tu")],
    "domain": [("QueryName", "ten_mien"), ("DestinationHostname", "ten_mien"), ("CommandLine", "chua_tu"),
               ("ParentCommandLine", "chua_tu"), ("ScriptBlockText", "chua_tu"), ("Payload", "chua_tu")],
    "url": [("CommandLine", "chua"), ("ParentCommandLine", "chua"), ("ScriptBlockText", "chua"), ("Payload", "chua")],
    "duong_dan": [("Image", "bang"), ("ParentImage", "bang"), ("TargetFilename", "bang"), ("ImageLoaded", "bang"),
                  ("CommandLine", "chua"), ("ParentCommandLine", "chua"), ("ScriptBlockText", "chua")],
    "ten_file": [("Image", "duoi"), ("ParentImage", "duoi"), ("TargetFilename", "duoi"), ("ImageLoaded", "duoi")],
    "registry": [("TargetObject", "chua")],
    "named_pipe": [("PipeName", "bang")],
    "email": [("CommandLine", "chua"), ("ScriptBlockText", "chua")],
}
HIVE = re.compile(r"^(hklm|hkcu|hku|hkcr|hkey_[a-z_]+)\\", re.I)


def _host_in(host: str, names) -> bool:
    return any(host == n or host.endswith("." + n) for n in names)


def _ip_strength(ip: str) -> tuple[str, str]:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "bo", "không phải địa chỉ IP hợp lệ"
    if not a.is_global or a.is_multicast or any(a in n for n in SPECIAL_NETS):
        return "yeu", "IP nội bộ hoặc dải đặc biệt: có ở mọi mạng"
    if ip in PUBLIC_DNS:
        return "yeu", "máy chủ DNS công cộng"
    if any(a in n for n in CDN_NETS):
        return "yeu", "IP của CDN dùng chung (Cloudflare): nhiều trang hợp lệ cùng địa chỉ"
    if ip.endswith(".0"):
        return "yeu", "địa chỉ mạng (đuôi .0): thường là dải hoặc số phiên bản, không phải một máy"
    return "manh", "IP công khai"


def _host_strength(host: str, publisher: str) -> tuple[str, str]:
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        return _ip_strength(host)
    if publisher and (host == publisher or host.endswith("." + publisher)):
        return "bo", "tên miền của chính nhà xuất bản report"
    if _host_in(host, REFERENCE_HOSTS):
        return "bo", "nhà xuất bản CTI hoặc tài liệu tham khảo"
    if _host_in(host, COMMON_SERVICES):
        return "yeu", "dịch vụ phổ biến: người dùng hợp lệ cũng truy cập"
    if NAME_SERVER.match(host):
        return "yeu", "máy chủ tên miền của nhà cung cấp DNS, dùng chung cho nhiều tên miền"
    return "manh", "tên miền không thuộc dịch vụ phổ biến"


def classify(ioc: IOC, value: str, publisher: str = "") -> tuple[str, str]:
    """Trả (mức, lý do). ``value`` là giá trị đã đưa về dạng thật, chữ thường."""
    kind = ioc.type
    if kind == "hash":
        text = ioc.source_span.text or ""
        at = text.lower().find(value)
        if at > 0 and FINGERPRINT.search(text[max(0, at - 24):at]):
            return "yeu", "dấu vân tay dùng chung (imphash/JA3), không phải mã băm của một tệp"
        if at > 0 and NOT_FILE_HASH.search(text[max(0, at - 24):at]):
            return "yeu", "chuỗi hex của mã đối tượng git, khóa hay dấu vân tay khóa, không phải mã băm của một tệp"
        return "manh", "mã băm tệp"
    if kind == "ip":
        return _ip_strength(value)
    if kind == "domain":
        return _host_strength(value, publisher)
    if kind == "url":
        parts = urlsplit(value)
        if parts.path.lower().endswith(IMAGE_EXT):
            return "bo", "ảnh minh họa của bài"
        return _host_strength((parts.hostname or "").lower(), publisher)
    if kind == "ten_file":
        return "yeu", "tên tệp không kèm đường dẫn: dễ trùng tệp hợp lệ"
    if kind == "duong_dan":
        last = value.rstrip("\\").rsplit("\\", 1)[-1]
        if value.endswith("\\") or not re.search(r"\.[a-z0-9]{1,6}$", last):
            return "yeu", "thư mục, không phải một tệp cụ thể: khớp mọi tệp bên trong"
        if SYSTEM_FILE.match(value):
            return "yeu", "chương trình nằm thẳng trong thư mục hệ thống của Windows: thường là công cụ có sẵn, chạy cả khi bình thường"
        return "manh", "đường dẫn tới một tệp cụ thể"
    if kind == "registry":
        parts = [p for p in value.split("\\") if p]
        if value.endswith("\\") or len(parts) < 4 or parts[-1] in COMMON_KEYS:
            return "yeu", "vị trí registry chung (Run, Services…) hoặc khóa bị cắt: cần kèm tên khóa con hay giá trị"
        return "manh", "khóa registry cụ thể"
    if kind == "named_pipe":
        return "manh", "named pipe cụ thể"
    if kind == "email":
        return "manh", "địa chỉ email"
    return "yeu", f"loại {kind} chưa có quy tắc"


def plan(contract: ContractA, rules: dict) -> list[dict]:
    """Danh sách giá trị sẽ quét: IOC của Contract A, đã đưa về dạng thật, gộp trùng, kèm mức và lý do. Tên máy trong URL
    mạnh được tách thành một mục riêng, vì log hiếm khi ghi nguyên URL."""
    publisher = (urlsplit(contract.source_url).hostname or "").lower().removeprefix("www.")
    out: dict[tuple[str, str], dict] = {}
    for ioc in contract.iocs:
        value = s2_ioc.normalize(ioc.value, rules)
        if ioc.type == "duong_dan" and "\\" not in value:
            continue
        level, reason = classify(ioc, value, publisher)
        out.setdefault((ioc.type, value), {"loai": ioc.type, "gia_tri": value, "goc": ioc.value, "muc": level,
                                           "ly_do": reason, "doan": ioc.source_span.segment_id or ""})
        if ioc.type == "url" and level == "manh":
            host = (urlsplit(value).hostname or "").lower()
            kind = "ip" if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) else "domain"
            out.setdefault((kind, host), {"loai": kind, "gia_tri": host, "goc": ioc.value, "muc": "manh",
                                          "ly_do": "tên máy tách từ URL", "doan": ioc.source_span.segment_id or ""})
    return list(out.values())


def _cond(field: str, how: str, value: str) -> tuple[str, list]:
    col = f'lower("{field}")'
    if how == "bang":
        return f"{col} = ?", [value]
    if how == "ten_mien":
        return f"({col} = ? OR ends_with({col}, ?))", [value, "." + value]
    if how == "duoi":
        return f"({col} = ? OR ends_with({col}, ?))", [value, "\\" + value]
    if how == "chua_tu":
        edge = r"[^a-z0-9_.\-\\]"
        return f"(contains({col}, ?) AND regexp_matches({col}, ?))", [value, f"(^|{edge}){re.escape(value)}($|{edge})"]
    return f"contains({col}, ?)", [value]


def sweep_dir(items: list[dict], events: Path, **kw) -> dict:
    """Quét trên ``events/events.parquet`` (lệnh ``ioc-sweep``)."""
    con = duckdb.connect()
    con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet('{(Path(events) / 'events.parquet').as_posix()}')")
    return {**sweep(items, con, **kw), "bo_log": str(events)}


def sweep(items: list[dict], con: duckdb.DuckDBPyConnection, *, include_weak: bool = False,
          exclude_accounts: list[str] | None = None, sample: int = 20) -> dict:
    """Quét các mục của ``plan`` trên view ``events`` của ``con``. Không đọc cột nhãn: chỉ chọn các cột trong ``FIELDS``,
    cột khóa sự kiện và cột tài khoản."""
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    acc_cols = [c for c in ACCOUNT_COLUMNS if c in columns]
    excl = [re.compile(p, re.I) for p in exclude_accounts or []]
    total = con.execute("SELECT count(*) FROM events").fetchone()[0]
    results, hosts, accounts = [], Counter(), Counter()
    for item in items:
        row = {**item, "truong_quet": [], "so_su_kien": 0, "theo_nguon": {}, "may": {}, "tai_khoan": {}, "mau": []}
        if item["muc"] == "bo" or (item["muc"] == "yeu" and not include_weak):
            row["trang_thai"] = "khong_quet"
            results.append(row)
            continue
        parts, params, fields = [], [], []
        for field, how in FIELDS.get(item["loai"], []):
            if field in columns:
                value = HIVE.sub("", item["gia_tri"]) if item["loai"] == "registry" else item["gia_tri"]
                sql, p = _cond(field, how, value)
                parts.append(sql)
                params += p
                fields.append(field)
        row["truong_quet"] = fields
        if not parts:
            row["trang_thai"] = "khong_co_truong"
            results.append(row)
            continue
        acc_sql = ", ".join(f'"{c}"' for c in acc_cols) or "NULL"
        rows = con.execute(f"SELECT ev_host, ev_channel, ev_eid, ev_rec, {acc_sql} FROM events WHERE {' OR '.join(parts)}",
                           params).fetchall()
        row["trang_thai"] = "da_quet"
        row["so_su_kien"] = len(rows)
        src, may, acc = Counter(), Counter(), Counter()
        for r in rows:
            src[f"{r[1]} · {r[2]}"] += 1
            may[r[0]] += 1
            for a in {norm_account(x) for x in r[4:4 + len(acc_cols)] if x} - {""}:
                acc[a] += 1
        row["theo_nguon"], row["may"] = dict(src.most_common()), dict(may.most_common())
        row["tai_khoan"] = {a: n for a, n in acc.most_common() if not any(x.search(a) for x in excl)}
        row["mau"] = [{"ev_host": r[0], "ev_channel": r[1], "ev_eid": r[2], "ev_rec": r[3]} for r in rows[:sample]]
        hosts.update(row["may"])
        accounts.update(row["tai_khoan"])
        results.append(row)
    by = Counter((r["muc"], r["trang_thai"]) for r in results)
    return {"version": VERSION, "bo_log": "events", "so_su_kien_log": total, "ca_ioc_yeu": include_weak,
            "tong": {"so_muc": len(results), "manh": sum(r["muc"] == "manh" for r in results),
                     "yeu": sum(r["muc"] == "yeu" for r in results), "bo": sum(r["muc"] == "bo" for r in results),
                     "da_quet": by[("manh", "da_quet")] + by[("yeu", "da_quet")],
                     "co_khop": sum(r["so_su_kien"] > 0 for r in results)},
            # Máy, tài khoản dính IOC: gợi ý cho người săn và cho vòng pivot; không tự kết luận là bị xâm nhập.
            "thuc_the": {"may": dict(hosts.most_common()), "tai_khoan": dict(accounts.most_common())},
            "muc": results}


def render(result: dict) -> str:
    """Bảng Markdown để người săn đọc; không có thông tin từ nhãn."""
    t = result["tong"]
    lines = [f"### Quét IOC ({result['version']})", "",
             f"Bộ log `{result['bo_log']}` ({result['so_su_kien_log']} sự kiện). {t['so_muc']} giá trị: {t['manh']} mạnh, "
             f"{t['yeu']} yếu, {t['bo']} bỏ; đã quét {t['da_quet']}, có khớp {t['co_khop']}.", "",
             "| Giá trị | Loại | Mức | Lý do | Trường quét | Sự kiện khớp | Máy | Tài khoản |", "|---|---|---|---|---|---:|---|---|"]
    for r in sorted(result["muc"], key=lambda r: (-r["so_su_kien"], r["muc"], r["loai"], r["gia_tri"])):
        shown = r["so_su_kien"] if r["trang_thai"] == "da_quet" else {"khong_quet": "không quét",
                                                                       "khong_co_truong": "log không có trường"}[r["trang_thai"]]
        lines.append(f"| `{r['gia_tri']}` | {r['loai']} | {r['muc']} | {r['ly_do']} | {', '.join(r['truong_quet']) or '—'} | "
                     f"{shown} | {', '.join(r['may']) or '—'} | {', '.join(r['tai_khoan']) or '—'} |")
    lines += ["", "Khớp IOC là đầu mối để người săn kiểm, không tự kết luận máy bị xâm nhập. Không khớp không có nghĩa là "
              "sạch: chiến dịch mới thường đổi hạ tầng; săn theo hành vi ở các khâu sau mới là phần chính."]
    return "\n".join(lines) + "\n"
