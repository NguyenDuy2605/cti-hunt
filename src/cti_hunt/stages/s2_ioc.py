"""Khâu ② — nhánh IOC: regex + refang + kiểm tra định dạng (v3 §4.2, §4.4).

Xử lý xác định hoàn toàn, không dùng mô hình ngôn ngữ (v3 §4.4).

Bốn điểm bám theo quy tắc R10 của bộ nhãn tham chiếu, để đo được bằng cách so tập (report, giá trị):
- Giá trị trả về là ĐÚNG chuỗi trong văn bản, kể cả dạng defang (bigtopweb[.]com). Vì vậy văn bản
  được refang để nhận dạng, nhưng có bảng ánh xạ vị trí để cắt lại từ văn bản gốc.
- Mỗi IOC ghi một lần cho mỗi report, ở đoạn xuất hiện đầu tiên; dạng viết khác của cùng một giá trị
  được ghi vào trường context.
- URL ghi loại url, không tách domain thành dòng riêng: vùng văn bản đã thuộc về IOC trước thì IOC
  sau không lấy nữa (thứ tự ưu tiên trong PATTERNS).
- Không ghi tên binary hệ thống ở đúng tên và vị trí mặc định; đổi tên hoặc nằm ở đường dẫn lạ thì ghi.

Chưa lọc được tự động: IOC nằm trong truy vấn săn tìm của vendor vẫn tính (R10) — đúng như module này
làm; ngược lại, phân biệt "file kẻ tấn công mang vào" với file lạ khác thì code không quyết được, nên
mọi tên tệp không thuộc danh sách binary hệ thống đều được ghi.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from ..contracts import IOC, SourceSpan
from ..integrity import require_frozen

# Thứ tự quyết định ai lấy vùng văn bản trước (URL trước domain, đường dẫn trước tên tệp).
PATTERNS: list[tuple[str, str]] = [
    # 15/10: dấu nháy cong (“ ” ‘ ’) không thuộc giá trị; trước đây dính vào cuối URL, khóa registry, đường dẫn (cmd.exe”).
    ("url", r"\bhttps?://[^\s<>\"'\]\)},;“”‘’]+"),
    ("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
    ("registry", r"\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)\\[^\s<>\"',;“”‘’]+"),
    ("named_pipe", r"\\\\\.\\pipe\\[A-Za-z0-9_.\-]+"),
    # Đường dẫn có thư mục chứa dấu cách (C:\Program Files\…\a.exe): chỉ nhận khi kết thúc bằng tên tệp có đuôi (14/10;
    # trước đó bị cắt thành C:\Program). Không khớp thì rơi xuống mẫu dưới như cũ.
    ("duong_dan", r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n“”‘’]+\\)+[^\\/:*?\"<>|\s“”‘’]+\.[A-Za-z0-9]{1,6}\b"),
    ("duong_dan", r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.\-]+\\|%[A-Za-z0-9_()]+%\\)[^\s<>\"',;“”‘’]+"),
    ("hash", r"\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{32}\b"),
    ("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("domain", r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
    ("ten_file", r"\b[A-Za-z0-9_\-.]+\.[A-Za-z0-9]{1,6}\b"),
]
COMPILED = [(t, re.compile(p)) for t, p in PATTERNS]


def load_rules(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    def low(items) -> set[str]:
        return {str(x).lower() for x in items or []}      # str(): YAML đọc no/on/yes thành boolean

    tld, file_ext = low(r.get("tld")), low(r.get("file_ext"))
    # Đuôi vừa là TLD vừa là đuôi tệp (com, pl...) thì hiểu là domain: trong CTI report, chuỗi dạng
    # "abc.com" gần như luôn là domain. Tên tệp .com thật sẽ bị bỏ sót; ghi nhận giới hạn này.
    file_ext -= tld
    return {"defang": r.get("defang") or {}, "tld": tld, "file_ext": file_ext,
            "system_binaries": low(r.get("system_binaries")),
            # 15/10: sắp thêm theo chữ khi cùng độ dài; trước đây thứ tự hai thư mục cùng độ dài (system32, syswow64) theo
            # thứ tự duyệt tập hợp, đổi giữa các tiến trình Python, làm băm quy tắc IOC trong meta lượt trích đổi theo.
            "system_dirs": sorted(low(r.get("system_dirs")), key=lambda d: (-len(d), d))}


def refang(text: str, defang: dict[str, str]) -> tuple[str, list[int], list[int]]:
    """Trả (văn bản đã refang, vị trí đầu, vị trí cuối trong văn bản GỐC của từng ký tự)."""
    tokens = sorted(defang.items(), key=lambda kv: -len(kv[0]))
    low = text.lower()
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i = 0
    while i < len(text):
        for src, dst in tokens:
            if low.startswith(src.lower(), i):
                for ch in dst:
                    out.append(ch)
                    starts.append(i)
                    ends.append(i + len(src))
                i += len(src)
                break
        else:
            out.append(text[i])
            starts.append(i)
            ends.append(i + 1)
            i += 1
    return "".join(out), starts, ends


def _tail(path: str) -> str:
    return re.split(r"[\\/]", path)[-1].lower()


def _valid(kind: str, value: str, was_defanged: bool, rules: dict) -> tuple[bool, str]:
    """Trả (nhận hay không, loại cuối cùng). Loại có thể đổi, vd hash -> hash theo độ dài."""
    v = value.lower()
    if kind == "ip":
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return False, kind
        return True, kind
    if kind == "hash":
        return len(value) in (32, 40, 64), kind
    if kind == "url":
        try:
            return bool(urlsplit(value).netloc), kind
        except ValueError:                          # vd "https://x.workers[." khi dạng che không có trong bảng defang
            return False, kind
    if kind == "domain":
        tld = v.rsplit(".", 1)[-1]
        if tld in rules["file_ext"]:
            return False, kind                      # kxwn.lock, m.exe không phải domain
        return tld in rules["tld"] or was_defanged, kind
    if kind == "ten_file":
        name, _, ext = v.rpartition(".")
        if ext not in rules["file_ext"]:
            return False, kind
        return v not in rules["system_binaries"], kind   # R10
    if kind == "duong_dan":
        if _tail(v) in rules["system_binaries"] and any(v.startswith(d) for d in rules["system_dirs"]):
            return False, kind                      # binary hệ thống ở vị trí mặc định
        return True, kind
    return True, kind


def extract(text: str, rules: dict, segment_id: str | None = None,
            section: str = "", page: int = 0) -> list[IOC]:
    refanged, starts, ends = refang(text, rules["defang"])
    claimed: list[tuple[int, int]] = []
    found: list[tuple[int, IOC]] = []
    for kind, rx in COMPILED:
        for m in rx.finditer(refanged):
            s, e = m.span()
            if any(s < ce and cs < e for cs, ce in claimed):
                continue
            original = text[starts[s]:ends[e - 1]]
            ok, kind2 = _valid(kind, m.group(0), original != m.group(0), rules)
            if not ok:
                if kind == "duong_dan":
                    # 15/10: đường dẫn hệ thống bị bỏ (R10) vẫn giữ chỗ; trước đây mẫu tên miền cắt lại `Microsoft.NET` từ
                    # giữa `C:\Windows\Microsoft.NET\Framework\...\MSBuild.exe` thành IOC tên miền.
                    claimed.append((s, e))
                continue
            claimed.append((s, e))
            found.append((starts[s], IOC(type=kind2, value=original, validated=True,
                                         source_span=SourceSpan(section=section, page=page,
                                                                text=text[:400], segment_id=segment_id))))
    return [ioc for _, ioc in sorted(found, key=lambda x: x[0])]


def normalize(value: str, rules: dict) -> str:
    """Khóa so trùng: refang + chữ thường + bỏ dấu câu cuối. Không dùng làm giá trị ghi ra."""
    v, _, _ = refang(value, rules["defang"])
    return v.lower().rstrip("./,;)")


def extract_report(segments: list[dict], rules: dict) -> list[IOC]:
    """R10: mỗi IOC một dòng cho mỗi report, ở đoạn xuất hiện đầu tiên."""
    seen: dict[tuple[str, str], IOC] = {}
    order: list[IOC] = []
    for seg in segments:
        for ioc in extract(seg.get("van_ban", ""), rules, segment_id=seg.get("ma_doan")):
            key = (ioc.type, normalize(ioc.value, rules))
            first = seen.get(key)
            if first is None:
                seen[key] = ioc
                order.append(ioc)
            elif ioc.value != first.value and ioc.value not in first.context:
                first.context = (first.context + "; " if first.context else "") + f"cũng xuất hiện dạng {ioc.value}"
    return order


def run_on_eval_set(segments_jsonl: Path, frozen_dir: Path, rules: dict,
                    out_json: Path | None = None) -> dict[str, list[IOC]]:
    """Chạy trên 3 report đánh giá. Chỉ được chạy sau khi bộ nhãn tham chiếu đã đóng băng."""
    require_frozen(frozen_dir)
    by_report: dict[str, list[dict]] = {}
    with open(segments_jsonl, encoding="utf-8") as f:
        for line in f:
            seg = json.loads(line)
            by_report.setdefault(seg["report"], []).append(seg)
    result = {rp: extract_report(segs, rules) for rp, segs in by_report.items()}
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps({rp: [i.model_dump() for i in iocs] for rp, iocs in result.items()},
                                       ensure_ascii=False, indent=2), encoding="utf-8")
    return result
