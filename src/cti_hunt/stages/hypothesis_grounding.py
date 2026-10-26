"""H5 — phép kiểm từ vựng giúp người duyệt ◆: chuỗi kỹ thuật trong hành vi/phạm vi của giả thuyết có căn cứ không.

Chỉ cảnh báo. Không duyệt, từ chối, sửa hay chặn giả thuyết; quyết định vẫn ở người duyệt (G0(d)).

- Chuỗi được rút: đường dẫn Windows/registry, tên tệp thực thi hoặc script, cờ dòng lệnh, lớp WMI, cmdlet PowerShell,
  cổng mạng. Tình tiết viết bằng văn xuôi không rút được, nên danh sách rỗng không chứng minh giả thuyết bám nguồn.
- Căn cứ hợp lệ: câu trích trong `source_spans`; ghi chú danh mục ③ của kỹ thuật được gắn có nguồn log trùng channel
  và mã sự kiện của giả thuyết (ghi chú này là đầu vào của prompt ④). Tên máy/tài khoản pivot không thuộc loại chuỗi
  được rút nên không cần căn cứ.
- So nguyên chuỗi sau khi chuẩn hóa hoa/thường, Unicode, dấu gạch đường dẫn và cách viết gốc registry; không suy đồng
  nghĩa. Riêng tên tệp: căn cứ có phần tên bỏ đuôi (từ 3 ký tự) thì coi là có, vì CTI viết "PowerShell" còn giả thuyết
  viết giá trị của trường log `powershell.exe`.
"""
from __future__ import annotations

import re
import unicodedata

from ..contracts import ContractB
from .s3_telemetry import NOTE_FIELDS, map_technique

LABELS = {"duong_dan": "đường dẫn", "tep": "tên tệp", "lop_wmi": "lớp WMI", "cmdlet": "cmdlet",
          "co_lenh": "cờ lệnh", "cong": "cổng"}
FIELD_LABELS = {"hanh_vi": "hành vi", "pham_vi": "phạm vi"}

_EXT = "exe|dll|sys|scr|cpl|ocx|msi|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|lnk"
_HIVE = r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)"
# UNC cần đủ `\\máy\`: "\\WmiPrvSE.exe" (dấu \ bị viết đôi) không phải đường dẫn, để phần tên tệp được xét riêng.
_ROOT = r"(?:[A-Z]:[\\/]|\\\\[\w.$-]+[\\/]|%[\w()]+%[\\/]|" + _HIVE + r"(?::[\\/]*|[\\/]))"
# Động từ được PowerShell chấp thuận; danh từ phải viết hoa chữ đầu để không bắt từ ghép tiếng Anh như "read-only".
_VERBS = ("add|approve|assert|backup|block|build|checkpoint|clear|close|compare|complete|compress|confirm|connect|"
          "convert|convertfrom|convertto|copy|debug|deny|deploy|disable|disconnect|dismount|edit|enable|enter|exit|"
          "expand|export|find|foreach|format|get|grant|group|hide|import|initialize|install|invoke|join|limit|lock|"
          "measure|merge|mount|move|new|open|optimize|out|ping|pop|protect|publish|push|read|receive|redo|register|"
          "remove|rename|repair|request|reset|resize|resolve|restart|restore|resume|revoke|save|search|select|send|"
          "set|show|skip|sort|split|start|step|stop|submit|suspend|switch|sync|tee|test|trace|unblock|undo|"
          "uninstall|unlock|unprotect|unpublish|unregister|update|use|wait|watch|where|write")
# Thứ tự là thứ tự ưu tiên: chuỗi nằm trọn trong chuỗi đã nhận trước thì không báo lần hai (tên tệp trong đường dẫn).
_PATTERNS = (
    ("duong_dan", re.compile(
        r"[\"'`](" + _ROOT + r"[^\"'`\r\n]+)[\"'`]"                     # trong nháy: được chứa dấu cách
        r"|(?<![\w\\/:%])(" + _ROOT + r"[^\s\"'`<>|,;]+)"                 # không nháy: tới dấu cách
        r"|(?<![\w\\/:%.$-])([\w.$-]+(?:\\+[\w.$-]+){2,})", re.I)),       # không gốc: từ ba đoạn nối bằng dấu \
    ("tep", re.compile(r"(?<![\w.-])\w[\w.-]*\.(?:" + _EXT + r")(?!\w)(?!\.\w)", re.I)),
    ("lop_wmi", re.compile(r"(?<!\w)(?:(?:Win32_|CIM_|MSFT_)[A-Z]\w*|__[A-Z]+"
                           r"|(?:ActiveScript|CommandLine|LogFile|NTEventLog|SMTP)EventConsumer)(?!\w)", re.I)),
    ("cmdlet", re.compile(r"(?<![\w-])(?i:" + _VERBS + r")-[A-Z][A-Za-z0-9]+(?![\w-])")),
    ("co_lenh", re.compile(r"(?<![\w:/\\.-])(?:--?|/)[A-Z][A-Z0-9_-]*(?=$|[\s\"'`=:,;.)\]])", re.I)),
)
_PORT_LIST = r"\d{1,5}(?:(?:\s*[,/]\s*|\s+(?:and|or|và|hoặc)\s+)\d{1,5})*"
# Phải là cách viết cổng ("cổng 443", "DestinationPort=443", "445/tcp"); số đứng sau "EID" hay "report" không tính.
_PORT = re.compile(
    r"(?<![\w.])(?:(?:destination|dest|dst|source|src|remote|local)?ports?|cổng|tcp|udp)"
    r"(?:\s+(?:number|số|đích|nguồn|là|is|bằng))?\s*[:=/]?\s*(" + _PORT_LIST + r")(?!\w)(?!\.\d)"
    r"|(?<![\w.])(\d{1,5})\s*/\s*(?:tcp|udp)(?!\w)", re.I)
_HIVES = (("hkey_local_machine", "hklm"), ("hkey_current_user", "hkcu"), ("hkey_classes_root", "hkcr"),
          ("hkey_users", "hku"), ("hkey_current_config", "hkcc"))


def norm(text: str) -> str:
    """Một dạng để so: NFC, không phân biệt hoa thường, `/` và `\\\\` thành `\\`, gốc registry về `hklm\\`."""
    text = re.sub(r"[\\/]+", lambda m: "\\", unicodedata.normalize("NFC", text).casefold())
    for long, short in _HIVES:
        text = text.replace(long, short)
    return re.sub(r"(?<!\w)(hk(?:lm|cu|cr|u|cc)):\\?", lambda m: m.group(1) + "\\", text)


def _ports(text: str) -> list[tuple[int, str]]:
    return [(m.start(), str(int(v))) for m in _PORT.finditer(text)
            for v in re.findall(r"\d+", m.group(1) or m.group(2)) if 0 < int(v) <= 65535]


def details(text: str) -> list[tuple[str, str]]:
    """(loại, chuỗi) theo thứ tự xuất hiện. Dùng chung cho H5 (phiếu ◆) và H6 (điều kiện rule ⑤ bỏ sót)."""
    found, taken = [], []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            if any(a <= m.start() and m.end() <= b for a, b in taken):
                continue
            taken.append(m.span())
            value = next((g for g in m.groups() if g), m.group()).rstrip(".,;:)]}\\/")
            found.append((m.start(), kind, value))
    found.extend((start, "cong", value) for start, value in _ports(text))
    return [(kind, value) for _, kind, value in sorted(found, key=lambda x: x[0])]


def _has(value: str, text: str) -> bool:
    """Chuỗi đứng riêng trong văn bản (cả hai đã chuẩn hóa); dấu chấm cuối câu không làm mất khớp."""
    return re.search(r"(?<![\w.-])" + re.escape(value) + r"(?!\w)(?!\.\w)", text) is not None


def _supported(kind: str, value: str, texts: list[str]) -> bool:
    if any(_has(value, t) for t in texts):
        return True
    stem = value.rsplit(".", 1)[0]
    return kind == "tep" and len(stem) >= 3 and any(_has(stem, t) for t in texts)


def _catalog_notes(h: ContractB, telemetry: dict) -> list[str]:
    """Ghi chú danh mục ③ của kỹ thuật được gắn, chỉ khi kỹ thuật đó có nguồn trùng channel + mã sự kiện đã chọn."""
    channel, eids = h.evidence.data_source.casefold(), set(h.evidence.event_ids)
    notes = []
    for tid in h.linked_ttps:
        entry = map_technique(tid, telemetry)
        if any(s["channel"].casefold() == channel and eids & set(s["event_ids"]) for s in entry.get("sources") or []):
            notes.extend(str(entry.get(k) or "") for k in NOTE_FIELDS)
    return notes


def warnings(h: ContractB, telemetry: dict | None = None) -> list[dict]:
    """Chuỗi kỹ thuật trong hành vi/phạm vi không thấy ở căn cứ nào. Mỗi chuỗi một mục, kèm các trường chứa nó.

    Từng căn cứ được so riêng: không ghép hai câu trích để tạo ra một chuỗi. Không truyền `telemetry` thì chỉ so với
    câu nguồn. Số trong ghi chú danh mục chỉ đỡ cho cổng khi nó được viết như cổng (ghi chú có nhiều mã sự kiện).
    """
    quotes = [norm(s.text) for s in h.source_spans]
    notes = _catalog_notes(h, telemetry or {})
    texts = quotes + [norm(n) for n in notes]
    note_ports = {p for n in notes for _, p in _ports(n)}
    found: dict[tuple[str, str], dict] = {}
    for field, text in (("hanh_vi", h.behavior), ("pham_vi", h.scope)):
        for kind, value in details(text):
            key = (kind, norm(value))
            if key in found:
                if field not in found[key]["truong"]:
                    found[key]["truong"].append(field)
            elif kind == "cong":
                if value not in note_ports and not any(
                        re.search(r"(?<![\w.])" + value + r"(?!\w)(?!\.\d)", q) for q in quotes):
                    found[key] = {"loai": kind, "gia_tri": value, "truong": [field]}
            elif not _supported(kind, key[1], texts):
                found[key] = {"loai": kind, "gia_tri": value, "truong": [field]}
    return list(found.values())


def describe(items: list[dict]) -> str:
    """Một dòng cho giao diện; chuỗi nằm trong dấu mã để Markdown không diễn giải `$`, `_`, `\\`."""
    return "; ".join(f"`{i['gia_tri']}` ({LABELS.get(i['loai'], i['loai'])}, trong "
                     f"{' và '.join(FIELD_LABELS.get(f, f) for f in i['truong'])})" for i in items)
