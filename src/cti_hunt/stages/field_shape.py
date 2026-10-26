"""Kiểm hình dạng trường (``hinh_dang_truong_v1``, 19/10): điều kiện của hunt đúng cú pháp nhưng trái với hình dạng mà giá trị
thật của trường có trong log. Chỉ cảnh báo; không chặn, không sửa rule, không dùng nhãn, không gọi mô hình.

Vấn đề (``docs/METHODOLOGY.md``): kiểm tĩnh của khâu ⑤ bắt lỗi cú pháp và lỗi tên trường, nhưng để lọt điều kiện đúng cú
pháp mà không bao giờ khớp, như ``Image='netsh.exe'`` (trường luôn là đường dẫn đầy đủ), ``Type='CommandLineEventConsumer'``
(Sysmon chỉ ghi ``Command Line``), ``regexp_matches(CommandLine, '^\\s*/c')`` (dòng lệnh luôn bắt đầu bằng tên chương trình).

Cách làm: đọc điều kiện ở dạng SQL mà adapter DuckDB sinh (``=``, ``ILIKE … ESCAPE '\\'``, ``regexp_matches``, ``IN (…)``),
rồi so từng điều kiện với hồ sơ của trường trên đúng channel và mã sự kiện của hunt, dựng từ log không nhãn:

- ``truong_rong``: nguồn có ≥ N_MIN sự kiện nhưng trường không có giá trị nào;
- ``khong_phai_so``: trường gần như toàn số (≥ TY_LE) mà phép bằng dùng giá trị không phải số;
- ``ngoai_tap_gia_tri``: trường có tập giá trị đóng (trên mọi nguồn, ≤ DONG_MAX giá trị khác nhau) mà phép bằng dùng giá trị
  ngoài tập;
- ``khong_phai_duong_dan``: trường gần như luôn chứa ``\\`` (≥ TY_LE) mà phép bằng dùng giá trị không có ``\\``;
- ``ky_tu_dau``: điều kiện neo đầu chuỗi (phép bằng, ``ILIKE`` không mở đầu bằng ``%``, regex mở đầu bằng ``^``) mà ký tự
  đầu bắt buộc chưa từng là ký tự đầu của giá trị nào của trường ở nguồn đó;
- ``regex_trong_mau``: giá trị của phép bằng hoặc ``ILIKE`` mang cú pháp regex (``.*``, ``(?``, mở đầu ``re:``/``re|``, kết
  thúc ``|i``, ``\\.`` đứng trước chữ cái). Phép này không cần log.

Ba phép đầu về giá trị và ``ky_tu_dau`` chỉ xét khi nguồn có ≥ N_MIN giá trị khác rỗng. Một hunt bị gắn cờ khi có ít nhất một
điều kiện bị gắn cờ, kể cả điều kiện nằm trong một nhánh ``OR``: đây là cảnh báo cho người duyệt, không phải chứng minh hunt
không thể khớp.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import duckdb

VERSION = "hinh_dang_truong_v1"
N_MIN = 10          # số sự kiện (giá trị khác rỗng) tối thiểu của nguồn để kết luận về hình dạng
DONG_MAX = 50       # tập giá trị đóng: ≤ DONG_MAX giá trị khác nhau trên mọi nguồn của mọi bộ log
TY_LE = 0.99        # "gần như toàn" số / đường dẫn

_FIELD = r"(?:[A-Za-z_][A-Za-z0-9_]*|\"[^\"]+\"|`[^`]+`)"
_LIT = r"'(?:[^']|'')*'"
_TOKEN = re.compile(
    rf"regexp_matches\(\s*(?P<rf>{_FIELD})\s*,\s*'(?P<rv>(?:[^']|'')*)'\s*\)"
    rf"|(?P<f>{_FIELD})\s*(?P<op>=|ILIKE\b|IN\b)\s*(?:'(?P<v>(?:[^']|'')*)'|\((?P<lst>\s*{_LIT}(?:\s*,\s*{_LIT})*\s*)\))"
    rf"|{_LIT}", re.IGNORECASE)
_REGEX_META = set(".^$*+?()[]{}|\\")


@dataclass
class Atom:
    kind: str                 # "bang" (so bằng, gồm ILIKE không ký tự đại diện), "ilike", "regex"
    field: str
    value: str                # giá trị đã bỏ thoát (với ilike: ký tự đại diện ghi là % và _)
    anchored: bool            # điều kiện buộc đầu chuỗi
    first: str | None         # ký tự đầu bắt buộc (None: không xác định)
    raw: str


@dataclass
class Profile:
    n: int = 0                # số sự kiện của nguồn
    nonempty: int = 0
    backslash: int = 0
    numeric: int = 0
    first_chars: set = field(default_factory=set)


def _unquote_field(f: str) -> str:
    return f[1:-1] if f[:1] in "\"`" else f


def _ilike(v: str) -> tuple[list[tuple[bool, str]], bool]:
    """Mẫu ILIKE với ESCAPE '\\' → [(là_ký_tự_đại_diện, ký_tự)], có ký tự đại diện hay không."""
    out, i, wild = [], 0, False
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v):
            out.append((False, v[i + 1]))
            i += 2
            continue
        if c in "%_":
            out.append((True, c))
            wild = True
        else:
            out.append((False, c))
        i += 1
    return out, wild


def _regex_first(v: str) -> tuple[bool, str | None]:
    """Regex có neo ``^`` không, và ký tự đầu bắt buộc sau ``^`` (bỏ qua cờ ``(?i)`` và khoảng trắng tùy chọn)."""
    s = re.sub(r"^\(\?[a-zA-Z]+\)", "", v)
    if not s.startswith("^"):
        return False, None
    s = s[1:]
    while True:                                   # \s* \s+ \s? ở đầu: bỏ qua
        m = re.match(r"\\s[*+?]", s)
        if not m:
            break
        s = s[m.end():]
    if not s:
        return True, None
    if s[0] == "\\" and len(s) > 1 and not s[1].isalnum():
        return True, s[1]
    if s[0] in _REGEX_META:
        return True, None
    if len(s) > 1 and s[1] in "?*{":              # ký tự đầu có thể vắng mặt
        return True, None
    return True, s[0]


def atoms(sql: str) -> list[Atom]:
    """Các điều kiện so trường–giá trị trong biểu thức SQL do adapter sinh; bỏ qua cột dẫn xuất ``ev_*``."""
    out = []
    for m in _TOKEN.finditer(sql or ""):
        if m.group("rf"):
            f = _unquote_field(m.group("rf"))
            v = m.group("rv").replace("''", "'")
            anchored, first = _regex_first(v)
            out.append(Atom("regex", f, v, anchored, first, m.group(0)))
        elif m.group("f"):
            f = _unquote_field(m.group("f"))
            op = m.group("op").upper()
            vals = ([x[1:-1].replace("''", "'") for x in re.findall(_LIT, m.group("lst"))] if op == "IN"
                    else [m.group("v").replace("''", "'")])
            for v in vals:
                if op == "ILIKE":
                    parts, wild = _ilike(v)
                    text = "".join(c for _, c in parts)
                    if not wild:
                        out.append(Atom("bang", f, text, True, text[:1] or None, m.group(0)))
                    else:
                        anchored = not (parts and parts[0] == (True, "%"))
                        first = parts[0][1] if parts and anchored and not parts[0][0] else None
                        out.append(Atom("ilike", f, text, anchored, first, m.group(0)))
                else:
                    out.append(Atom("bang", f, v, True, v[:1] or None, m.group(0)))
    return [a for a in out if not a.field.lower().startswith("ev_")]


def _is_number(v: str) -> bool:
    try:
        float(v)
        return True
    except ValueError:
        return False


def regex_trong_mau(text: str) -> bool:
    t = text.lower()
    return (".*" in t or "(?" in t or t.startswith(("re:", "re|")) or t.endswith("|i")
            or re.search(r"\\\.[a-z]", t) is not None)


def _scope(channel: str, event_ids: list) -> str:
    ch = str(channel).lower().replace("'", "''")
    return f"ev_channel = '{ch}' AND ev_eid IN ({', '.join(str(int(e)) for e in event_ids)})"


def profile_slice(cons: list, channel: str, event_ids: list, f: str) -> Profile:
    """Hồ sơ của trường ``f`` trên nguồn (channel, mã sự kiện), cộng qua mọi kết nối (mỗi kết nối có bảng/view ``events``)."""
    p = Profile()
    col = '"' + f.replace('"', '""') + '"'
    for con in cons:
        sc = _scope(channel, event_ids)
        p.n += con.execute(f"SELECT count(*) FROM events WHERE {sc}").fetchone()[0]
        try:
            ne, bs, nu, fc = con.execute(
                f"""SELECT count(*), count(*) FILTER (WHERE strpos(CAST({col} AS VARCHAR), chr(92)) > 0),
                           count(*) FILTER (WHERE TRY_CAST({col} AS DOUBLE) IS NOT NULL),
                           list(DISTINCT lower(left(CAST({col} AS VARCHAR), 1)))
                    FROM events WHERE {sc} AND {col} IS NOT NULL AND CAST({col} AS VARCHAR) <> ''""").fetchone()
        except duckdb.Error:          # cột không có ở bộ này: không có giá trị
            continue
        p.nonempty += ne
        p.backslash += bs
        p.numeric += nu
        p.first_chars |= set(fc or [])
    return p


def vocabulary(cons: list, f: str) -> set | None:
    """Tập giá trị (chữ thường) của trường trên mọi nguồn; None nếu nhiều hơn DONG_MAX giá trị khác nhau."""
    col = '"' + f.replace('"', '""') + '"'
    vals: set = set()
    for con in cons:
        try:
            rows = con.execute(f"""SELECT DISTINCT lower(CAST({col} AS VARCHAR)) FROM events
                                   WHERE {col} IS NOT NULL AND CAST({col} AS VARCHAR) <> '' LIMIT {DONG_MAX + 1}""").fetchall()
        except duckdb.Error:
            continue
        vals |= {r[0] for r in rows}
        if len(vals) > DONG_MAX:
            return None
    return vals


class Checker:
    """Kiểm nhiều hunt trên cùng một bộ log; hồ sơ trường được dựng một lần và dùng lại."""

    def __init__(self, cons: list):
        self.cons = cons
        self._p: dict = {}
        self._v: dict = {}

    def _profile(self, channel, event_ids, f) -> Profile:
        k = (str(channel).lower(), tuple(sorted(int(e) for e in event_ids)), f.lower())
        if k not in self._p:
            self._p[k] = profile_slice(self.cons, channel, event_ids, f)
        return self._p[k]

    def _vocab(self, f) -> set | None:
        if f.lower() not in self._v:
            self._v[f.lower()] = vocabulary(self.cons, f)
        return self._v[f.lower()]

    def check(self, spec: dict) -> list[dict]:
        """Các điều kiện bị gắn cờ của một hunt spec (chỉ phần chọn ứng viên ``candidates``)."""
        sc = spec["scope"]
        if not sc.get("event_ids"):
            return []
        out = []
        for a in atoms(spec["candidates"]):
            p = self._profile(sc["channel"], sc["event_ids"], a.field)
            ly_do = []
            if a.kind in ("bang", "ilike") and regex_trong_mau(a.value):
                ly_do.append("regex_trong_mau")
            if p.n >= N_MIN and p.nonempty == 0:
                ly_do.append("truong_rong")
            elif p.nonempty >= N_MIN:
                if a.kind == "bang":
                    if p.numeric / p.nonempty >= TY_LE and not _is_number(a.value):
                        ly_do.append("khong_phai_so")
                    vocab = self._vocab(a.field)
                    if vocab is not None and a.value.lower() not in vocab:
                        ly_do.append("ngoai_tap_gia_tri")
                    if p.backslash / p.nonempty >= TY_LE and "\\" not in a.value:
                        ly_do.append("khong_phai_duong_dan")
                if a.anchored and a.first and a.first.lower() not in p.first_chars:
                    ly_do.append("ky_tu_dau")
            if ly_do:
                out.append({"truong": a.field, "kieu": a.kind, "gia_tri": a.value[:120], "ly_do": ly_do})
        return out
