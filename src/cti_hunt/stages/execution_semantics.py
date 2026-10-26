"""Conservative capability checks, not a proof of arbitrary natural-language semantics.

The current Sigma adapter evaluates individual events. Do not quietly replace
multi-event/absence/relative-time hypotheses with a broad single-event filter.

Từ 04/10: giả thuyết có `rang_buoc` tham số hóa thì phép tương ứng không bị chặn;
`bind_constraints` ghép điều kiện vào `candidates` dưới dạng khóa sự kiện IN (truy vấn con tự chứa), nên mọi nơi dùng
`candidates` (runner, observe, ⑦, ⑧, cổng lọc) áp cùng một ràng buộc. Ràng buộc tính trên tập ứng viên trong phạm vi
hunt, trước các mục lọc; SPL sinh từ Sigma không có phần này.
"""
import re
import unicodedata

from ..hunt.runner import _scope_where


class ConstraintError(ValueError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


# Phép nào được ràng buộc nào thực hiện; người duyệt ◆ thấy cả câu chữ lẫn ràng buộc trước khi duyệt.
COVERS = {"dem_khac_nhau": {"distinct_count"}, "vang_mat": {"absence"},
          "moc_neo": {"event_sequence", "relative_time", "timeframe_unbound"}}
_KEY = "concat_ws(chr(31), {p}ev_host, {p}ev_channel, CAST({p}ev_rec AS VARCHAR))"


def normalized(text):
    text = unicodedata.normalize('NFD', text.casefold().replace('đ', 'd'))
    return ' '.join(''.join(c for c in text if unicodedata.category(c) != 'Mn').split()).strip(' .')


WHOLE_PERIOD = {'toan bo', 'toan bo log', 'toan bo thoi gian', 'toan bo khoang thoi gian cua log',
                'toan bo thoi gian cua log', 'toan bo khoang thoi gian trong log',
                'all time', 'full dataset', 'entire dataset', 'all available logs', 'entire log period'}


def issues(h):
    found = {op: 'Adapter hiện chỉ hỗ trợ điều kiện trên từng sự kiện; chưa thực thi phép ' + op
             for op in h.required_operations}
    prose = normalized(' '.join((h.behavior, h.scope, h.timeframe)))
    rb = getattr(h, 'rang_buoc', None)
    # These patterns guard known failure families; unrecognized prose still needs human review.
    if re.search(r'(?:nhieu|multiple|distinct|different)\s+(?:(?:dia chi|destination|external|remote)\s+)?(?:ip|dich|destinations?|hosts?|may chu)', prose):
        found['distinct_count'] = 'Chưa hỗ trợ đếm nhiều đích/giá trị theo nhóm và cửa sổ thời gian.'
    if re.search(r'(?:khong (?:qua |co |thay )?(?:phan giai|dns)|(?:without|no|absence of)\s+(?:a |any )?(?:dns|name resolution))', prose):
        found['absence'] = 'Không thể chứng minh vắng DNS chỉ bằng điều kiện trên một sự kiện kết nối.'
    anchor_prose = prose
    if rb is not None and rb.vang_mat is not None:
        # "trong N giây trước" at a clause boundary can name the already-bound absence window,
        # rather than another event anchor. Only exempt its exact parameter; explicit anchor prose stays.
        w = int(rb.vang_mat.truoc_giay)
        window_before = (rf'\b(?:trong (?:vong |khoang )?|within ){w}\s*(?:giay|seconds?)\s+'
                         r'(?:lien |immediately )?(?:truoc|before)')
        if h.evidence.data_source.casefold() == 'microsoft-windows-sysmon/operational' \
                and set(h.evidence.event_ids) == {3}:
            # The named connection is this primary candidate, not a second executed-event anchor.
            anchor_prose = re.sub(window_before +
                r'\s+(?:(?:su kien )?ket noi(?: mang)?(?: do)?|'
                r'(?:the |that )?(?:network )?connection(?: event)?)\b', '', anchor_prose)
        anchor_prose = re.sub(
            window_before + r'(?=\s*(?:[,;.]|$))', '', anchor_prose)
    if rb is not None and rb.dem_khac_nhau is not None:
        # "từ N giây trước đến N giây sau" names the bound ±N count window around each candidate (07/10).
        # Same limits as the absence window: exact parameter, clause boundary or the primary connection itself.
        w = int(rb.dem_khac_nhau.cua_so_giay)
        unit = r'\s*(?:giay|seconds?)\s+'
        centered = (rf'\b(?:tu |from )?{w}{unit}(?:truoc|before)\s+(?:den|toi|va|to|and)\s+'
                    rf'(?:{w}{unit})?(?:sau|after)')
        if h.evidence.data_source.casefold() == 'microsoft-windows-sysmon/operational' \
                and set(h.evidence.event_ids) == {3}:
            anchor_prose = re.sub(centered + r'\s+(?:(?:moi|mot|each|every|a|the|that) )?'
                                  r'(?:(?:su kien )?ket noi(?: mang)?(?: do)?|'
                                  r'(?:network )?connection(?: event)?)\b', '', anchor_prose)
        anchor_prose = re.sub(centered + r'(?=\s*(?:[,;.:]|$))', '', anchor_prose)
    relative_anchor = re.search(
        r'(?:\b\d+\s*(?:phut|gio|giay|minutes?|hours?|seconds?)\s+(?:sau|truoc|after|before)|'
        r'(?:sau|truoc|after|before)\s+(?:thoi diem|cac su kien|su kien|the event|the previous))', anchor_prose)
    window = re.search(r'(?:\b(?:trong (?:vong |khoang )?|within )\d+\s*'
                       r'(?:phut|gio|giay|minutes?|hours?|seconds?)|(?:thoi gian ngan|short (?:time|window)))', prose)
    # A count/absence window is not an anchor relation. Prose/parameter agreement still needs ◆ review.
    bound_window = rb is not None and (rb.dem_khac_nhau is not None or rb.vang_mat is not None)
    if relative_anchor or (window and not bound_window):
        found['relative_time'] = 'Thiếu phép nối/mốc neo thời gian đã kiểm chứng; không được bỏ điều kiện thời gian.'
    if h.origin == 'pivot' and normalized(h.timeframe) not in WHOLE_PERIOD and h.execution_window is None:
        found['timeframe_unbound'] = 'Pivot cần toàn bộ khoảng log hoặc execution_window UTC đã duyệt.'
    covered = set().union(*(ops for name, ops in COVERS.items() if rb is not None and getattr(rb, name)))
    return [{'kind': 'ngu_nghia_chua_ho_tro', 'operation': op, 'message': message}
            for op, message in sorted(found.items()) if op not in covered]


def anchor_sql(specs: list[dict]) -> str:
    """Tập sự kiện cuối của giả thuyết neo (mọi hunt của nó), viết lại thành SQL trên ``events``."""
    parts = []
    for s in specs:
        where = [_scope_where(s["scope"]), f"({s['candidates']})"]
        where += [f"({f['where']}) IS NOT TRUE" for f in s.get("filters") or []]
        parts.append("SELECT * FROM events WHERE " + " AND ".join(where))
    return " UNION ALL ".join(parts)


def _column(name: str, columns: set[str] | None) -> str:
    if columns is not None and name not in columns:
        same = [c for c in columns if c.lower() == name.lower()]
        if len(same) != 1:
            raise ConstraintError("rang_buoc_loi", f"trường {name} không có (hoặc trùng tên khác hoa/thường) trong dữ liệu")
        name = same[0]
    return '"' + name.replace('"', '""') + '"'


def _text(alias: str, col: str) -> str:
    return f"NULLIF(lower(trim(CAST({alias}.{col} AS VARCHAR))), '')"


def _same(a: str, b: str, col_a: str, col_b: str | None = None) -> str:
    # `=` không khớp NULL: trường rỗng ở một phía thì không thỏa ràng buộc.
    return f"{_text(a, col_a)} = {_text(b, col_b or col_a)}"


def bind_constraints(spec: dict, h, columns: set[str] | None = None, anchors: dict[str, str] | None = None) -> dict:
    """Ghép `h.rang_buoc` vào `candidates`; giữ bản gốc và điều kiện trong `spec['rang_buoc']` để hiển thị/tái kiểm."""
    rb = getattr(h, "rang_buoc", None)
    if rb is None:
        return spec
    ctes = [f"_rb_c AS (SELECT * FROM events WHERE {_scope_where(spec['scope'])} AND ({spec['candidates']}))"]
    conds, neo = [], ""
    if rb.dem_khac_nhau:
        d = rb.dem_khac_nhau
        col = _column(d.truong, columns)
        same = " AND ".join(_same("c2", "c", _column(g, columns)) for g in d.theo)
        w = int(d.cua_so_giay)
        conds.append(f"(SELECT count(DISTINCT {_text('c2', col)}) FROM _rb_c c2 WHERE {same} AND c2.ev_ts BETWEEN "
                     f"c.ev_ts - INTERVAL {w} SECOND AND c.ev_ts + INTERVAL {w} SECOND) >= {int(d.toi_thieu)}")
    if rb.vang_mat:
        v = rb.vang_mat
        pairs = [(_column(p.ung_vien, columns), _column(p.nguon, columns)) for p in v.khop]
        ch = v.channel.lower().replace("'", "''")
        src = f"a.ev_channel = '{ch}' AND a.ev_eid IN ({', '.join(str(int(e)) for e in v.event_ids)})"
        present = " AND ".join(f"{_text('c', a)} IS NOT NULL" for a, _ in pairs)
        match = " AND ".join(_same("c", "a", a, b) for a, b in pairs)
        t = int(v.truoc_giay)
        conds.append(f"{present} AND NOT EXISTS (SELECT 1 FROM events a WHERE {src} AND {match} AND a.ev_ts BETWEEN "
                     f"c.ev_ts - INTERVAL {t} SECOND AND c.ev_ts)")
    if rb.moc_neo:
        m = rb.moc_neo
        neo = (anchors or {}).get(m.gia_thuyet, "")
        if not neo:
            raise ConstraintError("thieu_moc_neo", f"giả thuyết neo {m.gia_thuyet} chưa có hunt đã chạy ở vòng trước")
        ctes.append(f"_rb_neo AS ({neo})")
        same = " AND ".join(_same("n", "c", _column(f, columns)) for f in m.cung)
        t = int(m.trong_vong_giay)
        conds.append(f"EXISTS (SELECT 1 FROM _rb_neo n WHERE {same} AND n.ev_ts < c.ev_ts "
                     f"AND c.ev_ts <= n.ev_ts + INTERVAL {t} SECOND)")
    pred = (f"{_KEY.format(p='')} IN (WITH {', '.join(ctes)} SELECT {_KEY.format(p='c.')} FROM _rb_c c "
            f"WHERE {' AND '.join(conds)})")
    meta = {"candidates_goc": spec["candidates"], "dieu_kien": rb.model_dump(mode="json", exclude_none=True),
            **({"neo_sql": neo} if neo else {})}
    return {**spec, "candidates": f"({spec['candidates']}) AND ({pred})", "rang_buoc": meta}


def bind_window(spec, h):
    if h.execution_window is None:
        return spec
    out = {**spec, 'scope': dict(spec['scope'])}
    w = h.execution_window
    out['scope'].update(time_from=w.start.replace(tzinfo=None).isoformat(sep=' '),
                        time_to=w.end.replace(tzinfo=None).isoformat(sep=' '))
    return out
