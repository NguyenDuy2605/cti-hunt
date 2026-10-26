"""Adapter: rule Sigma -> truy vấn DuckDB trên events.parquet (khâu ⑤–⑥, v3 §3.3).

Lõi sinh logic phát hiện giữ ở dạng trung lập (Sigma). Adapter làm ba việc:

1. Dịch điều kiện detection sang mệnh đề WHERE của DuckDB (pySigma, backend sqlite có sửa).
2. Ánh xạ logsource sang nguồn log thật (configs/logsource_catalog.yaml). Một logsource ứng với
   nhiều nguồn (process_creation = Sysmon 1 và Security 4688) thì sinh MỘT hunt cho MỖI nguồn, vì
   mẫu số FPR tính theo nguồn log (v3 §6.1).
3. Kiểm tra tĩnh: nguồn log có trong danh mục không, trường rule dùng có ở nguồn đó không, tên cột
   có thật trong dữ liệu không. Không đạt thì bỏ nguồn đó kèm lý do — khoảng trống quan sát.
4. Tách condition dạng `A and not B and not C`: A thành điều kiện sinh ứng viên, mỗi khối bị phủ định
   (B, C) thành một mục loại trừ của khâu ⑦. Lý do (v3 §4.3): mục loại trừ phải có giải trình và đếm được
   số bị loại; khối filter nằm trong WHERE thì bị loại âm thầm, và nhánh B không so được với nhánh A
   (hunts/manual/*.yaml đã tách như vậy). Không tách được (có `or` ở mức ngoài cùng, nhiều condition,
   không có vế dương) thì giữ nguyên cả condition làm ứng viên và ghi chú lý do.

   Khác biệt ngữ nghĩa có chủ ý: với trường NULL, `A AND NOT B` trong SQL loại luôn bản ghi (NOT NULL là
   NULL), còn Sigma coi khối B không khớp nên giữ bản ghi. Cách tách giữ bản ghi, tức theo đúng Sigma.

Hai khác biệt so với SQLite mà nếu bỏ qua thì truy vấn chạy được nhưng sai:
- Sigma so khớp không phân biệt hoa thường. LIKE của DuckDB có phân biệt, nên các biểu thức
  startswith/endswith/contains/wildcard đổi sang ILIKE. Phép bằng dùng '=' và dựa vào
  default_collation='nocase' đặt trong store.connect (không đổi '=' thành ILIKE, vì khi đó ký tự
  % hay _ trong giá trị sẽ thành ký tự đại diện).
- Mã sự kiện phải đi kèm channel (v3 §3.4). Điều kiện channel + EventID nằm ở scope của hunt, và
  hunt.runner từ chối hunt thiếu scope.channel.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaDetectionItem, SigmaRule


class DuckDBBackend(sqliteBackend):
    """Backend sqlite, đổi LIKE -> ILIKE và trả về riêng mệnh đề WHERE."""
    name: ClassVar[str] = "DuckDB (log dạng file)"
    startswith_expression: ClassVar[str] = "{field} ILIKE '{value}%' ESCAPE '\\'"
    endswith_expression: ClassVar[str] = "{field} ILIKE '%{value}' ESCAPE '\\'"
    contains_expression: ClassVar[str] = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = "{field} ILIKE '{value}' ESCAPE '\\'"
    wildcard_match_str_expression: ClassVar[str] = "{field} ILIKE '{value}' ESCAPE '\\'"
    # DuckDB không có toán tử REGEXP của SQLite. regexp_matches là tìm kiếm (không bắt khớp toàn chuỗi), đúng
    # ngữ nghĩa |re của Sigma; cờ |i |m |s đi dạng tiền tố (?i) mà RE2 của DuckDB hiểu. Nháy đơn trong regex
    # phải nhân đôi, nếu không chuỗi SQL bị vỡ.
    re_expression: ClassVar[str] = "regexp_matches({field}, '{regex}')"
    re_escape_char: ClassVar[str] = "'"
    re_escape: ClassVar[tuple[str, ...]] = ("'",)
    # Mọi trường gốc là VARCHAR (ingest giữ nguyên), nên |gt |lt |gte |lte phải ép kiểu, nếu không DuckDB từ chối
    # (VARCHAR so với số). TRY_CAST: giá trị không phải số thành NULL, không khớp — không làm vỡ cả truy vấn.
    # Phép '=' với số không cần: DuckDB tự so theo số ('09' = 9).
    compare_op_expression: ClassVar[str] = "TRY_CAST({field} AS DOUBLE) {operator} {value}"

    def finalize_query_default(self, rule, query, index, state):
        return query          # chỉ WHERE; scope (channel + EventID) do hunt spec giữ


@dataclass
class CompiledHunt:
    id: str
    title: str
    source: str
    scope: dict
    candidates: str
    linked_ttps: list[str] = field(default_factory=list)
    ghi_chu: str = ""
    filters: list[dict] = field(default_factory=list)
    filter_policy: str = ""
    sigma_context: dict = field(default_factory=dict)

    def to_hunt_spec(self) -> dict:
        spec = {"id": self.id, "nhanh": "B", "gia_thuyet": self.title, "linked_ttps": self.linked_ttps,
                "scope": self.scope, "candidates": self.candidates, "filters": list(self.filters)}
        if self.filter_policy:
            spec.update(filter_policy=self.filter_policy, filter_phase="draft", sigma_context=self.sigma_context)
        return spec


@dataclass
class Skipped:
    source: str
    ly_do: str


def load_catalog(path: Path) -> dict[str, list[dict]]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _fields(detection) -> set[str]:
    out: set[str] = set()
    stack = list(detection.detection_items)
    while stack:
        item = stack.pop()
        if isinstance(item, SigmaDetectionItem):
            if item.field:
                out.add(item.field)
        else:
            stack.extend(item.detection_items)
    return out


def rule_fields(rule) -> set[str]:
    out: set[str] = set()
    for det in rule.detection.detections.values():
        out |= _fields(det)
    return out


def attack_techniques(rule) -> list[str]:
    ids = []
    for t in rule.tags:
        if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name, re.I):
            ids.append(t.name.upper().replace("T", "T", 1))
    return sorted({i.upper() for i in ids})


def _logsource_key(rule) -> str | None:
    ls = rule.logsource
    if ls.category:
        return ls.category
    if ls.service:
        return f"service:{ls.service}"
    return None


def _stable_rule(rule: SigmaRule) -> SigmaRule:
    """Rule ở dạng không đổi qua một lần ghi YAML rồi đọc lại (cổng lọc v2 lưu rule rồi biên dịch lại để đối chiếu).

    pySigma `to_dict()` bỏ dấu thoát của '\\', nên một giá trị như 'sc.exe \\\\' đổi 4 → 2 → 1 dấu '\\' qua mỗi lần
    ghi lại dù SQL không đổi. Nếu dạng ổn định cho SQL khác, bước kiểm draft của cổng lọc vẫn báo lệch.
    """
    d = rule.to_dict()
    for _ in range(5):
        nxt = SigmaRule.from_dict(yaml.safe_load(yaml.safe_dump(d, allow_unicode=True, sort_keys=False)))
        if nxt.to_dict() == d:
            return nxt
        d = nxt.to_dict()
    raise ValueError(f"rule '{rule.title}' không ổn định qua ghi/đọc YAML")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]


_TOKEN = re.compile(r"\(|\)|[^\s()]+")


@dataclass
class SplitCondition:
    candidates: str                       # điều kiện Sigma sinh ứng viên
    filters: list[str] = field(default_factory=list)   # điều kiện Sigma (dạng dương) bị phủ định ở rule gốc
    ghi_chu: str = ""


def _join(tokens: list[str]) -> str:
    return " ".join(tokens).replace("( ", "(").replace(" )", ")")


def _strip_outer(tokens: list[str]) -> list[str]:
    """Bỏ cặp ngoặc bao trọn cả biểu thức: `(a and not b)` -> `a and not b`."""
    while len(tokens) >= 2 and tokens[0] == "(" and tokens[-1] == ")":
        depth = 0
        for i, t in enumerate(tokens):
            depth += (t == "(") - (t == ")")
            if depth == 0 and i < len(tokens) - 1:
                return tokens                 # ngoặc đầu đóng trước khi hết, không bao trọn
        tokens = tokens[1:-1]
    return tokens


def split_condition(condition: str) -> SplitCondition:
    """`A and not B and not C` -> ứng viên `A`, mục lọc [`B`, `C`]. Chỉ tách ở mức ngoài cùng."""
    tokens = _strip_outer(_TOKEN.findall(condition))
    terms: list[list[str]] = [[]]
    depth = 0
    for t in tokens:
        depth += (t == "(") - (t == ")")
        low = t.lower()
        if depth == 0 and low == "or":
            return SplitCondition(condition, [], "condition có 'or' ở mức ngoài cùng, không tách khối lọc")
        if depth == 0 and low == "and":
            terms.append([])
            continue
        terms[-1].append(t)
    pos = [_join(x) for x in terms if not (x and x[0].lower() == "not")]
    neg = [_join(x[1:]) for x in terms if x and x[0].lower() == "not" and len(x) > 1]
    if not pos:
        return SplitCondition(condition, [], "condition không có vế dương, không tách khối lọc")
    return SplitCondition(" and ".join(pos), neg)


def _compile_condition(rule, condition: str, fmap: dict, src_name: str) -> str:
    """Biên dịch một điều kiện con trên cùng các khối detection của rule, cùng ánh xạ trường."""
    d = rule.to_dict()
    d["detection"]["condition"] = condition
    pipeline = ProcessingPipeline.from_dict(
        {"name": src_name, "priority": 10,
         "transformations": [{"id": "map", "type": "field_name_mapping", "mapping": fmap}]}
    ) if fmap else ProcessingPipeline()
    return DuckDBBackend(processing_pipeline=pipeline).convert_rule(SigmaRule.from_dict(d))[0]


def _filter_spec(i: int, cond: str, where: str, rule, rule_id: str) -> dict:
    fp = "; ".join(str(x) for x in (rule.falsepositives or []))
    return {
        "id": f"S-{i:02d}",
        "mo_ta": f"khối `{cond}` bị phủ định trong condition của rule Sigma",
        "where": where,
        "ly_do": f"Rule '{rule.title}' coi `{cond}` là hoạt động hợp lệ"
                 + (f" (falsepositives của rule: {fp})" if fp else "")
                 + ". Chưa có giải trình của người duyệt.",
        "nguoi_chiu_trach_nhiem": f"he_thong (rule {rule_id})",
        "het_han": "het_de_tai",
        "nguon": "sigma_rule",            # v3 §4.3: hệ thống chỉ đề xuất, người duyệt quyết ở điểm dừng
    }


def compile_rule(rule_path: Path, catalog: dict[str, list[dict]],
                 available_columns: set[str] | None = None, *, filter_policy: str = "") -> tuple[list[CompiledHunt], list[Skipped]]:
    return compile_text(rule_path.read_text(encoding="utf-8"), catalog, available_columns, filter_policy=filter_policy)


def compile_text(text: str, catalog: dict[str, list[dict]],
                 available_columns: set[str] | None = None, *, filter_policy: str = "") -> tuple[list[CompiledHunt], list[Skipped]]:
    if filter_policy:
        from ..filter_approval import POLICY
        if filter_policy != POLICY:
            raise ValueError("chính sách lọc không được hỗ trợ")
    collection = SigmaCollection.from_yaml(text)
    hunts, skipped = [], []
    cols = {c.lower() for c in available_columns} if available_columns else None
    for rule in collection.rules:
        if filter_policy:
            rule = _stable_rule(rule)
        key = _logsource_key(rule)
        sources = catalog.get(key or "")
        base_id = str(rule.id) if rule.id else _slug(rule.title)
        if not sources:
            skipped.append(Skipped(key or "(không có logsource)",
                                   f"logsource '{key}' không có nguồn log nào trong danh mục"))
            continue
        used = rule_fields(rule)
        for src in sources:
            miss = sorted(used & set(src.get("unavailable") or []))
            if miss:
                skipped.append(Skipped(src["name"], f"nguồn này không có trường {miss}"))
                continue
            fmap = src.get("field_map") or {}
            if cols is not None:
                unknown = sorted(f for f in used if fmap.get(f, f).lower() not in cols)
                if unknown:
                    skipped.append(Skipped(src["name"], f"tên trường không có trong dữ liệu: {unknown}"))
                    continue
            notes = [src.get("ghi_chu", "")]
            conds = list(rule.detection.condition)
            groups = []
            if filter_policy:
                from .filter_structure import partition
                positive, groups = partition(rule)
                split = SplitCondition(positive, [g["condition"] for g in groups])
            elif len(conds) == 1:
                split = split_condition(conds[0])
            else:
                split = SplitCondition(conds[0], [], f"rule có {len(conds)} condition, chỉ dùng condition đầu")
            notes.append(split.ghi_chu)
            candidates = _compile_condition(rule, split.candidates, fmap, src["name"])
            filters = [_filter_spec(i, c, _compile_condition(rule, c, fmap, src["name"]), rule, base_id)
                       for i, c in enumerate(split.filters, start=1)]
            if filter_policy:
                for f, group in zip(filters, groups):
                    f.update(status="pending_review", bieu_thuc_sigma=group["condition"], selectors=group["selectors"])
            hunts.append(CompiledHunt(
                id=f"{base_id}__{src['name']}", title=rule.title, source=src["name"],
                scope={"channel": src["channel"], "event_ids": list(src.get("event_ids") or [])},
                candidates=candidates, linked_ttps=attack_techniques(rule),
                ghi_chu=" | ".join(n for n in notes if n), filters=filters,
                filter_policy=filter_policy,
                sigma_context={"rule": rule.to_dict(), "field_map": fmap, "source": src["name"], "source_config": dict(src),
                               "candidate_condition": split.candidates} if filter_policy else {}))
    return hunts, skipped
