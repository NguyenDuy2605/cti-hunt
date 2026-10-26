"""Bounded static guard for newly generated candidate regexes; not a semantic proof.

Numeric regex repetitions are deliberately unsupported under this policy, even
when they express a legitimate fixed format. No number in prose, source spans,
event IDs or cross-event constraints grants an exception. Old prompts/specs
retain their original validation policy.

`condition_grounding` (09/10, B3) is advisory only: it never blocks a rule, never
reaches the model and never sees results. It lists candidate values the approved
hypothesis does not mention, so a reviewer can check what ⑤ added or changed.
`shorten_rule` (10/10) removes exactly the listed items a reviewer selects; it only
deletes, never adds, and refuses when the result is not exactly that removal.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re
import unicodedata

from sigma.rule import SigmaDetectionItem, SigmaRule
from sigma.types import SigmaCompareExpression, SigmaNumber, SigmaRegularExpression, SigmaString

from ..adapters.filter_structure import Expr, FilterStructureError, Parser, partition

POLICY = "candidate_regex_no_numeric_repetition_v1"
ENCODED_POLICY = "candidate_regex_and_encoded_command_trace_v2"
# 12/10 (H6): v2 plus "no encoded-command launch switch on script-content fields". A new id, not a change to v2:
# specs and drafts written under v2 keep the validation they were created with.
SCRIPT_POLICY = "candidate_regex_encoded_trace_and_script_content_v3"
ENCODED_POLICIES = (ENCODED_POLICY, SCRIPT_POLICY)
ISSUE = "regex_lap_so_khong_ho_tro"
_REPETITION = re.compile(r"\{[0-9]+(?:,[0-9]*)?\}")


def check_policy(policy: str) -> None:
    if policy not in ("", POLICY, *ENCODED_POLICIES):
        raise ValueError(f"unknown candidate regex policy: {policy}")


def numeric_repetitions(pattern: str) -> list[str]:
    """Find numeric repeat syntax, ignoring escaped text and character classes.

    This is a lexical check on already parsed Sigma regexes, not a regex engine.
    A leading ] (also after ^) inside a character class is a literal character.
    """
    result = []
    i = 0
    in_class = False
    class_start = False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            i += 2
            if in_class:
                class_start = False
            continue
        if in_class:
            if char == "^" and class_start:
                # Only the first ^ can be the character-class negation prefix.
                i += 1
                if i < len(pattern) and pattern[i] == "]":
                    i += 1
                class_start = False
                continue
            if char == "]" and not class_start:
                in_class = False
            class_start = False
        elif char == "[":
            in_class = True
            class_start = True
        elif char == "{":
            match = _REPETITION.match(pattern, i)
            if match:
                result.append(match.group())
                i = match.end()
                continue
        i += 1
    return list(dict.fromkeys(result))


def candidate_regex_issues(rule, policy: str, h=None) -> list[dict]:
    check_policy(policy)
    if not policy:
        return []
    candidates, _ = partition(rule)
    names = Parser(candidates, list(rule.detection.detections)).parse().names()
    issues = []
    for name in names:
        stack = [rule.detection.detections[name]]
        while stack:
            node = stack.pop()
            if not isinstance(node, SigmaDetectionItem):
                stack.extend(node.detection_items)
                continue
            for value in node.value:
                if not isinstance(value, SigmaRegularExpression):
                    continue
                repetitions = numeric_repetitions(str(value.regexp))
                if repetitions:
                    issues.append({"kind": ISSUE, "message":
                        f"{name}.{node.field}: numeric regex repetition {', '.join(repetitions)} "
                        "is unsupported by the candidate policy. Do not invent a length threshold. "
                        "Implement the approved primary trace without an extra length condition; "
                        "if an approved length requirement cannot be represented faithfully, "
                        "return no rule and explain the incompatibility in note."})
    if policy in ENCODED_POLICIES:
        from . import encoded_trace
        issues.extend(encoded_trace.issues(rule, h))
        if policy == SCRIPT_POLICY:
            issues.extend(encoded_trace.script_field_issues(rule, h))
    return issues


GROUNDING_VALUE = "gia_tri_khong_co_trong_gia_thuyet"
GROUNDING_REGEX = "regex_ngoai_thu_vien"
_EXECUTABLE = (".exe", ".com", ".bat", ".cmd")


def _norm(text) -> str:
    text = unicodedata.normalize("NFC", str(text)).casefold().replace("\\\\", "\\")
    return re.sub(r"\s+", " ", text).strip()


def _hypothesis_text(h) -> str:
    parts = [h.behavior, h.scope, h.timeframe, h.evidence.data_source, " ".join(h.evidence.key_fields),
             *(s.text for s in h.source_spans), h.pivot_value or ""]
    return _norm(" ".join(p for p in parts if p))


def _fragments(value: SigmaString) -> list[str]:
    """Literal runs between wildcards (spaces inside a run are kept), without surrounding backslashes or spaces.
    A forward slash is kept: on Windows it starts a command-line switch, not a path."""
    plain = "".join(part if isinstance(part, str) else "\0" for part in value.s)
    return [f for f in (_norm(x).strip("\\ ") for x in plain.split("\0")) if f]


def _found(run: str, text: str) -> bool:
    # A short run ("-w", "/c") must stand alone, not sit inside another word ("microsoft-windows", "/domain").
    return (len(run) >= 4 and run in text) or re.search(r"(?<!\w)" + re.escape(run) + r"(?!\w)", text) is not None


def _grounded(fragment: str, text: str) -> bool:
    if _found(fragment, text):
        return True
    base = fragment.rsplit("\\", 1)[-1]                       # full path for a named binary (Windows separator only)
    if base != fragment and base and _found(base, text):
        return True
    stem = base[:-4] if base.endswith(_EXECUTABLE) else ""
    return bool(stem) and re.search(r"(?<![\w.])" + re.escape(stem) + r"(?!\w)", text) is not None   # "net" → net.exe


def condition_grounding(rule, h) -> list[dict]:
    """Candidate values of a parsed Sigma rule that the approved hypothesis text does not contain.

    Text = behavior, scope, timeframe, evidence source/fields, source quotes and pivot value. A string value is
    split at wildcards; each run must occur in that text, as the full path's basename, or as a tool name whose
    executable file name it is. Numbers (also in comparisons) must occur as written. Regexes are listed unless they
    are a named pattern of the encoded-command library. Filter blocks are left to the filter review. A listed value
    is not proven wrong (a binary path, a sub-binary such as net1.exe can be legitimate); an unlisted rule is not
    proven faithful: dropped conditions and "for example" values turned into conditions are not detected."""
    if h is None:
        return []
    from . import encoded_trace
    text = _hypothesis_text(h)
    candidates, _ = partition(rule)
    found = []
    for name in Parser(candidates, list(rule.detection.detections)).parse().names():
        stack = [rule.detection.detections[name]]
        while stack:
            node = stack.pop()
            if not isinstance(node, SigmaDetectionItem):
                stack.extend(reversed(node.detection_items))
                continue
            for value in node.value:
                if isinstance(value, SigmaRegularExpression):
                    if str(value.regexp) not in encoded_trace.PATTERNS:
                        found.append({"kind": GROUNDING_REGEX, "khoi": name, "truong": node.field,
                                      "gia_tri": str(value.regexp)})
                    continue
                if isinstance(value, SigmaString):
                    fragments = _fragments(value)
                elif isinstance(value, (SigmaNumber, SigmaCompareExpression)):
                    fragments = [_norm(getattr(value, "number", value))]
                else:                                             # exists, null, bool, field reference, CIDR
                    fragments = []
                found += [{"kind": GROUNDING_VALUE, "khoi": name, "truong": node.field, "gia_tri": f}
                          for f in fragments if not _grounded(f, text)]
    # Thứ tự chuẩn, không theo thứ tự khối/trường trong YAML: manifest lưu rule bằng JSON sắp khóa, nên tính lại từ
    # manifest phải ra đúng danh sách (và băm) đã lưu (kiểm thật 10/10, G1).
    return sorted(found, key=_item_key)


def _item_key(item: dict) -> tuple:
    return tuple(str(item[k] or "") for k in ("khoi", "truong", "kind", "gia_tri"))


def missing_conditions(rule, h) -> list[dict]:
    """12/10 (H6): the reverse of `condition_grounding` — technical literals the approved hypothesis writes in
    behavior/scope (file, path, switch, WMI class, cmdlet, port; the H5 extractor) that no candidate value contains.

    Advisory only, like `condition_grounding`: never blocks, never reaches the model, never sees results, and is not
    part of the hashed rule-review items. A value covers a literal when it contains the literal, its last path
    segment, its file stem or its switch name as a standalone token, or when the value is the leading or trailing
    path segments of the literal (`\\a.dll` for a full path). A listed literal is not proof of a dropped condition: the hypothesis
    may give it as an example or negate it. An empty list is not proof that every condition was kept: conditions
    written as prose, and constraints executed by code, are not compared."""
    if h is None:
        return []
    from . import hypothesis_grounding as hg
    candidates, _ = partition(rule)
    values, numbers = [], set()
    for name in Parser(candidates, list(rule.detection.detections)).parse().names():
        stack = [rule.detection.detections[name]]
        while stack:
            node = stack.pop()
            if not isinstance(node, SigmaDetectionItem):
                stack.extend(node.detection_items)
                continue
            for value in node.value:
                if isinstance(value, SigmaRegularExpression):
                    values.append(hg.norm(re.sub(r"\\(\W)", r"\1", str(value.regexp))))   # \. and \\ as written text
                elif isinstance(value, SigmaString):
                    values.extend(hg.norm(f) for f in _fragments(value))
                elif isinstance(value, (SigmaNumber, SigmaCompareExpression)):
                    numbers.add(_norm(getattr(value, "number", value)))

    def covered(kind: str, literal: str) -> bool:
        if kind == "cong":
            return literal in numbers or any(re.search(r"(?<!\d)" + literal + r"(?!\d)", v) for v in values)
        names = {literal, literal.rsplit("\\", 1)[-1]}
        if kind == "co_lenh":
            names = {literal.lstrip("-\\")}                       # "-enc", "/create" (normalized "\create")
        elif kind == "tep" and len(literal.rsplit(".", 1)[0]) >= 3:
            names.add(literal.rsplit(".", 1)[0])
        return any(re.search(r"(?<![a-z0-9_])" + re.escape(n) + r"(?![a-z0-9_])", v) for n in names if n for v in values) \
            or any(literal.endswith("\\" + v) or literal.startswith(v + "\\") for v in values if v)   # whole path segments

    found: dict[tuple[str, str], dict] = {}
    for text in (h.behavior, h.scope):
        for kind, value in hg.details(text):
            key = (kind, hg.norm(value))
            if key not in found and not covered(*key):
                found[key] = {"loai": kind, "gia_tri": value}
    return list(found.values())


class ShortenError(ValueError):
    """The selected items cannot be removed on their own; only keeping or dropping the whole rule remains."""


def _prune(expr: Expr, gone: set[str]) -> Expr | None:
    """Delete selectors from a parsed condition: in `or` an alternative goes, in `and` a condition goes."""
    if expr.op == "id":
        return None if expr.value in gone else expr
    args = [a for a in (_prune(x, gone) for x in expr.args) if a is not None]
    if not args:
        return None
    if expr.op == "not":
        return Expr("not", tuple(args))
    return args[0] if len(args) == 1 else Expr(expr.op, tuple(args))


def shorten_rule(rule: dict, h, items: list[dict]) -> dict:
    """Remove from a stored rule (dict form) exactly the grounding items a reviewer selected — delete only, never add.

    Each item is traced back to its source value by running `condition_grounding` on that single block/field/value.
    A value leaves its list; a field without values leaves its block; a block without fields leaves the detection and
    its name leaves the condition. Refused when: an item is not part of this rule's grounding, cannot be traced, or
    shares its source value with an item that was not selected; no candidate selection would remain; or the result's
    grounding is not exactly the original minus the selected items."""
    if not items:
        raise ShortenError("chưa chọn mục nào để bỏ")
    try:
        before = condition_grounding(SigmaRule.from_dict(rule), h)
    except FilterStructureError as e:
        raise ShortenError(f"rule gốc không phân tích được: {e}") from e
    chosen = Counter(_item_key(i) for i in items)
    if any(n > 1 for n in chosen.values()) or chosen - Counter(_item_key(i) for i in before):
        raise ShortenError("mục được chọn không thuộc phép đối chiếu của rule này")
    out = deepcopy(rule)
    det = out.get("detection")
    if not isinstance(det, dict) or not isinstance(det.get("condition"), str):
        raise ShortenError("rule cần detection dạng ánh xạ với đúng một condition")
    header = {k: v for k, v in rule.items() if k != "detection"}
    marks: dict[str, dict[str, set[int]]] = {}
    for item in items:
        block = det.get(item["khoi"])
        if not isinstance(block, dict):
            raise ShortenError(f"khối {item['khoi']} không phải ánh xạ trường → giá trị")
        hit = False
        for key, raw in block.items():
            if key.split("|")[0] != item["truong"]:
                continue
            for index, value in enumerate(raw if isinstance(raw, list) else [raw]):
                single = {**header, "detection": {item["khoi"]: {key: value}, "condition": item["khoi"]}}
                try:
                    probe = condition_grounding(SigmaRule.from_dict(single), h)
                except Exception:                                 # noqa: BLE001 — giá trị không đứng riêng được
                    continue                                       # (vd modifier |all một giá trị): không định vị
                if _item_key(item) in {_item_key(i) for i in probe}:
                    marks.setdefault(item["khoi"], {}).setdefault(key, set()).add(index)
                    hit = True
        if not hit:
            raise ShortenError(f"không định vị được mục {item['truong']} = {item['gia_tri']} trong khối {item['khoi']}")
    gone = set()
    for name, keys in marks.items():
        block = det[name]
        for key, indexes in keys.items():
            raw = block[key]
            kept = [v for i, v in enumerate(raw) if i not in indexes] if isinstance(raw, list) else []
            if kept:
                block[key] = kept
            else:
                del block[key]
        if not block:
            del det[name]
            gone.add(name)
    if gone:
        names = [n for n in rule["detection"] if n != "condition"]
        pruned = _prune(Parser(rule["detection"]["condition"], names).parse(), gone)
        if pruned is None:
            raise ShortenError("bỏ các mục này thì rule không còn điều kiện nào; chỉ còn bỏ cả rule")
        det["condition"] = pruned.text()
    try:
        after = condition_grounding(SigmaRule.from_dict(out), h)
    except FilterStructureError as e:
        raise ShortenError(f"bỏ các mục này thì rule không còn vế sinh ứng viên; chỉ còn bỏ cả rule ({e})") from e
    except Exception as e:                                        # noqa: BLE001 — mọi lỗi pySigma là rule không hợp lệ
        raise ShortenError(f"rule sau rút gọn không hợp lệ: {type(e).__name__}: {e}") from e
    if Counter(_item_key(i) for i in after) != Counter(_item_key(i) for i in before) - chosen:
        raise ShortenError("một giá trị nguồn chứa cả mục chưa chọn; chọn đủ các mục đó hoặc bỏ cả rule")
    return out
