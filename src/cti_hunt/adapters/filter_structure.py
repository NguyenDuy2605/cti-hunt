"""Strict, source-level Sigma condition partition for the reviewed-filter policy.

The legacy adapter remains available for pinned v1 runs. No SQL-string heuristics:
parse the source grammar, expand selectors, then reject hidden/nested exclusions.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import re

from sigma.modifiers import SigmaNegateModifier
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaExists


class FilterStructureError(ValueError):
    pass


@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple[Expr, ...] = ()
    value: str = ""

    def text(self) -> str:
        if self.op == "id":
            return self.value
        if self.op == "not":
            return f"not ({self.args[0].text()})"
        return "(" + f" {self.op} ".join(a.text() for a in self.args) + ")"

    def names(self) -> list[str]:
        return [self.value] if self.op == "id" else list(dict.fromkeys(n for a in self.args for n in a.names()))


class Parser:
    def __init__(self, text: str, names: list[str]):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0
        self.names = names

    def take(self, token: str) -> bool:
        if self.pos < len(self.tokens) and self.tokens[self.pos].lower() == token:
            self.pos += 1
            return True
        return False

    def binary(self, op: str, child) -> Expr:
        args = [child()]
        while self.take(op):
            args.append(child())
        return args[0] if len(args) == 1 else Expr(op, tuple(args))

    def disjunction(self) -> Expr:
        return self.binary("or", self.conjunction)

    def conjunction(self) -> Expr:
        return self.binary("and", self.atom)

    def atom(self) -> Expr:
        if self.take("not"):
            return Expr("not", (self.atom(),))
        if self.take("("):
            result = self.disjunction()
            if not self.take(")"):
                raise FilterStructureError("condition thiếu ngoặc đóng")
            return result
        if self.pos >= len(self.tokens):
            raise FilterStructureError("condition thiếu biểu thức")
        token = self.tokens[self.pos]
        self.pos += 1
        if token.lower() in ("1", "all"):
            if not self.take("of") or self.pos >= len(self.tokens):
                raise FilterStructureError("nhóm selector phải là 1 of hoặc all of")
            pattern = self.tokens[self.pos]
            self.pos += 1
            chosen = self.names if pattern.lower() == "them" else [n for n in self.names if fnmatchcase(n, pattern)]
            if not chosen:
                raise FilterStructureError(f"selector không khớp: {pattern}")
            args = tuple(Expr("id", value=n) for n in chosen)
            return args[0] if len(args) == 1 else Expr("or" if token == "1" else "and", args)
        if token not in self.names:
            raise FilterStructureError(f"selector không có hoặc cú pháp chưa hỗ trợ: {token}")
        return Expr("id", value=token)

    def parse(self) -> Expr:
        result = self.disjunction()
        if self.pos != len(self.tokens):
            raise FilterStructureError("condition có phần chưa phân tích")
        return result


def _positive(expr: Expr, *, filters: bool) -> None:
    if expr.op == "not" or any(n.startswith("filter_") != filters for n in expr.names()):
        raise FilterStructureError("phủ định lồng hoặc selector lọc/ứng viên sai vị trí")
    for arg in expr.args:
        _positive(arg, filters=filters)


def partition(rule) -> tuple[str, list[dict]]:
    conditions = list(rule.detection.condition)
    if len(conditions) != 1:
        raise FilterStructureError("v2 cần đúng một condition")
    tree = Parser(conditions[0], list(rule.detection.detections)).parse()
    def conjuncts(expr):
        return [term for arg in expr.args for term in conjuncts(arg)] if expr.op == "and" else [expr]
    terms = conjuncts(tree)
    candidates, filters = [], []
    for term in terms:
        if term.op == "not":
            expr = term.args[0]
            _positive(expr, filters=True)
            filters.append({"condition": expr.text(), "selectors": expr.names()})
        else:
            _positive(term, filters=False)
            candidates.append(term)
    if not candidates:
        raise FilterStructureError("condition không có vế dương sinh ứng viên")
    # Both C and Fi must be positive; modifiers can hide negation inside a selector.
    names = dict.fromkeys([n for e in candidates for n in e.names()] +
                          [n for f in filters for n in f["selectors"]])
    for name in names:
        stack = [rule.detection.detections[name]]
        while stack:
            node = stack.pop()
            if isinstance(node, SigmaDetectionItem):
                if any(issubclass(m, SigmaNegateModifier) for m in node.modifiers):
                    raise FilterStructureError("modifier phủ định trong biểu thức dương C/Fi")
                if any(isinstance(v, SigmaExists) and not v.exists for v in node.value):
                    raise FilterStructureError("exists:false là phủ định ẩn trong biểu thức dương C/Fi")
            else:
                stack.extend(node.detection_items)
    c = candidates[0] if len(candidates) == 1 else Expr("and", tuple(candidates))
    return c.text(), filters
