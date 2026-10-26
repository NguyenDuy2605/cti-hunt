"""A bounded representation of an explicitly approved encoded PowerShell command.

This is a textual trace, not a PowerShell parser or a Base64 decoder. Only named
patterns are statically certified here; equivalent arbitrary regexes are not.
No ATT&CK ID, hypothesis ID, source quote, event samples or event labels gate it.
"""
from __future__ import annotations

import re
import unicodedata

from sigma.conditions import ConditionAND, ConditionOR
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaRegularExpression, SigmaRegularExpressionFlag, SigmaString, SpecialChars

from ..adapters.filter_structure import Parser, partition

ISSUE = 'dau_vet_ma_hoa_khong_du_cau_truc'
SCRIPT_ISSUE = 'co_ma_hoa_tren_noi_dung_script'
# Script-block and module-logging content. The switch that launched the host process is recorded in process-creation
# command lines (and in the "Host Application" line of 4103 ContextInfo), not in these fields.
SCRIPT_FIELDS = frozenset({'scriptblock', 'scriptblocktext', 'payload'})      # Sigma name and log column of 4104; 4103
_SWITCH_NAMES = ('e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|'
                 'encodedcomman|encodedcommand')
_STATED = re.compile(r'(?<![\w-])-(?:' + _SWITCH_NAMES + r')(?![\w-])', re.I)
_BLOB = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
# (command line carrying the switch, the same line with only the switch token removed)
_PROBES = tuple((line.format(sw=switch + ' ', b=_BLOB), line.format(sw='', b=_BLOB)) for line, switch in (
    ('powershell.exe {sw}{b}', '-enc'), ('powershell {sw}{b}', '-EncodedCommand'),
    ('powershell.exe -NoP -NonI -W Hidden {sw}{b}', '-e'), ('{sw}{b}', '-ec'), ('pwsh {sw}"{b}"', '-Enc')))
# Intrinsic alphabet/padding syntax, without an arbitrary minimum length.
_BODY = r'[A-Za-z0-9+/]+=?=?'
# Use the regex code point for an apostrophe, avoiding double SQL escaping in
# the existing pySigma SQLite-derived regex transport. Verify on DuckDB below.
_QUOTED = r'(?:"' + _BODY + r'"|\x27' + _BODY + r'\x27)'
_ARG = '(?:' + _BODY + '|' + _QUOTED + ')'
SWITCH = r'(?:^|[ \t])-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)[ \t]+' + _ARG + r'(?:[ \t]|$)'
DECODE = r'\[(?:System\.)?Convert\][ \t]*::[ \t]*FromBase64String[ \t]*\([ \t]*' + _QUOTED + r'[ \t]*\)'
PATTERNS = (SWITCH, DECODE)


def required(h) -> bool:
    """Conservative opt-in for a limited affirmative prose vocabulary and process evidence.

    Unrecognized/negative prose is not silently assigned this representation.
    Missing this gate is not evidence that another hypothesis is semantically safe.
    """
    if h is None:
        return False
    text = ''.join(c for c in unicodedata.normalize('NFD', h.behavior.casefold()) if not unicodedata.combining(c))
    text = text.replace('đ', 'd')
    fields = {f.casefold() for f in h.evidence.key_fields}
    process_source = (h.evidence.data_source.casefold() == 'security' and set(h.evidence.event_ids) == {4688}) or \
        (h.evidence.data_source.casefold() == 'microsoft-windows-sysmon/operational' and set(h.evidence.event_ids) == {1})
    return bool(process_source and 'commandline' in fields and fields & {'image', 'newprocessname'}
                and 'powershell' in text and 'base64' in text
                and re.search(r'\b(?:lenh|command|argument|doi so)\b', text)
                and re.search(r'\b(?:ma hoa|encoded)\b', text)
                and not re.search(r'\b(?:not|without|khong)\b', text))


def requirements(h) -> dict | None:
    if not required(h):
        return None
    return {'kind': 'powershell_encoded_command_text_v1', 'field': 'CommandLine',
            'modifier': 're|i', 'supported_patterns': list(PATTERNS),
            'semantics': 'Nonempty encoded argument with switch boundaries, or a qualified literal decode-call trace. '
                         'Do not add length thresholds. This does not prove parsing, decoding, execution or intent.',
            'unsupported': 'Variable/computed decode arguments and equivalent arbitrary patterns are not certified; '
                           'return no rule rather than silently substituting a bare indicator.'}


def _combine(values: list[bool], linking) -> bool:
    if not values:
        return False
    if linking is ConditionAND:
        return any(values)  # A conjunction retains a required predicate.
    if linking is ConditionOR:
        return all(values)  # Every disjunct must retain a required predicate.
    return False


def _guarantees(node) -> bool:
    if isinstance(node, SigmaDetectionItem):
        if node.field is None or node.field.casefold() != 'commandline':
            return False
        values = [isinstance(v, SigmaRegularExpression) and str(v.regexp) in PATTERNS
                  and v.flags == {SigmaRegularExpressionFlag.IGNORECASE} for v in node.value]
        return _combine(values, node.value_linking)
    return _combine([_guarantees(n) for n in node.detection_items], node.item_linking)


def issues(rule, h) -> list[dict]:
    if not required(h):
        return []
    candidate, _ = partition(rule)
    tree = Parser(candidate, list(rule.detection.detections)).parse()
    def guaranteed(expr):
        if expr.op == 'id':
            return _guarantees(rule.detection.detections[expr.value])
        flags = [guaranteed(e) for e in expr.args]
        return any(flags) if expr.op == 'and' else bool(flags) and all(flags) if expr.op == 'or' else False
    if guaranteed(tree):
        return []
    return [{'kind': ISSUE, 'message':
             'Approved prose requires an encoded PowerShell command trace. Every candidate branch must require '
             'one supported CommandLine pattern with re|i from primary_trace_requirements. Bare switch/method '
             'substrings do not establish a nonempty argument or decode call. Fix the representation while '
             'preserving approved conditions; if unsupported, return no rule and explain in note.'}]


def _selects_switch(value) -> bool:
    """The value matches a command line because of its encoded-command switch: it matches a probe line and stops
    matching once only the switch token is removed. Decided on fixed self-authored lines, never on event data."""
    if isinstance(value, SigmaRegularExpression):
        try:
            test = re.compile(str(value.regexp), re.I | re.S).search
        except re.error:
            return False                                          # an invalid regex is reported by the SQL check
    elif isinstance(value, SigmaString):
        test = re.compile(''.join(re.escape(p) if isinstance(p, str) else
                                  '.' if p is SpecialChars.WILDCARD_SINGLE else '.*' for p in value.s),
                          re.I | re.S).fullmatch
    else:
        return False
    return any(test(with_switch) and not test(without) for with_switch, without in _PROBES)


def script_field_issues(rule, h) -> list[dict]:
    """12/10 (H6): ⑤ put the launch switch on the 4104 script-block field in five real runs; no hypothesis stated it.

    Candidate blocks only (filters go to the filter review). Not raised when the approved hypothesis itself writes
    the switch in behavior/scope (a script that starts another encoded PowerShell): ⑤ implements what was approved.
    Lexical and bounded: other launch switches, and a switch reached only through a variable, are not covered."""
    if h is not None and _STATED.search(f'{h.behavior} {h.scope}'):
        return []
    candidate, _ = partition(rule)
    found = []
    for name in Parser(candidate, list(rule.detection.detections)).parse().names():
        stack = [rule.detection.detections[name]]
        while stack:
            node = stack.pop()
            if not isinstance(node, SigmaDetectionItem):
                stack.extend(node.detection_items)
            elif node.field and node.field.casefold() in SCRIPT_FIELDS and any(_selects_switch(v) for v in node.value):
                found.append(f'{name}.{node.field}')
    if not found:
        return []
    return [{'kind': SCRIPT_ISSUE, 'message':
             f"{', '.join(dict.fromkeys(found))}: a value selects the PowerShell encoded-command launch switch "
             '(-e, -enc, -EncodedCommand). Script-block and module-logging payload fields hold script content; the '
             'switch that started the host process is recorded in process-creation command lines, not there, and '
             'the approved hypothesis does not state this switch as script content. Remove that value or branch and '
             'keep every other approved condition. Do not move it to another field or invent a replacement. '
             'If no approved condition remains, return an empty rule_yaml and explain in note.'}]
