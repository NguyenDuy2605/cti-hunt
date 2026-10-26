"""B3 (09/10): đối chiếu giá trị điều kiện của rule ⑤ với giả thuyết đã duyệt — chỉ cảnh báo, không chặn.

Rule và giả thuyết tự soạn theo các mẫu ⑤ từng thêm/biến điều kiện (dấu phẩy thay dấu cách, "/C", ngưỡng số, regex tự
chế); không dùng artifact của lượt đánh giá hay nhãn."""
import json
import runpy

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from cti_hunt import approval, demo
from cti_hunt.config import ROOT
from cti_hunt.contracts import ContractB, Evidence, SourceSpan
from cti_hunt.stages import encoded_trace, rule_fidelity

SYS = "microsoft-windows-sysmon/operational"


def _hyp(behavior, quote="Câu nguồn tự soạn.", **kw):
    return ContractB(hypothesis_id="TU-H01", behavior=behavior, scope="mọi máy", timeframe="toàn bộ log",
                     evidence=Evidence(data_source=SYS, event_ids=[1], key_fields=["Image", "ParentImage", "CommandLine"]),
                     linked_ttps=["T1059"], source_spans=[SourceSpan(text=quote)], status="approved", **kw)


def _rule(selection, extra=""):
    lines = "\n".join(f"        {k}: {json.dumps(v)}" for k, v in selection.items())
    text = ("title: t\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n"
            f"    selection:\n{lines}\n{extra}    condition: selection{' and not filter_x' if extra else ''}\nlevel: low\n")
    return SigmaCollection.from_yaml(text).rules[0]


def _values(items):
    return [(i["kind"], i["truong"], i["gia_tri"]) for i in items]


def test_values_named_by_the_hypothesis_or_its_quote_are_grounded():
    h = _hyp("Tiến trình powershell.exe do WmiPrvSE.exe sinh ra", quote="spawn a Powershell command via a WMI call")
    rule = _rule({"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\powershell.exe"})
    assert rule_fidelity.condition_grounding(rule, h) == []
    full_path = _rule({"Image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"})   # đường dẫn đầy đủ của tệp được nêu
    assert rule_fidelity.condition_grounding(full_path, h) == []


def test_tool_name_grounds_its_executable_but_not_a_different_binary():
    h = _hyp("Chạy lệnh net group /domain để liệt kê nhóm")
    rule = _rule({"Image|endswith": ["\\net.exe", "\\net1.exe"], "CommandLine|contains|all": ["group", "/domain"]})
    assert _values(rule_fidelity.condition_grounding(rule, h)) == [
        (rule_fidelity.GROUNDING_VALUE, "Image", "net1.exe")]
    internet = _hyp("Kết nối internet ra ngoài")              # "net" trong một từ khác không tính là tên công cụ
    assert _values(rule_fidelity.condition_grounding(_rule({"Image|endswith": "\\net.exe"}), internet)) == [
        (rule_fidelity.GROUNDING_VALUE, "Image", "net.exe")]


@pytest.mark.parametrize("selection,flagged", [
    ({"CommandLine|contains": "shell32.dll,Control_RunDLL"}, "shell32.dll,control_rundll"),   # dấu phẩy tự thêm
    ({"CommandLine|startswith": "/C"}, "/c"),                                               # tham số tự thêm
    ({"CommandLine|contains": "Control_RunDLL", "Image|endswith": "\\rundll32.exe",
      "ParentImage|endswith": "\\cmd.exe"}, "cmd.exe"),                                      # tiến trình cha tự chọn
])
def test_values_added_or_changed_by_the_rule_are_listed(selection, flagged):
    h = _hyp("rundll32.exe nạp shell32.dll Control_RunDLL", quote="rundll32.exe shell32.dll Control_RunDLL")
    assert flagged in [i["gia_tri"] for i in rule_fidelity.condition_grounding(_rule(selection), h)]


def test_numbers_and_regexes():
    h = _hyp("Kết nối tới cổng 443 từ powershell.exe")
    found = _values(rule_fidelity.condition_grounding(_rule({"DestinationPort": [443, 4444]}), h))
    assert found == [(rule_fidelity.GROUNDING_VALUE, "DestinationPort", "4444")]
    threshold = _rule({"CommandLine|re": "-enc [A-Za-z0-9+/=]{20,}"})                     # ngưỡng tự thêm
    assert _values(rule_fidelity.condition_grounding(threshold, h)) == [
        (rule_fidelity.GROUNDING_REGEX, "CommandLine", "-enc [A-Za-z0-9+/=]{20,}")]
    library = _rule({"CommandLine|re|i": encoded_trace.SWITCH})                          # mẫu đã chứng nhận
    assert rule_fidelity.condition_grounding(library, h) == []


def test_filters_wildcards_and_existence_are_not_listed_and_none_hypothesis_is_empty():
    h = _hyp("Tiến trình powershell.exe")
    rule = _rule({"Image|endswith": "\\powershell.exe", "CommandLine": "*", "ParentImage|exists": True},
                 extra="    filter_x:\n        CommandLine|contains: 'không có trong giả thuyết'\n")
    assert rule_fidelity.condition_grounding(rule, h) == []                  # khối lọc để cổng duyệt lọc xét
    assert rule_fidelity.condition_grounding(rule, None) == []


def test_ui_helper_reads_the_approved_hypothesis_of_the_same_round(tmp_path):
    round_dir = tmp_path / "round_01"
    (round_dir / "rules_draft").mkdir(parents=True)
    h = _hyp("Tiến trình powershell.exe do WmiPrvSE.exe sinh ra")
    (round_dir / approval.APPROVED_FILE).write_text(json.dumps([h.model_dump(mode="json")]), encoding="utf-8")
    rule = round_dir / "rules_draft" / "TU-H01.yml"
    rule.write_text("title: t\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n"
                    "    selection:\n        Image|endswith: '\\powershell.exe'\n        CommandLine|contains: ' -w hidden'\n"
                    "    condition: selection\nlevel: low\n", encoding="utf-8")
    assert _values(demo.rule_grounding(rule)) == [(rule_fidelity.GROUNDING_VALUE, "CommandLine", "-w hidden")]
    other = round_dir / "rules_draft" / "TU-H02.yml"
    other.write_text(rule.read_text(encoding="utf-8"), encoding="utf-8")
    assert demo.rule_grounding(other) is None                              # không có giả thuyết đã duyệt trùng tên
    script = runpy.run_path(str(ROOT / "scripts" / "doi_chieu_dieu_kien_khau5.py"))
    assert [r["rule"] for r in script["rows"](tmp_path)] == ["rules_draft/TU-H01.yml"]


def test_item_order_does_not_depend_on_block_or_field_order():
    # 10/10 (G1): manifest ghi JSON sắp khóa nên đọc lại thì thứ tự khối/trường của rule đổi; danh sách mục phải giữ nguyên.
    h = _hyp("Tiến trình con tự soạn")
    def rule(blocks):
        text = "title: t\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n"
        for name, fields in blocks:
            text += f"    {name}:\n" + "".join(f"        {k}: {json.dumps(v)}\n" for k, v in fields)
        return SigmaCollection.from_yaml(text + "    condition: 1 of selection_*\nlevel: low\n").rules[0]
    z = ("selection_z", [("ParentImage|endswith", "\\wmiprvse.exe"), ("Image|endswith", "\\cmd.exe")])
    a = ("selection_a", [("CommandLine|re", "-x [0-9]+"), ("Image|endswith", ["\\b-tool.exe", "\\a-tool.exe"])])
    first = rule([z, a])
    second = rule([(a[0], list(reversed(a[1]))), (z[0], list(reversed(z[1])))])
    found = rule_fidelity.condition_grounding(first, h)
    assert len(found) == 5 and found == rule_fidelity.condition_grounding(second, h)
    key = [(i["khoi"], i["truong"], i["kind"], i["gia_tri"]) for i in found]
    assert key == sorted(key)


# 10/10: rút gọn rule — bỏ đúng các mục đối chiếu người duyệt chọn, chỉ xóa, không thêm.
def _doc(detection: str) -> dict:
    return yaml.safe_load("title: t\nlogsource:\n  product: windows\n  category: process_creation\n"
                          "detection:\n" + detection + "level: low\n")


def _pick(rule: dict, h, value: str) -> dict:
    return next(i for i in rule_fidelity.condition_grounding(SigmaRule.from_dict(rule), h) if i["gia_tri"] == value)


@pytest.mark.parametrize("condition, kept", [("1 of selection_*", "selection_decode"),       # "hoặc": bỏ một nhánh
                                             ("selection_flag or selection_decode", "selection_decode"),
                                             ("selection_flag and selection_decode", "selection_decode")])  # "và": bỏ điều kiện
def test_shorten_removes_a_whole_block_and_rewrites_the_condition(condition, kept):
    h = _hyp("PowerShell giải mã base64")
    rule = _doc("  selection_flag:\n    ScriptBlockText|re: '-e(nc)?\\s+[A-Za-z0-9+/=]+'\n"
                "  selection_decode:\n    ScriptBlockText|re: 'FromBase64String\\('\n"
                f"  condition: {condition}\n")
    before = json.dumps(rule, sort_keys=True)
    flag = _pick(rule, h, "-e(nc)?\\s+[A-Za-z0-9+/=]+")
    out = rule_fidelity.shorten_rule(rule, h, [flag])
    assert json.dumps(rule, sort_keys=True) == before                      # rule gốc không đổi
    assert set(out["detection"]) == {kept, "condition"} and out["detection"]["condition"] == kept
    assert out["detection"][kept] == rule["detection"][kept]
    left = rule_fidelity.condition_grounding(SigmaRule.from_dict(out), h)
    assert [i["gia_tri"] for i in left] == ["FromBase64String\\("]


def test_shorten_removes_a_field_or_one_value_and_keeps_filters():
    h = _hyp("powershell.exe chạy lệnh winword.exe")
    rule = _doc("  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|re: '-enc [A-Za-z0-9+/=]{20,}'\n"
                "    ParentImage|endswith:\n      - '\\winword.exe'\n      - '\\excel.exe'\n"
                "  filter_x:\n    Image|endswith: '\\sppsvc.exe'\n  condition: selection and not filter_x\n")
    out = rule_fidelity.shorten_rule(rule, h, [_pick(rule, h, "-enc [A-Za-z0-9+/=]{20,}"), _pick(rule, h, "excel.exe")])
    sel = out["detection"]["selection"]
    assert set(sel) == {"Image|endswith", "ParentImage|endswith"} and sel["ParentImage|endswith"] == ["\\winword.exe"]
    assert out["detection"]["filter_x"] == rule["detection"]["filter_x"]
    assert out["detection"]["condition"] == "selection and not filter_x"     # không bỏ khối nào: condition giữ nguyên
    assert rule_fidelity.condition_grounding(SigmaRule.from_dict(out), h) == []


def test_shorten_refuses_what_is_not_an_exact_removal():
    h = _hyp("Kết nối mạng ra ngoài")
    only = _doc("  selection:\n    DestinationPort: 80\n  filter_x:\n    Image|endswith: '\\chrome.exe'\n"
                "  condition: selection and not filter_x\n")
    with pytest.raises(rule_fidelity.ShortenError, match="vế sinh ứng viên"):     # bỏ điều kiện ứng viên duy nhất
        rule_fidelity.shorten_rule(only, h, [_pick(only, h, "80")])
    sole = _doc("  selection:\n    DestinationPort: 80\n  condition: selection\n")
    with pytest.raises(rule_fidelity.ShortenError, match="không còn điều kiện"):
        rule_fidelity.shorten_rule(sole, h, [_pick(sole, h, "80")])
    shared = _doc("  selection:\n    CommandLine|contains: 'alpha*omega'\n    Image|endswith: '\\tool.exe'\n"
                  "  condition: selection\n")
    with pytest.raises(rule_fidelity.ShortenError, match="chưa chọn"):          # một giá trị sinh hai mục, chọn một
        rule_fidelity.shorten_rule(shared, h, [_pick(shared, h, "alpha")])
    both = rule_fidelity.shorten_rule(shared, h, [_pick(shared, h, "alpha"), _pick(shared, h, "omega")])
    assert set(both["detection"]["selection"]) == {"Image|endswith"}
    foreign = {"kind": rule_fidelity.GROUNDING_VALUE, "khoi": "selection", "truong": "Image", "gia_tri": "other.exe"}
    with pytest.raises(rule_fidelity.ShortenError, match="không thuộc"):
        rule_fidelity.shorten_rule(shared, h, [foreign])
    with pytest.raises(rule_fidelity.ShortenError, match="chưa chọn mục"):
        rule_fidelity.shorten_rule(shared, h, [])
