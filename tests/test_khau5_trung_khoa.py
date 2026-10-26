"""07/10: a repeated key in one YAML mapping silently dropped conditions of a real ⑤ rule; now a static error."""
import yaml

from cti_hunt.adapters import duckdb_sigma as adapter
from cti_hunt.config import ROOT, agent_config
from cti_hunt.contracts import ContractB, SourceSpan
from cti_hunt.llm.prompting import load_sections
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s5_rule as S5

LS = adapter.load_catalog(ROOT / "configs/logsource_catalog.yaml")
CFG = agent_config("v2")
PROMPT = load_sections(ROOT / CFG["prompt_khau5"], ("SYSTEM", "USER", "REPAIR"))
H = ContractB(hypothesis_id="SELF-H02", behavior='Thực thi net group "Domain Admins" /domain', scope="mọi máy",
              timeframe="toàn bộ khoảng thời gian của log", status="approved", linked_ttps=["T1069.002"],
              evidence={"data_source": "security", "event_ids": [4688], "key_fields": ["NewProcessName", "CommandLine"]},
              source_spans=[SourceSpan(segment_id="SELF-1", text='net group "Domain Admins" /domain')])
DUPLICATE = r"""title: Domain Admins enumeration
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: ['\net.exe', '\net1.exe']
    CommandLine|contains: 'group'
    CommandLine|contains: 'Domain Admins'
    CommandLine|contains: '/domain'
  condition: selection
level: low
"""
FIXED = DUPLICATE.replace("    CommandLine|contains: 'group'\n    CommandLine|contains: 'Domain Admins'\n"
                          "    CommandLine|contains: '/domain'\n",
                          "    CommandLine|contains|all: ['group', 'Domain Admins', '/domain']\n")


def test_repeated_key_is_a_static_error_naming_the_key():
    issues, specs = S5.validate_rule(DUPLICATE, H, LS)
    assert [i.kind for i in issues] == ["yaml_trung_khoa"] and specs == []
    assert "CommandLine|contains" in issues[0].message and "|all" in issues[0].message
    # Plain safe_load would have accepted it and kept only the last condition.
    assert yaml.safe_load(DUPLICATE)["detection"]["selection"]["CommandLine|contains"] == "/domain"


def test_fixed_rule_keeps_every_condition():
    issues, specs = S5.validate_rule(FIXED, H, LS)
    assert not issues and len(specs) == 1
    cand = specs[0]["candidates"].lower()
    assert "group" in cand and "domain admins" in cand and "/domain" in cand


def test_repair_receives_only_the_static_message_and_accepts_the_fix():
    llm = MockClient(responses=[{"rule_yaml": DUPLICATE, "note": "x"}, {"rule_yaml": FIXED, "note": "x"}])
    result = S5.generate_rule(H, llm, PROMPT, LS, 2)
    assert result["hop_le"] and not result["hop_le_lan_dau"] and result["so_lan_sua"] == 1
    assert result["lan_thu"][0]["loi"][0]["kind"] == "yaml_trung_khoa"
    repair = llm.calls[1][1]
    assert "yaml_trung_khoa" in repair and "CommandLine|contains" in repair
