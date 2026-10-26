"""Biến thể mức kỹ thuật của rule ⑤ (stages/rule_variant.py): quy tắc xác định, không mô hình, không nhãn."""
import duckdb
import pytest

from cti_hunt.stages import rule_variant as rv

CFG = rv.load_config()


def _rule(category, selection, condition="selection", **extra):
    det = {"selection": selection, "condition": condition, **extra}
    return {"title": "Thử", "logsource": {"product": "windows", "category": category}, "detection": det,
            "tags": ["attack.t1047"]}


def _spec(rule, source, eids, **kw):
    return {"id": "H01__thu", "scope": {"channel": "microsoft-windows-sysmon/operational", "event_ids": eids},
            "candidates": "TRUE", "linked_ttps": ["T1047"], "filters": kw.pop("filters", []),
            "sigma_context": {"rule": rule, "source": source, "binding": kw.pop("binding", {})}, **kw}


def test_process_keeps_mechanism_parent_and_relaxes_payload():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\rundll32.exe",
                                      "CommandLine|contains": "enUS.Media.dll"})
    var, note = rv.variant_rule(rule, [1], CFG)
    sel = var["detection"]["selection"]
    assert sel["ParentImage|endswith"] == "\\WmiPrvSE.exe"
    assert "\\powershell.exe" in sel["Image|endswith"] and "\\rundll32.exe" in sel["Image|endswith"]
    assert "CommandLine|contains" not in sel
    assert "wmiprvse.exe" in note and "CommandLine" in note


@pytest.mark.parametrize("selection, reason", [
    ({"ParentImage|endswith": "\\wscript.exe", "Image|endswith": "\\rundll32.exe"}, "không thuộc danh sách vết cơ chế"),
    ({"Image|endswith": "\\7z.exe", "CommandLine|contains": " x "}, "không có điều kiện tiến trình cha"),
])
def test_process_without_mechanism_parent_has_no_variant(selection, reason):
    var, note = rv.variant_rule(_rule("process_creation", selection), [1], CFG)
    assert var is None and reason in note


def test_or_condition_not_supported_for_process_rules():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe"}, condition="1 of selection*",
                 selection_b={"Image|endswith": "\\cmd.exe"})
    var, note = rv.variant_rule(rule, [1], CFG)
    assert var is None and "OR" in note


def test_filters_are_not_carried_over():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\rundll32.exe"},
                 condition="selection and not 1 of filter_*", filter_cpl={"CommandLine|contains": "shell32.dll"})
    var, note = rv.variant_rule(rule, [1], CFG)
    assert list(var["detection"]) == ["selection", "condition"] and "1 khối lọc" in note


def test_script_keeps_only_cmdlet_names():
    rule = _rule("ps_script", {"ScriptBlock|contains|all": ["Invoke-Command", "rundll32", "-ComputerName"],
                               "ScriptBlock|re|ignorecase": "enUS\\.Media"})
    var, note = rv.variant_rule(rule, [4104], CFG)
    assert var["detection"]["selection"] == {"ScriptBlock|contains|all": ["Invoke-Command"]}
    assert "Invoke-Command" in note


def test_script_or_list_stays_or_and_payload_block_is_dropped():
    rule = _rule("ps_script", {"ScriptBlock|contains": ["Get-WmiObject", "Get-CimInstance"]},
                 condition="selection and selection_decode", selection_decode={"ScriptBlock|contains": "FromBase64String"})
    var, note = rv.variant_rule(rule, [4104], CFG)
    assert var["detection"] == {"selection": {"ScriptBlock|contains": ["Get-WmiObject", "Get-CimInstance"]},
                                "condition": "selection"}
    assert "1 điều kiện" in note


def test_script_or_list_with_payload_alternative_is_dropped_whole():
    rule = _rule("ps_script", {"ScriptBlock|contains": ["Invoke-Command", "rundll32"],
                               "ScriptBlock|contains|all": ["Invoke-WmiMethod", "win32_process"]})
    var, _ = rv.variant_rule(rule, [4104], CFG)
    assert var["detection"]["selection"] == {"ScriptBlock|contains|all": ["Invoke-WmiMethod"]}


def test_script_two_cmdlet_conditions_stay_and_in_separate_blocks():
    rule = _rule("ps_script", {"ScriptBlock|contains": "Invoke-Command"}, condition="selection and selection_b",
                 selection_b={"ScriptBlock|contains": ["Enter-PSSession", "New-PSSession"], "ContextInfo|contains": "x"})
    var, _ = rv.variant_rule(rule, [4104], CFG)
    det = var["detection"]
    assert det["condition"] == "all of selection_*"
    assert det["selection_1"] == {"ScriptBlock|contains": "Invoke-Command"}
    assert det["selection_2"] == {"ScriptBlock|contains": ["Enter-PSSession", "New-PSSession"]}


def test_process_variant_keeps_original_child_in_group():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\scrcons.exe"})
    var, _ = rv.variant_rule(rule, [1], CFG)
    assert "\\scrcons.exe" in var["detection"]["selection"]["Image|endswith"]


def test_multi_block_variant_compiles():
    rule = _rule("ps_script", {"ScriptBlock|contains": "Invoke-Command"}, condition="selection and selection_b",
                 selection_b={"ScriptBlock|contains|all": ["New-PSSession", "rundll32"]})
    spec = _spec(rule, "powershell_4104", [4104])
    spec["scope"]["channel"] = "microsoft-windows-powershell/operational"
    var, _ = rv.variant_spec(spec, CFG)
    assert "Invoke-Command" in var["candidates"] and "New-PSSession" in var["candidates"]
    assert " AND " in var["candidates"].upper()


def test_script_without_cmdlet_has_no_variant():
    var, note = rv.variant_rule(_rule("ps_script", {"ScriptBlock|contains": "FromBase64String"}), [4104], CFG)
    assert var is None and "cmdlet" in note


def test_wmi_drops_content_and_keeps_event_id_of_original_scope():
    rule = _rule("wmi_event", {"Query|contains": "Win32_LocalTime"})
    var, _ = rv.variant_rule(rule, [19], CFG)
    assert var["detection"]["selection"] == {"EventID": [19]}


def test_wmi_keeps_type_fields():
    rule = _rule("wmi_event", {"Type": "Command Line", "Destination|contains": "rundll32"})
    var, note = rv.variant_rule(rule, [20], CFG)
    assert var["detection"]["selection"] == {"Type": "Command Line"} and "Destination" in note


def test_identical_variant_is_skipped():
    var, note = rv.variant_rule(_rule("wmi_event", {"Operation": "Created"}), [19], CFG)
    assert var is None and "mức kỹ thuật" in note


def test_other_logsources_have_no_variant():
    var, note = rv.variant_rule(_rule("file_event", {"TargetFilename|endswith": ".dll"}), [11], CFG)
    assert var is None and "file_event" in note


def test_variant_spec_compiles_on_same_source_and_matches_other_payload():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\rundll32.exe"})
    spec = _spec(rule, "sysmon_1", [1])
    spec["candidates"] = "ParentImage ILIKE '%\\\\WmiPrvSE.exe' ESCAPE '\\' AND Image ILIKE '%\\\\rundll32.exe' ESCAPE '\\'"
    var, _ = rv.variant_spec(spec, CFG)
    assert var["id"] == "H01__thu__bien_the" and var["scope"]["event_ids"] == [1]
    assert var["bien_the"]["tu_rule"] == "H01__thu" and var["filters"] == []
    con = duckdb.connect()
    con.execute("CREATE TABLE events (ev_channel VARCHAR, ev_eid INTEGER, ev_host VARCHAR, ParentImage VARCHAR, "
                "Image VARCHAR, CommandLine VARCHAR)")
    con.execute("INSERT INTO events VALUES "
                "('microsoft-windows-sysmon/operational', 1, 'W1', 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', "
                "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell -enc AAA'), "
                "('microsoft-windows-sysmon/operational', 1, 'W1', 'C:\\Windows\\explorer.exe', "
                "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell')")
    rows = rv.compare([spec], con, CFG)
    assert [(r["pham_vi"], r["goc"], r["bien_the"]) for r in rows] == [(2, 0, 1)]
    md = rv.render(rows)
    assert "Biến thể mức kỹ thuật" in md and "| 2 | 0 | 1 |" in md


def test_pivot_and_constrained_hunts_are_skipped():
    rule = _rule("process_creation", {"ParentImage|endswith": "\\WmiPrvSE.exe", "Image|endswith": "\\rundll32.exe"})
    con = duckdb.connect()
    pivot = _spec(rule, "sysmon_1", [1], binding={"pivot_value": "dschrute"})
    neo = _spec(rule, "sysmon_1", [1], rang_buoc={"moc_neo": {}})
    assert rv.compare([pivot, neo], con, CFG) == []


def test_spec_without_sigma_rule_has_no_variant():
    var, note = rv.variant_spec({"id": "x", "scope": {"event_ids": [1]}}, CFG)
    assert var is None and "Sigma" in note


def test_config_lists_are_lowercase_exe_names():
    for name in list(CFG["tien_trinh_cha_co_che"]) + CFG["tien_trinh_con"]:
        assert name == name.lower() and name.endswith(".exe")
