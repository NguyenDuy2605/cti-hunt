import uuid

import pytest

from cti_hunt import config
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.contracts import ContractB, Evidence, SourceSpan
from cti_hunt.data.store import connect
from cti_hunt.eval import g0c

SYSMON = "microsoft-windows-sysmon/operational"


def _rule(root, name, status, logsource, tags, selection="ParentImage|endswith: '\\\\WmiPrvSE.exe'"):
    path = root / "rules/windows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    ls = "".join(f"\n  {k}: {v}" for k, v in logsource.items())
    tag_lines = "".join(f"\n  - {t}" for t in tags)
    path.write_text(f"title: {name}\nid: {uuid.uuid5(uuid.NAMESPACE_URL, name)}\nstatus: {status}\n"
                    f"logsource:{ls}\ntags:{tag_lines}\n"
                    f"detection:\n  selection:\n    {selection}\n  condition: selection\n", encoding="utf-8")
    return path


def test_select_follows_g0c_metadata_rules_only(tmp_path):
    proc = {"product": "windows", "category": "process_creation"}
    _rule(tmp_path, "a_stable.yml", "stable", proc, ["attack.execution", "attack.t1047"])
    _rule(tmp_path, "b_experimental.yml", "experimental", proc, ["attack.t1047"])
    _rule(tmp_path, "c_parent.yml", "test", proc, ["attack.t1546"])
    _rule(tmp_path, "d_child.yml", "Test", proc, ["attack.t1546.003"])
    _rule(tmp_path, "e_other_logsource.yml", "test", {**proc, "service": "sysmon"}, ["attack.t1047"])
    _rule(tmp_path, "f_tactic_only.yml", "test", proc, ["attack.execution", "attack.persistence"])
    (tmp_path / "rules/windows/g_two_docs.yml").write_text("title: a\n---\ntitle: b\n", encoding="utf-8")
    metas, errors = g0c.index_rules(tmp_path)
    assert [e["relative_path"] for e in errors] == ["rules/windows/g_two_docs.yml"]
    names = lambda sel: [m["title"] for m in sel]
    assert names(g0c.select(metas, proc, ["T1047"])) == ["a_stable.yml"]
    assert names(g0c.select(metas, proc, ["T1546.003"])) == ["d_child.yml"]   # không lấy cha T1546
    assert names(g0c.select(metas, proc, ["T1546"])) == ["c_parent.yml"]      # không lấy con T1546.003
    assert names(g0c.select(metas, {**proc, "service": "sysmon"}, ["T1047"])) == ["e_other_logsource.yml"]
    assert g0c.select(metas, proc, ["T1059.001"]) == []
    assert g0c.logsource_key({"product": "Windows ", "category": "process_creation"}) == \
        g0c.logsource_key({"category": "process_creation", "product": "windows", "service": None})


def test_pin_without_git_records_manifest(tmp_path):
    _rule(tmp_path, "b.yml", "test", {"product": "windows"}, [])
    _rule(tmp_path, "a/x.yml", "test", {"product": "windows"}, [])
    pin, manifest = g0c.pin_sigmahq(tmp_path)
    assert pin["files"] == 2 and pin["commit"] is None and pin["clean"] is None
    paths = [line.split("  ", 1)[1] for line in manifest.splitlines()]
    assert paths == ["rules/windows/a/x.yml", "rules/windows/b.yml"]
    assert pin["manifest_sha256"] == g0c.pin_sigmahq(tmp_path)[0]["manifest_sha256"]


def _pivot(kind, value):
    return ContractB(hypothesis_id="TU-H09", behavior="Dấu vết pivot", scope="máy được chọn", timeframe="toàn bộ",
                     evidence=Evidence(data_source=SYSMON, event_ids=[1], key_fields=["ParentImage", "Image"]),
                     linked_ttps=["T1047"], source_spans=[SourceSpan(text="Đoạn CTI tự soạn")],
                     origin="pivot", pivot_depth=1, pivot_kind=kind, pivot_value=value)


def test_pivot_reference_carries_same_lock_without_narrowing_eids(work, tmp_path):
    rule = _rule(tmp_path, "proc.yml", "test", {"product": "windows", "category": "process_creation"},
                 ["attack.t1047"])
    con = connect(work)
    columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()} | {"User"}
    con.close()
    catalog = duckdb_sigma.load_catalog(config.resolve("configs/logsource_catalog.yaml"))
    scope = {"channel": SYSMON, "event_ids": [1]}

    specs, _ = g0c.pivot_reference_specs(rule, catalog, columns, scope, _pivot("may", "utica"))
    assert len(specs) == 1 and specs[0]["scope"]["hosts"] == ["UTICA"]
    assert "split_part" not in specs[0]["candidates"]

    specs, _ = g0c.pivot_reference_specs(rule, catalog, columns, scope, _pivot("tai_khoan", "dschrute"))
    assert len(specs) == 1 and not specs[0]["scope"].get("hosts")
    assert specs[0]["candidates"].endswith(
        "AND (lower(trim(split_part(split_part(coalesce(\"User\", ''), chr(92), -1), '@', 1))) = 'dschrute')")

    # Hunt sinh đã thu EID khác chuẩn: không tự thu hẹp chuẩn, để exec-acc báo không so được
    specs, _ = g0c.pivot_reference_specs(rule, catalog, columns, {"channel": SYSMON, "event_ids": [1, 3]},
                                         _pivot("may", "UTICA"))
    assert specs == []
    with pytest.raises(Exception):
        g0c.pivot_reference_specs(rule, catalog, columns - {"User"}, scope, _pivot("tai_khoan", "dschrute"))
