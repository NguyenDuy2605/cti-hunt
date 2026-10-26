"""Query breadth is an advisory signal on synthetic, unlabeled data only."""
import json

import pytest

from cti_hunt import demo, config, integrity
from cti_hunt.contracts import ContractA
from cti_hunt.data.store import connect
from cti_hunt.hunt.breadth import summarize, from_observation
from cti_hunt.hunt.observe import run_unlabeled
from cti_hunt.report_cli import coverage


@pytest.mark.parametrize("scope,hits,broad", [(0, 0, False), (1, 1, True), (100, 94, False),
                                           (100, 95, True), (100, 100, True)])
def test_breadth_boundary_and_empty_scope(scope, hits, broad):
    result = summarize(scope, hits)
    assert result["broad"] is broad
    assert result["ratio"] == (hits / scope if scope else None)


@pytest.mark.parametrize("scope,hits", [(-1, 0), (1, 2), (True, 1), (1, -1), (1.5, 1)])
def test_bad_counts_do_not_become_a_quality_signal(scope, hits):
    with pytest.raises(ValueError):
        summarize(scope, hits)


def test_scope_uses_channel_and_breadth_keeps_original_results(work):
    con = connect(work)
    spec = {"id": "SYN", "scope": {"channel": "microsoft-windows-sysmon/operational", "event_ids": [1]},
            "candidates": "TRUE", "filters": []}
    try:
        observed = run_unlabeled(con, spec)
        before = json.dumps(observed)
        assert from_observation(observed) == {"hunt_id": "SYN", "scope": 5, "candidates": 5,
                                              "ratio": 1.0, "broad": True, "remaining": 5}
        assert json.dumps(observed) == before
        assert run_unlabeled(con, spec) == observed
    finally:
        con.close()


def test_ui_coverage_uses_same_version_catalog_as_session(work):
    ca = ContractA(report_id="SYN", title="synthetic")
    for version in ("v1", "v2"):
        result = coverage(ca, work, version=version)
        assert result["phien_ban"] == version
        assert result["catalog_sha256"] == integrity.sha256_file(config.telemetry_catalog(version))
        from cti_hunt.stages.s3_telemetry import load_catalog
        assert set(result["profile"]["ky_thuat"]) == set(load_catalog(config.telemetry_catalog(version)))
    with pytest.raises(ValueError):
        coverage(ca, work, version="unknown")


def test_report_coverage_cli_accepts_v2_and_records_its_catalog(tmp_path, work):
    from cti_hunt.cli import main
    contract, output = tmp_path / "contract.json", tmp_path / "coverage.json"
    contract.write_text(ContractA(report_id="SYN").model_dump_json(), encoding="utf-8")
    assert main(["report-coverage", str(contract), "--events", str(work),
                 "--out", str(output), "--phien-ban", "v2"]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["phien_ban"] == "v2"
    assert result["catalog_sha256"] == integrity.sha256_file(config.telemetry_catalog("v2"))


def test_result_summary_reads_all_rounds_and_preserves_saved_bytes(tmp_path):
    paths = []
    for i, hits in enumerate((10, 1), 1):
        folder = tmp_path / f"round_{i:02d}"
        folder.mkdir()
        path = folder / "agent_execute.json"
        path.write_text(json.dumps({"observations": [{"hunt_id": f"SYN-H{i}",
            "stages": [{"stage": "pham_vi", "hits": 10}, {"stage": "ung_vien", "hits": hits},
                       {"stage": "sau_F1", "hits": 0}]}]}), encoding="utf-8")
        paths.append(path)
    before = [p.read_bytes() for p in paths]
    summary = demo.result_summary(tmp_path)
    assert [r["broad"] for r in summary["hunts"]] == [True, False]
    assert [r["remaining"] for r in summary["hunts"]] == [0, 0]
    assert summary["decisions"] == []
    assert before == [p.read_bytes() for p in paths]


def test_filter_ui_warns_before_review_without_changing_packet(tmp_path, work):
    from streamlit.testing.v1 import AppTest
    from cti_hunt import filter_approval as filters
    from cti_hunt.adapters.duckdb_sigma import compile_text, load_catalog
    con = connect(work)
    root = tmp_path / "run"
    rd = root / "round_01/filter_review/r01"
    rule = """title: Synthetic broad rule
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '.exe'
  filter_example:
    Image|endswith: 'notepad.exe'
  condition: selection and not filter_example
"""
    try:
        catalog = load_catalog(config.resolve(config.load("dataset")["logsource_catalog"]))
        specs = [r.to_hunt_spec() for r in compile_text(rule, catalog, filter_policy=filters.POLICY)[0]]
        filters.bind(con, root)
        filters.prepare(con, specs, root, rd)
    finally:
        con.close()
    original = {p.name: p.read_bytes() for p in rd.iterdir() if p.is_file()}
    app = tmp_path / "preview_app.py"
    app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import filter_form\n"
                   f"filter_form(Path({str(rd)!r}), Path({str(root)!r}))\n", encoding="utf-8")
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception and not at.error
    assert any("5/5" in w.value and "≥95%" in w.value for w in at.warning)
    assert all(x.value == "" for x in at.selectbox if x.label == "Quyết định")
    assert original == {p.name: p.read_bytes() for p in rd.iterdir() if p.is_file()}
    assert not (root / "hunt_record.md").exists()


def test_coverage_table_shows_sources_and_evidence_as_text_without_changing_result():
    rows = [{"technique_id": "T1047", "status": "huntable", "mapping_kind": "exact",
             "sources": [{"channel": "microsoft-windows-sysmon/operational", "event_ids": [1],
                          "key_fields": ["Image", "ParentImage"], "truong_bat_buoc": ["Image"]},
                         {"channel": "microsoft-windows-wmi-activity/operational", "event_ids": [5857, 5861],
                          "key_fields": [], "truong_bat_buoc": []}],
             "reason": "r", "review_note": "",
             "evidence": [{"section": "s", "page": 0, "text": "spawn via WMI", "segment_id": "SYN-0001"},
                          {"section": "s", "page": 0, "text": "no id", "segment_id": None}]},
            {"technique_id": "T9999", "status": "not_huntable", "mapping_kind": "catalog_gap",
             "sources": [], "reason": "", "review_note": "gap", "evidence": []}]
    before = json.dumps(rows)
    table = demo.coverage_table(rows)
    assert json.dumps(rows) == before
    assert all(isinstance(r["sources"], str) and isinstance(r["evidence"], str) for r in table)
    assert table[0]["sources"] == ("microsoft-windows-sysmon/operational · EID 1 · trường: Image, ParentImage ; "
                                   "microsoft-windows-wmi-activity/operational · EID 5857, 5861")
    assert table[0]["evidence"] == "SYN-0001: “spawn via WMI” ; không có mã đoạn: “no id”"
    assert table[1]["sources"] == "" and table[1]["evidence"] == ""
    assert [{k: v for k, v in r.items() if k not in ("sources", "evidence")} for r in table] == \
           [{k: v for k, v in r.items() if k not in ("sources", "evidence")} for r in rows]
