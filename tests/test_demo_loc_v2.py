"""Synthetic historical packets: verify links without executing SQL, graph or API."""
import json
from pathlib import Path
import sys

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import chuan_bi_demo_loc_v2 as packet
import ra_ho_so_tuyen_a as audit
from cti_hunt.filter_approval import _rows, digest


@pytest.fixture
def historical(tmp_path, monkeypatch):
    monkeypatch.setattr(packet, "ROOT", tmp_path)
    monkeypatch.setattr(audit, "ROOT", tmp_path)
    # Hypothesis gate has its own existing tests. This fixture isolates filter links.
    monkeypatch.setattr(packet, "verify_saved_review", lambda _: None)
    base = tmp_path / "data/dev/fixture"
    rnd = base / "round_01"
    review = rnd / "filter_review/r01"
    def write(path, data, as_yaml=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, allow_unicode=True) if as_yaml else
                        json.dumps(data, ensure_ascii=False), encoding="utf-8")
    for name in ("hypotheses.json", "duyet.yaml", "hypotheses_da_duyet.json", "approval_log.json"):
        write(rnd / name, [{"hypothesis_id": "SYNTHETIC-H01", "status": "approved"}])
    draft = {"id": "SYNTHETIC", "hypothesis_id": "SYNTHETIC-H01", "scope": {"channel": "security", "event_ids": [4698]},
             "candidates": "EventID=4698", "filters": [
                 {"id": "S-01", "where": "TaskName='synthetic1'", "bieu_thuc_sigma": "synthetic1",
                  "selectors": ["synthetic1"], "ly_do": "Synthetic proposal"},
                 {"id": "S-02", "where": "TaskName='synthetic2'", "bieu_thuc_sigma": "synthetic2",
                  "selectors": ["synthetic2"], "ly_do": "Synthetic proposal"}]}
    manifest = {"specs": [draft], "events": {"sha256": "a" * 64}}
    write(review / "manifest.json", manifest)
    choices = _rows(manifest)
    for row in choices:
        row.update(quyet_dinh="approved", ly_do="Synthetic review", can_cu="Fixture only",
                   nguoi_chiu_trach_nhiem="synthetic tester", hieu_luc_den_utc="2026-01-01T00:00:00Z")
    form = {"manifest_sha256": packet.sha(review / "manifest.json"), "nguoi_duyet": "synthetic tester", "muc_loc": choices}
    write(review / "duyet_loc.yaml", form, True)
    log = {"manifest_sha256": form["manifest_sha256"], "phieu_sha256": packet.sha(review / "duyet_loc.yaml"),
           "nguoi_duyet": form["nguoi_duyet"], "quyet_dinh": choices}
    write(review / "approval_log.json", log)
    spec = json.loads(json.dumps(draft))
    spec["filter_phase"] = "effective"
    for f, row in zip(spec["filters"], choices):
        f.update(status="approved", het_han=row["hieu_luc_den_utc"])
    specpath = rnd / "hunts_effective/r01/hunt_000.yaml"
    write(specpath, spec, True)
    effective = {"manifest_sha256": form["manifest_sha256"], "approval_log_sha256": packet.sha(review / "approval_log.json"),
                 "files": {str(specpath): packet.sha(specpath)}}
    write(review / "effective_manifest.json", effective)
    write(review / "execution_receipt.json", {"kind": "completed_execution", "executed_at_utc": "2025-12-01T00:00:00Z",
                                               "effective_manifest_sha256": packet.sha(review / "effective_manifest.json")})
    imported = {"operator": "synthetic tester", "license_checked": True, "events_sha256": "a" * 64}
    importpath = base / "splunk_goi_nap/import/import_manifest.confirmed.json"
    write(importpath, imported)
    stages = [{"stage": name, "duck_count": n, "splunk_count": n, "intersection": n, "jaccard": 1,
               "only_duckdb": [], "only_splunk": [], "status": "compared"}
              for name, n in (("ung_vien", 3), ("sau_S-01", 2), ("sau_S-02", 1))]
    import hashlib
    comparison = {"events_sha256": "a" * 64,
                  "import_manifest_sha256": hashlib.sha256(json.dumps(imported, sort_keys=True).encode()).hexdigest(),
                  "rules": [{"rule_sha256": digest(spec), "results": stages}]}
    write(base / "splunk_compare_01/comparison.json", comparison)
    write(base / "splunk_compare_01/plan.json", {})
    post = {"stages": stages, "api_llm_called": False, "sha256": {
        "comparison.json": packet.sha(base / "splunk_compare_01/comparison.json"),
        "plan.json": packet.sha(base / "splunk_compare_01/plan.json"),
        "import_manifest.confirmed.json": packet.sha(importpath)}}
    write(base / "post_splunk_verification.json", post)
    write(rnd / "agent_execute.json", {"observations": [{"stages": [{"stage": "pham_vi", "hits": 3}] +
        [{"stage": s["stage"], "hits": s["duck_count"]} for s in stages]}]})
    (rnd / "rules_draft").mkdir()
    (rnd / "rules_draft/DEV-SCHTASKS-H01.yml").write_text("title: synthetic mock", encoding="utf-8")
    (base / "hunt_record.md").write_text("Synthetic historical record", encoding="utf-8")
    return base, review, write


def test_historical_receipt_is_readable_after_expiry_without_execution(historical, monkeypatch):
    base, _, _ = historical
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("No network allowed"))
    ev = audit.Evidence()
    result = packet.filter_evidence(ev, base)
    assert result["historical_only"] and result["rule_origin"] == "mock"
    assert [r["duck_count"] for r in result["stages"]] == [3, 2, 1]
    ev.unchanged()


def test_changed_filter_form_is_rejected(historical):
    base, review, _ = historical
    with (review / "duyet_loc.yaml").open("a", encoding="utf-8") as stream:
        stream.write("\n# changed\n")
    with pytest.raises(ValueError, match="Phiếu lọc đã đổi"):
        packet.filter_evidence(audit.Evidence(), base)


def test_receipt_from_another_packet_is_rejected(historical):
    base, review, write = historical
    write(review / "execution_receipt.json", {"kind": "completed_execution", "effective_manifest_sha256": "0" * 64})
    with pytest.raises(ValueError, match="Biên nhận không khớp"):
        packet.filter_evidence(audit.Evidence(), base)


def test_consistent_comparison_hash_cannot_hide_different_counts(historical):
    base, _, write = historical
    path = base / "splunk_compare_01/comparison.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rules"][0]["results"][0]["duck_count"] = 99
    write(path, data)
    postpath = base / "post_splunk_verification.json"
    post = json.loads(postpath.read_text(encoding="utf-8"))
    post["sha256"]["comparison.json"] = packet.sha(path)
    write(postpath, post)
    with pytest.raises(ValueError, match="Số đếm khác nhật ký"):
        packet.filter_evidence(audit.Evidence(), base)
