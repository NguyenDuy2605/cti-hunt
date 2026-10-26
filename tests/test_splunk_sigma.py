"""D14: kiểm chuyển đổi thực bằng backend trên rule tổng hợp, không dùng log/nhãn."""
from pathlib import Path

import pytest

pytest.importorskip("sigma.backends.splunk")

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.splunk import splunk_windows_pipeline

from cti_hunt.adapters.splunk_sigma import check_paths, convert_rule


RULE = """\
title: D14 synthetic process rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\tool.exe'
    ParentImage|endswith: '\\parent.exe'
    CommandLine|contains: test-marker
    User: test-user
    EventID: 1
  condition: selection
"""


def test_identity_pipeline_preserves_otrf_fields(tmp_path: Path):
    path = tmp_path / "synthetic.yml"
    path.write_text(RULE, encoding="utf-8")
    spl = convert_rule(path)[0]
    for field in ("Image", "ParentImage", "CommandLine", "User", "EventID"):
        assert field in spl
    assert "EventCode" not in spl


def test_builtin_windows_pipeline_maps_eventid_only():
    collection = SigmaCollection.from_yaml(RULE)
    spl = SplunkBackend(processing_pipeline=splunk_windows_pipeline()).convert(collection)[0]
    for field in ("Image", "ParentImage", "CommandLine", "User"):
        assert field in spl
    assert "EventCode" in spl
    assert "EventID" not in spl


def test_batch_reports_conversion_errors_without_stopping(tmp_path: Path):
    (tmp_path / "ok.yml").write_text(RULE, encoding="utf-8")
    (tmp_path / "bad.yml").write_text("not: a sigma rule\n", encoding="utf-8")
    result = check_paths([tmp_path])
    assert (result["converted"], result["failed"]) == (1, 1)
    assert [rule["status"] for rule in result["rules"]] == ["error", "ok"]
    assert result["rules"][0]["reason"]


def test_batch_refuses_label_path(tmp_path: Path, monkeypatch):
    labels = tmp_path / "data" / "labels"
    labels.mkdir(parents=True)
    secret = labels / "secret.yml"
    secret.write_text("do not read", encoding="utf-8")
    original_read_text = Path.read_text

    def guarded_read_text(path, *args, **kwargs):
        if path == secret:
            raise AssertionError("read label file")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    result = check_paths([tmp_path])
    assert result["converted"] == 0
    assert result["failed"] == 1
    assert result["rules"][0]["reason"].startswith("refused")
