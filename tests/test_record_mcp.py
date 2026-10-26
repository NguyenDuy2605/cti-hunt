import json

import pytest

from cti_hunt import config, record_mcp
from cti_hunt.record_store import RecordStore


def test_real_record_lookup_and_mcp_read_only_guards(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    root = tmp_path / "data/dev"
    folder = root / "completed"
    folder.mkdir(parents=True)
    record = {"kind": "development_only_unlabeled", "report_id": "SYNTHETIC", "executed_specs": [{}]}
    (folder / "agent_dev_record.json").write_text(json.dumps(record), encoding="utf-8")
    (folder / "hunt_record.md").write_text("# Synthetic\nT1059.001", encoding="utf-8")
    store = RecordStore(root)
    assert store.find(technique="T1059") == []
    assert store.find(technique="T1059.001")[0]["executed_hunts"] == 1
    assert store.find(report="other") == []
    def call(name, args):
        return record_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}}, store)["result"]
    result = call("doc_hunt_record", {"record_id": "completed"})
    assert not result["isError"]
    assert json.loads(result["content"][0]["text"])["record"] == record
    assert call("doc_hunt_record", {"record_id": "../../labels"})["isError"]
    assert call("execute_hunt", {})["isError"]
    assert call("tra_hunt_memory", {"technique": "T1059x"})["isError"]
    assert record_mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, store) is None
    with pytest.raises(ValueError):
        RecordStore(tmp_path / "data/labels")
    (folder / "agent_dev_record.json").write_text('{"kind":"evaluation"}', encoding="utf-8")
    assert store.find() == []
