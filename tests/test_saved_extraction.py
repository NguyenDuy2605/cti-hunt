import json
from pathlib import Path

import pytest

from cti_hunt import config, demo, integrity, saved_extraction
from cti_hunt.contracts import ContractA, SourceSpan, TTP

QUOTE = "The actor used WMI to execute a process."


def sources(tmp_path, *, quote=QUOTE, unread=False):
    source = tmp_path / "source.html"
    source.write_text(f"<article><p>{quote}</p>" + ("<img src='unread.png'>" if unread else "") + "</article>",
                      encoding="utf-8")
    bundle = demo.ingest(str(source), "UPLOADED", root=tmp_path / "reports")
    original = tmp_path / "saved"
    original.mkdir()
    old = original / "segments.jsonl"
    old.write_text(json.dumps({"report": "ORIGINAL", "ma_doan": "ORIGINAL-001", "loai": "đoạn văn",
                               "van_ban": QUOTE}) + "\n", encoding="utf-8")
    contract = original / "contract_a_ORIGINAL.json"
    contract.write_text(ContractA(report_id="ORIGINAL", ttps=[TTP(tactic="execution", technique_id="T1047",
                          source_span=SourceSpan(segment_id="ORIGINAL-001", text=QUOTE))]).model_dump_json(indent=2),
                        encoding="utf-8")
    metadata = original / "meta.json"
    metadata.write_text(json.dumps({"xong_luc": "2026-09-25T16:36:01", "segments_sha256": integrity.sha256_file(old),
                                   "log": {"ORIGINAL": {"so_muc_giu": 1, "su_co": {"lo_that_bai": []}}}}),
                        encoding="utf-8")
    entry = {"title": "Saved synthetic extraction", "contract": contract, "metadata": metadata, "segments": old}
    entry.update({f"{key}_sha256": integrity.sha256_file(entry[key]) for key in saved_extraction.SNAPSHOTS})
    return bundle, entry


def test_reuse_preserves_entire_contract_and_inputs_and_survives_removed_originals(tmp_path):
    bundle, entry = sources(tmp_path, quote="The actor used WMI to execute a\nprocess.")
    before = {key: Path(entry[key]).read_bytes() for key in saved_extraction.SNAPSHOTS}
    prepared = bundle / "extractions/extract_prepared/meta.json"
    prepared.parent.mkdir(parents=True)
    prepared.write_text('{"status":"prepared"}', encoding="utf-8")
    out = demo.reuse_saved(bundle, entry)
    assert demo.verified_contract(bundle, out).read_bytes() == before["contract"]
    assert {key: Path(entry[key]).read_bytes() for key in saved_extraction.SNAPSHOTS} == before
    assert prepared.read_text() == '{"status":"prepared"}'
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["report_id"] == "ORIGINAL" and meta["bundle_report_id"] == "UPLOADED"
    assert meta["api_called"] is False
    assert meta["source_bindings"] == [{"ttp_ref": 0, "original_segment_id": "ORIGINAL-001",
                                       "current_segment_ids": ["UPLOADED-0001"]}]
    for key in saved_extraction.SNAPSHOTS:
        Path(entry[key]).unlink()
    assert demo.verified_contract(bundle, out).read_bytes() == before["contract"]


@pytest.mark.parametrize("key", list(saved_extraction.SNAPSHOTS))
def test_changed_saved_input_rejected_before_any_output_is_created(tmp_path, key):
    bundle, entry = sources(tmp_path)
    Path(entry[key]).write_bytes(b"changed")
    out = bundle / "extractions/new"
    with pytest.raises(ValueError, match="hash"):
        saved_extraction.import_saved(bundle, out, entry)
    assert not out.exists()


@pytest.mark.parametrize("quote", ["Different article about ordinary processes.", QUOTE.upper(),
                                  "The actor used WMI to execute a process!", ""])
def test_wrong_report_or_changed_characters_never_match(tmp_path, quote):
    bundle, entry = sources(tmp_path, quote=quote)
    out = bundle / "extractions/new"
    with pytest.raises(ValueError, match="không khớp chữ"):
        saved_extraction.import_saved(bundle, out, entry)
    assert not out.exists()


@pytest.mark.parametrize("change", ["unfinished", "wrong_segment_hash", "failed_batch", "wrong_original_report",
                                  "missing_original_quote", "changed_binding", "changed_snapshot"])
def test_source_proof_cannot_be_bypassed(tmp_path, change):
    bundle, entry = sources(tmp_path)
    if change in ("changed_binding", "changed_snapshot"):
        out = demo.reuse_saved(bundle, entry)
        if change == "changed_binding":
            path = out / "meta.json"
            meta = json.loads(path.read_text(encoding="utf-8"))
            meta["source_bindings"][0]["current_segment_ids"] = ["OTHER-001"]
            path.write_text(json.dumps(meta), encoding="utf-8")
        else:
            (out / "original_segments.jsonl").write_text("changed", encoding="utf-8")
        with pytest.raises(ValueError):
            demo.verified_contract(bundle, out)
        return
    meta = json.loads(Path(entry["metadata"]).read_text(encoding="utf-8"))
    if change == "unfinished":
        meta.pop("xong_luc")
    elif change == "wrong_segment_hash":
        meta["segments_sha256"] = "0" * 64
    elif change == "failed_batch":
        meta["log"]["ORIGINAL"]["su_co"]["lo_that_bai"] = [0]
    else:
        row = json.loads(Path(entry["segments"]).read_text(encoding="utf-8"))
        row["report" if change == "wrong_original_report" else "van_ban"] = "OTHER"
        Path(entry["segments"]).write_text(json.dumps(row), encoding="utf-8")
        meta["segments_sha256"] = integrity.sha256_file(entry["segments"])
    Path(entry["metadata"]).write_text(json.dumps(meta), encoding="utf-8")
    entry.update({f"{key}_sha256": integrity.sha256_file(entry[key]) for key in saved_extraction.SNAPSHOTS})
    out = bundle / "extractions/new"
    with pytest.raises(ValueError):
        saved_extraction.import_saved(bundle, out, entry)
    assert not out.exists()


def test_streamlit_prepared_to_saved_extraction_coverage_and_dry_run(tmp_path, work, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from cti_hunt.agent import dev_data
    from cti_hunt.llm import providers
    app = config.ROOT / "app/streamlit_app.py"
    ui_root = tmp_path / "ui"
    bundle, entry = sources(tmp_path, unread=True)
    entry["source_title_contains"] = "UPLOADED"
    target = ui_root / "data/reports/moi/UPLOADED"
    target.parent.mkdir(parents=True)
    bundle.rename(target)
    prepared = target / "extractions/extract_prepared/meta.json"
    prepared.parent.mkdir(parents=True)
    prepared.write_text('{"status":"prepared","api_called":false}', encoding="utf-8")
    events = ui_root / "data/dev/otrf-fixture"
    events.parent.mkdir(parents=True)
    work.rename(events)
    (events / "ingest_manifest.json").write_text('{}', encoding="utf-8")
    monkeypatch.setattr(config, "ROOT", ui_root)
    monkeypatch.setattr(demo, "saved_options", lambda: {"synthetic": entry})
    monkeypatch.setattr(demo, "dataset", lambda folder: {"dataset_id": "fixture", "source_sha256": "0" * 64})
    monkeypatch.setattr(dev_data, "check_manifest", lambda *a, **kw: None)
    load_cfg = config.agent_config
    def isolated_config(version="v1", root=app.parents[1]):
        cfg = load_cfg(version, root)
        cfg["memory_root"] = str(ui_root / "data/dev/empty_memory")
        return cfg
    monkeypatch.setattr(config, "agent_config", isolated_config)
    class NoAPI:
        model_id = "mock"
        def describe(self): return {"model": "mock"}
        def complete_json(self, *a, **kw): raise AssertionError("API must never be called")
    monkeypatch.setattr(providers, "from_config", lambda cfg: NoAPI())
    at = AppTest.from_file(str(app), default_timeout=30).run()
    def field(kind, label):
        return next(x for x in getattr(at, kind) if x.label == label)
    field("selectbox", "Lượt trích").select(prepared.parent).run()
    assert not at.exception and not at.error
    assert field("button", "Đối chiếu telemetry").disabled
    assert field("button", "Bắt đầu lượt săn mới").disabled
    assert any("mới chuẩn bị" in x.value for x in at.info)
    field("checkbox", "Chỉ chuẩn bị prompt, chưa gọi API").uncheck().run()
    assert field("button", "Chạy / tiếp tục trích TTP").disabled
    field("button", "Dùng kết quả trích đã lưu").click().run()
    assert not at.exception and not at.error
    out = field("selectbox", "Lượt trích").value
    assert out != prepared.parent
    assert demo.verified_contract(target, out).read_bytes() == Path(entry["contract"]).read_bytes()
    assert field("button", "Chạy / tiếp tục trích TTP").disabled
    assert field("button", "Đối chiếu telemetry").disabled  # Unread-image acknowledgement remains required.
    field("checkbox", "Tôi đã rà và chấp nhận phần chưa đọc/cảnh báo").check().run()
    field("button", "Đối chiếu telemetry").click().run()
    assert not at.exception and not at.error
    assert any("Đối chiếu v2" in x.value for x in at.caption)
    field("selectbox", "Chế độ").select("agent").run()
    field("button", "Bắt đầu lượt săn mới").click().run()
    assert not at.exception and not at.error
    assert any('"dry_run"' in x.value and '"goi_api": false' in x.value for x in at.json)
    assert not list(out.glob("hunts/run_*/run_meta.json"))
    assert json.loads(prepared.read_text())["status"] == "prepared"
    # Saved binding is persisted; only acknowledgement is a new-session choice.
    at = AppTest.from_file(str(app), default_timeout=30).run()
    field("selectbox", "Lượt trích").select(out).run()
    field("checkbox", "Tôi đã rà và chấp nhận phần chưa đọc/cảnh báo").check().run()
    field("button", "Đối chiếu telemetry").click().run()
    assert not at.exception and not at.error
