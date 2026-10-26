import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from cti_hunt import approval, config, demo, integrity
from cti_hunt.agent import session
from cti_hunt.contracts import TTP, SourceSpan
from cti_hunt.data.store import connect
from cti_hunt.llm import providers
from cti_hunt.stages import s1_ingest, s2_report, s2_ioc

_CAN_STIX = pytest.mark.skipif(not (config.ROOT / "data" / "attack" / "enterprise-attack-19.2.json").exists(),
                               reason="chưa có file STIX v19.2 trong data/attack")

QUOTE = "The actor used WMI to execute a process."


@pytest.mark.parametrize("name", ["../../..", "..", "x/y", "x\\y", "C:\\Windows", "", ".hidden"])
def test_report_paths_reject_escape_before_touching_files(tmp_path, name):
    with pytest.raises(ValueError):
        demo.report_folder(name, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_ingest_same_id_preserves_old_artifacts(tmp_path):
    source = tmp_path / "source.html"
    source.write_text(f"<article><p>{QUOTE}</p></article>", encoding="utf-8")
    root = tmp_path / "reports"
    bundle = demo.ingest(str(source), "NEW", root=root)
    proof = bundle / "duyet.yaml"
    proof.write_text("approved: historic", encoding="utf-8")
    before = {p.name: p.read_bytes() for p in bundle.iterdir()}
    with pytest.raises(ValueError, match="đã tồn tại"):
        demo.ingest(str(source), "NEW", root=root)
    assert before == {p.name: p.read_bytes() for p in bundle.iterdir()}


def test_confidence_bounds_local_and_transport_preserves_source_schema():
    for value in (-1, 2, float('nan'), float('inf')):
        with pytest.raises(ValidationError):
            TTP(tactic="Execution", technique_id="T1047", source_span=SourceSpan(), confidence=value)
    schema = s2_report.GroundedBatch.model_json_schema()
    sent = providers.strict_schema(schema)
    original = schema["$defs"]["GroundedItem"]["properties"]["confidence"]
    outgoing = sent["$defs"]["GroundedItem"]["properties"]["confidence"]
    assert original["minimum"] == 0 and original["maximum"] == 1
    assert "minimum" not in outgoing and "maximum" not in outgoing
    assert '"maximum": 1' in outgoing["description"]
    assert schema == s2_report.GroundedBatch.model_json_schema()


def test_sql_preserves_scope_and_null_safe_exclusions(work):
    con = connect(work)
    spec = {"scope": {"channel": "microsoft-windows-sysmon/operational", "event_ids": [1]},
            "candidates": "TRUE", "filters": [{"id": "f", "where": "Image ILIKE '%svchost.exe'",
                "ly_do": "fixture", "nguoi_chiu_trach_nhiem": "tester", "het_han": "fixture"}]}
    statements = demo.sql_stages(spec)
    counts = [len(con.execute(s["sql"]).fetchall()) for s in statements]
    assert counts == [5, 4]
    assert "IS NOT TRUE" in statements[-1]["sql"]
    assert "ev_eid IN (1)" in statements[0]["sql"]
    con.close()


class Scripted:
    model_id = "mock"

    def __init__(self):
        self.rule = (config.ROOT / "hunts/sigma/H-03.yml").read_text(encoding="utf-8")

    def describe(self):
        return {"model": "mock"}

    def complete_json(self, system, user, json_schema, log=None):
        if json_schema["title"] == "_PlannerOutput":
            view = json.loads(user.split("Current safe planning context:", 1)[1].split("Return JSON", 1)[0])
            refs = view["remaining_refs"]
            return {"action": "hunt" if refs else "stop", "ttp_refs": refs[:1], "pivot_targets": [],
                    "reason": "synthetic next technique" if refs else "synthetic exhausted techniques"}
        if json_schema["title"] == "LLMRule":
            return {"rule_yaml": self.rule}
        return {"items": [{"ttp_refs": [0], "behavior": "Tiến trình con qua WMI",
            "scope": "mọi máy", "timeframe": "toàn bộ log",
            "data_source": "microsoft-windows-sysmon/operational", "event_ids": [1],
            "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}]}


def extracted_bundle(tmp_path):
    source = tmp_path / "report.html"
    source.write_text(f"<article><p>{QUOTE}</p></article>", encoding="utf-8")
    bundle = tmp_path / "bundle"
    s1_ingest.ingest(str(source), "FIXTURE", bundle)
    client = providers.MockClient(responses=[{"items": [{"segment_id": "FIXTURE-0001", "quote": QUOTE,
        "technique_id": "T1047", "tactic": "execution", "behavior_description": "WMI process execution",
        "rationale": "Explicit WMI process execution", "outside_candidates_reason": "Explicit behavior"}]}])
    out = bundle / "extraction"
    s2_report.run(bundle, config.resolve(config.load("reports")["attack"]["stix_path"]),
                  config.resolve("prompts/report_extract_v1.md"), {"provider": "mock", "model": "test"}, out,
                  s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml")), send=True, llm=client)
    return bundle, out


@_CAN_STIX
def test_ui_service_report_to_checkpoint_review_execution_and_record(tmp_path, work, monkeypatch):
    bundle, extraction = extracted_bundle(tmp_path)
    monkeypatch.setattr(providers, "from_config", lambda cfg: Scripted())
    # Synthetic fixture only: bypass OTRF source attestation, not the graph/approval/SQL.
    monkeypatch.setattr(demo, "dataset", lambda folder: {"dataset_id": "fixture", "source_sha256": "0" * 64})
    from cti_hunt.agent import dev_data
    monkeypatch.setattr(dev_data, "check_manifest", lambda *a, **kw: None)
    run = tmp_path / "hunt"
    result = demo.start(bundle, extraction, work, run, mode="pipeline", dry_run=False)
    assert result["trang_thai"] == "cho_duyet"
    assert session.inspect(run)["trang_thai"] == "cho_duyet"
    assert not (run / "hunt_record.md").exists()
    with pytest.raises(session.SessionError, match="chưa có quyết định"):
        session.resume(run)
    review = Path(result["review_dir"])
    form_path = review / approval.REVIEW_FILE
    sha = integrity.sha256_file(form_path)
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    decisions = {r["id"]: {"quyet_dinh": "approved", "ly_do": "synthetic test"} for r in form["gia_thuyet"]}
    with pytest.raises(approval.ReviewError):
        approval.save_decisions(review, "", decisions, sha)
    assert integrity.sha256_file(form_path) == sha
    approval.save_decisions(review, "fixture tester", decisions, sha)
    with pytest.raises(approval.ReviewError, match="thay đổi"):
        approval.save_decisions(review, "fixture tester", decisions, sha)
    assert session.resume(run)["trang_thai"] == "xong"
    assert session.inspect(run)["trang_thai"] == "xong"
    record = json.loads((run / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert record["executed_specs"] and record["observations"] and record["rarity_summary"]
    assert record["history"][-1]["decision"]["action"] == "stop"
    assert (run / "hunt_record.md").exists()
    assert "mau_so_fpr" not in json.dumps(record)
    (bundle / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        demo.verified_contract(bundle, extraction)


@_CAN_STIX
@pytest.mark.parametrize('version', ['v1', 'v2'])
@pytest.mark.parametrize('mode', ['pipeline', 'agent'])
def test_streamlit_clicks_report_extraction_review_and_hunt_record(tmp_path, work, monkeypatch, version, mode):
    """Real Streamlit actions and graph/SQL; synthetic report/logs, model replies mocked."""
    from streamlit.testing.v1 import AppTest
    from cti_hunt import demo_app
    from cti_hunt.agent import dev_data
    app_path = config.ROOT / "app/streamlit_app.py"
    scripted = Scripted()
    grounded = providers.MockClient(responses=[{"items": [{"segment_id": "FIXTURE-0001", "quote": QUOTE,
        "technique_id": "T1047", "tactic": "execution", "behavior_description": "WMI process execution",
        "rationale": "Explicit WMI process execution", "outside_candidates_reason": "Explicit behavior"}]}])
    class Client:
        model_id = "mock"
        def describe(self): return {"model": "mock"}
        def complete_json(self, system, user, json_schema, log=None):
            target = grounded if json_schema["title"] == "GroundedBatch" else scripted
            return target.complete_json(system, user, json_schema, log=log)
    ui_root = tmp_path / "ui"
    events = ui_root / "data/dev/otrf-fixture"
    events.parent.mkdir(parents=True)
    work.rename(events)
    (events / "ingest_manifest.json").write_text('{}', encoding="utf-8")
    monkeypatch.setattr(config, "ROOT", ui_root)
    # Empty synthetic memory stays inside the isolated UI root; keep the real path guard.
    load_agent_config = config.agent_config
    def fixture_agent_config(version="v1", root=app_path.parents[1]):
        cfg = load_agent_config(version, root)
        cfg["memory_root"] = str(ui_root / "data/dev/fixture_memory")
        return cfg
    monkeypatch.setattr(config, "agent_config", fixture_agent_config)
    monkeypatch.setattr(providers, "from_config", lambda cfg: Client())
    monkeypatch.setattr(demo_app, "api_key", lambda: None)
    monkeypatch.setattr(demo, "dataset", lambda folder: {"dataset_id": "fixture", "source_sha256": "0" * 64})
    monkeypatch.setattr(dev_data, "check_manifest", lambda *a, **kw: None)
    # Rào ngân sách vẫn phải được gọi, nhưng không đọc sổ thật của repo (config.resolve giữ ROOT gốc).
    from cti_hunt.llm import budget
    guard = []
    monkeypatch.setattr(budget.Ledger, "require_ready", lambda self: guard.append(self.path.name))
    source = tmp_path / "source.html"
    source.write_text(f"<article><p>{QUOTE}</p></article>", encoding="utf-8")
    at = AppTest.from_file(str(app_path), default_timeout=30).run()
    def field(kind, label):
        return next(x for x in getattr(at, kind) if x.label == label)
    field("text_input", "Mã report mới").set_value("FIXTURE")
    field("text_input", "URL report (hoặc tải file bên dưới)").set_value(str(source))
    field("button", "Nhập report mới").click().run()
    assert not at.exception
    assert any(QUOTE in t.value for t in at.text)
    bundle = ui_root / "data/reports/moi/FIXTURE"
    # H2: cost appears before the first extraction, with no API call or output folder.
    assert any("Ước tính khâu ②" in info.value and "USD" in info.value for info in at.info)
    assert not grounded.calls and not (bundle / "extractions").exists()
    source_hash = integrity.sha256_file(bundle / "manifest.json")
    field("button", "Nhập report mới").click().run()
    assert any("đã tồn tại" in e.value for e in at.error)
    assert integrity.sha256_file(bundle / "manifest.json") == source_hash
    field("checkbox", "Chỉ chuẩn bị prompt, chưa gọi API").uncheck()
    field("button", "Chạy / tiếp tục trích TTP").click().run()
    assert not at.exception and not at.error and guard
    extraction = next((bundle / "extractions").glob("extract_*"))
    assert field("selectbox", "Lượt trích").value == extraction
    assert not at.error
    field("selectbox", "Phiên bản hệ thống").select(version).run()
    field("button", "Đối chiếu telemetry").click().run()
    assert not at.exception and not at.error
    assert any(f"Đối chiếu {version}" in c.value for c in at.caption)
    other_version = "v1" if version == "v2" else "v2"
    field("selectbox", "Phiên bản hệ thống").select(other_version).run()
    assert not any(f"Đối chiếu {version}" in c.value for c in at.caption)
    field("selectbox", "Phiên bản hệ thống").select(version).run()
    assert any(f"Đối chiếu {version}" in c.value for c in at.caption)
    field("selectbox", "Chế độ").select(mode).run()
    assert any(f"Đối chiếu {version}" in c.value for c in at.caption)
    field("checkbox", "Kiểm tra trước, chưa gọi API sinh giả thuyết").uncheck()
    field("button", "Bắt đầu lượt săn mới").click().run()
    assert not at.exception and not at.error, [e.value for e in at.error]
    run = next((extraction / "hunts").glob("run_*"))
    assert field("selectbox", "Lượt săn đã lưu").value == run
    # Re-open while paused: decisions and continuation belong to the saved checkpoint.
    at = AppTest.from_file(str(app_path), default_timeout=30).run()
    field("selectbox", "Lượt trích").select(extraction).run()
    field("selectbox", "Lượt săn đã lưu").select(run).run()
    assert not at.exception and not at.error
    assert any(f"Lượt đã lưu: {version} · {mode}" in c.value for c in at.caption)
    assert field("selectbox", "Quyết định").value == ""
    assert not (run / "hunt_record.md").exists()
    field("button", "Tiếp tục sau duyệt (có gọi API)").click().run()
    assert any("chưa có quyết định" in e.value for e in at.error)
    assert not (run / "hunt_record.md").exists()
    field("text_input", "Người duyệt").set_value("synthetic UI tester")
    field("selectbox", "Quyết định").select("approved")
    field("button", "Lưu phiếu duyệt").click().run()
    assert not at.exception and not at.error
    field("button", "Tiếp tục sau duyệt (có gọi API)").click().run()
    assert not at.exception and not at.error
    if version == 'v2':
        assert not (run / 'hunt_record.md').exists()
        assert field('text_input', 'Người duyệt').value == ''
        assert field('text_input', 'Người chịu trách nhiệm').value == ''
        field('button', 'Tiếp tục sau duyệt (có thể gọi API ở bước kế tiếp)').click().run()
        assert any('pending_review' in e.value for e in at.error)
        field('text_input', 'Người duyệt').set_value('synthetic UI tester')
        field('selectbox', 'Quyết định').select('rejected')
        field('text_input', 'Lý do').set_value('Synthetic fixture rejection')
        field('button', 'Lưu quyết định lọc').click().run()
        assert not at.exception and not at.error
        # 09/10: rule ⑤ của fixture có giá trị giả thuyết không nêu, nên cổng còn chờ quyết định giữ/bỏ rule.
        assert (run / 'round_01/filter_review/r01/duyet_rule.yaml').exists()
        field('button', 'Tiếp tục sau duyệt (có thể gọi API ở bước kế tiếp)').click().run()
        assert any('rule chưa quyết định' in e.value for e in at.error)
        assert not (run / 'hunt_record.md').exists()
        field('text_input', 'Người duyệt rule').set_value('synthetic UI tester')
        for box in [x for x in at.selectbox if x.label == 'Giữ/bỏ rule']:
            box.select('giu')
        # 15/10: rule của fixture giữ 4/5 sự kiện tạo tiến trình (cổng độ rộng) → giữ phải ghi lý do.
        for reason in [x for x in at.text_input if x.label.startswith('Lý do (bắt buộc khi bỏ')]:
            reason.set_value('synthetic: fixture has only five process events')
        field('button', 'Lưu quyết định rule').click().run()
        assert not at.exception and not at.error
        field('button', 'Tiếp tục sau duyệt (có thể gọi API ở bước kế tiếp)').click().run()
        assert not at.exception and not at.error
    record = json.loads((run / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert record["executed_specs"] and record["observations"] and record["rarity_summary"]
    if mode == 'agent':
        assert [h['decision']['action'] for h in record['history']] == ['hunt', 'stop']
    assert any("#" in m.value and "Observe" in m.value for m in at.markdown)
    sql = [c.value for c in at.code if "SELECT * FROM events" in c.value]
    assert sql
    con = connect(events)
    for statement in sql:
        con.execute("EXPLAIN " + statement)
    con.close()
    # Re-open completed checkpoint in a fresh UI session (no in-memory workflow dependence).
    at = AppTest.from_file(str(app_path), default_timeout=30).run()
    field("selectbox", "Lượt trích").select(extraction).run()
    field("selectbox", "Lượt săn đã lưu").select(run).run()
    assert not at.exception and not at.error
    assert any(f"Lượt đã lưu: {version} · {mode}" in c.value for c in at.caption)
    assert any("Observe" in m.value for m in at.markdown)
    assert any("Tỷ lệ là ứng viên/phạm vi" in c.value for c in at.caption)
    # A different report must not inherit the previous extraction/approval widgets.
    field("text_input", "Mã report mới").set_value("OTHER")
    field("text_input", "URL report (hoặc tải file bên dưới)").set_value(str(source))
    field("button", "Nhập report mới").click().run()
    field("selectbox", "Mở report đã lưu").select(bundle.parent / "OTHER").run()
    assert field("selectbox", "Lượt trích").value is None
    assert field("selectbox", "Lượt săn đã lưu").value is None
    assert not at.exception
