"""H4: nhập ảnh, chạy OCR và rà bản chép từ UI. Ảnh tự tạo, engine OCR giả; không gọi API, không tự duyệt phiếu."""
import io
import json

import pytest
from PIL import Image

from cti_hunt import demo
from cti_hunt.stages import s1_ingest as S1

TEXT = "The actor used a scheduled task."


class FakeEngine:
    meta = {"engine": "mock", "version": "1"}

    def recognize(self, raw):
        return {"text": TEXT, "lines": [{"text": TEXT, "score": 0.999,
                                         "polygon_px": [[0, 0], [100, 0], [100, 30], [0, 30]]}]}


@pytest.fixture
def reports(tmp_path):
    """Thư mục kiểu data/reports/moi với một report ảnh đã nhập qua đúng hàm UI dùng."""
    root = tmp_path / "reports" / "moi"
    root.mkdir(parents=True)
    buf = io.BytesIO()
    Image.new("RGB", (300, 100), "white").save(buf, format="PNG")
    source = tmp_path / "shot.png"
    source.write_bytes(buf.getvalue())
    return root, demo.ingest(str(source), "SHOT", root=root)


def files(folder):
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*") if p.is_file()}


def test_image_report_goes_through_ocr_and_review_into_new_folders_only(reports):
    root, native = reports
    manifest, _, _ = S1.load_bundle(native)
    assert manifest["format"] == "png" and manifest["unread_blocks"] == 1 and demo.ocr_review(native) is None
    before = files(native)
    ocr = demo.ocr_bundle(native, engine=FakeEngine())
    assert ocr == root / "SHOT-ocr" and files(native) == before               # bản gốc không đổi
    with pytest.raises(ValueError):
        demo.ocr_bundle(native, engine=FakeEngine())                          # không ghi đè lượt OCR đã có
    form = demo.ocr_review(ocr)
    sid = form["decisions"][0]["segment_id"]
    assert [d["status"] for d in form["decisions"]] == ["pending"] and form["decisions"][0]["text"] == TEXT
    assert form["decisions"][0]["image"].endswith(".png") and form["reviewer"] == ""
    _, segments, provenance = S1.load_bundle(ocr)
    assert not any(S1.extraction_ready(s, provenance) for s in segments)      # chưa rà thì chưa vào trích

    ocr_before = files(ocr)
    for reviewer, choice, message in [
            ("", {"status": "approved", "text": TEXT, "reason": "khớp ảnh"}, "tên người"),
            ("Synthetic reviewer", {"status": "approved", "text": TEXT, "reason": ""}, "lý do"),
            ("Synthetic reviewer", {"status": "approved", "text": " ", "reason": "khớp ảnh"}, "không được trống"),
            ("Synthetic reviewer", {"status": "pending", "text": TEXT, "reason": ""}, "Chưa có quyết định")]:
        with pytest.raises(ValueError, match=message):
            demo.ocr_apply(ocr, reviewer, {sid: choice})
        assert not (root / "SHOT-ocr-ra").exists() and files(ocr) == ocr_before
    with pytest.raises(ValueError, match="không thuộc phiếu"):
        demo.ocr_apply(ocr, "Synthetic reviewer", {"KHAC-0001": {"status": "approved", "text": TEXT, "reason": "x"}})

    fixed = TEXT.replace("scheduled", "Scheduled")
    reviewed = demo.ocr_apply(ocr, "Synthetic reviewer", {sid: {"status": "approved", "text": fixed, "reason": "khớp ảnh"}})
    assert reviewed == root / "SHOT-ocr-ra" and files(ocr) == ocr_before
    _, segments, provenance = S1.load_bundle(reviewed)
    ready = [s for s in segments if S1.extraction_ready(s, provenance)]
    assert [s["van_ban"] for s in ready] == [fixed] and provenance[sid]["reviewer"] == "Synthetic reviewer"
    applied = json.loads((reviewed / "ocr_review_applied.json").read_text(encoding="utf-8"))
    assert set(applied) == {"bundle_manifest_sha256", "reviewer", "reviewed_at", "decisions"}     # định dạng review-ocr
    assert set(applied["decisions"][0]) == {"segment_id", "status", "text", "reason", "image_sha256"}
    assert demo.ocr_review(reviewed) is None                                   # không còn đoạn chờ rà
    with pytest.raises(ValueError, match="Đã có bản sau rà"):
        demo.ocr_apply(ocr, "Synthetic reviewer", {sid: {"status": "rejected", "text": TEXT, "reason": "thử lại"}})


def _app(tmp_path, bundle):
    from streamlit.testing.v1 import AppTest
    app = tmp_path / f"ocr_app_{bundle.name}.py"
    app.write_text("from pathlib import Path\nfrom cti_hunt.demo_app import ocr_form\n"
                   f"ocr_form(Path({str(bundle)!r}))\n", encoding="utf-8")
    at = AppTest.from_file(str(app), default_timeout=30).run()
    assert not at.exception
    return at


def test_ui_form_preselects_nothing_shows_the_reason_error_and_then_creates_the_reviewed_bundle(reports, tmp_path):
    root, native = reports
    at = _app(tmp_path, native)
    assert not at.selectbox and not at.subheader                               # bundle chưa OCR: không có form
    ocr = demo.ocr_bundle(native, engine=FakeEngine())
    at = _app(tmp_path, ocr)
    assert [x.value for x in at.selectbox if x.label == "Kết quả rà"] == ["pending"]
    assert [x.value for x in at.text_area] == [TEXT] and at.text_input[0].value == ""
    next(x for x in at.text_input if x.label == "Người rà OCR").set_value("Synthetic UI reviewer")
    at.selectbox[0].set_value("approved")
    next(x for x in at.button if x.label == "Áp phiếu rà OCR").click().run()
    assert any("lý do" in e.value for e in at.error) and not (root / "SHOT-ocr-ra").exists()
    next(x for x in at.text_input if x.label.startswith("Lý do")).set_value("khớp ảnh")
    next(x for x in at.button if x.label == "Áp phiếu rà OCR").click().run()
    assert not at.error and any("SHOT-ocr-ra" in s.value for s in at.success)
    _, segments, provenance = S1.load_bundle(root / "SHOT-ocr-ra")
    assert [s["van_ban"] for s in segments if S1.extraction_ready(s, provenance)] == [TEXT]


def test_app_opens_the_new_report_by_itself_after_ocr_and_after_review(tmp_path, monkeypatch):
    """12/10: sau khi chạy OCR/áp phiếu, report mới phải có trong ô chọn và được mở, không cần người dùng tự chạy lại trang."""
    from streamlit.testing.v1 import AppTest
    from cti_hunt import config
    app_path = config.ROOT / "app/streamlit_app.py"
    ui_root = tmp_path / "ui"
    moi = ui_root / "data/reports/moi"
    buf = io.BytesIO()
    Image.new("RGB", (300, 100), "white").save(buf, format="PNG")
    source = tmp_path / "shot.png"
    source.write_bytes(buf.getvalue())
    monkeypatch.setattr(config, "ROOT", ui_root)
    real_ocr = demo.ocr_bundle
    monkeypatch.setattr(demo, "ocr_bundle", lambda bundle: real_ocr(bundle, engine=FakeEngine()))
    monkeypatch.setattr("cti_hunt.demo_app.api_key", lambda: pytest.fail("API key requested"))
    at = AppTest.from_file(str(app_path), default_timeout=30).run()

    def field(kind, label):
        return next(x for x in getattr(at, kind) if x.label == label)

    def notices(text):
        return [s.value for s in at.success if text in s.value]

    field("text_input", "Mã report mới").set_value("SHOT")
    field("text_input", "URL report (hoặc tải file bên dưới)").set_value(str(source))
    field("button", "Nhập report mới").click().run()
    assert not at.exception and field("selectbox", "Mở report đã lưu").value == moi / "SHOT"
    native = files(moi / "SHOT")

    field("button", "Chạy OCR cục bộ cho các khối chưa đọc").click().run()
    assert not at.exception and not at.error
    assert field("selectbox", "Mở report đã lưu").value == moi / "SHOT-ocr"            # tự mở bản OCR
    assert len(notices("Đã tạo bản OCR `SHOT-ocr` và đang mở nó")) == 1
    assert [x.value for x in at.selectbox if x.label == "Kết quả rà"] == ["pending"]    # form rà hiện ngay
    assert not any(b.label == "Chạy OCR cục bộ cho các khối chưa đọc" for b in at.button)  # bản OCR không OCR lại
    at.run()
    assert not notices("Đã tạo bản OCR") and field("selectbox", "Mở report đã lưu").value == moi / "SHOT-ocr"
    ocr = files(moi / "SHOT-ocr")

    field("button", "Áp phiếu rà OCR").click().run()                                    # phiếu trống: bị từ chối, ở nguyên chỗ
    assert any("tên người" in e.value for e in at.error) and not (moi / "SHOT-ocr-ra").exists()
    assert field("selectbox", "Mở report đã lưu").value == moi / "SHOT-ocr" and not at.success

    field("text_input", "Người rà OCR").set_value("Synthetic UI reviewer")
    field("selectbox", "Kết quả rà").set_value("approved")
    next(x for x in at.text_input if x.label.startswith("Lý do")).set_value("khớp ảnh")
    field("button", "Áp phiếu rà OCR").click().run()
    assert not at.exception and not at.error
    assert field("selectbox", "Mở report đã lưu").value == moi / "SHOT-ocr-ra"         # tự mở bản sau rà
    assert len(notices("Đã tạo bản sau rà `SHOT-ocr-ra` và đang mở nó")) == 1
    assert not any(x.label == "Kết quả rà" for x in at.selectbox)                       # không còn đoạn chờ rà
    _, segments, provenance = S1.load_bundle(moi / "SHOT-ocr-ra")
    assert [s["van_ban"] for s in segments if S1.extraction_ready(s, provenance)] == [TEXT]
    assert files(moi / "SHOT") == native and files(moi / "SHOT-ocr") == ocr            # bản trước không bị sửa
    assert sorted(p.name for p in moi.iterdir()) == ["SHOT", "SHOT-ocr", "SHOT-ocr-ra"]
    at.run()
    assert not notices("Đã tạo bản sau rà") and field("selectbox", "Mở report đã lưu").value == moi / "SHOT-ocr-ra"


def test_ui_upload_accepts_images_and_offers_local_ocr_only_for_unread_bundles():
    import inspect
    from cti_hunt import demo_app
    source = inspect.getsource(demo_app.main)
    assert 'type=["html", "pdf", "png", "jpg", "jpeg"]' in source
    assert 'manifest["unread_blocks"] and not manifest.get("ocr")' in source and "demo.ocr_bundle(bundle)" in source
