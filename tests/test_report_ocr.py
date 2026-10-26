import base64
import io
import json
from pathlib import Path

import pytest
from PIL import Image

from cti_hunt.stages import s1_ingest as S1, s1_ocr as OCR, s2_report as S2


def png():
    buf = io.BytesIO()
    Image.new("RGB", (300, 100), "white").save(buf, format="PNG")
    return buf.getvalue()


class FakeEngine:
    meta = {"engine": "mock", "version": "1"}

    def __init__(self, text="The actor used a scheduled task."):
        self.text = text
        self.calls = 0

    def recognize(self, raw):
        self.calls += 1
        return {"text": self.text, "lines": [{"text": self.text, "score": 0.999,
                 "polygon_px": [[0, 0], [100, 0], [100, 30], [0, 30]]}] if self.text else []}


@pytest.fixture
def image_bundle(tmp_path):
    path = tmp_path / "shot.png"
    path.write_bytes(png())
    bundle = tmp_path / "native"
    S1.ingest(str(path), "SHOT", bundle)
    return bundle


def test_image_ingest_and_ocr_are_distinct(image_bundle, tmp_path):
    m, _, _ = S1.load_bundle(image_bundle)
    assert m["format"] == "png" and m["status"] == "blocked"
    before = (image_bundle / "manifest.json").read_bytes()
    out = tmp_path / "ocr"
    result = OCR.enrich(image_bundle, out, engine=FakeEngine())
    m, segs, prov = S1.load_bundle(out)
    assert result["ocr_pending_blocks"] == 1 and result["readable_segments"] == 0
    assert prov["SHOT-0001"]["extraction"] == "ocr"
    assert S2.units(segs, prov) == []  # even with confidence 0.999
    assert not S1.extraction_ready(segs[0], prov)
    assert "data:image/png;base64," in (out / "review.html").read_text(encoding="utf-8")
    assert (image_bundle / "manifest.json").read_bytes() == before


def test_review_requires_identity_hash_and_image_and_keeps_transcript_history(image_bundle, tmp_path):
    out = tmp_path / "ocr"
    OCR.enrich(image_bundle, out, engine=FakeEngine("sample[.]c0m"))
    form = json.loads((out / "ocr_review_template.json").read_text(encoding="utf-8"))
    path = tmp_path / "review.json"
    S1.write_json(path, form)
    with pytest.raises(ValueError, match="tên người"):
        OCR.apply_review(out, path, tmp_path / "invalid")
    form.update(reviewer="Synthetic test reviewer", reviewed_at="2026-09-28T10:00:00+07:00")
    form["decisions"][0].update(status="approved", text="sample[.]com", reason="Synthetic test correction")
    S1.write_json(path, form)
    reviewed = tmp_path / "reviewed"
    result = OCR.apply_review(out, path, reviewed)
    _, segs, prov = S1.load_bundle(reviewed)
    assert result["readable_segments"] == 1 and S2.units(segs, prov)[0]["evidence_origin"] == "ocr"
    assert segs[0]["van_ban"] == "sample[.]com"
    assert "sample[.]c0m" in (reviewed / "ocr_assets/SHOT-0001.json").read_text(encoding="utf-8")
    assert (reviewed / "ocr_review_applied.json").is_file()
    form["decisions"][0]["image_sha256"] = "wrong"
    S1.write_json(path, form)
    with pytest.raises(ValueError, match="Ảnh"):
        OCR.apply_review(out, path, tmp_path / "wrong-image")


@pytest.mark.parametrize("artifact", ["ocr_assets/SHOT-0001.png", "ocr_assets/SHOT-0001.json", "ocr_assets/SHOT-0001.source"])
def test_ocr_artifacts_hash_checked(image_bundle, tmp_path, artifact):
    out = tmp_path / "ocr"
    OCR.enrich(image_bundle, out, engine=FakeEngine())
    (out / artifact).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Artifact OCR"):
        S1.load_bundle(out)


def test_ocr_no_text_does_not_mean_no_content(image_bundle, tmp_path):
    result = OCR.enrich(image_bundle, tmp_path / "empty", engine=FakeEngine(""))
    assert result["unread_blocks"] == 1
    assert any(w["code"] == "ocr_no_text" for w in result["warnings"])


def test_ocr_failure_keeps_image_and_unread_status(image_bundle, tmp_path):
    class Failing(FakeEngine):
        def recognize(self, raw): raise TimeoutError("timed out")
    out = tmp_path / "failed"
    result = OCR.enrich(image_bundle, out, engine=Failing())
    assert result["unread_blocks"] == 1 and result["ocr_pending_blocks"] == 0
    assert (out / "ocr_assets/SHOT-0001.png").exists()
    assert any(w["code"] == "ocr_failed" for w in result["warnings"])


def test_html_relative_image_and_cache(tmp_path):
    (tmp_path / "a.png").write_bytes(png())
    html = tmp_path / "x.html"
    html.write_text('<article><p>Native context.</p><img src="a.png"><img src="a.png"></article>', encoding="utf-8")
    native = tmp_path / "native"
    S1.ingest(str(html), "HTML", native)
    engine = FakeEngine()
    out = tmp_path / "ocr"
    result = OCR.enrich(native, out, engine=engine)
    _, segs, prov = S1.load_bundle(out)
    assert engine.calls == 1 and result["ocr_pending_blocks"] == 2
    assert len(S2.units(segs, prov)) == 1
    assert not S2.units(segs, prov)[0]["neighbors"]  # pending OCR cannot leak via neighbors


def test_local_html_image_cannot_escape_parent(tmp_path):
    root = tmp_path / "report"
    root.mkdir()
    (tmp_path / "secret.png").write_bytes(png())
    html = root / "x.html"
    html.write_text('<article><p>Text.</p><img src="../secret.png"></article>', encoding="utf-8")
    native = tmp_path / "native"
    S1.ingest(str(html), "HTML", native)
    engine = FakeEngine()
    result = OCR.enrich(native, tmp_path / "ocr", engine=engine)
    assert not engine.calls and result["unread_blocks"] == 1


def test_remote_html_cannot_read_local_file():
    with pytest.raises(ValueError, match="cục bộ"):
        OCR._html_image({"asset": "file:///C:/secret.png"}, {"resolved_source": "https://example.com/report"}, allow_network=True)


def test_inline_image_and_no_network_by_default(tmp_path, monkeypatch):
    uri = "data:image/png;base64," + base64.b64encode(png()).decode()
    html = tmp_path / "x.html"
    html.write_text(f'<article><img src="{uri}"><img src="https://example.com/a.png"></article>', encoding="utf-8")
    native = tmp_path / "native"
    S1.ingest(str(html), "HTML", native)
    monkeypatch.setattr(S1, "fetch", lambda *args: pytest.fail("network call"))
    _, _, prov = S1.load_bundle(native)
    assert any(p.get("asset") == "https://example.com/a.png" for p in prov.values())
    engine = FakeEngine()
    result = OCR.enrich(native, tmp_path / "ocr", engine=engine)
    assert engine.calls == 1 and result["unread_blocks"] == 1


def test_scan_pdf_is_one_target_and_native_text_not_replaced(tmp_path):
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.lib.utils import ImageReader
    path = tmp_path / "mixed.pdf"
    c = Canvas(str(path), pagesize=(400, 400))
    c.drawImage(ImageReader(io.BytesIO(png())), 0, 0, width=400, height=400)
    c.showPage()
    c.drawString(20, 370, "Native text stays unchanged")
    c.drawImage(ImageReader(io.BytesIO(png())), 20, 100, width=300, height=100)
    c.save()
    native = tmp_path / "native"
    m = S1.ingest(str(path), "PDF", native)
    _, original, prov = S1.load_bundle(native)
    assert sum(p["extraction"] == "unread" for p in prov.values()) == 2
    out = tmp_path / "ocr"
    OCR.enrich(native, out, engine=FakeEngine())
    _, segs, prov = S1.load_bundle(out)
    assert any(s["van_ban"] == "Native text stays unchanged" for s in segs)
    assert sum(p["extraction"] == "ocr" for p in prov.values()) == 2
    assert all(p["image_origin"]["dpi"] == 200 for p in prov.values() if p["extraction"] == "ocr")


def test_target_limit_preserves_unread_blocks(tmp_path):
    uri = "data:image/png;base64," + base64.b64encode(png()).decode()
    html = tmp_path / "x.html"
    html.write_text(f'<article><img src="{uri}"><img src="{uri}"></article>', encoding="utf-8")
    native = tmp_path / "native"
    S1.ingest(str(html), "HTML", native)
    result = OCR.enrich(native, tmp_path / "ocr", engine=FakeEngine(), max_targets=1)
    assert result["ocr_pending_blocks"] == 1 and result["unread_blocks"] == 1


def test_rejected_ocr_stays_out_of_extraction(image_bundle, tmp_path):
    out = tmp_path / "ocr"
    OCR.enrich(image_bundle, out, engine=FakeEngine())
    form = json.loads((out / "ocr_review_template.json").read_text(encoding="utf-8"))
    form.update(reviewer="Synthetic reviewer", reviewed_at="2026-09-28T00:00:00Z")
    form["decisions"][0].update(status="rejected", reason="Not legible")
    review = tmp_path / "decision.json"
    S1.write_json(review, form)
    OCR.apply_review(out, review, tmp_path / "reviewed")
    _, segs, prov = S1.load_bundle(tmp_path / "reviewed")
    assert S2.units(segs, prov) == []
