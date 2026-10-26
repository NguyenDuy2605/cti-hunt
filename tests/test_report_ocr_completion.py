import base64
import io
import json

import pytest
from PIL import Image

from cti_hunt.stages import s1_ingest as S1, s1_ocr as OCR
from cti_hunt.stages.s1_layout import reading_order


class Engine:
    meta = {"engine": "completion-test"}
    def __init__(self, text="Recognized text"):
        self.calls = 0
        self.text = text
    def recognize(self, raw):
        self.calls += 1
        return {"text": self.text, "lines": [{"text": self.text, "score": 0.9}] if self.text else []}


def bundle(tmp_path):
    buf = io.BytesIO()
    Image.new("RGB", (100, 60), "white").save(buf, format="PNG")
    uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    source = tmp_path / "input.html"
    source.write_text(f'<article><p>Native evidence.</p><img src="{uri}"><img src="{uri}"></article>', encoding="utf-8")
    folder = tmp_path / "native"
    S1.ingest(str(source), "C", folder)
    return folder


def decision(folder, tmp_path, status, text="Verified transcript"):
    form = json.loads((folder / "ocr_review_template.json").read_text(encoding="utf-8"))
    form.update(reviewer="Synthetic reviewer", reviewed_at="2026-09-28T00:00:00Z")
    for d in form["decisions"]:
        d.update(status=status, text=text, reason="Checked against synthetic image")
    target = tmp_path / "decision.json"
    S1.write_json(target, form)
    return target


def test_continue_keeps_approved_text_and_only_processes_remaining(tmp_path):
    first, reviewed, last = (tmp_path / n for n in ("first", "reviewed", "last"))
    engine = Engine()
    OCR.enrich(bundle(tmp_path), first, engine=engine, max_targets=1)
    OCR.apply_review(first, decision(first, tmp_path, "approved"), reviewed)
    result = OCR.enrich(reviewed, last, engine=engine, continue_ocr=True)
    assert engine.calls == 2 and result["ocr"]["attempts"] == 1
    _, segs, prov = S1.load_bundle(last)
    assert segs[1]["van_ban"] == "Verified transcript" and prov["C-0002"]["review_status"] == "approved"
    assert (last / prov["C-0003"]["ocr_result_file"]).is_file()
    assert "ocr_review_applied.json" in result["artifacts"]
    assert any(n.startswith("bundle_history/") and n.endswith("provenance.json") for n in result["artifacts"])


@pytest.mark.parametrize("status", ["approved", "no_text", "rejected"])
def test_empty_ocr_can_be_resolved_by_a_real_review_decision(tmp_path, status):
    first, reviewed = tmp_path / "first", tmp_path / "reviewed"
    OCR.enrich(bundle(tmp_path), first, engine=Engine(""))
    form = json.loads((first / "ocr_review_template.json").read_text(encoding="utf-8"))
    assert len(form["decisions"]) == 2 and all(d["text"] == "" for d in form["decisions"])
    result = OCR.apply_review(first, decision(first, tmp_path, status), reviewed)
    _, segs, prov = S1.load_bundle(reviewed)
    assert S1.extraction_ready(segs[1], prov) is (status == "approved")
    assert result["image_review_pending_blocks"] == 0
    if status == "approved":
        assert prov["C-0002"]["transcript_origin"] == "manual_from_image"


def test_empty_retry_is_explicit_and_keeps_old_raw_result(tmp_path):
    first, skipped, retried = (tmp_path / n for n in ("first", "skipped", "retried"))
    OCR.enrich(bundle(tmp_path), first, engine=Engine(""))
    engine = Engine()
    OCR.enrich(first, skipped, engine=engine, continue_ocr=True)
    assert engine.calls == 0
    OCR.enrich(skipped, retried, engine=engine, continue_ocr=True, retry_failed=True)
    m, _, p = S1.load_bundle(retried)
    assert engine.calls == 1  # duplicate image is cached within the round
    assert json.loads((retried / "ocr_assets/C-0002.json").read_text())["text"] == ""
    assert "round_0003" in p["C-0002"]["ocr_result_file"]
    assert m["unread_blocks"] == 0


def test_continue_rejects_engine_or_dpi_change(tmp_path):
    first = tmp_path / "first"
    OCR.enrich(bundle(tmp_path), first, engine=Engine(), max_targets=1)
    with pytest.raises(ValueError, match="DPI"):
        OCR.enrich(first, tmp_path / "bad", engine=Engine(), continue_ocr=True, dpi=100)
    changed = Engine()
    changed.meta = {"engine": "changed"}
    with pytest.raises(ValueError, match="Engine"):
        OCR.enrich(first, tmp_path / "bad2", engine=changed, continue_ocr=True)


def line(x, y, width=180):
    return {"polygon_px": [[x, y], [x+width, y], [x+width, y+20], [x, y+20]], "text": str((x,y))}


def test_three_columns_with_heading_preserve_every_line():
    lines = [line(0, 0, 900), line(0, 60), line(350, 60), line(700, 60),
             line(0, 100), line(350, 100), line(700, 100)]
    order, meta = reading_order(lines)
    assert order == [0, 1, 4, 2, 5, 3, 6] and meta["column_splits"] == 2
    assert reading_order(lines[1:], table=True)[0] == list(range(6))


def test_pdf_renders_small_region_on_huge_page_without_downscaling(tmp_path):
    from reportlab.pdfgen.canvas import Canvas
    path = tmp_path / "huge.pdf"
    c = Canvas(str(path), pagesize=(5000, 5000))
    c.setFillColorRGB(1, 0, 0)
    c.rect(200, 4700, 100, 100, fill=1, stroke=0)
    c.save()
    raw, origin = OCR._pdf_image(path.read_bytes(), {"page": 1, "bbox": [200, 200, 300, 300]}, 200)
    with Image.open(io.BytesIO(raw)) as im:
        assert max(im.size) <= 279
        assert im.getpixel((100,100))[:3] == (255,0,0)
    assert origin["dpi"] == 200 and not origin["resolution_reduced"]
