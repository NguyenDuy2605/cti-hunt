"""H3: đoạn đọc được nhưng không gửi khâu ② (đầu/chân trang PDF, dòng không có chữ, nhãn nút bấm web).

Report và đoạn đều tự soạn; client giả; không nhãn, không gọi API."""
import json

import pytest

from cti_hunt import config, demo
from cti_hunt.cli import main
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s1_ingest as S1, s2_ioc, s2_report as S2

PROMPT = config.ROOT / "prompts/report_extract_v1.md"
LLM_CFG = {"provider": "mock", "model": "test"}
QUOTE = "The actor used WMI to execute a process on another host."


def doc(fmt, pages):
    """pages: danh sách trang, mỗi trang là danh sách chuỗi → (manifest, segments, provenance) như một bundle."""
    segments, provenance = [], {}
    for page, texts in enumerate(pages, 1):
        for text in texts:
            sid = f"X-{len(segments) + 1:04d}"
            segments.append({"ma_doan": sid, "report": "X", "loai": "đoạn văn", "van_ban": text})
            provenance[sid] = {"extraction": "text", "page": page if fmt == "pdf" else 0, "section": ""}
    return {"format": fmt}, segments, provenance


def marked(fmt, pages):
    manifest, segments, provenance = doc(fmt, pages)
    text = {s["ma_doan"]: s["van_ban"] for s in segments}
    return sorted((text[k], v) for k, v in S2.noise_marks(manifest, segments, provenance).items())


LONG = "This confidentiality sentence is longer than eighty characters and is printed again on every single page."


def test_pdf_header_footer_and_letterless_rows_are_marked_and_content_is_kept():
    # Câu nội dung chỉ khác nhau một con số, không theo số trang: phải được giữ.
    pages = [["TLP:CLEAR", f"Page {n + 2} of 8", f"The actor did step {7 - n} on the host.", LONG] for n in range(1, 7)]
    pages[0] += ["| |", "•", "12.5%", "Persistence"]
    pages[3] += ["Persistence"]                                        # lặp 2 trang: dưới ngưỡng 3 trang
    got = marked("pdf", pages)
    assert got == sorted([("TLP:CLEAR", "lap_tren_nhieu_trang")] * 6
                         + [(f"Page {n + 2} of 8", "lap_tren_nhieu_trang") for n in range(1, 7)]   # số in lệch 2 trang
                         + [("| |", "khong_co_chu"), ("•", "khong_co_chu"), ("12.5%", "khong_co_chu")])


def test_repetition_needs_three_pages_and_a_third_of_the_document():
    assert marked("pdf", [["TLP:CLEAR", "Text of page one."], ["TLP:CLEAR", "Text of page two."]]) == []
    pages = [[f"Paragraph {chr(96 + n)} describes the intrusion."] for n in range(1, 13)]
    for n in (0, 1, 2):
        pages[n].append("Malware family table")                         # 3/12 trang: dưới 1/3
    assert marked("pdf", pages) == []
    pages[3].append("Malware family table")                             # 4/12 trang
    assert marked("pdf", pages) == [("Malware family table", "lap_tren_nhieu_trang")] * 4


def test_web_button_labels_use_a_closed_vocabulary_only_on_html():
    buttons = ["Download", "Download PDF", "Share this publication", "Copy link", "Print:"]
    content = ["Download payload via BITS", "Impacket toolkit", "MD5", "History:", "Print spooler abuse",
               "Share enumeration with net view", QUOTE]
    assert marked("html", [buttons + content]) == sorted((b, "chu_giao_dien") for b in buttons)
    assert marked("pdf", [buttons + content]) == []


def test_marked_segments_are_not_targets_and_only_letterless_ones_stay_as_context():
    manifest, segments, provenance = doc("html", [["It listens on the following port:", "8443", "Download PDF",
                                                   "Second real paragraph of the report."]])
    marks = S2.noise_marks(manifest, segments, provenance)
    assert marks == {"X-0002": "khong_co_chu", "X-0003": "chu_giao_dien"}
    plain = S2.units(segments, provenance)
    kept = S2.units(segments, provenance, skip=frozenset(marks), no_context=frozenset({"X-0003"}))
    assert [u["segment_id"] for u in plain] == ["X-0001", "X-0002", "X-0003", "X-0004"]
    assert [u["segment_id"] for u in kept] == ["X-0001", "X-0004"]
    assert [[n["segment_id"] for n in u["neighbors"]] for u in kept] == [["X-0002"], []]   # số cổng còn là ngữ cảnh
    assert S2.units(segments, provenance, skip=frozenset()) == plain


@pytest.fixture
def stix(tmp_path):
    objects = [{"type": "x-mitre-tactic", "id": "tactic--1", "x_mitre_shortname": "execution", "name": "Execution"},
               {"type": "attack-pattern", "id": "attack-pattern--T1047", "name": "Windows Management Instrumentation",
                "description": "WMI can execute a process on another host.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1047"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]}]
    path = tmp_path / "attack.json"
    S1.write_json(path, {"objects": objects})
    return path


def ingest(tmp_path, body, name="bundle"):
    source = tmp_path / f"{name}.html"
    source.write_text(f"<html><head><title>New report</title></head><body><article><h1>Execution</h1>{body}"
                      "</article></body></html>", encoding="utf-8")
    folder = tmp_path / name
    S1.ingest(str(source), "NEW", folder)
    return folder


NOISY = f"<p>{QUOTE}</p><p>Download PDF</p><p>203.0.113.7</p><p>The next paragraph provides context.</p>"


def run(bundle, stix, out, responses=None, **kwargs):
    client = MockClient(responses=responses or [])
    return S2.run(bundle, stix, PROMPT, LLM_CFG, out, s2_ioc.load_rules(config.ROOT / "configs/ioc_rules.yaml"),
                  llm=client, **kwargs), client


def targets(out):
    return [t["segment_id"] for r in json.loads((out / "requests.json").read_text(encoding="utf-8"))
            for t in json.loads(r["user"])["targets"]]


def test_extraction_skips_marked_segments_keeps_the_bundle_and_still_scans_them_for_iocs(tmp_path, stix):
    bundle = ingest(tmp_path, NOISY)
    before = {p.name: p.read_bytes() for p in bundle.iterdir() if p.is_file()}
    _, segments, _ = S1.load_bundle(bundle)
    by_text = {s["van_ban"]: s["ma_doan"] for s in segments}
    meta, _ = run(bundle, stix, tmp_path / "dry")
    note = meta["khong_gui_khau2"]
    assert note == {"quy_tac": "h3_v1", "so_doan": 2, "theo_ly_do": {"khong_co_chu": 1, "chu_giao_dien": 1},
                    "doan": {by_text["Download PDF"]: "chu_giao_dien", by_text["203.0.113.7"]: "khong_co_chu"}}
    assert targets(tmp_path / "dry") == [by_text[QUOTE], by_text["The next paragraph provides context."]]
    assert meta["target_units"] == 2
    done, client = run(bundle, stix, tmp_path / "sent", responses=[{"items": []}], send=True)
    assert done["status"] == "complete" and len(client.calls) == 1
    contract = json.loads((tmp_path / "sent" / "contract_a.json").read_text(encoding="utf-8"))
    assert [(i["value"], i["source_span"]["segment_id"]) for i in contract["iocs"]] == [("203.0.113.7", by_text["203.0.113.7"])]
    assert before == {p.name: p.read_bytes() for p in bundle.iterdir() if p.is_file()}


def test_report_without_noise_has_no_note_and_an_explicit_selection_overrides_a_mark(tmp_path, stix):
    clean = ingest(tmp_path, f"<p>{QUOTE}</p><p>The next paragraph provides context.</p>", "clean")
    meta, _ = run(clean, stix, tmp_path / "clean-dry")
    assert "khong_gui_khau2" not in meta and meta["target_units"] == 2
    assert demo.extraction_noise(clean) is None

    noisy = ingest(tmp_path, NOISY, "noisy")
    _, segments, _ = S1.load_bundle(noisy)
    button = next(s["ma_doan"] for s in segments if s["van_ban"] == "Download PDF")
    chosen, _ = run(noisy, stix, tmp_path / "chosen", segments_selected=[button])
    assert targets(tmp_path / "chosen") == [button]
    assert chosen["khong_gui_khau2"]["so_doan"] == 1 and button not in chosen["khong_gui_khau2"]["doan"]


def test_cli_and_ui_preview_report_the_skipped_segments(tmp_path, stix, monkeypatch, capsys):
    import yaml
    from cti_hunt import report_cli
    bundle = ingest(tmp_path, NOISY)
    original_load = config.load
    monkeypatch.setattr(report_cli.config, "load", lambda name: {
        "attack": {"stix_path": str(stix), "stix_sha256": S1.digest(stix.read_bytes())}
    } if name == "reports" else original_load(name))
    monkeypatch.setattr("cti_hunt.llm.providers.from_config", lambda *a: pytest.fail("API client created"))
    cfg = tmp_path / "llm.yaml"
    cfg.write_text(yaml.safe_dump({"provider": "anthropic", "model": "claude-sonnet-5", "max_output_tokens": 32000}),
                   encoding="utf-8")
    out = bundle / "extractions" / "cli"
    assert main(["extract-report", str(bundle), "--out", str(out), "--llm-config", str(cfg), "--dry-run"]) == 0
    line = "Không gửi khâu ② 2 đoạn không mang nội dung (không có chữ 1, chữ nút bấm của trang web 1)"
    assert line in capsys.readouterr().out
    assert demo.extraction_noise(bundle).startswith(line)               # trước khi có lượt: tính từ bundle
    assert demo.extraction_noise(bundle, out).startswith(line)          # lượt đã lưu: đọc meta của nó
    old = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    old.pop("khong_gui_khau2")                                          # meta của lượt trước H3
    S1.write_json(out / "meta.json", old)
    assert demo.extraction_noise(bundle, out) is None
