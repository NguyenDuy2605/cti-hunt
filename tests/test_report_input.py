"""New-report path: real HTML/PDF parsing, evidence validation and graph handoff.

All reports are synthetic; all model calls are injected mocks. No labels/API.
"""
import io
import json
import socket

import pytest

from cti_hunt import config
from cti_hunt.attack.catalog import AttackCatalog
from cti_hunt.attack.retrieval import TechniqueIndex
from cti_hunt.cli import main
from cti_hunt.contracts import ContractA
from cti_hunt.llm.providers import MockClient
from cti_hunt.stages import s1_ingest as S1, s2_report as S2, s2_ioc, s3_telemetry

QUOTE = "The actor used WMI to execute a process on another host."
PROMPT = config.ROOT / "prompts/report_extract_v1.md"
LLM_CFG = {"provider": "mock", "model": "test"}


@pytest.fixture
def bundle(tmp_path):
    source = tmp_path / "input.html"
    source.write_text(f'<html><head><title>New report</title></head><body><nav>Skip menu</nav><article>'
                      f'<h1>Execution</h1><p>{QUOTE}</p><p>The next paragraph provides context.</p>'
                      '</article><footer>Skip footer</footer></body></html>', encoding="utf-8")
    folder = tmp_path / "bundle"
    S1.ingest(str(source), "NEW", folder)
    return folder


@pytest.fixture
def stix(tmp_path):
    objects = [{"type": "x-mitre-tactic", "id": "tactic--1", "x_mitre_shortname": "execution", "name": "Execution"}]
    for tid, name, description in [("T1047", "Windows Management Instrumentation", "WMI can execute a process on another host."),
                                   ("T1053.005", "Scheduled Task", "Schedule a task for persistence."),
                                   ("T1111", "Other", "Unrelated technique.")]:
        objects.append({"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
                        "description": description, "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]})
    objects.append({"type": "relationship", "id": "relationship--example", "description": "DO NOT INDEX THIS PROCEDURE EXAMPLE"})
    path = tmp_path / "attack.json"
    S1.write_json(path, {"objects": objects})
    return path


def item(**updates):
    return {"segment_id": "NEW-0002", "technique_id": "T1047", "tactic": "execution", "quote": QUOTE,
            "behavior_description": "Remote process execution through WMI", "confidence": 0.8,
            "rationale": "The source explicitly describes process execution using WMI.", **updates}


def run_extract(bundle, stix, out, responses=None, **kwargs):
    client = MockClient(responses=responses or [{"items": [item()]}])
    result = S2.run(bundle, stix, PROMPT, LLM_CFG, out,
                    s2_ioc.load_rules(config.ROOT / "configs/ioc_rules.yaml"), llm=client, **kwargs)
    return result, client


def test_html_roundtrip_and_provenance(bundle):
    manifest, segments, provenance = S1.load_bundle(bundle)
    assert manifest["status"] == "extracted"
    assert [s["van_ban"] for s in segments] == ["Execution", QUOTE, "The next paragraph provides context."]
    assert set(segments[0]) == {"ma_doan", "report", "loai", "van_ban"}
    assert provenance["NEW-0002"]["section"] == "Execution"
    assert provenance["NEW-0002"]["dom_path"].endswith("p:nth-of-type(1)")


def test_html_lists_code_table_image_and_xss(tmp_path):
    source = tmp_path / "x.html"
    source.write_text('<article><p>Hello <strong>world</strong>.</p><ul><li>Parent<ul><li>Child</li></ul>tail</li></ul>'
                      '<pre><code>a &lt; b\n  second line</code></pre><table><tr><th>Key</th><th>Value</th></tr>'
                      '<tr><td>Domain</td><td>example[.]com</td></tr></table><figure>'
                      '<img src="cmd.png" alt="screenshot"><figcaption>Caption</figcaption></figure>'
                      '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p><script>bad()</script></article>', encoding="utf-8")
    out = tmp_path / "parsed"
    manifest = S1.ingest(str(source), "N", out)
    _, segs, prov = S1.load_bundle(out)
    texts = [s["van_ban"] for s in segs]
    assert texts.count("Parent") == texts.count("Child") == texts.count("tail") == 1
    assert "Hello world." in texts and "a < b\n  second line" in texts
    assert "Domain | example[.]com" in texts
    # Trang tổng hợp toàn mục ngắn, không có đoạn dài: bị cảnh báo giống menu (10/10), trạng thái cần rà thay vì partial.
    assert manifest["status"] == "needs_review" and manifest["unread_blocks"] == 1
    assert "html_content_suspect" in {w["code"] for w in manifest["warnings"]}
    review = (out / "review.html").read_text(encoding="utf-8")
    assert "<script>" not in review and "&lt;script&gt;" in review and "bad()" not in review
    assert not any(u["kind"] == "ảnh" for u in S2.units(segs, prov))


LONG = ("The intruder launched a remote process through WMI and staged further tooling on the host, then queried "
        "domain trusts and enumerated administrative groups before moving laterally to the next server. ")


def test_report_outside_main_is_found_when_main_holds_only_menu(tmp_path):
    # H1 (10/10): trang blog để bài ngoài <main>, còn <main> chỉ có menu; bản cũ đọc menu, 0 chữ của bài.
    menu = "".join(f"<li><a href='/{w}'>{w}</a></li>" for w in ("Products", "Threat Intel", "Services", "Training",
                                                                 "About us", "Careers", "Contact Us"))
    source = tmp_path / "blog.html"
    source.write_text(f"<html><body><div class='top'><main><ul>{menu}</ul></main></div>"
                      f"<div class='wrap'><div class='post'><h2>Initial access</h2>"
                      + "".join(f"<p>{LONG}{i}</p>" for i in range(6)) +
                      "<img src='shot.png'></div></div></body></html>", encoding="utf-8")
    manifest = S1.ingest(str(source), "BLOG", tmp_path / "blog")
    _, segs, _ = S1.load_bundle(tmp_path / "blog")
    texts = [s["van_ban"] for s in segs]
    assert sum(t.startswith("The intruder") for t in texts) == 6 and "Products" not in texts
    codes = {w["code"] for w in manifest["warnings"]}
    assert "html_root_fallback" in codes and "html_content_suspect" not in codes
    # Ảnh chưa đọc không che cảnh báo chọn vùng: trạng thái là cần rà, không phải partial.
    assert manifest["status"] == "needs_review" and manifest["unread_blocks"] == 1
    from cti_hunt import demo
    assert [a["code"] for a in demo.selection_alerts(manifest)] == ["html_root_fallback"]


def test_br_inside_code_and_inline_tags_keeps_lines_apart():
    """15/10: danh sách IOC tách bằng <br> trong <pre> hay trong <span> không được dính liền."""
    raw = ("<html><body><article id='a'><h2>IoCs</h2><pre>evil[.]com<br>bad[.]net</pre>"
           "<p><span>119.8.186[.]227<br>longlog[.]cc</span></p></article></body></html>").encode()
    texts = [b["text"] for b in S1.parse_html(raw, "x", "#a")[0]]
    assert "evil[.]com\nbad[.]net" in texts
    assert "119.8.186[.]227 longlog[.]cc" in texts


def test_menu_like_region_is_flagged_but_short_ioc_table_is_not():
    menu = "".join(f"<li>{w}</li>" for w in ("Home", "Blog", "Reports", "Labs", "Pricing", "Login"))
    blocks, warnings, _ = S1.parse_html(f"<html><div id='m'><ul>{menu}</ul></div></html>".encode(), "x", "#m")
    assert len(blocks) == 6 and "html_content_suspect" in {w["code"] for w in warnings}
    rows = "".join(f"<tr><td>10.0.0.{i}</td><td>C2</td></tr>" for i in range(12))
    raw = f"<article><p>{LONG}</p><p>{LONG}</p><table>{rows}</table></article>".encode()
    _, warnings, _ = S1.parse_html(raw, "x")
    assert not {w["code"] for w in warnings} & set(S1.SELECTION_ALERTS)


def test_article_holding_most_prose_is_kept_without_new_warnings():
    raw = (f"<html><body><div><a href='/a'>Menu</a></div><article>" + "".join(f"<p>{LONG}</p>" for _ in range(4))
           + "</article><div><p>Short footer note.</p></div></body></html>").encode()
    blocks, warnings, _ = S1.parse_html(raw, "x")
    assert len(blocks) == 4 and warnings == []


def test_html_fallback_selector_and_no_text(tmp_path):
    raw = b'<html><div id="main"><p>Body text</p></div><div>Other</div></html>'
    blocks, warnings, _ = S1.parse_html(raw, "https://example.com/report", "#main")
    assert [b["text"] for b in blocks] == ["Body text"] and warnings == []
    with pytest.raises(ValueError, match="đúng một"):
        S1.parse_html(raw, "x", "div")
    source = tmp_path / "scan.html"
    source.write_text('<article><img src="scan.png"></article>', encoding="utf-8")
    result = S1.ingest(str(source), "X", tmp_path / "scan")
    assert result["status"] == "blocked"


def test_article_cards_do_not_displace_main_report():
    raw = ('<main><article><h1>Report title</h1></article><div class="entry-content">'
           '<h2>Activity</h2><p>' + QUOTE * 10 + '</p><pre>query text</pre></div>'
           '<article><a href="/related">Related story only</a></article></main>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    text = " ".join(b["text"] for b in blocks)
    assert QUOTE in text and "query text" in text and "Related story only" not in text


def test_main_beats_short_article_even_without_cms_classes():
    raw = ('<main><div><p>' + QUOTE * 10 + '</p></div></main><article>Related teaser</article>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    assert QUOTE in " ".join(b["text"] for b in blocks)


# Ba lỗi N1 §5.1, phát triển trên hai trang ngoài tập đánh giá (05/10); fixture dưới đây rút gọn cấu trúc của chúng.
CARDS = "".join(f'<div><a href="/p{i}"><img src="banner.png"><h4>Other post {i} about something else</h4></a>'
                f'<p><a href="/topic">Threat Intelligence</a></p></div>' for i in range(3))


def test_lightbox_dialog_copy_is_not_read_twice():
    raw = ('<article><p>' + QUOTE * 5 + '</p><figure><img src="fig1.png" alt="Figure 1">'
           '<section role="dialog" class="modal"><img src="fig1.png" alt="Figure 1"></section></figure>'
           '<dialog><img src="fig2.png"></dialog></article>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    assert [b["text"] for b in blocks if b["kind"] == "ảnh"] == ["[CHƯA ĐỌC img] https://example.com/fig1.png — alt: Figure 1"]


def test_article_inside_main_wins_over_related_and_event_blocks():
    raw = ('<main><article><h1>Report</h1><p>' + QUOTE * 10 + '</p><h2>Indicators</h2><p>abc.exe</p></article>'
           '<div class="related-blog-posts"><h2>Related Blog Posts</h2>' + CARDS + '</div>'
           '<div class="events"><h2>Upcoming Events</h2><p><a href="/e">See what is next</a></p></div></main>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    text = " ".join(b["text"] for b in blocks)
    assert QUOTE in text and "abc.exe" in text
    assert "Related Blog Posts" not in text and "Other post" not in text and "Upcoming Events" not in text


def test_related_link_list_inside_article_is_dropped_but_related_prose_stays():
    raw = ('<article><div><h1>Report</h1><p>' + QUOTE * 10 + '</p>'
           '<h2>Related activity</h2><p>' + QUOTE + ' The same actor also used scheduled tasks.</p></div>'
           '<section><div><h5>Related articles</h5></div>' + CARDS + '</section></article>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    text = " ".join(b["text"] for b in blocks)
    assert "Related activity" in text and "scheduled tasks" in text      # văn xuôi, ít liên kết: giữ
    assert "Related articles" not in text and "Other post" not in text
    assert not [b for b in blocks if b["kind"] == "ảnh"]


def test_pre_in_table_cell_stays_a_code_block():
    raw = ('<article><p>' + QUOTE * 5 + '</p><table><tr><td>Hunting query</td>'
           '<td><pre>DeviceProcessEvents\n| where FileName =~ "x.exe"</pre></td></tr>'
           '<tr><td>Plain</td><td>row</td></tr></table></article>').encode()
    blocks, _, _ = S1.parse_html(raw, "https://example.com/report")
    kinds = [(b["kind"], b["text"]) for b in blocks if b["kind"] != "đoạn văn"]
    assert kinds == [("dòng bảng", "Hunting query |"), ("mã/truy vấn", 'DeviceProcessEvents\n| where FileName =~ "x.exe"'),
                     ("dòng bảng", "Plain | row")]


@pytest.mark.parametrize("changed", ["source.html", "segments.jsonl", "provenance.json"])
def test_bundle_detects_changed_inputs(bundle, changed):
    with (bundle / changed).open("ab") as f:
        f.write(b" ")
    with pytest.raises(ValueError, match="đã đổi"):
        S1.load_bundle(bundle)


def test_no_overwrite_and_path_id(tmp_path, bundle):
    with pytest.raises(ValueError, match="đã tồn tại"):
        S1.ingest(str(bundle / "source.html"), "N", bundle)
    with pytest.raises(ValueError, match="Mã report"):
        S1.ingest(str(bundle / "source.html"), "../oops", tmp_path / "other")


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "192.168.1.1"])
def test_public_url_rejects_internal_resolutions(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (address, 443))])
    with pytest.raises(ValueError, match="không công khai"):
        S1.public_address("https://public-looking.example/report")


def test_redirect_revalidates_destination(monkeypatch):
    checked = []
    def resolve(url):
        checked.append(url)
        if "127.0.0.1" in url:
            raise ValueError("blocked")
        return "example.com", 443, "1.1.1.1"
    class Connection:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): pass
        def getresponse(self): return self
        status = 302
        def getheader(self, key): return "http://127.0.0.1/private"
        def close(self): pass
    monkeypatch.setattr(S1, "public_address", resolve)
    monkeypatch.setattr(S1.http.client, "HTTPSConnection", Connection)
    with pytest.raises(ValueError, match="blocked"):
        S1.fetch("https://example.com/report")
    assert len(checked) == 2


def test_pdf_text_columns_and_blank_page(tmp_path):
    from reportlab.pdfgen.canvas import Canvas
    source = tmp_path / "report.pdf"
    c = Canvas(str(source), pagesize=(600, 800))
    c.setFont("Helvetica-Bold", 20)
    c.drawString(40, 750, "Test report")
    c.setFont("Helvetica", 10)
    for y, left, right in [(700, "Left one.", "Right one."), (680, "Left two.", "Right two.")]:
        c.drawString(40, y, left)
        c.drawString(340, y, right)
    c.showPage()
    c.rect(100, 100, 20, 20)
    c.showPage()
    c.save()
    out = tmp_path / "pdf"
    manifest = S1.ingest(str(source), "PDF", out)
    _, segs, prov = S1.load_bundle(out)
    text = " ".join(s["van_ban"] for s in segs)
    assert text.index("Left two") < text.index("Right one")
    assert any(p["page"] == 2 and p["extraction"] == "unread" for p in prov.values())
    assert all("bbox" in p for p in prov.values())
    assert manifest["status"] == "partial"


def test_pdf_table_keeps_rows_once(tmp_path):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    from reportlab.lib import colors
    source = tmp_path / "table.pdf"
    table = Table([["Type", "Value"], ["Domain", "sample[.]invalid"]])
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 1, colors.black)]))
    SimpleDocTemplate(str(source)).build([table])
    blocks, _, _ = S1.parse_pdf(source.read_bytes())
    assert sum("sample[.]invalid" in b["text"] for b in blocks) == 1
    assert any(b["kind"] == "dòng bảng" for b in blocks)


def test_retrieval_uses_only_definitions(stix):
    index = TechniqueIndex.from_stix(stix)
    assert index.search(QUOTE, 1)[0]["technique_id"] == "T1047"
    assert "PROCEDURE EXAMPLE" not in json.dumps(index.documents)
    assert index.search("zzzzzzzz", 3) == []


def test_units_cover_long_segment_without_losing_characters():
    text = "Word with punctuation. " * 200
    seg = {"ma_doan": "X-1", "van_ban": text, "loai": "đoạn văn"}
    result = S2.units([seg], {"X-1": {"extraction": "text"}}, max_chars=500)
    assert "".join(u["text"] for u in result) == text
    assert all(len(u["text"]) <= 500 for u in result)
    assert result[1]["same_segment_context_before"]


def test_prepare_and_cli_no_labels_or_api(bundle, stix, tmp_path, monkeypatch):
    monkeypatch.setattr("cti_hunt.cli._labels_gate", lambda *a: pytest.fail("must not read labels"))
    out = tmp_path / "prepared"
    result, client = run_extract(bundle, stix, out)
    assert result["status"] == "prepared" and not client.calls
    requests = json.loads((out / "requests.json").read_text(encoding="utf-8"))
    target = json.loads(requests[0]["user"])["targets"][0]
    assert target["section"] == "Execution" and target["neighbors"]
    assert target["candidates"][0]["technique_id"] == "T1047"
    assert not (out / "contract_a.json").exists()


def test_cost_metadata_is_outside_fingerprint_and_legacy_metadata_resumes(bundle, stix, tmp_path, monkeypatch):
    out = tmp_path / "legacy-meta"
    result, _ = run_extract(bundle, stix, out)
    assert "uoc_tinh_chi_phi" in result and result["uoc_tinh_chi_phi"] is None
    saved = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    fingerprint = saved["fingerprint"]
    saved.pop("uoc_tinh_chi_phi")  # Format before H2, with the same pinned source version.
    S1.write_json(out / "meta.json", saved)
    monkeypatch.setattr(S2, "estimate_cost", lambda *a: {"typical_usd": "9.000000"})
    preview, client = run_extract(bundle, stix, out, resume=True)
    assert preview["fingerprint"] == fingerprint and not client.calls
    assert json.loads((out / "meta.json").read_text(encoding="utf-8")) == saved
    resumed, client = run_extract(bundle, stix, out, send=True, resume=True)
    assert resumed["fingerprint"] == fingerprint and len(client.calls) == 1
    assert resumed["uoc_tinh_chi_phi"] == {"typical_usd": "9.000000"}


def test_cli_dry_run_displays_and_saves_cost_without_api(bundle, stix, tmp_path, monkeypatch, capsys):
    import yaml
    from cti_hunt import report_cli
    original_load = config.load
    monkeypatch.setattr(report_cli.config, "load", lambda name: {
        "attack": {"stix_path": str(stix), "stix_sha256": S1.digest(stix.read_bytes())}
    } if name == "reports" else original_load(name))
    monkeypatch.setattr("cti_hunt.llm.providers.from_config", lambda *a: pytest.fail("API client created"))
    cfg = tmp_path / "llm-cost.yaml"
    cfg.write_text(yaml.safe_dump({"provider": "anthropic", "model": "claude-sonnet-5",
                                  "max_output_tokens": 32000}), encoding="utf-8")
    out = tmp_path / "cli-cost"
    assert main(["extract-report", str(bundle), "--out", str(out), "--llm-config", str(cfg), "--dry-run"]) == 0
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    estimate = meta["uoc_tinh_chi_phi"]
    output = capsys.readouterr().out
    assert estimate["batches"] == meta["batches"] and not meta["api_called"]
    assert estimate["typical_usd"] in output and estimate["reserve_usd"] in output
    assert "token vào" in output and "Chưa gọi API" in output


def test_ui_cost_preview_and_old_metadata_are_read_only(bundle, stix, tmp_path, monkeypatch):
    from cti_hunt import demo
    original_load = config.load
    monkeypatch.setattr(config, "load", lambda name: {
        "attack": {"stix_path": str(stix), "stix_sha256": S1.digest(stix.read_bytes())}
    } if name == "reports" else {"model": "claude-sonnet-5", "max_output_tokens": 32000}
        if name == "llm_hunt" else original_load(name))
    monkeypatch.setattr("cti_hunt.llm.providers.from_config", lambda *a: pytest.fail("API client created"))
    before = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    estimate = demo.extraction_cost(bundle)
    assert estimate["batches"] == 1 and estimate["input_tokens"] > 0
    assert {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()} == before
    out = bundle / "extraction"
    run_extract(bundle, stix, out)
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    meta.pop("uoc_tinh_chi_phi")
    meta["llm_config"] = {"model": "claude-opus-5-5", "max_output_tokens": 32000}
    S1.write_json(out / "meta.json", meta)
    before = (out / "meta.json").read_bytes()
    old_estimate = demo.extraction_cost(bundle, out)
    assert old_estimate["model"] == "claude-opus-5-5"
    assert (out / "meta.json").read_bytes() == before


@pytest.mark.parametrize("updates", [
    {"quote": "invented quote"}, {"quote": ""}, {"quote": QUOTE.lower()}, {"segment_id": "NEW-0001"},
    {"technique_id": "T9999"}, {"tactic": "persistence"}, {"rationale": " "},
    {"context": {"command_example": "invented command"}},
])
def test_invalid_evidence_is_rejected(bundle, stix, tmp_path, updates):
    result, _ = run_extract(bundle, stix, tmp_path / "out", [{"items": [item(**updates)]}], send=True)
    assert result["accepted_ttp"] == 0 and result["rejected_items"] == 1
    audit = json.loads((tmp_path / "out/evidence_audit.json").read_text(encoding="utf-8"))
    assert audit[0]["status"] == "rejected" and audit[0]["reason"]


def test_extract_resume_no_repeat_and_input_guard(bundle, stix, tmp_path):
    out = tmp_path / "extract"
    run_extract(bundle, stix, out)  # prepare
    result, client = run_extract(bundle, stix, out, send=True, resume=True)
    assert result["accepted_ttp"] == 1 and len(client.calls) == 1
    result, client = run_extract(bundle, stix, out, send=True, resume=True)
    assert result["accepted_ttp"] == 1 and not client.calls
    with pytest.raises(ValueError, match="thay đổi"):
        run_extract(bundle, stix, out, send=True, resume=True, top_k=2)


def test_failed_batch_never_publishes_complete_contract(bundle, stix, tmp_path):
    out = tmp_path / "failed"
    with pytest.raises(RuntimeError):
        run_extract(bundle, stix, out, [{"items": [item()]}, RuntimeError("transport")], send=True, batch_size=1)
    assert not (out / "contract_a.json").exists()
    assert json.loads((out / "meta.json").read_text(encoding="utf-8"))["status"] == "failed"
    result, client = run_extract(bundle, stix, out, [{"items": []}], send=True, resume=True, batch_size=1)
    assert len(client.calls) == 1 and result["accepted_ttp"] == 1


def test_refusal_cannot_be_resumed(bundle, stix, tmp_path):
    from cti_hunt.llm.providers import RefusalError
    out = tmp_path / "refusal"
    with pytest.raises(RefusalError):
        run_extract(bundle, stix, out, [RefusalError("refused")], send=True)
    with pytest.raises(ValueError, match="từ chối"):
        run_extract(bundle, stix, out, send=True, resume=True)


def test_truncated_response_is_not_published_or_reused(bundle, stix, tmp_path):
    class Truncated:
        def complete_json(self, system, user, schema, log):
            log({"stop_reason": "max_tokens"})
            return {"items": [item()]}
    out = tmp_path / "truncated"
    with pytest.raises(ValueError, match="max_tokens"):
        S2.run(bundle, stix, PROMPT, LLM_CFG, out, s2_ioc.load_rules(config.ROOT / "configs/ioc_rules.yaml"),
               send=True, llm=Truncated())
    assert not (out / "contract_a.json").exists()
    with pytest.raises(ValueError, match="max_tokens"):
        run_extract(bundle, stix, out, send=True, resume=True)


def test_outside_candidate_requires_explicit_reason(bundle, stix):
    _, requests = S2.prepare(bundle, stix, PROMPT, LLM_CFG, top_k=1)
    _, segs, prov = S1.load_bundle(bundle)
    catalog = AttackCatalog.from_stix(stix)
    accepted, audit = S2.validate_items({"items": [item(technique_id="T1111")]}, requests[0], segs, prov, catalog)
    assert not accepted and "ứng viên" in audit[0]["reason"]
    accepted, audit = S2.validate_items({"items": [item(technique_id="T1111", outside_candidates_reason="Model explanation requiring review")]}, requests[0], segs, prov, catalog)
    assert accepted and audit[0]["outside_candidates"] is True
    assert audit[0]["semantic_review"] == "not_independently_verified"


def test_contract_flows_to_telemetry_and_graph_review(bundle, stix, tmp_path, work):
    from cti_hunt.report_cli import coverage
    from cti_hunt.data.store import connect
    from cti_hunt.agent.graph import PipelinePlanner, build_graph
    from cti_hunt.agent.stage_tools import StageTools
    from cti_hunt.adapters.duckdb_sigma import load_catalog
    from cti_hunt.llm.prompting import load_sections
    out = tmp_path / "extracted"
    run_extract(bundle, stix, out, send=True)
    ca = ContractA.model_validate_json((out / "contract_a.json").read_text(encoding="utf-8"))
    result = coverage(ca, work)
    assert result["labels_used"] is False
    assert result["techniques"][0]["technique_id"] == "T1047"
    cfg = config.load("agent")
    cat = s3_telemetry.load_catalog(config.ROOT / "configs/telemetry_catalog.yaml")
    con = connect(work)
    profile = s3_telemetry.build_profile(con, cat, "fixture")
    mock_hyp = {"ttp_refs": [0], "behavior": "Process created by WMI", "scope": "All Windows hosts",
                "timeframe": "Full dataset", "data_source": "microsoft-windows-sysmon/operational",
                "event_ids": [1], "key_fields": ["ParentImage", "Image"], "rationale": "Source describes WMI process execution"}
    review = tmp_path / "graph"
    tools = StageTools(ca, s3_telemetry.apply_profile(cat, profile),
                       load_catalog(config.ROOT / "configs/logsource_catalog.yaml"), con, cfg,
                       MockClient(responses=[{"items": [mock_hyp]}]), MockClient(),
                       load_sections(config.ROOT / cfg["prompt_khau4"]),
                       load_sections(config.ROOT / cfg["prompt_khau4_pivot"]),
                       load_sections(config.ROOT / cfg["prompt_khau5"], ("SYSTEM", "USER", "REPAIR")),
                       review, dataset_kind="fixture", dataset_id="fixture", attack_catalog=AttackCatalog.from_stix(stix))
    try:
        graph = build_graph(PipelinePlanner(), tools, cfg, review)
        state = graph.invoke(tools.initial_state(), {"configurable": {"thread_id": "new-report-test"}})
        assert state.get("__interrupt__")
        assert (review / "round_01/duyet.yaml").exists()
        assert ca.ttps[0].source_span.text == QUOTE
    finally:
        con.close()


def test_cli_ingest_produces_review(tmp_path, capsys):
    source = tmp_path / "cli.html"
    source.write_text(f"<article><p>{QUOTE}</p></article>", encoding="utf-8")
    out = tmp_path / "cli"
    assert main(["ingest-report", str(source), "--id", "CLI", "--out", str(out)]) == 0
    assert "review.html" in capsys.readouterr().out
    assert (out / "review.html").exists()


def test_extract_cli_defaults_to_no_api_and_rejects_unbudgeted_send(bundle, stix, tmp_path, monkeypatch):
    import yaml
    from cti_hunt import report_cli
    original_load = config.load
    monkeypatch.setattr(report_cli.config, "load", lambda name: {
        "attack": {"stix_path": str(stix), "stix_sha256": S1.digest(stix.read_bytes())}
    } if name == "reports" else original_load(name))
    monkeypatch.setattr("cti_hunt.cli._labels_gate", lambda *args: pytest.fail("labels gate used"))
    monkeypatch.setattr("cti_hunt.llm.providers.from_config", lambda *args: pytest.fail("API client created"))
    cfg = tmp_path / "llm.yaml"
    cfg.write_text(yaml.safe_dump(LLM_CFG), encoding="utf-8")
    args = ["extract-report", str(bundle), "--out", str(tmp_path / "cli-extract"), "--llm-config", str(cfg)]
    assert main(args) == 0
    assert main(args + ["--send", "--resume"]) == 1


def test_unbudgeted_library_send_is_blocked(bundle, stix, tmp_path):
    with pytest.raises(ValueError, match="budget_ledger"):
        S2.run(bundle, stix, PROMPT, LLM_CFG, tmp_path / "unbudgeted", {}, send=True)


def test_no_contract_for_context_only_quote(bundle, stix, tmp_path):
    # Batch size 1: segment 3 is visible as neighboring context but cannot be a target in batch 0.
    result, _ = run_extract(bundle, stix, tmp_path / "context", [
        {"items": [item(segment_id="NEW-0003", quote="The next paragraph provides context.")]}, {"items": []}
    ], send=True, batch_size=1)
    assert result["accepted_ttp"] == 0 and result["rejected_items"] == 1


@pytest.mark.parametrize("approved", [False, True])
def test_ocr_gate_covers_iocs_and_prompts_even_with_accept_partial(stix, tmp_path, approved):
    import base64
    from PIL import Image
    from cti_hunt.stages import s1_ocr as OCR
    raw = io.BytesIO()
    Image.new("RGB", (80, 40), "white").save(raw, format="PNG")
    encoded = base64.b64encode(raw.getvalue()).decode()
    source = tmp_path / "input.html"
    source.write_text(f'<article><p>{QUOTE}</p><img src="data:image/png;base64,{encoded}"></article>', encoding="utf-8")
    native, enriched = tmp_path / "native", tmp_path / "ocr"
    S1.ingest(str(source), "GATE", native)
    class Engine:
        meta = {"engine": "test"}
        def recognize(self, raw):
            return {"text": "203.0.113.9", "lines": [{"text": "203.0.113.9", "score": 1.0}]}
    OCR.enrich(native, enriched, engine=Engine())
    if approved:
        form = json.loads((enriched / "ocr_review_template.json").read_text(encoding="utf-8"))
        form.update(reviewer="Synthetic test", reviewed_at="2026-09-28T00:00:00Z")
        form["decisions"][0].update(status="approved", reason="Synthetic reference")
        review = tmp_path / "review.json"
        S1.write_json(review, form)
        OCR.apply_review(enriched, review, tmp_path / "reviewed")
        enriched = tmp_path / "reviewed"
    output = tmp_path / "extracted"
    result, _ = run_extract(enriched, stix, output, [{"items": []}], send=True, accept_partial=True)
    contract = ContractA.model_validate_json((output / "contract_a.json").read_text(encoding="utf-8"))
    assert any(i.value == "203.0.113.9" for i in contract.iocs) is approved
    assert ("203.0.113.9" in (output / "requests.json").read_text(encoding="utf-8")) is approved


# 07/10: trích một phần report theo mã đoạn (người vận hành duyệt, ca CTI thật IcedID) — mặc định không đổi.
def test_partial_extraction_targets_only_selected_segments(bundle, stix, tmp_path):
    out = tmp_path / "partial"
    result, client = run_extract(bundle, stix, out, segments_selected=["NEW-0003"])
    requests = json.loads((out / "requests.json").read_text(encoding="utf-8"))
    targets = [t["segment_id"] for r in requests for t in json.loads(r["user"])["targets"]]
    assert targets == ["NEW-0003"] and not client.calls
    assert result["partial_extraction"] and result["selected_segments"] == ["NEW-0003"]
    assert result["target_units"] == 1 and result["target_units_total"] > 1
    full, _ = run_extract(bundle, stix, tmp_path / "full")
    assert "partial_extraction" not in full and "selected_segments" not in full


@pytest.mark.parametrize("selected", [["NEW-9999"], ["NEW-0001"], []])
def test_partial_extraction_rejects_unknown_unreadable_or_empty_selection(bundle, stix, tmp_path, selected):
    with pytest.raises(ValueError, match="Chọn đoạn"):
        run_extract(bundle, stix, tmp_path / "bad", segments_selected=selected)


def test_partial_send_keeps_only_selected_evidence(bundle, stix, tmp_path):
    out = tmp_path / "partial-send"
    other = item(segment_id="NEW-0003", quote="The next paragraph provides context.")
    result, client = run_extract(bundle, stix, out, [{"items": [item(), other]}], send=True,
                                 segments_selected=["NEW-0002"])
    assert len(client.calls) == 1 and result["accepted_ttp"] == 1 and result["rejected_items"] == 1
    contract = json.loads((out / "contract_a.json").read_text(encoding="utf-8"))
    assert {t["source_span"]["segment_id"] for t in contract["ttps"]} == {"NEW-0002"}
    with pytest.raises(ValueError, match="thay đổi"):
        run_extract(bundle, stix, out, send=True, resume=True)  # whole-report resume is another run


def test_extract_cli_segments_option(bundle, stix, tmp_path, monkeypatch):
    import yaml
    from cti_hunt import report_cli
    original_load = config.load
    monkeypatch.setattr(report_cli.config, "load", lambda name: {
        "attack": {"stix_path": str(stix), "stix_sha256": S1.digest(stix.read_bytes())}
    } if name == "reports" else original_load(name))
    cfg = tmp_path / "llm.yaml"
    cfg.write_text(yaml.safe_dump(LLM_CFG), encoding="utf-8")
    out = tmp_path / "cli-partial"
    assert main(["extract-report", str(bundle), "--out", str(out), "--llm-config", str(cfg),
                 "--segments", "NEW-0002"]) == 0
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["selected_segments"] == ["NEW-0002"] and meta["status"] == "prepared"
    assert main(["extract-report", str(bundle), "--out", str(tmp_path / "cli-bad"), "--llm-config", str(cfg),
                 "--segments", "NEW-9999"]) == 1
