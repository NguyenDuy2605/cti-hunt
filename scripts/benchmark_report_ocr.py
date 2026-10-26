"""Reproducible development fixtures, independent of CTI evaluation labels.

Run with .venv/Scripts/python.exe scripts/benchmark_report_ocr.py --out NEW_DIR
No network, no LLM, no transcript auto-approval. References precede recognition.
"""
from __future__ import annotations

import argparse
import io
import platform
import re
import time
from pathlib import Path

from cti_hunt.stages import s1_ingest as ingest
from cti_hunt.stages import s1_ocr as ocr


def distance(a, b):
    previous = list(range(len(b) + 1))
    for i, left in enumerate(a, 1):
        current = [i]
        for j, right in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (left != right)))
        previous = current
    return previous[-1]


def metrics(reference, hypothesis, strings=(), anchors=(), technical_text=None):
    ref = re.sub(r"\s+", " ", reference).strip()
    hyp = re.sub(r"\s+", " ", hypothesis).strip()
    if not ref:
        raise ValueError("Reference must not be empty")
    positions = [hyp.find(a) for a in anchors]
    # Technical fixtures place each string on its own line or in a table cell.
    # Substring matching would falsely accept 192.0.2.10 inside 192.0.2.100.
    raw = hypothesis if technical_text is None else technical_text
    cells = {cell.strip() for line in raw.splitlines() for cell in line.split(" | ")}
    return {"character_edits": distance(ref, hyp), "reference_characters": len(ref),
            "cer": distance(ref, hyp) / len(ref), "word_edits": distance(ref.split(), hyp.split()),
            "reference_words": len(ref.split()), "wer": distance(ref.split(), hyp.split()) / len(ref.split()),
            "technical_exact": [{"reference": s, "found_verbatim": s in cells} for s in strings],
            "anchor_order_ok": (all(p >= 0 for p in positions) and positions == sorted(positions)) if anchors else None,
            "anchor_occurrences": {a: hypothesis.count(a) for a in anchors}}


def build_fixtures(folder):
    from PIL import Image, ImageFilter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    folder.mkdir()
    prose = ["Synthetic CTI report for ingestion testing.",
             "The operator launched a command interpreter on the test host.",
             "Process creation logs can preserve the parent process and command line.",
             "This document describes a simulation, not a confirmed intrusion."]
    technical = ["powershell.exe -NoProfile -Command Get-Date", r"C:\Windows\System32\cmd.exe",
                 "192.0.2.10", "https://example.invalid/a?x=1&y=0", "0123456789abcdef0123456789abcdef"]
    columns = ["ALPHA begins the first column.", "BRAVO finishes the first column.",
               "CHARLIE begins the second column.", "DELTA finishes the second column."]
    table = ["Field Value", "Tool powershell.exe", "Host WIN-TEST", "Address 192.0.2.10"]
    refs = {"prose": {"text": "\n".join(prose), "technical": [], "anchors": []},
            "technical": {"text": "\n".join(technical), "technical": technical, "anchors": []},
            "columns": {"text": "\n".join(columns), "technical": [], "anchors": ["ALPHA", "BRAVO", "CHARLIE", "DELTA"]},
            "table": {"text": "\n".join(table), "technical": ["powershell.exe", "WIN-TEST", "192.0.2.10"], "anchors": ["Field", "Tool", "Host", "Address"]}}
    # Fixed references are written before OCR or any metric computation.
    ingest.write_json(folder / "references.json", refs)
    for name, lines in (("prose", prose), ("technical", technical), ("columns", columns), ("table", table)):
        doc = canvas.Canvas(str(folder / f"{name}.pdf"), pagesize=(612, 420), invariant=1)
        doc.setFont("Courier" if name == "technical" else "Helvetica", 12)
        if name == "columns":
            for text, x, y in zip(lines, [30, 30, 318, 318], [370, 340, 370, 340]):
                doc.drawString(x, y, text)
        elif name == "table":
            for i, line in enumerate(lines):
                left, right = line.split(" ", 1)
                doc.drawString(40, 370 - i * 32, left)
                doc.drawString(210, 370 - i * 32, right)
            for y in [388, 356, 324, 292, 260]:
                doc.line(30, y, 560, y)
            for x in [30, 200, 560]:
                doc.line(x, 260, x, 388)
        else:
            for i, line in enumerate(lines):
                doc.drawString(30, 370 - i * 32, line)
        doc.save()
        png, _ = ocr._pdf_image((folder / f"{name}.pdf").read_bytes(), {"page": 1, "bbox": [0, 0, 612, 420]}, 200)
        (folder / f"{name}.png").write_bytes(png)
        scan = canvas.Canvas(str(folder / f"{name}_scan.pdf"), pagesize=(612, 420), invariant=1)
        scan.drawImage(ImageReader(io.BytesIO(png)), 0, 0, width=612, height=420)
        scan.save()
    with Image.open(folder / "technical.png") as im:
        im.convert("RGB").save(folder / "technical.jpg", quality=80)
        im.resize((510, 350)).filter(ImageFilter.GaussianBlur(0.7)).save(folder / "technical_degraded.png")
    mixed = canvas.Canvas(str(folder / "mixed.pdf"), pagesize=(612, 600), invariant=1)
    mixed.setFont("Helvetica", 12)
    mixed.drawString(30, 560, prose[0])
    mixed.drawImage(str(folder / "technical.png"), 0, 0, width=612, height=420)
    mixed.save()
    return refs


def run(out):
    if out.exists():
        raise ValueError("Use a new output directory; previous evidence is immutable")
    out.mkdir(parents=True)
    refs = build_fixtures(out / "fixtures")
    engine = ocr.RapidEngine()
    environment = {"python": platform.python_version(), "platform": platform.platform(), "engine": engine.meta,
                   "script_sha256": ingest.digest(Path(__file__).read_bytes()),
                   "parser_sha256": ingest.digest(Path(ingest.__file__).read_bytes()),
                   "ocr_code_sha256": ingest.digest(Path(ocr.__file__).read_bytes()),
                   "scope": "synthetic development fixtures, not real-report accuracy; no LLM or human approval",
                   "scoring": "collapse whitespace for CER/WER only; remove native table cell delimiter ' | '; technical exact uses raw text"}
    ingest.write_json(out / "environment.json", environment)
    results = []
    for name, ref in refs.items():
        start = time.monotonic()
        native = out / f"{name}_native"
        ingest.ingest(str(out / "fixtures" / f"{name}.pdf"), f"DEV-{name.upper()}", native)
        m, segs, _ = ingest.load_bundle(native)
        text = "\n".join(s["van_ban"] for s in segs if s["loai"] != "ảnh")
        scored = text.replace(" | ", " ") if name == "table" else text
        results.append({"case": name, "method": "native_pdf", "text": text, "seconds": round(time.monotonic()-start, 4),
                        "metrics": metrics(ref["text"], scored, ref["technical"], ref["anchors"], technical_text=text), "warnings": m["warnings"]})
        result = engine.recognize((out / "fixtures" / f"{name}.png").read_bytes())
        ingest.write_json(out / f"{name}_fullpage_ocr.json", result)
        results.append({"case": name, "method": "fullpage_ocr_comparison", "text": result["text"], "seconds": result["seconds"],
                        "metrics": metrics(ref["text"], result["text"], ref["technical"], ref["anchors"])})
        scan = out / f"{name}_scan_native"
        ingest.ingest(str(out / "fixtures" / f"{name}_scan.pdf"), f"DEV-{name.upper()}-SCAN", scan)
        enriched = out / f"{name}_scan_ocr"
        ocr.enrich(scan, enriched, engine=engine)
        em, es, _ = ingest.load_bundle(enriched)
        text = "\n".join(s["van_ban"] for s in es if s["loai"] != "ảnh")
        results.append({"case": name, "method": "scanned_pdf_pipeline", "text": text,
                        "metrics": metrics(ref["text"], text, ref["technical"], ref["anchors"]),
                        "pending": em["ocr_pending_blocks"], "unread": em["unread_blocks"]})
        print(f"Measured {name}: native, fullpage OCR, scanned PDF", flush=True)
    for filename in ("technical.jpg", "technical_degraded.png", "mixed.pdf"):
        name = Path(filename).stem + ("_jpeg" if filename.endswith("jpg") else "")
        native = out / f"{name}_input"
        ingest.ingest(str(out / "fixtures" / filename), f"DEV-{name.upper()}", native)
        enriched = out / f"{name}_ocr"
        ocr.enrich(native, enriched, engine=engine)
        em, es, _ = ingest.load_bundle(enriched)
        text = "\n".join(s["van_ban"] for s in es if s["loai"] != "ảnh")
        reference = (refs["prose"]["text"].splitlines()[0] + "\n" if name == "mixed" else "") + refs["technical"]["text"]
        results.append({"case": name, "method": "image_or_mixed_pipeline", "text": text,
                        "metrics": metrics(reference, text, refs["technical"]["technical"]),
                        "pending": em["ocr_pending_blocks"], "unread": em["unread_blocks"]})
        print(f"Measured {name}", flush=True)
    ingest.write_json(out / "results.json", results)
    lines = ["# Synthetic development benchmark", "", "No LLM calls; OCR proposals remain pending review.", "",
             "| Case | Method | CER | WER | Technical exact | Anchor order |", "|---|---|---:|---:|---:|---|"]
    for r in results:
        m = r["metrics"]
        exact = m["technical_exact"]
        lines.append(f"| {r['case']} | {r['method']} | {m['cer']:.4f} | {m['wer']:.4f} | "
                     f"{sum(x['found_verbatim'] for x in exact)}/{len(exact)} | {m['anchor_order_ok']} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(out / "summary.md", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args().out)
