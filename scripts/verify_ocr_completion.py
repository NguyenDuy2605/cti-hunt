"""Offline engine comparison and fresh fixtures. No labels, APIs, or auto-review."""
import argparse
import json
import platform
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageFilter

from cti_hunt.stages import s1_ingest as S1, s1_ocr as OCR, s1_layout
from benchmark_report_ocr import metrics


def fresh(folder):
    folder.mkdir()
    font_path = Path("C:/Windows/Fonts/arial.ttf")
    mono_path = Path("C:/Windows/Fonts/consola.ttf")
    font = ImageFont.truetype(str(font_path), 28)
    mono = ImageFont.truetype(str(mono_path), 27)
    # This content is fixed and written before running any OCR on these images.
    technical = [r"C:\ProgramData\Lab\stage_07.ps1", "203.0.113.27", "https://sample.invalid/log?id=701&mode=read",
                 "a1b2c3d4e5f60718293a4b5c6d7e8f90", "whoami.exe /all", "Get-Process -Name explorer"]
    prose = ["Analysts observed an unusual child process on a workstation.",
             "The report does not establish how the account was obtained.",
             "Evidence includes process creation and authentication events."]
    refs = {
        "fresh_technical": {"text": "\n".join(technical), "technical": technical, "anchors": []},
        "fresh_prose": {"text": "\n".join(prose), "technical": [], "anchors": []},
        "fresh_two_columns": {"text": "\n".join(["ORION first observation.", "LYRA second observation.", "VEGA third observation.", "RIGEL final observation."]),
                              "technical": [], "anchors": ["ORION", "LYRA", "VEGA", "RIGEL"]},
        "fresh_three_columns": {"text": "\n".join(["Separate observations from three hosts", "HOSTA event one.", "HOSTA event two.", "HOSTB event one.", "HOSTB event two.", "HOSTC event one.", "HOSTC event two."]),
                                "technical": [], "anchors": ["HOSTA event one.", "HOSTA event two.", "HOSTB event one.", "HOSTB event two.", "HOSTC event one.", "HOSTC event two."]},
        "fresh_table": {"text": "Key Value\nDomain lab.invalid\nProcess whoami.exe\nHost WORKSTATION-07",
                        "technical": ["lab.invalid", "whoami.exe", "WORKSTATION-07"], "anchors": ["Key", "Domain", "Process", "Host"]},
        "fresh_blank": {"text": "", "technical": [], "anchors": []}}
    refs["fresh_degraded"] = refs["fresh_technical"].copy()
    S1.write_json(folder / "references.json", refs)
    for name, ref in refs.items():
        im = Image.new("RGB", (1500, 650), "white")
        draw = ImageDraw.Draw(im)
        lines = ref["text"].splitlines()
        if name == "fresh_two_columns":
            for text, x, y in zip(lines, [45,45,810,810], [100,160,100,160]):
                draw.text((x,y), text, fill="black", font=font)
        elif name == "fresh_three_columns":
            draw.text((360,30), lines[0], fill="black", font=font)
            for i, text in enumerate(lines[1:]):
                draw.text((40 + (i//2)*500, 120 + (i%2)*70), text, fill="black", font=font)
        elif name == "fresh_table":
            for i, text in enumerate(lines):
                key, val = text.split(" ", 1)
                draw.text((60,70+i*70), key, fill="black", font=font)
                draw.text((440,70+i*70), val, fill="black", font=font)
            for y in range(50, 331, 70):
                draw.line((40,y,1100,y), fill="black", width=3)
            for x in (40,410,1100):
                draw.line((x,50,x,330), fill="black", width=3)
        else:
            for i, text in enumerate(lines):
                draw.text((45,55+65*i), text, fill="black", font=mono if "technical" in name or "degraded" in name else font)
        if name == "fresh_degraded":
            im = im.resize((750,325)).filter(ImageFilter.GaussianBlur(.45))
        im.save(folder / f"{name}.png")
    S1.write_json(folder / "font_hashes.json", {p.name:S1.digest(p.read_bytes()) for p in [font_path,mono_path]})
    return refs


def main(out):
    out.mkdir(parents=True, exist_ok=False)
    references = fresh(out / "fresh")
    old = Path("data/dev/ocr_benchmark_28-9/synthetic_v2/fixtures")
    old_refs = json.loads((old / "references.json").read_text(encoding="utf-8"))
    old_refs["technical_degraded"] = old_refs["technical"]
    engines = {"baseline": OCR.RapidEngine(layout=False),
               "english_layout": OCR.RapidEngine(english=True, layout=True),
               "tesseract": OCR.TesseractEngine(layout=False)}
    S1.write_json(out / "environment.json", {"python": platform.python_version(), "platform": platform.platform(),
                 "engines": {k:v.meta for k,v in engines.items()},
                 "code_sha256": {Path(p).name:S1.digest(Path(p).read_bytes()) for p in [__file__, OCR.__file__, s1_layout.__file__]},
                 "selection": "English v5 plus geometric layout fixed before fresh fixtures; no per-case oracle selection"})
    rows = []
    for split, folder, refs in [("development", old, old_refs), ("fresh", out / "fresh", references)]:
        for name, ref in refs.items():
            for engine_name, engine in engines.items():
                # Fresh fixtures check only the fixed choice vs original baseline.
                if split == "fresh" and engine_name == "tesseract":
                    continue
                result = engine.recognize((folder / f"{name}.png").read_bytes())
                S1.write_json(out / f"{split}_{name}_{engine_name}.json", result)
                score = metrics(ref["text"], result["text"], ref["technical"], ref["anchors"]) if ref["text"] else {"empty_correct": not result["text"].strip()}
                rows.append({"split": split, "case": name, "engine": engine_name, "metrics": score, "seconds": result["seconds"]})
                S1.write_json(out / "results.json", rows)
                print(f"{split} {name} {engine_name}: {score.get('cer',score.get('empty_correct'))}", flush=True)
    lines = ["# OCR comparison", "", "| Split | Case | Engine | CER | Exact | Order |", "|---|---|---|---:|---:|---|"]
    for r in rows:
        m=r["metrics"]; exact=m.get("technical_exact",[])
        lines.append(f"| {r['split']} | {r['case']} | {r['engine']} | {m.get('cer','empty='+str(m.get('empty_correct')))} | {sum(v['found_verbatim'] for v in exact)}/{len(exact)} | {m.get('anchor_order_ok')} |")
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    main(parser.parse_args().out)
