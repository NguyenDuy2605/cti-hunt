"""Independent DOM comparison for the CERT-EU 2019-021 development input.

Reads the saved full HTML, not parser-produced text as the expected answer.
Only checks this page's block coverage/order; not OCR or semantic accuracy.
"""
import argparse
import json
import re
from pathlib import Path

from bs4 import BeautifulSoup

from cti_hunt.stages.s1_ingest import digest, load_bundle


def check(bundle: Path) -> dict:
    manifest, segments, provenance = load_bundle(bundle)
    expected_sha = "962f1f92716e3db0cebeb847f4a85be1778b9d79c19a4b85e77ebda7defa1168"
    if manifest["source_sha256"] != expected_sha:
        raise ValueError("Không phải snapshot Emotet đã ghim; cần rà lại bộ đối chiếu")
    soup = BeautifulSoup((bundle / "source.html").read_bytes(), "html.parser")
    roots = soup.select(".publication--body")
    if len(roots) != 1:
        raise ValueError("Không xác định duy nhất phần nội dung bài")
    body = roots[0]
    normalize = lambda t: re.sub(r"\s+", " ", t).strip()
    checks = []
    for node in body.select("p, pre, li, h1, h2, h3, h4, h5, h6"):
        if node.find_parent("pre") or (node.name == "li" and node.find(["p", "ul", "ol"])):
            continue
        original = node.get_text().replace("\r\n", "\n").strip()
        if not original:
            continue
        # Prose spacing is normalized; code must preserve internal line breaks.
        value = original if node.name == "pre" else normalize(original)
        matches = [i for i, s in enumerate(segments)
                   if (s["van_ban"] if node.name == "pre" else normalize(s["van_ban"])) == value]
        checks.append({"tag": node.name, "source_text_sha256": digest(value.encode()),
                       "matched_indices": matches, "matched": len(matches) == 1})
    outside = []
    unresolved = []
    for seg in segments:
        nodes = soup.select(provenance[seg["ma_doan"]]["dom_path"])
        if len(nodes) != 1:
            unresolved.append(seg["ma_doan"])
        elif nodes[0] is not body and body not in nodes[0].parents:
            outside.append({"segment_id": seg["ma_doan"], "text": seg["van_ban"]})
    indices = [r["matched_indices"][0] for r in checks if r["matched"]]
    return {"report_id": manifest["report_id"], "source_sha256": expected_sha,
            "comparison": "Saved HTML body DOM vs parser segments; code exact, prose whitespace normalized",
            "expected_blocks": len(checks), "matched_blocks": sum(r["matched"] for r in checks),
            "order_preserved": len(indices) == len(checks) and indices == sorted(set(indices)),
            "checks": checks, "outside_article_body": outside, "unresolved_dom_paths": unresolved,
            "human_review": "pending", "semantic_accuracy": "not_evaluated"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bundle", type=Path)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = check(a.bundle)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("x", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"Khớp {result['matched_blocks']}/{result['expected_blocks']} khối; thứ tự: {result['order_preserved']}; "
          f"{len(result['outside_article_body'])} đoạn ngoài thân bài; {len(result['unresolved_dom_paths'])} vị trí không truy được.")
    raise SystemExit(0 if result["matched_blocks"] == result["expected_blocks"] and result["order_preserved"]
                     and not result["unresolved_dom_paths"] else 1)
