"""Explicitly download the RapidAI English recognition model for local OCR."""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

URL = "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/v3.9.2/onnx/PP-OCRv5/rec/en_PP-OCRv5_rec_mobile.onnx"
SHA256 = "c3461add59bb4323ecba96a492ab75e06dda42467c9e3d0c18db5d1d21924be8"


def main():
    folder = Path("data/models/rapid-english")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "en_PP-OCRv5_rec_mobile.onnx"
    if path.exists():
        raise SystemExit("Model exists; preserve its hash")
    with urlopen(Request(URL, headers={"User-Agent": "cti-hunt-model-setup/1"}), timeout=60) as response:
        raw = response.read(30 * 1024 * 1024 + 1)
    if not 1_000_000 < len(raw) <= 30 * 1024 * 1024:
        raise ValueError("Unexpected model size")
    record = {"url": URL, "file": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    if record["sha256"] != SHA256:
        raise ValueError("Model hash differs from the pinned upstream model list")
    path.write_bytes(raw)
    (folder / "model_v5_manifest.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
