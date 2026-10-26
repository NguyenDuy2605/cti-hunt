"""Download the English Tesseract model explicitly, never during report processing."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

URL = "https://raw.githubusercontent.com/tesseract-ocr/tessdata_best/main/eng.traineddata"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("data/models/tesseract"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / "eng.traineddata"
    if path.exists():
        raise SystemExit("Model already exists; preserve its hash, do not silently replace it")
    with urlopen(Request(URL, headers={"User-Agent": "cti-hunt-model-setup/1"}), timeout=60) as response:
        raw = response.read(30 * 1024 * 1024 + 1)
    if len(raw) > 30 * 1024 * 1024 or len(raw) < 1_000_000:
        raise ValueError("Unexpected model size")
    record = {"url": URL, "file": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    if record["sha256"] != "8280aed0782fe27257a68ea10fe7ef324ca0f8d85bd2fd145d1c2b560bcb66ba":
        raise ValueError("Model differs from pinned English model hash")
    path.write_bytes(raw)
    (args.out / "model_manifest.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
