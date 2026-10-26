"""Local OCR enrichment, separate from native extraction and human verification.

Never replace a native text block. OCR proposals remain quarantined from TTP/IOC
until an explicit transcript review creates a new, traceable bundle.
"""
from __future__ import annotations

import base64
import copy
import io
import json
import math
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from . import s1_ingest as S1

OCR_VERSION = "local_ocr_v2"
MAX_PIXELS = 25_000_000
MAX_TARGETS = 60
PARAMS = {"intra_op_num_threads": 2, "inter_op_num_threads": 2, "text_score": 0.0,
          "det_limit_side_len": 736, "max_side_len": 2000, "use_cls": True}


def engine_metadata() -> dict:
    try:
        import importlib.util
        spec = importlib.util.find_spec("rapidocr_onnxruntime")
        if spec is None:
            raise ImportError("rapidocr_onnxruntime")
        folder = Path(spec.origin).parent
        models = {p.name: S1.digest(p.read_bytes()) for p in sorted((folder / "models").glob("*.onnx"))}
        if len(models) != 3:
            raise ValueError("RapidOCR thiếu mô hình đóng gói; không tự tải model khi chạy")
        return {"engine": "rapidocr_onnxruntime", "version": version("rapidocr-onnxruntime"),
                "runtime": version("onnxruntime"), "numpy": version("numpy"), "opencv": version("opencv-python"),
                "pillow": version("Pillow"), "pdfium": version("pypdfium2"),
                "models_sha256": models, "config_sha256": S1.digest((folder / "config.yaml").read_bytes()),
                "parameters": PARAMS, "device": "CPU", "language_scope": "bundled Chinese/English model; CTI checks focus on English",
                "confidence_is_probability_of_correctness": False}
    except ImportError as e:
        raise ValueError('Cần cài OCR cục bộ: pip install -e ".[ocr]"') from e


def normalize_image(raw: bytes) -> tuple[bytes, tuple[int, int]]:
    from PIL import Image, ImageOps
    with Image.open(io.BytesIO(raw)) as source:
        if source.format not in ("PNG", "JPEG", "WEBP", "BMP", "TIFF", "GIF"):
            raise ValueError("Chỉ OCR ảnh raster; SVG và nội dung chủ động không được thực thi")
        if getattr(source, "n_frames", 1) > 1:
            raise ValueError("Ảnh nhiều frame cần tách riêng; không âm thầm chỉ đọc frame đầu")
        if source.width * source.height > MAX_PIXELS:
            raise ValueError("Ảnh vượt giới hạn 25 megapixel")
        image = ImageOps.exif_transpose(source).convert("RGBA")
        background = Image.new("RGBA", image.size, "white")
        background.alpha_composite(image)
        normalized = background.convert("RGB")
        buffer = io.BytesIO()
        normalized.save(buffer, format="PNG")
        return buffer.getvalue(), normalized.size


class RapidEngine:
    def __init__(self, *, english: bool = False, layout: bool = True):
        from rapidocr_onnxruntime import RapidOCR
        self.meta = engine_metadata()
        self.layout = layout
        extra = {}
        if english:
            from .. import config
            model = config.ROOT / "data/models/rapid-english/en_PP-OCRv5_rec_mobile.onnx"
            if not model.is_file():
                raise ValueError("Thiếu model English; chạy scripts/setup_rapid_english.py một lần trước khi OCR")
            expected = "c3461add59bb4323ecba96a492ab75e06dda42467c9e3d0c18db5d1d21924be8"
            if S1.digest(model.read_bytes()) != expected:
                raise ValueError("Model English không khớp hash đã kiểm chứng")
            extra["rec_model_path"] = str(model)
            self.meta.update(recognition_model={"file": model.name, "sha256": expected}, language_scope="English")
        self.meta["layout"] = layout
        self.engine = RapidOCR(**PARAMS, **extra)

    def recognize(self, raw: bytes) -> dict:
        import time
        import numpy as np
        from PIL import Image
        png, size = normalize_image(raw)
        with Image.open(io.BytesIO(png)) as im:
            array = np.asarray(im.convert("RGB"))[:, :, ::-1].copy()
        start = time.monotonic()
        result, timings = self.engine(array)
        lines = []
        for box, text, score in result or []:
            points = [[round(float(x), 2), round(float(y), 2)] for x, y in box]
            if not math.isfinite(float(score)):
                raise ValueError("Engine trả confidence không hữu hạn")
            lines.append({"polygon_px": points, "text": text, "score": float(score)})
        raw_lines = copy.deepcopy(lines)
        layout_meta = {"mode": "engine_order"}
        if self.layout:
            from .s1_layout import reading_order, ruled_table
            with Image.open(io.BytesIO(png)) as im:
                order, layout_meta = reading_order(lines, table=ruled_table(im))
            lines = [lines[i] for i in order]
        return {"text": "\n".join(line["text"] for line in lines), "lines": lines,
                "raw_engine_lines": raw_lines, "layout": layout_meta,
                "seconds": round(time.monotonic() - start, 4), "size_px": list(size),
                "engine_timings": [float(x) for x in timings] if timings else [], "engine": self.meta,
                "input_sha256": S1.digest(raw), "normalized_sha256": S1.digest(png),
                "reading_order": "geometric; raw engine order retained" if self.layout else "engine order; requires review"}


def tesseract_metadata() -> dict:
    from .. import config
    import tesserocr
    data_file = config.ROOT / "data/models/tesseract/eng.traineddata"
    expected = "8280aed0782fe27257a68ea10fe7ef324ca0f8d85bd2fd145d1c2b560bcb66ba"
    if not data_file.is_file() or S1.digest(data_file.read_bytes()) != expected:
        raise ValueError("Thiếu/sai hash model Tesseract English; chạy scripts/setup_tesseract_data.py")
    return {
        "engine": "tesseract", "wrapper_version": version("tesserocr"),
        "version": tesserocr.tesseract_version(), "traineddata_sha256": expected,
        "parameters": {"psm": "AUTO", "oem": "LSTM_ONLY", "load_system_dawg": False, "load_freq_dawg": False},
        "device": "CPU",
        "language_scope": "English (eng.traineddata)",
        "confidence_is_probability_of_correctness": False
    }


class TesseractEngine:
    def __init__(self, *, layout: bool = True):
        self.meta = tesseract_metadata()
        self.layout = layout
        self.meta["layout"] = layout

    def recognize(self, raw: bytes) -> dict:
        import time
        from tesserocr import PyTessBaseAPI, OEM, PSM, RIL, iterate_level
        from PIL import Image
        from .. import config
        tess_folder = config.ROOT / "data/models/tesseract"
        png, size = normalize_image(raw)
        with Image.open(io.BytesIO(png)) as im, PyTessBaseAPI(path=str(tess_folder), lang="eng",
                oem=OEM.LSTM_ONLY, psm=PSM.AUTO,
                variables={"load_system_dawg": "0", "load_freq_dawg": "0"}) as api:
            start = time.monotonic()
            api.SetImage(im)
            api.Recognize()
            lines = []
            iterator = api.GetIterator()
            if iterator:
                for line in iterate_level(iterator, RIL.TEXTLINE):
                    txt = (line.GetUTF8Text(RIL.TEXTLINE) or "").strip()
                    if not txt:
                        continue
                    x, y, right, bottom = line.BoundingBox(RIL.TEXTLINE)
                    lines.append({"polygon_px": [[x, y], [right, y], [right, bottom], [x, bottom]],
                                  "text": txt, "score": line.Confidence(RIL.TEXTLINE) / 100})
            raw_lines = copy.deepcopy(lines)
            layout_meta = {"mode": "engine_order"}
            if self.layout:
                from .s1_layout import reading_order, ruled_table
                order, layout_meta = reading_order(lines, table=ruled_table(im))
                lines = [lines[i] for i in order]
            return {"text": "\n".join(line["text"] for line in lines), "lines": lines,
                    "raw_engine_lines": raw_lines, "layout": layout_meta,
                    "seconds": round(time.monotonic() - start, 4), "size_px": list(size),
                    "engine_timings": [], "engine": self.meta,
                    "input_sha256": S1.digest(raw), "normalized_sha256": S1.digest(png),
                    "reading_order": "geometric; raw engine order retained" if self.layout else "engine order; requires review"}


class LocalWorker:
    """Per-image process bounds CPU runtime and avoids UI windows on Windows."""
    def __init__(self, timeout: int = 120, engine_name: str = "rapid-en"):
        if engine_name not in ("rapid", "rapid-en", "tesseract"):
            raise ValueError("Engine phải rapid, rapid-en hoặc tesseract")
        if engine_name == "tesseract":
            self.meta = TesseractEngine(layout=True).meta
        else:
            self.meta = RapidEngine(english=engine_name == "rapid-en", layout=True).meta
        self.engine_name = engine_name
        self.timeout = timeout

    def recognize(self, raw: bytes) -> dict:
        import os
        with tempfile.TemporaryDirectory(prefix="cti-ocr-") as temp:
            folder = Path(temp)
            (folder / "image.png").write_bytes(raw)
            completed = subprocess.run([sys.executable, "-m", "cti_hunt.stages.s1_ocr", "--worker",
                                        str(folder / "image.png"), str(folder / "result.json"), self.engine_name],
                                       capture_output=True, timeout=self.timeout,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            if completed.returncode:
                raise ValueError("OCR worker lỗi: " + completed.stderr.decode("utf-8", errors="replace")[-600:])
            return json.loads((folder / "result.json").read_text(encoding="utf-8"))


def _pdf_image(raw: bytes, p: dict, dpi: int) -> tuple[bytes, dict]:
    import pypdfium2 as pdfium
    with pdfium.PdfDocument(raw) as doc:
        page = doc[int(p["page"]) - 1]
        try:
            width, height = page.get_size()
            x0, top, x1, bottom = p["bbox"]
            box = (max(0, x0), max(0, top), min(width, x1), min(height, bottom))
            if box[2] <= box[0] or box[3] <= box[1]:
                raise ValueError("Vùng PDF ngoài trang")
            # Allocate only the requested region, not a full-page bitmap first.
            region_w, region_h = box[2] - box[0], box[3] - box[1]
            scale = min(dpi / 72, math.sqrt((MAX_PIXELS - 100_000) / (region_w * region_h)))
            crop = (box[0], height - box[3], width - box[2], box[1])
            bitmap = page.render(scale=scale, crop=crop)
            try:
                region = bitmap.to_pil().copy()
            finally:
                bitmap.close()
            offset = [math.ceil(box[0] * scale), math.ceil(box[1] * scale)]
            pixels = [*offset, offset[0] + region.width, offset[1] + region.height]
            buffer = io.BytesIO()
            region.save(buffer, format="PNG")
            return buffer.getvalue(), {"page_size_points": [width, height], "crop_bbox_px": pixels,
                                       "crop_bbox_points": list(box), "render_scale": [scale, scale],
                                       "dpi": scale * 72, "requested_dpi": dpi,
                                       "resolution_reduced": scale < dpi / 72,
                                       "render_method": "region_only", "pixel_to_page": "(pixel + crop_bbox_px origin) / render_scale"}
        finally:
            page.close()


def _html_image(p: dict, manifest: dict, *, allow_network: bool) -> tuple[bytes, dict]:
    if p.get("asset_kind", "img") != "img":
        raise ValueError("Chỉ OCR thẻ img raster; phần này cần người rà")
    ref = p.get("asset", "")
    if ref.startswith("data:"):
        header, encoded = ref.split(",", 1)
        if not re.fullmatch(r"data:image/(?:png|jpeg|webp|gif);base64", header, re.I):
            raise ValueError("Data URI không phải ảnh raster base64 hỗ trợ")
        if len(encoded) > S1.MAX_BYTES * 4 // 3 + 4:
            raise ValueError("Ảnh nhúng quá lớn")
        return base64.b64decode(encoded, validate=True), {"asset_source": "inline data URI"}
    if ref.startswith(("https://", "http://")):
        if not allow_network:
            raise ValueError("Ảnh URL chưa tải; dùng --fetch-images để tải ảnh công khai")
        raw, mime, resolved = S1.fetch(ref)
        return raw, {"asset_source": ref, "resolved_asset": resolved, "content_type": mime}
    if manifest["resolved_source"].startswith(("https://", "http://")):
        raise ValueError("Không đọc tệp cục bộ từ report trên mạng")
    if urlsplit(ref).scheme and not re.match(r"^[A-Za-z]:[\\/]", ref):
        raise ValueError("Định dạng đường dẫn ảnh không hỗ trợ")
    root = Path(manifest["resolved_source"]).resolve().parent
    path = Path(ref)
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError("Ảnh cục bộ phải nằm trong thư mục report hoặc thư mục con")
    with path.open("rb") as f:
        raw = f.read(S1.MAX_BYTES + 1)
    if len(raw) > S1.MAX_BYTES:
        raise ValueError("Ảnh quá lớn")
    return raw, {"asset_source": str(path)}


def _copy_inputs(bundle: Path, out: Path, manifest: dict) -> None:
    out.mkdir(parents=True, exist_ok=False)
    for name in [f"source.{manifest['format']}", *manifest.get("artifacts", {})]:
        src = (bundle / name).resolve()
        dst = (out / name).resolve()
        if not src.is_relative_to(bundle.resolve()) or not dst.is_relative_to(out.resolve()):
            raise ValueError("Đường dẫn artifact ngoài bundle")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    # Preserve provenance/history, not just the source and image artifacts.
    history = out / "bundle_history" / S1.digest((bundle / "manifest.json").read_bytes())[:16]
    history.mkdir(parents=True, exist_ok=True)
    for name in ("manifest.json", "provenance.json", "segments.jsonl"):
        (history / name).write_bytes((bundle / name).read_bytes())
    template = bundle / "ocr_review_template.json"
    if template.exists():
        (out / template.name).write_bytes(template.read_bytes())


def _save(out: Path, manifest: dict, segments: list[dict], provenance: dict) -> dict:
    seg_bytes = ("\n".join(json.dumps(s, ensure_ascii=False) for s in segments) + "\n").encode()
    prov_bytes = json.dumps(provenance, ensure_ascii=False, indent=2).encode()
    (out / "segments.jsonl").write_bytes(seg_bytes)
    (out / "provenance.json").write_bytes(prov_bytes)
    excluded = {"segments.jsonl", "provenance.json", "manifest.json", "review.html", "ocr_review_template.json",
                f"source.{manifest['format']}"}
    artifacts = {p.relative_to(out).as_posix(): S1.digest(p.read_bytes()) for p in sorted(out.rglob("*"))
                 if p.is_file() and p.relative_to(out).as_posix() not in excluded}
    pending = sum(p.get("extraction") == "ocr" and p.get("review_status") == "pending" for p in provenance.values())
    rejected = sum(p.get("extraction") == "ocr" and p.get("review_status") == "rejected" for p in provenance.values())
    unread = sum(p.get("extraction") == "unread" for p in provenance.values())
    review_pending = sum(bool(p.get("image_file")) and p.get("review_status", "pending") == "pending" for p in provenance.values())
    ready = sum(S1.extraction_ready(s, provenance) for s in segments)
    manifest.update(segments_sha256=S1.digest(seg_bytes), provenance_sha256=S1.digest(prov_bytes), artifacts=artifacts,
                    unread_blocks=unread, ocr_pending_blocks=pending, ocr_rejected_blocks=rejected, readable_segments=ready,
                    image_review_pending_blocks=review_pending,
                    status="blocked" if not ready else "partial" if (unread or pending or rejected) else "needs_review", segments=len(segments),
                    created_at=datetime.now(timezone.utc).isoformat())
    S1.write_json(out / "manifest.json", manifest)
    display = copy.deepcopy(provenance)
    for p in display.values():
        if p.get("image_file"):
            p["preview_data_uri"] = "data:image/png;base64," + base64.b64encode((out / p["image_file"]).read_bytes()).decode()
    (out / "review.html").write_text(S1.render_review(manifest, segments, display), encoding="utf-8")
    return manifest


def enrich(bundle: Path, out: Path, *, engine=None, dpi: int = 200, allow_network: bool = False,
           max_targets: int = MAX_TARGETS, continue_ocr: bool = False, retry_failed: bool = False,
           engine_name: str = "rapid-en", progress=None) -> dict:
    if out.exists():
        raise ValueError("Thư mục OCR đã tồn tại; dùng thư mục mới")
    if not 72 <= dpi <= 300 or not 0 <= max_targets <= 1000:
        raise ValueError("DPI phải 72–300 và max-targets phải 0–1000 (0 = toàn bộ)")
    manifest, segments, provenance = S1.load_bundle(bundle)
    source_manifest_sha = S1.digest((bundle / "manifest.json").read_bytes())
    if manifest.get("ocr") and not continue_ocr:
        raise ValueError("Bundle đã có lượt OCR; chạy lại từ bản native vào thư mục mới để so sánh")
    worker = engine or LocalWorker(engine_name=engine_name)
    previous_ocr = copy.deepcopy(manifest.get("ocr"))
    if previous_ocr and previous_ocr["engine"] != worker.meta:
        raise ValueError("Engine/cấu hình đã đổi; bắt đầu từ bundle native, không trộn vào lượt cũ")
    if previous_ocr and previous_ocr["dpi"] != dpi:
        raise ValueError("DPI đã đổi; bắt đầu từ bundle native để so sánh")
    if previous_ocr and previous_ocr.get("code_sha256") != S1.digest(Path(__file__).read_bytes()):
        raise ValueError("Mã OCR đã đổi; không trộn phiên bản trong lượt chạy tiếp")
    if previous_ocr and previous_ocr.get("layout_code_sha256") != S1.digest(Path(__file__).with_name("s1_layout.py").read_bytes()):
        raise ValueError("Mã bố cục đã đổi; bắt đầu lượt mới từ native")
    round_no = previous_ocr.get("round", 1) + 1 if previous_ocr else 1
    raw_source = (bundle / f"source.{manifest['format']}").read_bytes()
    _copy_inputs(bundle, out, manifest)
    manifest["ocr"] = {"version": OCR_VERSION, "engine": worker.meta, "dpi": dpi, "max_targets": max_targets, "round": round_no,
                       "code_sha256": S1.digest(Path(__file__).read_bytes()),
                       "layout_code_sha256": S1.digest(Path(__file__).with_name("s1_layout.py").read_bytes()),
                       "source_bundle_manifest_sha256": source_manifest_sha, "network_images_allowed": allow_network,
                       "review_policy": "all OCR transcripts require explicit review before TTP/IOC"}
    if previous_ocr:
        manifest.setdefault("ocr_history", []).append(previous_ocr)
    warnings = []
    cache = {}
    attempts = 0
    for seg in segments:
        sid = seg["ma_doan"]
        p = provenance[sid]
        if p.get("extraction") != "unread" or p.get("review_status") in ("approved", "rejected", "no_text"):
            continue
        if p.get("ocr_attempt_status") in ("failed", "empty") and not retry_failed:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
            raise ValueError("Mã đoạn không an toàn cho artifact OCR")
        if max_targets and attempts >= max_targets:
            warnings.append({"code": "ocr_limit", "segment_id": sid, "detail": "Chạm trần OCR; phần còn lại chưa đọc"})
            continue
        attempts += 1
        p.pop("ocr_error", None)
        try:
            kind = manifest["format"]
            if kind == "pdf":
                raw, origin = _pdf_image(raw_source, p, dpi)
                if origin["resolution_reduced"]:
                    warnings.append({"code": "ocr_resolution_reduced", "segment_id": sid,
                                     "detail": f"Vùng quá lớn; render {origin['dpi']:.1f} DPI thay {dpi}, giữ thông số trong provenance"})
            elif kind == "html":
                raw, origin = _html_image(p, manifest, allow_network=allow_network)
            else:
                raw, origin = raw_source, {"asset_source": f"source.{kind}"}
            png, size = normalize_image(raw)
            image_hash = S1.digest(png)
            asset_base = "ocr_assets" if round_no == 1 else f"ocr_assets/round_{round_no:04d}"
            asset_dir = out / asset_base
            asset_dir.mkdir(parents=True, exist_ok=True)
            (asset_dir / f"{sid}.source").write_bytes(raw)
            image_file = f"{asset_base}/{sid}.png"
            (out / image_file).write_bytes(png)
            p.update(image_file=image_file, image_sha256=image_hash, image_size_px=list(size),
                     original_asset_sha256=S1.digest(raw), image_origin=origin)
            cached = image_hash in cache
            result = cache[image_hash] if cached else worker.recognize(png)
            if not isinstance(result.get("text"), str) or not isinstance(result.get("lines"), list):
                raise ValueError("Kết quả OCR sai cấu trúc")
            cache[image_hash] = result
            S1.write_json(asset_dir / f"{sid}.json", {**result, "cache_hit": cached})
            p["ocr_result_file"] = f"{asset_base}/{sid}.json"
            if not result["text"].strip():
                p.update(ocr_attempt_status="empty", review_status="pending")
                warnings.append({"code": "ocr_no_text", "segment_id": sid,
                                 "detail": "OCR không nhận được chữ; có thể ảnh không chữ hoặc engine bỏ sót, cần rà"})
                continue
            seg["van_ban"] = result["text"]
            seg["loai"] = "đoạn văn"
            p.update(extraction="ocr", review_status="pending", ocr_result_file=f"{asset_base}/{sid}.json",
                     ocr_attempt_status="done",
                     ocr_text_sha256=S1.digest(result["text"].encode()),
                     ocr_min_line_score=min((float(line["score"]) for line in result["lines"]), default=None))
            warnings.append({"code": "ocr_pending_review", "segment_id": sid,
                             "detail": "Chữ OCR cần đối chiếu ảnh; chưa đưa vào TTP/IOC, không tự sửa chuỗi"})
        except Exception as e:
            p["ocr_error"] = type(e).__name__
            p["ocr_attempt_status"] = "failed"
            if p.get("image_file"):
                p["review_status"] = "pending"
            warnings.append({"code": "ocr_failed", "segment_id": sid, "detail": str(e)[:500]})
        finally:
            if progress:
                progress(sid, attempts, p.get("ocr_attempt_status", "unknown"))
    manifest["ocr"]["attempts"] = attempts
    manifest["ocr"]["remaining_unattempted"] = sum(p.get("extraction") == "unread" and not p.get("ocr_attempt_status") for p in provenance.values())
    manifest["warnings"] = [*({"stage": "native_ingest", **w} for w in manifest["warnings"]),
                            *({**w, "stage": "ocr"} for w in warnings)]
    result = _save(out, manifest, segments, provenance)
    # Editable review form is intentionally NOT part of immutable artifact hashes.
    write_review_template(out, segments, provenance)
    return result


def write_review_template(out: Path, segments: list[dict], provenance: dict) -> None:
    template_path = out / "ocr_review_template.json"
    existing_decisions = {}
    existing_reviewer = ""
    existing_reviewed_at = ""
    if template_path.exists():
        try:
            old = json.loads(template_path.read_text(encoding="utf-8"))
            existing_reviewer = old.get("reviewer", "")
            existing_reviewed_at = old.get("reviewed_at", "")
            for d in old.get("decisions", []):
                if d.get("segment_id"):
                    existing_decisions[d["segment_id"]] = d
        except Exception:
            pass

    decisions = []
    for s in segments:
        sid = s["ma_doan"]
        p = provenance[sid]
        if p.get("image_file") and p.get("review_status", "pending") == "pending":
            existing = existing_decisions.get(sid)
            if existing and existing.get("image_sha256") == p["image_sha256"]:
                decisions.append({
                    "segment_id": sid,
                    "status": existing.get("status", "pending"),
                    "text": existing.get("text", "" if p.get("extraction") == "unread" else s["van_ban"]),
                    "reason": existing.get("reason", ""),
                    "image_sha256": p["image_sha256"],
                })
            else:
                default_text = "" if p.get("extraction") == "unread" else s["van_ban"]
                decisions.append({
                    "segment_id": sid,
                    "status": "pending",
                    "text": default_text,
                    "reason": "",
                    "image_sha256": p["image_sha256"],
                })

    template = {
        "bundle_manifest_sha256": S1.digest((out / "manifest.json").read_bytes()),
        "reviewer": existing_reviewer,
        "reviewed_at": existing_reviewed_at,
        "decisions": decisions,
    }
    S1.write_json(template_path, template)


def apply_review(bundle: Path, review_path: Path, out: Path) -> dict:
    if out.exists():
        raise ValueError("Thư mục đã tồn tại; không ghi đè bản OCR gốc")
    manifest, segments, provenance = S1.load_bundle(bundle)
    review_raw = review_path.read_bytes()
    review = json.loads(review_raw)
    if review.get("bundle_manifest_sha256") != S1.digest((bundle / "manifest.json").read_bytes()):
        raise ValueError("Phiếu rà không khớp hash bundle OCR")
    if not str(review.get("reviewer", "")).strip():
        raise ValueError("Phiếu cần tên người đã đối chiếu ảnh")
    stamp = datetime.fromisoformat(review.get("reviewed_at", "").replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Thời điểm rà cần múi giờ ISO8601")
    targets = {s["ma_doan"]: s for s in segments if provenance[s["ma_doan"]].get("image_file")
               and provenance[s["ma_doan"]].get("review_status", "pending") == "pending"}
    decisions = review.get("decisions", [])
    ids = [d.get("segment_id") for d in decisions]
    if len(ids) != len(set(ids)) or set(ids) != set(targets):
        raise ValueError("Phiếu phải chứa đúng một quyết định cho mỗi đoạn OCR")
    changed = 0
    for d in decisions:
        sid = d["segment_id"]
        p = provenance[sid]
        if d.get("image_sha256") != p["image_sha256"]:
            raise ValueError("Ảnh trong phiếu không khớp ảnh đã OCR")
        status = d.get("status")
        if status not in ("approved", "rejected", "pending", "no_text"):
            raise ValueError("Trạng thái rà phải approved/rejected/pending/no_text")
        if status == "pending":
            continue
        if not str(d.get("reason", "")).strip():
            raise ValueError("Cần lý do xác nhận hoặc từ chối transcript")
        if status == "approved":
            if not isinstance(d.get("text"), str) or not d["text"].strip():
                raise ValueError("Transcript được duyệt không được trống")
            targets[sid]["van_ban"] = d["text"]
            targets[sid]["loai"] = "đoạn văn"
            if p.get("extraction") == "unread":
                p["transcript_origin"] = "manual_from_image"
            p["extraction"] = "ocr"
        elif status == "no_text":
            targets[sid]["van_ban"] = "[ĐÃ RÀ: không có chữ cần trích; xem ảnh và lý do trong phiếu]"
            targets[sid]["loai"] = "ảnh"
            p["extraction"] = "reviewed_nontext"
        p.update(review_status=status, reviewer=review["reviewer"], reviewed_at=review["reviewed_at"],
                 review_reason=d["reason"], reviewed_text_sha256=S1.digest(targets[sid]["van_ban"].encode()))
        changed += 1
    if not changed:
        raise ValueError("Chưa có quyết định rà nào; không thay thế bằng chấp nhận tự động")
    _copy_inputs(bundle, out, manifest)
    if (out / "ocr_review_applied.json").exists():
        old = (out / "ocr_review_applied.json").read_bytes()
        (out / f"ocr_review_history_{S1.digest(old)[:16]}.json").write_bytes(old)
    (out / "ocr_review_applied.json").write_bytes(review_raw)
    manifest["review_parent_manifest_sha256"] = S1.digest((bundle / "manifest.json").read_bytes())
    for warning in manifest["warnings"]:
        if warning.get("code") == "ocr_pending_review":
            warning["current_review_status"] = provenance[warning["segment_id"]].get("review_status", "pending")
    manifest["warnings"].append({"code": "ocr_review_applied", "detail": "Đã áp dụng phiếu; chữ OCR vẫn là bản chép, truy nguồn qua ảnh và phiếu"})
    result = _save(out, manifest, segments, provenance)
    write_review_template(out, segments, provenance)
    return result


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--worker":
        raise SystemExit("Internal worker: --worker INPUT OUTPUT ENGINE")
    eng_name = sys.argv[4]
    if eng_name == "tesseract":
        eng = TesseractEngine(layout=True)
    else:
        eng = RapidEngine(english=eng_name == "rapid-en", layout=True)
    S1.write_json(Path(sys.argv[3]), eng.recognize(Path(sys.argv[2]).read_bytes()))
