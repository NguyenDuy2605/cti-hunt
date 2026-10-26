"""Bind an unchanged, saved Contract A to verified current report evidence; no generation."""
from __future__ import annotations

import json
from pathlib import Path

from . import integrity
from .contracts import ContractA
from .stages import s1_ingest

VERSION = "saved_contract_v1"
SNAPSHOTS = {"contract": "contract_a.json", "metadata": "original_meta.json",
             "segments": "original_segments.jsonl"}


def _text(value: str) -> str:
    # Layout whitespace only. Never change case, punctuation, words or technique codes.
    return "".join(value.split())


def bindings(bundle: Path, payloads: dict[str, bytes]) -> tuple[ContractA, list[dict]]:
    _, current, provenance = s1_ingest.load_bundle(bundle)
    ca = ContractA.model_validate_json(payloads["contract"])
    original_meta = json.loads(payloads["metadata"])
    if not original_meta.get("xong_luc"):
        raise ValueError("Lần trích đã lưu chưa có bằng chứng hoàn tất")
    if s1_ingest.digest(payloads["segments"]) != original_meta.get("segments_sha256"):
        raise ValueError("Phân đoạn nguồn cũ không khớp metadata lần trích")
    log = original_meta.get("log", {}).get(ca.report_id, {})
    if not ca.ttps or log.get("so_muc_giu") != len(ca.ttps) or log.get("su_co", {}).get("lo_that_bai"):
        raise ValueError("Số TTP hoặc lô thất bại không khớp lần trích đã hoàn tất")
    old = [json.loads(line) for line in payloads["segments"].decode("utf-8").splitlines() if line.strip()]
    ids = [s["ma_doan"] for s in old]
    if len(ids) != len(set(ids)):
        raise ValueError("Phân đoạn nguồn cũ có mã trùng")
    by_id = {s["ma_doan"]: s for s in old}
    ready = [(s["ma_doan"], _text(s["van_ban"])) for s in current
             if s1_ingest.extraction_ready(s, provenance)]
    result = []
    for i, ttp in enumerate(ca.ttps):
        span = ttp.source_span
        original = by_id.get(span.segment_id)
        if (not original or original["report"] != ca.report_id or original["loai"] in ("ảnh", "tiêu đề")
                or not span.text.strip() or span.text not in original["van_ban"]):
            raise ValueError(f"TTP {i + 1} thiếu câu trích nguyên văn trong đúng đoạn nguồn cũ")
        matches = [sid for sid, text in ready if _text(span.text) in text]
        if not matches:
            raise ValueError(f"TTP {i + 1} ({span.segment_id}) không khớp chữ report đang mở; không dùng lại")
        result.append({"ttp_ref": i, "original_segment_id": span.segment_id,
                       "current_segment_ids": matches})
    return ca, result


def import_saved(bundle: Path, out: Path, entry: dict) -> dict:
    if out.exists():
        raise ValueError("Thư mục đầu ra đã tồn tại; giữ nguyên lượt cũ")
    if out.resolve() == bundle.resolve() or not out.resolve().is_relative_to(bundle.resolve()):
        raise ValueError("Bản dùng lại phải nằm trong report đang mở")
    payloads = {}
    for key in SNAPSHOTS:
        payloads[key] = Path(entry[key]).read_bytes()
        if s1_ingest.digest(payloads[key]) != entry[f"{key}_sha256"]:
            raise ValueError(f"Đầu ra trích đã lưu bị đổi hash: {key}")
    ca, matched = bindings(bundle, payloads)
    manifest, _, _ = s1_ingest.load_bundle(bundle)
    meta = {"version": VERSION, "status": "complete", "api_called": False,
            "report_id": ca.report_id, "bundle_report_id": manifest["report_id"],
            "bundle_manifest_sha256": integrity.sha256_file(bundle / "manifest.json"),
            "contract_a_sha256": s1_ingest.digest(payloads["contract"]), "accepted_ttp": len(ca.ttps),
            "semantic_quality": "Chưa đánh giá lại; dùng nguyên đầu ra đã lưu",
            "source_bindings": matched,
            "saved_source": {key: {"path": str(Path(entry[key]).resolve()),
                                   "sha256": entry[f"{key}_sha256"]} for key in SNAPSHOTS}}
    # All checks precede creation. Copy bytes, including original report/segment identifiers.
    out.mkdir(parents=True, exist_ok=False)
    for key, name in SNAPSHOTS.items():
        (out / name).write_bytes(payloads[key])
    s1_ingest.write_json(out / "meta.json", meta)
    return meta


def verify(bundle: Path, extraction: Path, meta: dict) -> None:
    manifest, _, _ = s1_ingest.load_bundle(bundle)
    if meta.get("bundle_report_id") != manifest["report_id"]:
        raise ValueError("Bản dùng lại sai report đang mở")
    payloads = {}
    for key, name in SNAPSHOTS.items():
        payloads[key] = (extraction / name).read_bytes()
        if s1_ingest.digest(payloads[key]) != meta["saved_source"][key]["sha256"]:
            raise ValueError(f"Snapshot nguồn trích đã đổi: {key}")
    ca, matched = bindings(bundle, payloads)
    if ca.report_id != meta["report_id"] or matched != meta["source_bindings"]:
        raise ValueError("Ánh xạ nguồn bản dùng lại đã thay đổi")
