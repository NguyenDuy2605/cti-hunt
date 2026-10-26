"""Local review packet: transcription and semantic judgments stay separate.

This is a worksheet, never a gold label set or an automatic accuracy score.
References are only read here, after extraction requests have been prepared.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .contracts import ContractA
from .stages import s1_ingest as ingest


def prepare(bundle: Path, extraction: Path, out: Path, reference: Path | None = None) -> dict:
    if out.exists():
        raise ValueError("Thư mục phiếu đã tồn tại; dùng thư mục mới để giữ lịch sử rà")
    manifest, segments, provenance = ingest.load_bundle(bundle)
    by_id = {s["ma_doan"]: s for s in segments}
    meta = json.loads((extraction / "meta.json").read_text(encoding="utf-8"))
    if (meta.get("bundle_manifest_sha256") != ingest.digest((bundle / "manifest.json").read_bytes())
            or meta.get("report_id") != manifest["report_id"]):
        raise ValueError("Lượt trích không thuộc đúng bản report này")
    requests = json.loads((extraction / "requests.json").read_text(encoding="utf-8"))
    if ingest.digest(json.dumps(requests, ensure_ascii=False, sort_keys=True).encode()) != meta["requests_sha256"]:
        raise ValueError("Prompt đã đổi so với lượt trích")
    completed = meta["status"] == "complete"
    contract = None
    contract_sha = None
    if completed:
        raw = (extraction / "contract_a.json").read_bytes()
        contract_sha = ingest.digest(raw)
        if contract_sha != meta.get("contract_a_sha256"):
            raise ValueError("Contract A đã đổi so với lượt trích")
        contract = ContractA.model_validate_json(raw)
        if contract.report_id != manifest["report_id"]:
            raise ValueError("Contract A sai report_id")
    elif meta["status"] not in ("prepared", "running", "failed"):
        raise ValueError("Trạng thái lượt trích không hỗ trợ")

    predictions = []
    for i, ttp in enumerate(contract.ttps if contract else []):
        sid, quote = ttp.source_span.segment_id, ttp.source_span.text
        if (sid not in by_id or not quote.strip() or quote not in by_id[sid]["van_ban"]
                or not ingest.extraction_ready(by_id[sid], provenance)):
            raise ValueError("Bằng chứng TTP không thuộc phần chữ được phép sử dụng")
        predictions.append({"prediction_id": f"P{i + 1:04d}", **ttp.model_dump(),
                            "semantic_verdict": "pending", "semantic_note": ""})

    ref = None
    reference_sha = None
    if reference:
        reference_sha = ingest.digest(reference.read_bytes())
        ref = json.loads(reference.read_text(encoding="utf-8"))
        for key in ("report_id", "source_sha256", "segments_sha256"):
            if ref.get(key) != manifest[key]:
                raise ValueError(f"Bản tham chiếu sai {key}; không đối chiếu hai bản nguồn khác nhau")
        seen = set()
        for row in ref["checks"]:
            if row["check_id"] in seen:
                raise ValueError("Trùng mã mục tham chiếu")
            seen.add(row["check_id"])
            if not row["segment_ids"] or any(s not in by_id for s in row["segment_ids"]):
                raise ValueError("Mục tham chiếu thiếu/sai đoạn nguồn")
            # Presence only, not semantic correctness or recall. Multiple source
            # passages may describe the same behavior; unmatched is not a FN.
            row["candidate_predictions"] = [p["prediction_id"] for p in predictions
                if p["source_span"]["segment_id"] in row["segment_ids"]
                and (not row.get("technique_ids") or p["technique_id"] in row["technique_ids"])]
            row["review_verdict"] = "pending" if completed else "not_run"
            row["review_note"] = ""

    packet = {
        "schema_version": "report_review_v1", "report_id": manifest["report_id"],
        "source_sha256": manifest["source_sha256"],
        "bundle_manifest_sha256": meta["bundle_manifest_sha256"],
        "extraction_meta_sha256": ingest.digest((extraction / "meta.json").read_bytes()),
        "requests_sha256": meta["requests_sha256"], "contract_a_sha256": contract_sha,
        "extraction_status": meta["status"], "semantic_status": "pending" if completed else "not_run",
        "ingestion_status": manifest["status"], "ingestion_warnings": manifest["warnings"],
        "reference_sha256": reference_sha, "reference": ref,
        "instructions": {
            "parsing": "Đối chiếu bản nguồn: đủ nội dung, thứ tự, ký tự kỹ thuật và phần chưa đọc.",
            "semantics": "Kiểm tra hành vi, mã kỹ thuật, bối cảnh, khuyến nghị và suy diễn; câu trích đúng chưa đủ.",
            "scope": "Đây là phiếu rà, không tự tính P/R; bản tham chiếu có thể thiếu hoặc sai. Không thay cổng duyệt giả thuyết.",
        },
        "reviewer": "", "reviewed_at": "",
        "segments": [{**s, "source": provenance[s["ma_doan"]],
                      "eligible_for_extraction": ingest.extraction_ready(s, provenance),
                      "parsing_verdict": "pending", "parsing_note": "",
                      "prediction_ids": [p["prediction_id"] for p in predictions
                                         if p["source_span"]["segment_id"] == s["ma_doan"]]}
                     for s in segments],
        "predictions": predictions,
    }
    out.mkdir(parents=True, exist_ok=False)
    ingest.write_json(out / "review_template.json", packet)
    (out / "review.html").write_text(render(packet), encoding="utf-8")
    return packet


def render(packet: dict) -> str:
    esc = lambda value: html.escape(str(value))
    parts = ['<!doctype html><html lang="vi"><meta charset="utf-8">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
             '<title>Rà report và TTP</title><style>body{font:16px system-ui;max-width:1100px;margin:30px auto;padding:0 20px;line-height:1.55} '
             'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:12px} '
             'article{border-top:1px solid #ccc;padding:16px 0}small{overflow-wrap:anywhere} '
             '.note{background:#fff4ce;padding:14px}</style>',
             f'<h1>{esc(packet["report_id"])}</h1>',
             f'<p>Trạng thái trích: <b>{esc(packet["extraction_status"])}</b>; '
             f'rà ngữ nghĩa: <b>{esc(packet["semantic_status"])}</b>.</p>',
             '<p class="note">Phiếu này không chứng nhận độ chính xác. Điền bản sao review_template.json; '
             'lỗi bóc chữ và lỗi hiểu nội dung có ô riêng. Mở bản nguồn trong bundle để đối chiếu. '
             'TTP có câu trích đúng vẫn có thể hiểu sai. Không có dự đoán khi lượt trích chưa hoàn tất.</p>']
    if packet["reference"]:
        ref = packet["reference"]
        parts.append(f'<h2>Mục cần đối chiếu</h2><p>{esc(ref.get("status", "unreviewed"))}</p>')
        for row in ref["checks"]:
            parts.append(f'<article><b>{esc(row["check_id"])} — {esc(row["description"])}</b>'
                         f'<p>Đoạn: {esc(", ".join(row["segment_ids"]))}</p>'
                         f'<p>Dự đoán cùng đoạn/mã để rà: {esc(row["candidate_predictions"])}</p>'
                         '<p>Danh sách này không phải kết luận đúng/sai hay điểm recall.</p></article>')
    preds = {p["prediction_id"]: p for p in packet["predictions"]}
    parts.append('<h2>Nội dung và dự đoán theo nguồn</h2>')
    for seg in packet["segments"]:
        parts.append(f'<article id="{esc(seg["ma_doan"])}"><h3>{esc(seg["ma_doan"])} · {esc(seg["loai"])}</h3>'
                     f'<small>{esc(json.dumps(seg["source"], ensure_ascii=False))}</small>'
                     f'<pre>{esc(seg["van_ban"])}</pre>')
        for pid in seg["prediction_ids"]:
            p = preds[pid]
            parts.append(f'<p><b>{esc(pid)} · {esc(p["technique_id"])}</b> — {esc(p["behavior_description"])}</p>'
                         f'<blockquote>{esc(p["source_span"]["text"])}</blockquote>'
                         f'<pre>{esc(json.dumps(p["context"], ensure_ascii=False, indent=2))}</pre>')
        parts.append('</article>')
    return "\n".join(parts) + '</html>'
