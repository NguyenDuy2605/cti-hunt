"""Run a new-report development case; no hand-written Contract A or automatic approval.

prepare: local extraction preview and review worksheet.
extract --send: real extraction under the existing budget; preserves responses for resume.
handoff: telemetry coverage and agent dry-run; --send calls hypothesis generation up to ◆.
"""
from __future__ import annotations

import argparse
import json
import os
from decimal import Decimal
from pathlib import Path

from cti_hunt import cli, config, report_review
from cti_hunt.llm.budget import Ledger, RATES, usd
from cti_hunt.stages import s1_ingest

DATASET_ID = "otrf-wmi-exec"
DATASET_SHA = "96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88"


def api_preflight(cfg: dict) -> None:
    if cfg.get("provider") != "anthropic" or not cfg.get("budget_ledger"):
        raise ValueError("Cần Anthropic và sổ ngân sách hiện có")
    ledger = Ledger(config.resolve(cfg["budget_ledger"]))
    ledger.require_ready()
    status = ledger.status()
    print(f"Ngân sách cục bộ còn {status['remaining_usd']} USD; không phải số dư tài khoản API.")
    # A necessary lower bound, NOT an input-token estimate or a run-cost promise.
    floor = cfg["max_output_tokens"] * RATES[cfg["model"]][1]
    print(f"Mỗi yêu cầu cần dự phòng ít nhất {usd(floor)} USD cho output, còn cộng input.")
    if Decimal(status["remaining_usd"]) < Decimal(usd(floor)):
        raise ValueError("Không đủ khoản dự phòng output; chưa gửi yêu cầu. Không tự tăng hạn mức/đổi model.")
    if not os.environ.get(cfg["api_key_env"]):
        raise ValueError(f"Chưa có {cfg['api_key_env']} trong phiên chạy; không gửi khóa vào chat")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", choices=("prepare", "extract", "handoff"))
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path, help="Thư mục ca; dùng lại cùng đường dẫn cho ba bước")
    p.add_argument("--reference", type=Path, help="Chỉ dùng ở prepare, không gửi vào LLM")
    p.add_argument("--send", action="store_true")
    p.add_argument("--accept-partial", action="store_true")
    a = p.parse_args(argv)
    try:
        a.bundle, a.out = config.resolve(a.bundle), config.resolve(a.out)
        extraction = a.out / "extraction"
        lock = a.out / "case.json"
        if a.stage == "prepare":
            if a.send:
                raise ValueError("prepare không gọi API; dùng extract --send sau khi xem phiếu")
            if a.out.exists():
                raise ValueError("Thư mục ca đã tồn tại; dùng tên mới")
            manifest, _, _ = s1_ingest.load_bundle(a.bundle)
            ref = config.resolve(a.reference) if a.reference else None
            a.out.mkdir(parents=True)
            command = ["extract-report", str(a.bundle), "--out", str(extraction), "--batch-size", "8"]
            if cli.main(command):
                return 1
            report_review.prepare(a.bundle, extraction, a.out / "review_before", ref)
            s1_ingest.write_json(lock, {"report_id": manifest["report_id"],
                "bundle_manifest_sha256": s1_ingest.digest((a.bundle / "manifest.json").read_bytes()),
                "reference": str(ref) if ref else None,
                "reference_sha256": s1_ingest.digest(ref.read_bytes()) if ref else None,
                "reference_frozen_before_extraction": True})
            print(f"Đã chuẩn bị: {a.out / 'review_before/review.html'}; chưa gọi API.")
            return 0
        if a.reference:
            raise ValueError("Bản tham chiếu đã ghim ở prepare; không đổi sau khi có dự đoán")
        frozen = json.loads(lock.read_text(encoding="utf-8"))
        if frozen["bundle_manifest_sha256"] != s1_ingest.digest((a.bundle / "manifest.json").read_bytes()):
            raise ValueError("Bundle thay đổi sau prepare")
        ref = Path(frozen["reference"]) if frozen["reference"] else None
        if ref and frozen["reference_sha256"] != s1_ingest.digest(ref.read_bytes()):
            raise ValueError("Bản tham chiếu thay đổi sau prepare; giữ nguyên để đối chiếu")
        if a.stage == "extract":
            if not a.send:
                raise ValueError("Chưa gọi API; thêm --send khi chạy trong phiên có khóa")
            api_preflight(config.load("llm_hunt"))
            command = ["extract-report", str(a.bundle), "--out", str(extraction),
                       "--batch-size", "8", "--send", "--resume"]
            if a.accept_partial:
                command.append("--accept-partial")
            code = cli.main(command)
            cli.main(["api-budget", "status"])
            if code:
                print("Lượt chưa hoàn tất; chưa chuyển sang săn. Các lô đã có phản hồi được giữ để resume.")
            return code
        # This validates the complete Contract A and its exact source binding
        # before coverage or a graph can consume it. Never substitute reference TTPs.
        meta = json.loads((extraction / "meta.json").read_text(encoding="utf-8"))
        if meta["status"] != "complete":
            raise ValueError("Chưa có Contract A từ lượt trích hoàn tất; không dùng bản soạn sẵn thay thế")
        if a.send:
            api_preflight(config.load("llm_hunt"))
        handoff = a.out / ("handoff_send" if a.send else "handoff_preview")
        report_review.prepare(a.bundle, extraction, handoff / "review", ref)
        contract = extraction / "contract_a.json"
        if cli.main(["report-coverage", str(contract), "--events", str(config.ROOT / "data/dev" / DATASET_ID),
                     "--out", str(handoff / "coverage.json")]):
            return 1
        command = ["agent", "start", "--mode", "pipeline", "--contract-a", str(contract),
                   "--events", str(config.ROOT / "data/dev" / DATASET_ID), "--dataset-kind", "otrf_dev",
                   "--dataset-id", DATASET_ID, "--dataset-sha256", DATASET_SHA,
                   "--out", str(handoff / "hunt")]
        if not a.send:
            command.append("--dry-run")
        code = cli.main(command)
        if a.send:
            cli.main(["api-budget", "status"])
        return code
    except Exception as exc:
        print(f"Chưa hoàn tất ca report mới: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
