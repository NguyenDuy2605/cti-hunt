"""Thử một cơ chế OTRF: mặc định kiểm cục bộ; thêm --send để gọi ④ và dừng ở ◆ nếu có giả thuyết hợp lệ.

Chọn --mechanism schtasks|wmi-exec và thư mục lượt mới bằng --out; prompt lấy từ configs/agent.yaml.
Giữ schtasks và sonnet5_pipeline_01 làm mặc định tương thích các lệnh cũ.
Trước --send cần có hạn mức trong sổ; chỉ init khi chưa có sổ, không khởi tạo lại sau mỗi lượt.
Không tự nạp tiền, khởi tạo/reset ngân sách, duyệt giả thuyết hoặc chạy khâu ②.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from cti_hunt import cli, config


# Các cặp Contract A v2 / bộ OTRF đã chốt trong docs/METHODOLOGY.md.
# Ghim SHA256 từ bản chốt; session kiểm lại manifest và Parquet trước khi tạo lượt/gọi API.
MECHANISMS = {
    "schtasks": {
        "report_id": "DEV-SCHTASKS",
        "dataset_id": "otrf-schtasks",
        "source_sha256": "74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b",
    },
    "wmi-exec": {
        "report_id": "DEV-WMIEXEC",
        "dataset_id": "otrf-wmi-exec",
        "source_sha256": "96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88",
    },
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mechanism", choices=tuple(MECHANISMS), default="schtasks",
                        help="Cơ chế phát triển; tự chọn đúng Contract A v2, bộ log và SHA256 đã chốt")
    parser.add_argument("--send", action="store_true", help="người vận hành chạy: gọi API thật, qua sổ ngân sách dùng chung")
    parser.add_argument("--out", type=Path, default=config.ROOT / "data/dev/sonnet5_pipeline_01",
                        help="Thư mục lượt mới; từ chối ghi đè nếu đã có nội dung")
    args = parser.parse_args(argv)
    mechanism = MECHANISMS[args.mechanism]
    if args.send:
        if cli.main(["api-budget", "status"]) != 0:
            return 1
        env_name = config.load("llm_hunt")["api_key_env"]
        if not os.environ.get(env_name):
            print(f"Chưa đặt {env_name} trong cửa sổ PowerShell này; chưa tạo lượt hay gọi API.")
            return 1
    command = ["agent", "start", "--mode", "pipeline", "--contract-a",
               str(config.ROOT / f"dev/contract_a_v2/contract_a_{mechanism['report_id']}.json"),
               "--events", str(config.ROOT / "data/dev" / mechanism["dataset_id"]),
               "--dataset-kind", "otrf_dev",
               "--dataset-id", mechanism["dataset_id"], "--dataset-sha256", mechanism["source_sha256"],
               "--out", str(args.out)]
    if not args.send:
        command.append("--dry-run")
    code = cli.main(command)
    if args.send:
        status = cli.main(["api-budget", "status"])
        if code == 0:
            code = status
    return code


if __name__ == "__main__":
    raise SystemExit(main())
