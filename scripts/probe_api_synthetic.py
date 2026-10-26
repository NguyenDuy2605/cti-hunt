"""Thử payload khâu ② trên đoạn CTI tự soạn; mặc định không gọi API.

Chạy `python scripts/probe_api_synthetic.py` để kiểm ngoại tuyến.
Chỉ thêm `--send` khi người vận hành sẵn sàng thử API. Không đọc report/nhãn/dataset thật,
không tạo kết quả cho lần chạy khâu ② ngày 29/9.
"""
from __future__ import annotations

import argparse
import json

from cti_hunt import config
from cti_hunt.llm import providers
from cti_hunt.stages import s2_ttp


SYNTHETIC_SEGMENT = {
    "ma_doan": "TU-API-001",
    "loai": "nội dung",
    "van_ban": (
        "In a fictional lab, an operator on TEST-HOST ran whoami from cmd.exe "
        "to check the current account. This paragraph is self-authored for an API schema test."
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true", help="Gọi API một lượt trên văn bản tự soạn")
    args = parser.parse_args(argv)

    cfg = config.load("llm")
    prompt = s2_ttp.load_prompt(config.resolve(cfg["prompt_file"]))
    client = providers.from_config(cfg)
    if not isinstance(client, providers.AnthropicClient):
        parser.error("probe này chỉ dành cho cấu hình Anthropic của khâu ②")
    system = prompt["system"]
    user = s2_ttp.render_batch(prompt, "TU", [SYNTHETIC_SEGMENT])
    schema = s2_ttp.ExtractionBatch.model_json_schema()
    payload = client.build_payload(system, user, schema)

    print(json.dumps({
        "mode": "SEND_SYNTHETIC_ONLY" if args.send else "OFFLINE_NO_API",
        "prompt_sha256": prompt["sha256"],
        "segment_id": SYNTHETIC_SEGMENT["ma_doan"],
        "model": payload["model"],
        "max_tokens": payload["max_tokens"],
        "timeout_giay": client.timeout,
        "effort": (payload.get("output_config") or {}).get("effort"),
        "tool_choice": payload["tool_choice"],
        "strict": payload["tools"][0].get("strict", False),
        "temperature_sent": "temperature" in payload,
    }, ensure_ascii=False, indent=2))

    if not args.send:
        return 0

    events = []

    def log(event: dict) -> None:
        allowed = ("lan", "http", "thu_lai", "stop_reason", "input_tokens", "output_tokens")
        events.append({k: event[k] for k in allowed if k in event})

    try:
        raw = client.complete_json(system, user, schema, log=log)
        parsed = s2_ttp.ExtractionBatch.model_validate(raw)
    except (providers.LLMError, ValueError) as exc:
        print(f"[THẤT BẠI] {type(exc).__name__}: {exc}")
        print(json.dumps({"api_events": events}, ensure_ascii=False))
        return 1

    print(json.dumps({"schema_ok": True, "items": len(parsed.items), "api_events": events},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
