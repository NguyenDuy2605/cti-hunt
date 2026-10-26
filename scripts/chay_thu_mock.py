"""Chạy thử chế độ pipeline của graph D10 trên một bộ OTRF phát triển, KHÔNG gọi API (quyết định 24/9, mục 4).

Mục đích: kiểm đường ống ④ → ◆ → ⑤ → ⑥ → ⑦ → ⑧ → ⑨ trên log OTRF thật (định dạng, cột, lọc, xếp hạng, hunt record)
trước khi có credit. Không đo chất lượng giả thuyết hay rule — mock không đọc hiểu gì:

- ④ và ④ pivot: mỗi kỹ thuật đầu vào một giả thuyết, dùng nguồn log đầu tiên trong `allowed_sources`.
- ⑤: rule `EventID ∈ {mã sự kiện của giả thuyết}` trên logsource đầu tiên mã đề xuất (bắt mọi sự kiện của nguồn đó).
- Phiếu ◆: tự điền approved, người duyệt ghi `chay-thu-mock (KHÔNG phải duyệt ◆ thật)`.

Chỉ nhận bộ `otrf_dev` (qua `session.start`, kiểm E1 như lệnh `agent`). Đầu ra mặc định ở
data/dev/_chay_thu_mock/<mã bộ>-<thời điểm>/ — không phải `runs/`, không phải kết quả đánh giá.

    python scripts/chay_thu_mock.py --contract-a dev/contract_a_v1/contract_a_DEV-PSEXEC.json --events data/dev/otrf-psexec
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import yaml

from cti_hunt import approval, config
from cti_hunt.agent import session
from cti_hunt.llm import providers

REVIEWER = "chay-thu-mock (KHÔNG phải duyệt ◆ thật)"


def _json_arrays(text: str) -> list:
    """Mọi mảng JSON xuất hiện trong prompt (đầu vào kỹ thuật, logsource...)."""
    dec, out, i = json.JSONDecoder(), [], 0
    while (i := text.find("[", i)) != -1:
        try:
            value, end = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            i += 1
            continue
        if isinstance(value, list):
            out.append(value)
        i = end
    return out


class EchoMock:
    """Trả lời xác định từ chính đầu vào; không mạng, không mô hình."""
    model_id = "echo-mock"

    def describe(self) -> dict:
        return {"model": self.model_id, "kieu_api": "mock_chay_thu"}

    def complete_json(self, system: str, user: str, json_schema: dict, log=None) -> dict:
        title = json_schema.get("title", "")
        if title == "LLMHypothesisBatch":
            techniques = next((a for a in _json_arrays(user) if a and isinstance(a[0], dict)
                               and "allowed_sources" in a[0]), [])
            items = []
            for t in techniques:
                src = (t.get("allowed_sources") or [None])[0]
                if not src:
                    continue
                items.append({"ttp_refs": [t["ref"]], "scope": "mọi máy trong log", "timeframe": "toàn bộ",
                              "behavior": f"Chạy thử mock: sự kiện {src['channel']} EID {src['event_ids']} "
                                          f"cho {t['technique_id']}",
                              "data_source": src["channel"], "event_ids": src["event_ids"],
                              "key_fields": (src.get("key_fields") or [])[:2], "priority": "thap"})
            return {"items": items[:1] if "Selected pivot" in user else items}
        if title == "LLMRule":
            offered = next((a for a in _json_arrays(user) if a and isinstance(a[0], dict) and "logsource" in a[0]), [])
            if not offered:
                return {"rule_yaml": "", "note": "mock: không có logsource"}
            rule = {"title": "Chạy thử mock", "status": "experimental", "logsource": offered[0]["logsource"],
                    "detection": {"selection": {"EventID": offered[0]["event_ids"]}, "condition": "selection"},
                    "level": "low"}
            return {"rule_yaml": yaml.safe_dump(rule, allow_unicode=True, sort_keys=False), "note": "mock"}
        raise providers.LLMError(f"mock chạy thử không hỗ trợ lược đồ {title!r} (chế độ agent cần mô hình thật)")


def _approve_all(review_dir: Path) -> None:
    f = review_dir / approval.REVIEW_FILE
    form = yaml.safe_load(f.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = REVIEWER
    for g in form["gia_thuyet"]:
        g["quyet_dinh"] = "approved"
    f.write_text("# Phiếu do scripts/chay_thu_mock.py điền: KHÔNG phải duyệt ◆ thật.\n"
                 + yaml.safe_dump(form, allow_unicode=True, sort_keys=False), encoding="utf-8")


def run(contract_a: Path, events: Path, out: Path, max_rounds: int = 20) -> dict:
    m = json.loads((events / "ingest_manifest.json").read_text(encoding="utf-8"))
    original = providers.from_config
    providers.from_config = lambda cfg: EchoMock()
    try:
        res = session.start("pipeline", contract_a, events, out, dataset_kind="otrf_dev",
                            dataset_id=m.get("dataset_id", ""), dataset_sha256=m.get("source_sha256", ""))
        rounds = 0
        while res["trang_thai"] == "cho_duyet":
            rounds += 1
            if rounds > max_rounds:
                raise RuntimeError(f"quá {max_rounds} phiếu ◆ — dừng chạy thử")
            _approve_all(Path(res["review_dir"]))
            res = session.resume(out)
    finally:
        providers.from_config = original
    return {**res, "so_phieu": rounds}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--contract-a", required=True, type=Path)
    p.add_argument("--events", required=True, type=Path, help="data/dev/<mã bộ> do ingest-dev nạp")
    p.add_argument("--out", type=Path)
    a = p.parse_args(argv)
    out = a.out or config.resolve("data/dev/_chay_thu_mock") / f"{a.events.name}-{datetime.now():%Y%m%d-%H%M%S}"
    res = run(a.contract_a, a.events, out)
    rec = json.loads(Path(res["record"]).read_text(encoding="utf-8"))
    print(json.dumps({"hunt_record": res["hunt_record"], "so_phieu_mock": res["so_phieu"],
                      "quyet_dinh": [h["decision"]["action"] + ": " + h["decision"]["reason"] for h in rec["history"]],
                      "so_hunt": len(rec["executed_specs"])}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
