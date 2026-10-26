"""Chi phí API của một lượt graph, tính từ nhật ký API của chính lượt (N5, 02/10).

Cùng công thức quyết toán của sổ ngân sách (token vào × giá vào + token ra × giá ra, không cache): kiểm ngày 02/10
khớp đúng số lời gọi và USD của sổ ở 9/9 lượt agent tuyến A. Không phụ thuộc cửa sổ thời gian, nên lượt dừng chờ
phiếu qua nhiều ngày vẫn chỉ cộng lời gọi của chính nó. Nguồn chuẩn:

- planner: `agent_plan_requests.jsonl` (mô hình ghi trên từng dòng);
- ④: `round_*/agent_proposal.json` → `khau4.api_events`;
- ④ pivot: `round_*/pivot_requests.jsonl`;
- ⑤: `round_*/khau5_requests.jsonl`.

`agent_execute.json` chỉ chép tóm tắt token ⑤ nên không cộng (tránh đếm hai lần). ④, ④ pivot và ⑤ dùng chung một
client (`configs/llm_hunt.yaml`), nên mô hình của dòng không ghi tên lấy từ `khau4.model`/`khau5.model` của lượt.
Lời gọi không kịp ghi nhật ký (lượt bị ngắt giữa khâu) không có ở đây: sổ vẫn là nguồn đối soát cuối.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..llm.budget import RATES, usd


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _hunt_model(run_dir: Path) -> str | None:
    models = set()
    for rnd in run_dir.glob("round_*"):
        for name, key in (("agent_proposal.json", "khau4"), ("agent_execute.json", "khau5")):
            path = rnd / name
            if path.exists():
                model = (json.loads(path.read_text(encoding="utf-8")).get(key) or {}).get("model")
                if model:
                    models.add(model)
    if len(models) > 1:
        raise ValueError(f"lượt có nhiều mô hình ④⑤ khác nhau: {sorted(models)}")
    return models.pop() if models else None


def run_cost(run_dir: Path) -> dict:
    """Số lời gọi, token và USD theo khâu. Mô hình không có trong biểu giá thì `usd` là None kèm lý do."""
    run_dir = Path(run_dir)
    hunt_model = _hunt_model(run_dir)
    stages: dict[str, dict] = {}
    unknown: set[str] = set()

    def add(stage: str, events, model):
        for e in events or []:
            if "input_tokens" not in e:
                continue
            row = stages.setdefault(stage, {"loi_goi": 0, "input_tokens": 0, "output_tokens": 0, "_micro": 0})
            inp, out = int(e["input_tokens"]), int(e.get("output_tokens") or 0)
            row["loi_goi"] += 1
            row["input_tokens"] += inp
            row["output_tokens"] += out
            if model in RATES:
                ir, orr = RATES[model]
                row["_micro"] += inp * ir + out * orr
            else:
                unknown.add(str(model))

    plan = run_dir / "agent_plan_requests.jsonl"
    if plan.exists():
        for d in _jsonl(plan):
            add("planner", d.get("api_events"), d.get("model"))
    for rnd in sorted(run_dir.glob("round_*")):
        proposal = rnd / "agent_proposal.json"
        if proposal.exists():
            k4 = json.loads(proposal.read_text(encoding="utf-8")).get("khau4") or {}
            add("khau4", k4.get("api_events"), k4.get("model") or hunt_model)
        for name, stage in (("pivot_requests.jsonl", "khau4_pivot"), ("khau5_requests.jsonl", "khau5")):
            if (rnd / name).exists():
                for d in _jsonl(rnd / name):
                    add(stage, d.get("api_events"), d.get("model") or hunt_model)
    total_micro = sum(r["_micro"] for r in stages.values())
    out = {"nguon": "nhat_ky_api_cua_luot", "loi_goi": sum(r["loi_goi"] for r in stages.values()),
           "input_tokens": sum(r["input_tokens"] for r in stages.values()),
           "output_tokens": sum(r["output_tokens"] for r in stages.values()),
           "usd": None if unknown else usd(total_micro),
           "theo_khau": {k: {**{f: v for f, v in r.items() if f != "_micro"},
                             "usd": None if unknown else usd(r["_micro"])} for k, r in stages.items()},
           "ghi_chu": "Lời gọi không kịp ghi nhật ký (lượt bị ngắt giữa khâu) không có ở đây; đối soát cuối bằng sổ."}
    if unknown:
        out["mo_hinh_khong_co_bieu_gia"] = sorted(unknown)
    return out
