"""Chi phí API theo lượt từ nhật ký của chính lượt (N5): cùng công thức quyết toán của sổ, không đếm trùng."""
import json

from cti_hunt.agent.chi_phi import run_cost


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _run(tmp_path, hunt_model="claude-sonnet-5"):
    run = tmp_path / "run"
    ev = lambda i, o: {"stop_reason": "tool_use", "input_tokens": i, "output_tokens": o, "max_tokens": 8192}
    _jsonl(run / "agent_plan_requests.jsonl", [{"model": "claude-sonnet-5", "api_events": [ev(1000, 100)]},
                                               {"model": "claude-sonnet-5", "api_events": [ev(2000, 200)]}])
    _write(run / "round_01/agent_proposal.json", {"khau4": {"model": hunt_model, "api_events": [ev(3000, 300)]}})
    _jsonl(run / "round_01/khau5_requests.jsonl", [{"hypothesis_id": "H1", "api_events": [ev(400, 40)]},
                                                   {"hypothesis_id": "H2", "api_events": [ev(500, 50)]}])
    # Bản tóm tắt ⑤ chép lại token: không được cộng lần nữa.
    _write(run / "round_01/agent_execute.json", {"khau5": {"model": hunt_model},
                                                 "rules": [{"token": {"input_tokens": 400, "output_tokens": 40}}]})
    _jsonl(run / "round_02/pivot_requests.jsonl", [{"pivot": {}, "api_events": [ev(600, 60)]}])
    return run


def test_counts_each_logged_call_once_with_ledger_formula(tmp_path):
    cost = run_cost(_run(tmp_path))
    assert cost["loi_goi"] == 6
    assert cost["input_tokens"] == 7500 and cost["output_tokens"] == 750
    assert cost["usd"] == "0.022500"             # 7500 × 2 + 750 × 10 = 22.500 micro-USD (Sonnet 5)
    assert {k: v["loi_goi"] for k, v in cost["theo_khau"].items()} == {"planner": 2, "khau4": 1, "khau5": 2,
                                                                      "khau4_pivot": 1}
    assert cost["theo_khau"]["khau5"]["usd"] == "0.002700"       # (400 + 500) × 2 + (40 + 50) × 10


def test_unknown_model_reports_no_price_instead_of_guessing(tmp_path):
    cost = run_cost(_run(tmp_path, hunt_model="mock-model"))
    assert cost["usd"] is None and cost["mo_hinh_khong_co_bieu_gia"] == ["mock-model"]
    assert cost["loi_goi"] == 6


def test_run_without_api_events_costs_nothing(tmp_path):
    run = tmp_path / "empty"
    run.mkdir()
    cost = run_cost(run)
    assert cost["loi_goi"] == 0 and cost["usd"] == "0.000000" and cost["theo_khau"] == {}
