"""Ngân sách dùng chung; chỉ transport giả, không gọi mạng hoặc đọc sổ chi phí thật."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from cti_hunt import cli, config
from cti_hunt.llm import budget, providers

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


@pytest.fixture
def ledger(tmp_path):
    out = budget.Ledger(tmp_path / "budget.sqlite")
    out.init("0.5")
    return out


@pytest.fixture
def client(ledger, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key")
    return providers.AnthropicClient("claude-sonnet-5", max_output_tokens=32000, effort="high",
                                     budget_ledger=str(ledger.path))


def response(**updates):
    return {"usage": {"input_tokens": 1000, "output_tokens": 100}, "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "input": {"ok": True}}], **updates}


def transport(monkeypatch, paid=None, count=None):
    calls = []

    def post(url, payload, headers, **kwargs):
        calls.append((url, payload, kwargs))
        if url.endswith("count_tokens"):   # R1: đếm token miễn phí được thử lại, chờ ngắn
            assert kwargs["retries"] == providers.RETRY_LAN and kwargs["timeout"] <= budget.COUNT_TIMEOUT_GIAY
        else:                              # lời gọi sinh nội dung (tính tiền) chỉ một lần
            assert kwargs["retries"] == 1
        result = (count if count is not None else {"input_tokens": 1000}) if url.endswith("count_tokens") \
            else (paid if paid is not None else response())
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(providers, "_post", post)
    return calls


@pytest.mark.parametrize("amount", ["nan", "inf", "-1", "0", "0.0000001", "abc"])
def test_invalid_limit_never_creates_a_ledger(tmp_path, amount):
    ledger = budget.Ledger(tmp_path / "ledger.sqlite")
    with pytest.raises(budget.BudgetError):
        ledger.init(amount)
    assert not ledger.path.exists()


def test_missing_ledger_blocks_before_any_network(client, monkeypatch, tmp_path):
    client.budget_ledger = str(tmp_path / "missing.sqlite")
    calls = transport(monkeypatch)
    with pytest.raises(budget.BudgetError, match="Chưa đặt ngân sách"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert calls == [] and not Path(client.budget_ledger).exists()


def test_reserves_full_output_then_settles_actual_usage_before_parsing(client, ledger, monkeypatch):
    calls = transport(monkeypatch)
    events = []
    assert client.complete_json("SECRET-PROMPT", "USER", SCHEMA, log=events.append) == {"ok": True}
    assert len(calls) == 2 and calls[0][0].endswith("count_tokens")
    assert "max_tokens" not in calls[0][1] and "tools" in calls[0][1]
    assert calls[1][1]["max_tokens"] == 32000  # không hạ max_tokens để lách hạn mức
    assert events[-1]["output_tokens"] == 100
    status = budget.Ledger(ledger.path).status()  # mở lại sau tiến trình/lượt khác
    assert status["known_cost_usd"] == "0.003000" and status["remaining_usd"] == "0.497000"
    assert status["pending"] == []
    with ledger.db() as con:
        row = con.execute("SELECT reserved, charged, input_tokens, output_tokens FROM requests").fetchone()
        assert row == (322712, 3000, 1000, 100)
    assert b"SECRET-PROMPT" not in ledger.path.read_bytes() and b"synthetic-test-key" not in ledger.path.read_bytes()


def test_insufficient_funds_never_sends_generation(client, ledger, monkeypatch):
    ledger.set_limit("0.32")
    calls = transport(monkeypatch)
    with pytest.raises(budget.BudgetError, match="Không đủ ngân sách"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 1 and calls[0][0].endswith("count_tokens")
    assert ledger.status()["known_cost_usd"] == "0.000000" and not ledger.status()["pending"]


def test_per_request_cap_checks_full_reservation_before_generation(client, ledger, monkeypatch):
    client.request_budget_usd = "0.40"
    calls = transport(monkeypatch, count={"input_tokens": 40000})
    with pytest.raises(budget.BudgetExhausted, match="trần riêng"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 1 and not ledger.status()["pending"]
    assert ledger.status()["known_cost_usd"] == "0.000000"


def test_per_request_cap_is_additional_to_shared_ledger_limit(client, ledger, monkeypatch):
    client.request_budget_usd = "0.40"
    ledger.set_limit("0.32")
    calls = transport(monkeypatch)
    with pytest.raises(budget.BudgetExhausted, match="Không đủ ngân sách"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 1 and not ledger.status()["pending"]


@pytest.mark.parametrize("cap", ["0.30", "nan", "0", "-1"])
def test_impossible_or_invalid_per_request_cap_blocks_before_network(client, monkeypatch, cap):
    client.request_budget_usd = cap
    calls = transport(monkeypatch)
    with pytest.raises(budget.BudgetError):
        client.complete_json("SYS", "USER", SCHEMA)
    assert calls == []


def test_per_request_cap_cannot_bypass_guard_using_no_ledger(monkeypatch):
    client = providers.AnthropicClient("claude-sonnet-5", request_budget_usd="0.40")
    calls = transport(monkeypatch)
    with pytest.raises(providers.LLMError, match="sổ ngân sách"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert calls == []


def test_timeout_keeps_reservation_and_blocks_other_clients_until_manual_reconciliation(client, ledger, monkeypatch):
    calls = transport(monkeypatch, paid=providers.TransportError("fake timeout"))
    with pytest.raises(providers.TransportError):
        client.complete_json("SYS", "USER", SCHEMA)
    status = ledger.status()
    assert status["known_cost_usd"] == "0.000000" and status["reserved_usd"] == "0.322712"
    other = providers.AnthropicClient("claude-sonnet-5", budget_ledger=str(ledger.path))
    with pytest.raises(budget.BudgetError, match="chưa rõ chi phí"):
        other.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 2  # không đếm token/gọi API lại khi chưa đối soát
    with pytest.raises(budget.BudgetError):
        ledger.set_limit("1")
    ledger.resolve(status["pending"][0]["id"], "0.1", "fixture: Console xác nhận 0.1 USD")
    assert ledger.status()["remaining_usd"] == "0.400000"
    transport(monkeypatch)
    assert client.complete_json("SYS", "USER", SCHEMA) == {"ok": True}
    assert ledger.status()["known_cost_usd"] == "0.103000"


@pytest.mark.parametrize("reply, error", [
    (response(stop_reason="refusal", content=[]), providers.RefusalError),
    (response(stop_reason="max_tokens", content=[]), providers.BadOutputError),
])
def test_refused_or_truncated_response_still_charges_usage(client, ledger, monkeypatch, reply, error):
    transport(monkeypatch, paid=reply)
    with pytest.raises(error):
        client.complete_json("SYS", "USER", SCHEMA)
    assert ledger.status()["known_cost_usd"] == "0.003000" and not ledger.status()["pending"]


@pytest.mark.parametrize("usage", [[], {}, {"input_tokens": -1, "output_tokens": 100},
                                    {"input_tokens": 10, "output_tokens": True},
                                    {"input_tokens": 10, "output_tokens": 100, "cache_read_input_tokens": 12}])
def test_missing_or_unsupported_usage_is_not_counted_as_zero(client, ledger, monkeypatch, usage):
    transport(monkeypatch, paid=response(usage=usage))
    with pytest.raises(budget.BudgetError):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(ledger.status()["pending"]) == 1


def test_count_failure_does_not_reserve_or_generate(client, ledger, monkeypatch):
    calls = transport(monkeypatch, count=providers.TransportError("count failed"))
    with pytest.raises(providers.TransportError):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 1 and not ledger.status()["pending"]


def test_parallel_reservations_cannot_overspend(ledger):
    def reserve():
        try:
            return budget.Ledger(ledger.path).reserve("claude-sonnet-5", 300000)
        except budget.BudgetError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: reserve(), range(2)))
    assert sum(r is not None for r in results) == 1
    assert ledger.status()["reserved_usd"] == "0.300000"


def test_limit_changes_preserve_spending_and_init_cannot_reset_it(ledger):
    rid = ledger.reserve("claude-sonnet-5", 20000)
    ledger.settle(rid, "claude-sonnet-5", {"input_tokens": 1000, "output_tokens": 100})
    with pytest.raises(budget.BudgetError, match="đã tồn tại"):
        ledger.init("0.5")
    with pytest.raises(budget.BudgetError):
        ledger.set_limit("0.001")
    assert ledger.set_limit("0.6")["remaining_usd"] == "0.597000"


def test_budget_cli_is_local_and_does_not_reset_usage(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(budget, "configured_path", lambda: tmp_path / "budget.sqlite")
    calls = transport(monkeypatch)
    assert cli.main(["api-budget", "status"]) == 1
    capsys.readouterr()
    assert cli.main(["api-budget", "init", "--usd", "0.5"]) == 0
    assert json.loads(capsys.readouterr().out)["remaining_usd"] == "0.500000"
    assert cli.main(["api-budget", "set-limit", "--usd", "0.6"]) == 0
    capsys.readouterr()
    assert cli.main(["api-budget", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["limit_usd"] == "0.600000"
    assert calls == []


def test_configuration_shares_hunt_budget_and_leaves_stage2_unchanged():
    hunt = providers.from_config(config.load("llm_hunt"))
    planner = providers.from_config(config.load("agent_planner"))
    extraction = providers.from_config(config.load("llm"))
    assert Path(hunt.budget_ledger) == Path(planner.budget_ledger) == budget.configured_path()
    assert extraction.budget_ledger is None
    assert hunt.describe()["budget_guard"]["generation_attempts"] == 1


def test_opus55_reserves_and_settles_at_its_own_rates(client, ledger, monkeypatch):
    # Khâu ② v2 (N3) dùng Opus 5.5: 4 / 20 USD mỗi triệu token, khác Sonnet 5.
    client.model_id, client.max_output_tokens = "claude-opus-5-5", 1000
    transport(monkeypatch)
    assert client.complete_json("SYS", "USER", SCHEMA) == {"ok": True}
    status = budget.Ledger(ledger.path).status()
    assert status["known_cost_usd"] == "0.006000"          # 1000 × 4 + 100 × 20 micro-USD
    assert budget.min_reserve("claude-opus-5-5", 32000) == 256 * 4 + 32000 * 20


@pytest.mark.parametrize("change", [{"model_id": "claude-fable-5-1"}, {"base_url": "https://example.com"}])
def test_unknown_pricing_never_sends_network(client, monkeypatch, change):
    for k, v in change.items():
        setattr(client, k, v)
    calls = transport(monkeypatch)
    with pytest.raises(budget.BudgetError, match="biểu giá"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert calls == []


def test_recorded_cost_over_the_estimate_blocks_the_next_call(client, ledger, monkeypatch):
    # Count là ước tính, usage là số đã tiêu: không hạ số tiền ghi sổ về khoản đã dự phòng.
    calls = transport(monkeypatch, paid=response(usage={"input_tokens": 300000, "output_tokens": 100}))
    client.complete_json("SYS", "USER", SCHEMA)
    assert ledger.status()["known_cost_usd"] == "0.601000"
    with pytest.raises(budget.BudgetError, match="hết hạn mức"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert len(calls) == 2


class _Reply:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


def _network(monkeypatch, plan):
    """urlopen giả theo kịch bản từng URL: phần tử là Exception (ném) hoặc dict (trả JSON)."""
    import urllib.error
    import urllib.request
    seen = []

    def urlopen(req, timeout):
        kind = "count" if req.full_url.endswith("count_tokens") else "paid"
        seen.append((kind, timeout))
        step = plan[kind].pop(0)
        if isinstance(step, Exception):
            raise urllib.error.URLError(step)
        return _Reply(step)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)
    return seen


def test_token_count_retries_a_network_failure_without_reserving_or_resending_generation(client, ledger, monkeypatch):
    """R1 (09/10): một lần TLS treo ở bước đếm token không còn làm vỡ lượt; lời gọi sinh nội dung vẫn một lần."""
    seen = _network(monkeypatch, {"count": [TimeoutError("The handshake operation timed out"), {"input_tokens": 1000}],
                                  "paid": [response()]})
    assert client.complete_json("SYS", "USER", SCHEMA) == {"ok": True}
    assert [k for k, _ in seen] == ["count", "count", "paid"]
    assert all(t <= budget.COUNT_TIMEOUT_GIAY for k, t in seen if k == "count")
    status = ledger.status()
    assert status["known_cost_usd"] == "0.003000" and status["pending"] == []


def test_token_count_gives_up_after_retries_before_any_reservation(client, ledger, monkeypatch):
    seen = _network(monkeypatch, {"count": [TimeoutError("timed out")] * providers.RETRY_LAN, "paid": []})
    with pytest.raises(providers.TransportError, match=f"sau {providers.RETRY_LAN} lần thử"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert [k for k, _ in seen] == ["count"] * providers.RETRY_LAN
    assert ledger.status()["reserved_usd"] == "0.000000" and ledger.status()["pending"] == []


def test_paid_generation_is_still_sent_once_when_its_response_is_lost(client, ledger, monkeypatch):
    seen = _network(monkeypatch, {"count": [{"input_tokens": 1000}], "paid": [TimeoutError("read timed out")]})
    with pytest.raises(providers.TransportError, match="sau 1 lần thử"):
        client.complete_json("SYS", "USER", SCHEMA)
    assert [k for k, _ in seen] == ["count", "paid"]
    assert ledger.status()["reserved_usd"] == "0.322712" and len(ledger.status()["pending"]) == 1
