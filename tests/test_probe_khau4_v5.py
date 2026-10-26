"""Offline and fake-transport checks; never sends API or reads the real shared ledger."""
import copy
import importlib.util
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
import pytest
import yaml

from cti_hunt import config
from cti_hunt.agent import probe_khau4 as P
from cti_hunt.llm import budget, providers


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / "root"
    # The probe pins its own code/config/prompt; use isolated copies for every test.
    # Reconstruct the pinned v5 config in the fixture; production may now use a newer prompt.
    names = ["configs/agent_v2.yaml", "configs/llm_hunt.yaml", "configs/chinh_sach_loc_v2.yaml",
             "prompts/khau4_gia_thuyet_v5.md", "scripts/probe_khau4_v5.py",
             "src/cti_hunt/agent/probe_khau4.py", "src/cti_hunt/contracts.py",
             "src/cti_hunt/stages/s4_hypothesis.py", "src/cti_hunt/stages/s3_telemetry.py",
             "src/cti_hunt/llm/providers.py", "src/cti_hunt/llm/budget.py",
             "src/cti_hunt/llm/prompting.py", "src/cti_hunt/config.py"]
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(config.ROOT / name, target)
    cfg_path = root / "configs/agent_v2.yaml"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    cfg["prompt_khau4"] = "prompts/khau4_gia_thuyet_v5.md"
    cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    ledger = budget.Ledger(root / "data/dev/api_budget.sqlite")
    ledger.init("0.626424")
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key")
    out = tmp_path / "probe"
    return root, out, ledger


def item(ref, kind=None, rb=None):
    return {"ttp_refs": [ref], "behavior": "Hành vi nguồn tự soạn", "scope": "mọi máy",
            "timeframe": "toàn bộ khoảng thời gian của log", "data_source": P.SYS,
            "event_ids": [11 if ref == 2 else 3], "key_fields": ["ProcessGuid"],
            "extra_techniques": [], "priority": "cao", "rationale": "câu tự soạn",
            "required_operations": [], "rang_buoc": {kind: rb} if kind else None}


GOOD = {"items": [item(0, "dem_khac_nhau", P.COUNT), item(1, "vang_mat", P.ABSENCE),
                  item(2, "moc_neo", P.ANCHOR)]}


def fake_transport(monkeypatch, *, count=5000, reply=None):
    calls = []
    def post(url, payload, headers, **kwargs):
        calls.append(url)
        assert kwargs['retries'] == (providers.RETRY_LAN if url.endswith('count_tokens') else 1)  # R1: chỉ đếm token được thử lại
        if url.endswith("count_tokens"):
            return {"input_tokens": count}
        if isinstance(reply, Exception):
            raise reply
        return reply if reply is not None else {
            "usage": {"input_tokens": 5000, "output_tokens": 200}, "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "input": GOOD}]}
    monkeypatch.setattr(providers, "_post", post)
    return calls


def test_offline_prepares_exact_payload_and_does_not_touch_ledger(prepared, monkeypatch):
    root, out, ledger = prepared
    before = ledger.path.read_bytes()
    calls = fake_transport(monkeypatch)
    result = P.run(out, root=root)
    assert calls == [] and result["mode"] == "OFFLINE_NO_API"
    assert before == ledger.path.read_bytes() and not (out / "attempt.json").exists()
    payload = json.loads((out / "payload.json").read_text(encoding="utf-8"))
    protocol = json.loads((out / "protocol.json").read_text(encoding="utf-8"))
    assert payload["max_tokens"] == 32000 and payload["output_config"] == {"effort": "high"}
    assert payload["tools"][0]["strict"] and payload["tool_choice"] == {"type": "auto"}
    assert "criteria" not in json.dumps(payload) and "synthetic-test-key" not in json.dumps(payload)
    assert protocol["criteria"]["ref_0"]["dem_khac_nhau"] == P.COUNT
    assert result["ledger"] == {"remaining_usd": "0.626424", "pending_count": 0}


def test_send_calls_once_records_cost_and_refuses_repeat(prepared, monkeypatch):
    root, out, ledger = prepared
    P.run(out, root=root)
    calls = fake_transport(monkeypatch)
    result = P.run(out, root=root, send=True)
    assert len(calls) == 2 and calls[0].endswith("count_tokens") and calls[1].endswith("messages")
    assert result["state"] == "received" and result["criteria_met"] and result["manual_review_required"]
    assert result["known_cost_usd"] == "0.012000" and not result["cost_exceeds_cap"]
    assert ledger.status()["known_cost_usd"] == "0.012000"
    for name in ("response_raw.json", "hypotheses.json", "khau4_log.json", "result.json", "attempt.json"):
        assert (out / name).exists()
    with pytest.raises(ValueError, match="không gửi lại"):
        P.run(out, root=root, send=True)
    with pytest.raises(ValueError, match="không gửi lại"):
        P.run(out, root=root)
    assert len(calls) == 2


def test_concurrent_send_can_enter_generation_only_once(prepared, monkeypatch):
    root, out, _ = prepared
    P.run(out, root=root)
    calls = fake_transport(monkeypatch)
    def send():
        try:
            return P.run(out, root=root, send=True)["state"]
        except (ValueError, OSError, budget.BudgetError):
            return "blocked"
    with ThreadPoolExecutor(max_workers=2) as pool:
        states = list(pool.map(lambda _: send(), range(2)))
    assert sorted(states) == ["blocked", "received"]
    assert sum(url.endswith("messages") for url in calls) == 1


def test_truncated_stop_is_not_a_pass_even_with_parseable_tool_input(prepared, monkeypatch):
    root, out, _ = prepared
    P.run(out, root=root)
    fake_transport(monkeypatch, reply={"usage": {"input_tokens": 5000, "output_tokens": 200},
        "stop_reason": "max_tokens", "content": [{"type": "tool_use", "input": GOOD}]})
    result = P.run(out, root=root, send=True)
    assert result["state"] == "received" and result["criteria_met"] is False and result["truncated"]


def test_cap_blocks_generation_after_token_count_without_charging(prepared, monkeypatch):
    root, out, ledger = prepared
    P.run(out, root=root)
    calls = fake_transport(monkeypatch, count=40000)
    result = P.run(out, root=root, send=True)
    assert len(calls) == 1 and calls[0].endswith("count_tokens")
    assert result["state"] == "failed_no_retry" and result["error_type"] == "BudgetExhausted"
    assert ledger.status()["known_cost_usd"] == "0.000000" and not ledger.status()["pending"]
    assert result["known_cost_usd"] is None  # no fake zero-cost success if no usage was received


@pytest.mark.parametrize("failure", [
    providers.TransportError("fictional timeout"),
    {"usage": {"input_tokens": 5000, "output_tokens": 200}, "stop_reason": "refusal", "content": []},
    {"usage": {"input_tokens": 5000, "output_tokens": 200}, "stop_reason": "max_tokens", "content": []},
])
def test_failed_send_never_retries_and_retains_budget_evidence(prepared, monkeypatch, failure):
    root, out, ledger = prepared
    P.run(out, root=root)
    calls = fake_transport(monkeypatch, reply=failure)
    result = P.run(out, root=root, send=True)
    assert result["state"] == "failed_no_retry" and len(calls) == 2
    with pytest.raises(ValueError):
        P.run(out, root=root, send=True)
    assert len(calls) == 2
    if isinstance(failure, Exception):
        assert ledger.status()["pending"] and result["known_cost_usd"] is None
    else:
        assert not ledger.status()["pending"] and result["known_cost_usd"] == "0.012000"


@pytest.mark.parametrize("name", ["payload.json", "contract_a.json", "telemetry.json", "fixture_anchors.json", "protocol.json"])
def test_tampered_prepared_inputs_block_before_network(prepared, monkeypatch, name):
    root, out, _ = prepared
    P.run(out, root=root)
    (out / name).write_text("{}", encoding="utf-8")
    calls = fake_transport(monkeypatch)
    with pytest.raises(ValueError):
        P.run(out, root=root, send=True)
    assert not calls and not (out / "attempt.json").exists()


def test_changed_code_or_prompt_blocks_before_network(prepared, monkeypatch):
    root, out, _ = prepared
    P.run(out, root=root)
    with (root / "prompts/khau4_gia_thuyet_v5.md").open("a", encoding="utf-8") as f:
        f.write("\nchanged")
    calls = fake_transport(monkeypatch)
    with pytest.raises(ValueError):
        P.run(out, root=root, send=True)
    assert not calls


def test_missing_key_or_insufficient_shared_budget_blocks_before_attempt(prepared, monkeypatch):
    root, out, ledger = prepared
    P.run(out, root=root)
    calls = fake_transport(monkeypatch)
    monkeypatch.delenv("LLM_API_KEY")
    with pytest.raises(providers.LLMError):
        P.run(out, root=root, send=True)
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key")
    ledger.set_limit("0.3")
    with pytest.raises(budget.BudgetError):
        P.run(out, root=root, send=True)
    assert not calls and not (out / "attempt.json").exists()


@pytest.mark.parametrize("change", ["wrong_number", "invent_vague", "missing_case", "wrong_source", "bad_schema"])
def test_probe_reports_parameter_or_coverage_failures_without_rerun(prepared, monkeypatch, change):
    root, out, _ = prepared
    P.run(out, root=root)
    raw = copy.deepcopy(GOOD)
    if change == "wrong_number":
        raw["items"][0]["rang_buoc"]["dem_khac_nhau"]["toi_thieu"] = 99
    elif change == "invent_vague":
        raw["items"].append(item(3, "dem_khac_nhau", P.COUNT))
    elif change == "missing_case":
        raw["items"].pop()
    elif change == "wrong_source":
        raw["items"][0]["event_ids"] = [22]
    else:
        raw["items"][0]["rang_buoc"] = {}
    calls = fake_transport(monkeypatch, reply={"usage": {"input_tokens": 5000, "output_tokens": 200},
        "stop_reason": "tool_use", "content": [{"type": "tool_use", "input": raw}]})
    result = P.run(out, root=root, send=True)
    assert result["state"] == "received" and result["criteria_met"] is False
    assert len(calls) == 2


def test_evidence_does_not_print_or_save_api_key(prepared, monkeypatch):
    root, out, _ = prepared
    P.run(out, root=root)
    fake_transport(monkeypatch, reply=providers.TransportError("synthetic-test-key echoed in fake error"))
    result = P.run(out, root=root, send=True)
    assert "synthetic-test-key" not in json.dumps(result)
    assert "[REDACTED]" in result["error"]


def test_wrapper_defaults_to_offline(monkeypatch):
    path = config.ROOT / "scripts/probe_khau4_v5.py"
    spec = importlib.util.spec_from_file_location("probe_wrapper", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    modes = []
    monkeypatch.setattr(P, "run", lambda **kw: modes.append(kw["send"]) or {"mode": "OFFLINE_NO_API"})
    assert module.main([]) == 0 and modes == [False]


@pytest.mark.parametrize("send", [False, True])
def test_old_probe_refuses_new_prompt_without_network_or_evidence_changes(prepared, monkeypatch, send):
    root, out, _ = prepared
    P.run(out, root=root)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    path = root / "configs/agent_v2.yaml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    cfg["prompt_khau4"] = "prompts/khau4_gia_thuyet_v6.md"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    calls = fake_transport(monkeypatch)
    with pytest.raises(ValueError, match="Cấu hình đã đổi"):
        P.run(out, root=root, send=send)
    assert calls == [] and before == {p.name: p.read_bytes() for p in out.iterdir()}
