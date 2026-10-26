"""Pilot mô hình cục bộ: chặn mạng ngoài máy và client API thật; client cục bộ không nhận kết quả bị cắt."""
import importlib.util
import socket
import sys

import pytest

from cti_hunt import config
from cti_hunt.llm import providers


@pytest.fixture
def pilot(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("pilot_llm_cuc_bo_test", config.ROOT / "scripts/pilot_llm_cuc_bo.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "pilot_llm_cuc_bo_test", mod)
    spec.loader.exec_module(mod)
    return mod


def test_guard_blocks_remote_hosts_and_real_api_clients(pilot):
    with pilot.guard():
        with pytest.raises(RuntimeError, match="chặn kết nối"):
            socket.create_connection(("api.anthropic.com", 443))
        with socket.socket() as sock, pytest.raises(RuntimeError, match="chặn kết nối"):
            sock.connect(("8.8.8.8", 53))
        for constructor in (providers.AnthropicClient, providers.OpenAICompatibleClient, providers.from_config):
            with pytest.raises(RuntimeError, match="cấm dựng client"):
                constructor({})
        with socket.socket() as server:                   # localhost vẫn được phép
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            socket.create_connection(server.getsockname(), timeout=2).close()


def _reply(prompt_tokens=100, done="stop", content='{"items": []}'):
    return {"done_reason": done, "prompt_eval_count": prompt_tokens, "eval_count": 20,
            "prompt_eval_duration": 2e9, "eval_duration": 3e9, "message": {"content": content}}


def test_local_client_sends_strict_schema_and_records_tokens(pilot, monkeypatch):
    sent = []
    monkeypatch.setattr(pilot, "_get", lambda path, body=None, timeout=30: sent.append((path, body)) or _reply())
    llm = pilot.LocalOllama("m:7b", num_ctx=4096, max_output_tokens=512, timeout=10)
    schema = {"type": "object", "properties": {"items": {"type": "array", "items": {"type": "string"}}}}
    events = []
    assert llm.complete_json("sys", "user", schema, log=events.append) == {"items": []}
    path, body = sent[0]
    assert path == "/api/chat" and body["options"]["num_ctx"] == 4096 and body["options"]["temperature"] == 0
    assert body["format"] == providers.strict_schema(schema)
    assert events == llm.calls and events[0]["input_tokens"] == 100 and events[0]["output_tokens"] == 20


@pytest.mark.parametrize("reply, message", [(_reply(prompt_tokens=4090), "num_ctx"), (_reply(done="length"), "num_predict")])
def test_local_client_rejects_truncated_prompt_or_output(pilot, monkeypatch, reply, message):
    monkeypatch.setattr(pilot, "_get", lambda path, body=None, timeout=30: reply)
    llm = pilot.LocalOllama("m:7b", num_ctx=4096, max_output_tokens=512, timeout=10)
    with pytest.raises(providers.BadOutputError, match=message):
        llm.complete_json("sys", "user", {"type": "object", "properties": {}})


@pytest.mark.parametrize("relative", ["data/dev", "data/work/x", "runs/x"])
def test_output_must_be_new_dir_under_data_dev(pilot, relative):
    with pytest.raises(SystemExit, match="data/dev"):
        pilot.main(["khau2", "--model", "m:7b", "--out", str(config.ROOT / relative)])
