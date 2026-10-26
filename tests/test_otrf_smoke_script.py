"""Lệnh thử OTRF: gắn đúng dữ liệu và giữ cổng gọi API; mọi lời gọi CLI trong test đều giả."""
import importlib.util
from pathlib import Path

import pytest

from cti_hunt.config import ROOT


@pytest.fixture
def script():
    spec = importlib.util.spec_from_file_location("thu_otrf_sonnet", ROOT / "scripts/thu_otrf_sonnet.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("options, report, dataset, sha", [
    ([], "DEV-SCHTASKS", "otrf-schtasks",
     "74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b"),
    (["--mechanism", "wmi-exec"], "DEV-WMIEXEC", "otrf-wmi-exec",
     "96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88"),
])
def test_dry_run_keeps_contract_dataset_binding_without_key_or_budget(
        script, monkeypatch, tmp_path, options, report, dataset, sha):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    calls = []
    monkeypatch.setattr(script.cli, "main", lambda args: calls.append(args) or 0)
    out = tmp_path / "luot moi"
    assert script.main([*options, "--out", str(out)]) == 0
    assert len(calls) == 1 and calls[0][:2] == ["agent", "start"]
    cmd = calls[0]
    assert cmd[-1] == "--dry-run"
    assert Path(cmd[cmd.index("--contract-a") + 1]).name == f"contract_a_{report}.json"
    assert Path(cmd[cmd.index("--events") + 1]) == ROOT / "data/dev" / dataset
    assert cmd[cmd.index("--dataset-id") + 1] == dataset
    assert cmd[cmd.index("--dataset-sha256") + 1] == sha
    assert cmd[cmd.index("--dataset-kind") + 1] == "otrf_dev"
    assert cmd[cmd.index("--mode") + 1] == "pipeline"
    assert Path(cmd[cmd.index("--out") + 1]) == out
    assert not out.exists()


def test_unknown_mechanism_stops_before_budget_or_agent(script, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(script.cli, "main", lambda args: calls.append(args) or 0)
    with pytest.raises(SystemExit) as exc:
        script.main(["--mechanism", "apt29_day2", "--send", "--out", str(tmp_path / "luot")])
    assert exc.value.code == 2 and calls == []


def test_send_without_budget_stops_before_agent(script, monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key")
    calls = []
    monkeypatch.setattr(script.cli, "main", lambda args: calls.append(args) or 1)
    assert script.main(["--mechanism", "wmi-exec", "--send", "--out", str(tmp_path / "luot")]) == 1
    assert calls == [["api-budget", "status"]]


def test_send_without_key_does_not_create_run(script, monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    calls = []
    monkeypatch.setattr(script.cli, "main", lambda args: calls.append(args) or 0)
    out = tmp_path / "luot"
    assert script.main(["--mechanism", "wmi-exec", "--send", "--out", str(out)]) == 1
    assert calls == [["api-budget", "status"]] and not out.exists()
    assert "Chưa đặt LLM_API_KEY" in capsys.readouterr().out


@pytest.mark.parametrize("start_code, status_code, expected", [(0, 0, 0), (1, 0, 1), (0, 1, 1)])
def test_send_reports_budget_after_start_and_keeps_failure_code(
        script, monkeypatch, tmp_path, start_code, status_code, expected):
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key")
    calls = []

    def fake_cli(args):
        calls.append(args)
        if args[:2] == ["agent", "start"]:
            return start_code
        assert args == ["api-budget", "status"]
        return 0 if len(calls) == 1 else status_code

    monkeypatch.setattr(script.cli, "main", fake_cli)
    assert script.main(["--mechanism", "wmi-exec", "--send", "--out", str(tmp_path / "luot")]) == expected
    assert len(calls) == 3 and calls[0] == calls[2] == ["api-budget", "status"]
    assert calls[1][:2] == ["agent", "start"] and "--dry-run" not in calls[1]
