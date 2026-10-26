"""Script mô hình mở (PC 17/10): đếm giây/lô hỏng của trích TTP không mất qua usage đã lọc; khóa cache IOC với model_info thật."""
import argparse
import importlib.util
import json
import sys

import pytest

from cti_hunt import config
from cti_hunt.llm import providers
from cti_hunt.stages import s1_ingest


@pytest.fixture
def load(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))

    def _load(name):
        spec = importlib.util.spec_from_file_location(f"{name}_test", config.ROOT / f"scripts/{name}.py")
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"{name}_test", mod)
        spec.loader.exec_module(mod)
        return mod
    return _load


class _Inner:
    """Như LocalOllama: ghi giây vào sự kiện; lời gọi thứ hai có đầu ra hỏng."""
    model_id = "ollama/m:7b"

    def __init__(self, *a):
        self.n = 0

    def complete_json(self, system, user, json_schema, log=None):
        self.n += 1
        log({"stop_reason": "stop", "input_tokens": 10, "output_tokens": 5, "giay": 12.5 if self.n == 1 else 7.5})
        if self.n == 2:
            raise providers.BadOutputError("hết num_predict trước khi xong JSON")
        return {"items": []}


def test_chay_mot_counts_seconds_and_broken_batches_despite_usage_filter(load, monkeypatch, tmp_path):
    m = load("trich_ttp_mo_hinh_mo")
    monkeypatch.setattr(m, "LocalOllama", _Inner)

    def fake_run(bundle, stix, prompt, cfg, run_dir, rules, **kw):
        run_dir.mkdir(parents=True)
        for b in range(2):  # như s2_report.run: usage ghi qua event_recorder (chỉ giữ SAFE_EVENT_KEYS)
            events, rec = providers.event_recorder()
            kw["llm"].complete_json("s", "u", {}, log=rec)
            s1_ingest.write_json(run_dir / f"usage_{b:04d}.json", events)
        return {"status": "complete", "batches": 2, "accepted_ttp": 0}
    monkeypatch.setattr(m.s2_report, "run", fake_run)
    out = tmp_path / "out"
    out.mkdir()
    # Dòng cũ không có report và dòng của report khác không được tính.
    (out / "lo_hong.jsonl").write_text('{"lo_hong": "cũ"}\n{"lo_hong": "khác", "report": "RM-Y"}\n', encoding="utf-8")
    a = argparse.Namespace(gia_lap=False, model="m:7b", num_ctx=4096, num_predict=512, timeout=10)
    r = m.chay_mot("RM-X", tmp_path / "bundle", a, out)
    assert r["giay_moi_loi_goi"] == [12.5, 7.5]
    assert r["lo_hong"] == 1
    assert r["token_vao"] == 20 and r["token_ra"] == 10
    dong = [json.loads(x) for x in (out / "lo_hong.jsonl").read_text(encoding="utf-8").splitlines()]
    assert dong[-1]["report"] == "RM-X"


def test_ioc_cache_key_works_with_real_model_info(load, monkeypatch, tmp_path):
    m = load("ioc_phan_loai_mo_hinh_mo")
    # model_info thật trả khóa "name"/"digest", không có "model" (KeyError trên PC 17/10).
    monkeypatch.setattr(m, "model_info", lambda model: {"name": model, "digest": "d" * 64})
    calls = []

    class Fake:
        model_id = "ollama/m:7b"

        def __init__(self, *a):
            pass

        def complete_json(self, system, user, json_schema, log=None):
            calls.append(user)
            return {"labels": [{"value": "evil.example", "is_ioc": True, "reason": "thử"}]}
    monkeypatch.setattr(m, "LocalOllama", Fake)
    goi = tmp_path / "goi.json"
    goi.write_text(json.dumps({"report": [{"report": "R1", "van_ban": "The actor contacted evil.example over HTTPS.",
                                           "ung_vien": [{"loai": "domain", "gia_tri": "evil.example"}]}]}),
                   encoding="utf-8")
    out = tmp_path / "ioc"
    args = ["--goi", str(goi), "--model", "m:7b", "--out", str(out)]
    assert m.main(args) == 0
    d = json.loads((out / "nhan_llm.json").read_text(encoding="utf-8"))
    assert d["nhan"]["R1"]["domain|evil.example"]["la_ioc"] is True
    assert m.main(args) == 0 and len(calls) == 1  # lần hai dùng lại cache
