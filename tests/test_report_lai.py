"""Khâu ② với cách gợi ý lai (BM25 + embedding, RRF). Report tự soạn, bộ mã hóa giả; không tải mô hình, không gọi API."""
import hashlib
import json
import re

import numpy as np
import pytest

from cti_hunt import config
from cti_hunt.attack import dense_retrieval as DR
from cti_hunt.attack.retrieval import TechniqueIndex
from cti_hunt.cli import main
from cti_hunt.stages import s1_ingest as S1, s2_report as S2

PROMPT = config.ROOT / "prompts/report_extract_v1.md"
LLM_CFG = {"provider": "mock", "model": "test"}


def fake_encoder(texts):
    out = np.zeros((len(texts), 64), dtype=np.float32)
    for i, t in enumerate(texts):
        for w in re.findall(r"[a-z]+", t.lower()):
            out[i, int(hashlib.md5(w.encode()).hexdigest(), 16) % 64] += 1
        n = np.linalg.norm(out[i])
        out[i] = out[i] / n if n else out[i]
    return out


TECHS = [("T1047", "Windows Management Instrumentation", "WMI can execute a process on another host."),
         ("T1005", "Data from Local System", "Adversaries may search local system sources such as files."),
         ("T1018", "Remote System Discovery", "Adversaries may list other systems by IP address or hostname."),
         ("T1059", "Command and Scripting Interpreter", "Adversaries may abuse shells such as cmd and powershell.")]


@pytest.fixture
def stix(tmp_path):
    objects = [{"type": "x-mitre-tactic", "id": "tactic--1", "x_mitre_shortname": "execution", "name": "Execution"}]
    for tid, name, desc in TECHS:
        objects.append({"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name, "description": desc,
                        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]})
    path = tmp_path / "attack.json"
    S1.write_json(path, {"objects": objects})
    return path


@pytest.fixture
def bundle(tmp_path):
    source = tmp_path / "r.html"
    source.write_text("<html><head><title>New report</title></head><body><article><h1>Activity</h1>"
                      "<p>The actor used WMI to execute a process on another host.</p>"
                      "<p>They collected files from the compromised machine and listed nearby computers.</p>"
                      "</article></body></html>", encoding="utf-8")
    folder = tmp_path / "bundle"
    S1.ingest(str(source), "NEW", folder)
    return folder


def test_default_is_bm25_and_unchanged(bundle, stix):
    meta0, req0 = S2.prepare(bundle, stix, PROMPT, LLM_CFG)
    meta1, req1 = S2.prepare(bundle, stix, PROMPT, LLM_CFG, retrieval="bm25")
    assert (meta0, req0) == (meta1, req1)
    assert "retrieval_dense" not in meta0 and "dense_retrieval.py" not in meta0["code_sha256"]
    with pytest.raises(ValueError):
        S2.prepare(bundle, stix, PROMPT, LLM_CFG, retrieval="vector")


def test_hybrid_candidates_are_rrf_of_bm25_and_dense(bundle, stix, tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_EMBED_CACHE", str(tmp_path / "cache"))
    meta_b, req_b = S2.prepare(bundle, stix, PROMPT, LLM_CFG, top_k=3)
    meta, req = S2.prepare(bundle, stix, PROMPT, LLM_CFG, top_k=3, retrieval="lai", encoder=fake_encoder)
    assert meta["retrieval_dense"]["model"] == DR.MODELS[DR.LAI_MODEL]["name"]
    assert meta["retrieval_dense"]["chunk_words"] == DR.LAI_CHUNK
    assert "dense_retrieval.py" in meta["code_sha256"] and meta["retrieval"].startswith("Hybrid")
    assert meta["requests_sha256"] != meta_b["requests_sha256"]
    index = TechniqueIndex.from_stix(stix)
    dense = DR.DenseIndex(index.documents, fake_encoder, DR.LAI_MODEL, DR.LAI_CHUNK)
    targets = [t for r in req for t in json.loads(r["user"])["targets"]]
    assert targets
    for t in targets:
        want = DR.rrf([[c["technique_id"] for c in index.search(t["text"], DR.RRF_DEPTH)],
                       [c["technique_id"] for c in dense.search(t["text"], DR.RRF_DEPTH)]], k=3)
        assert [(c["technique_id"], c["retrieval_score"]) for c in t["candidates"]] == \
               [(w["technique_id"], w["retrieval_score"]) for w in want]
        assert all(set(c) == {"technique_id", "name", "description", "tactics", "retrieval_score"}
                   for c in t["candidates"])
    # Văn bản đoạn và lô không đổi; chỉ gợi ý khác.
    strip = lambda rs: [[{k: v for k, v in t.items() if k != "candidates"} for t in json.loads(r["user"])["targets"]]
                        for r in rs]
    assert strip(req) == strip(req_b)


def test_cli_flag_reaches_extraction(bundle, tmp_path, monkeypatch):
    rp = config.load("reports")
    if not config.resolve(rp["attack"]["stix_path"]).exists():
        pytest.skip("Thiếu ATT&CK v19.2 cục bộ")
    monkeypatch.setenv("CTI_EMBED_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(DR, "load_encoder", lambda key: fake_encoder)
    out = tmp_path / "out"
    assert main(["extract-report", str(bundle), "--out", str(out), "--retrieval", "lai"]) == 0
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["retrieval_dense"]["chunk_words"] == DR.LAI_CHUNK and meta["api_called"] is False
