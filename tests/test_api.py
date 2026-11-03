"""API đợt 1: khóa token, 6 cửa, bảng việc. Dữ liệu tự soạn trong thư mục tạm; bộ mã hóa giả; không mạng, không LLM."""
import hashlib
import json
import re
import sqlite3
import time

import duckdb
import numpy as np
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from cti_hunt import config  # noqa: E402
from cti_hunt.api import services as S  # noqa: E402
from cti_hunt.api.app import create_app  # noqa: E402
from cti_hunt.api.jobs import JobStore  # noqa: E402
from cti_hunt.stages import s1_ingest  # noqa: E402

TOKEN = "t" * 24
AUTH = {"Authorization": f"Bearer {TOKEN}"}
SYSMON = "microsoft-windows-sysmon/operational"
HTML = ("<html><head><title>Lab report</title></head><body><article><h1>Activity</h1>"
        "<p>The actor used WMI to execute a process on another host.</p>"
        "<p>The implant connected to 45.77.12[.]34 and resolved evil-c2[.]net for tasking.</p>"
        "</article></body></html>")


def fake_encoder(texts):
    out = np.zeros((len(texts), 32), dtype=np.float32)
    for i, t in enumerate(texts):
        for w in re.findall(r"[a-z]+", t.lower()):
            out[i, int(hashlib.md5(w.encode()).hexdigest(), 16) % 32] += 1
        n = np.linalg.norm(out[i])
        out[i] = out[i] / n if n else out[i]
    return out


@pytest.fixture
def stix(tmp_path):
    objs = [{"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name, "description": desc,
             "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]}
            for tid, name, desc in [("T1047", "Windows Management Instrumentation", "WMI can execute a process."),
                                    ("T1071", "Application Layer Protocol", "Adversaries may communicate over web.")]]
    path = tmp_path / "attack.json"
    s1_ingest.write_json(path, {"objects": objs})
    return path


class StubRecords:
    def find(self, technique="", report=""):
        if technique and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            raise ValueError("Cần mã ATT&CK")
        return [{"record_id": "r1", "report_id": "LAB", "executed_hunts": 2}]

    def read(self, record_id):
        if record_id != "r1":
            raise ValueError("không có")
        return {"record_id": "r1", "markdown": "# Hunt record"}


@pytest.fixture
def env(tmp_path, stix):
    dev = tmp_path / "data/dev"
    ds = dev / "otrf-gia"
    ds.mkdir(parents=True)
    s1_ingest.write_json(ds / "ingest_manifest.json", {"dataset_kind": "otrf_dev", "dataset_id": "otrf-gia"})
    con = duckdb.connect()
    con.execute("CREATE TABLE events (ev_host VARCHAR, ev_channel VARCHAR, ev_eid INTEGER, ev_rec VARCHAR, "
                "DestinationIp VARCHAR, QueryName VARCHAR, \"User\" VARCHAR)")
    con.execute("INSERT INTO events VALUES ('WS1', ?, 3, '1', '45.77.12.34', NULL, 'DOM\\alice'), "
                "('WS2', ?, 22, '2', NULL, 'cdn.evil-c2.net', NULL), ('WS3', ?, 3, '3', '8.8.8.8', NULL, NULL)",
                [SYSMON] * 3)
    con.execute(f"COPY events TO '{(ds / 'events.parquet').as_posix()}' (FORMAT PARQUET)")
    settings = S.Settings(token=TOKEN, reports_root=tmp_path / "data/reports/moi", dev_root=dev,
                          jobs_db=tmp_path / "jobs.sqlite", dataset_check=lambda folder: {}, inline_jobs=True)
    app = create_app(settings, technique_search=S.TechniqueSearch(stix=stix, encoder=fake_encoder),
                     record_store=StubRecords())
    return TestClient(app), settings


def ingest(client, rid="LAB-1", body=HTML):
    r = client.post("/reports", headers=AUTH, data={"report_id": rid},
                    files={"file": ("report.html", body.encode("utf-8"), "text/html")})
    assert r.status_code == 202, r.text
    job = client.get(r.json()["status_url"], headers=AUTH).json()
    assert job["status"] == "done", job
    return job


def test_token_is_required_and_weak_tokens_refused(env, tmp_path):
    client, settings = env
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/datasets").status_code == 401
    assert client.get("/datasets", headers={"Authorization": "Bearer " + "x" * 24}).status_code == 401
    assert client.get("/datasets", headers=AUTH).json() == [{"dataset_id": "otrf-gia", "events": None}]
    with pytest.raises(ValueError):
        create_app(S.Settings(token="short", jobs_db=tmp_path / "j2.sqlite"))


def test_ingest_upload_then_summary_and_no_overwrite(env):
    client, settings = env
    job = ingest(client)
    assert job["kind"] == "ingest" and job["result"]["report_id"] == "LAB-1"
    assert job["result"]["readable_segments"] >= 2 and job["result"]["format"] == "html"
    summary = client.get("/reports/LAB-1", headers=AUTH).json()
    assert summary["title"] == "Lab report" and summary["extractions"] == []
    dup = client.post("/reports", headers=AUTH, data={"report_id": "LAB-1"},
                      files={"file": ("r.html", HTML.encode(), "text/html")})
    assert dup.status_code == 409
    assert client.get("/reports/NOPE", headers=AUTH).status_code == 404
    bad = client.post("/reports", headers=AUTH, data={"report_id": "LAB-2"},
                      files={"file": ("r.exe", b"MZ", "application/octet-stream")})
    assert bad.status_code == 400
    both = client.post("/reports", headers=AUTH, data={"report_id": "LAB-3", "url": "http://8.8.8.8/r"},
                       files={"file": ("r.html", HTML.encode(), "text/html")})
    assert both.status_code == 400
    assert client.post("/reports", headers=AUTH, data={"report_id": "../x", "url": "http://8.8.8.8/"}).status_code == 400


@pytest.mark.parametrize("url", ["http://127.0.0.1/r", "http://10.1.2.3/r", "http://169.254.169.254/latest",
                                 "http://[::1]/r", "ftp://8.8.8.8/r", "file:///etc/passwd"])
def test_url_to_internal_or_odd_targets_is_refused(env, url):
    client, _ = env
    r = client.post("/reports", headers=AUTH, data={"report_id": "LAB-U", "url": url})
    assert r.status_code == 400


def test_public_url_is_passed_to_the_reader(env, monkeypatch):
    client, settings = env
    seen = {}
    monkeypatch.setattr(S.demo, "ingest", lambda source, rid, selector, root: seen.update(source=source) or
                        (_ for _ in ()).throw(ValueError("dừng ở đây")))
    r = client.post("/reports", headers=AUTH, data={"report_id": "LAB-W", "url": "http://8.8.8.8/report"})
    assert r.status_code == 202
    job = client.get(r.json()["status_url"], headers=AUTH).json()
    assert seen["source"] == "http://8.8.8.8/report"
    assert job["status"] == "failed" and job["error"] == "ValueError: dừng ở đây"


def test_ioc_sweep_works_without_any_llm_extraction(env):
    client, _ = env
    ingest(client)
    r = client.post("/reports/LAB-1/ioc-sweep", headers=AUTH, json={"dataset_id": "otrf-gia"})
    assert r.status_code == 202
    res = client.get(r.json()["status_url"], headers=AUTH).json()["result"]
    rows = {row["gia_tri"]: row for row in res["bang"]}
    assert rows["45.77.12.34"]["su_kien_khop"] == 1 and rows["evil-c2.net"]["su_kien_khop"] == 1
    assert res["ket_qua"]["bo_log"] == "otrf-gia"                      # không lộ đường dẫn máy
    assert client.post("/reports/LAB-1/ioc-sweep", headers=AUTH, json={"dataset_id": "khong-co"}).status_code == 404
    assert client.post("/reports/LAB-1/ioc-sweep", headers=AUTH, json={"dataset_id": "../dev"}).status_code == 400


def test_cost_estimate_builds_requests_without_writing(env):
    client, settings = env
    if not config.resolve(config.load("reports")["attack"]["stix_path"]).exists():
        pytest.skip("Thiếu ATT&CK v19.2 cục bộ")
    ingest(client)
    before = sorted(p.name for p in (settings.reports_root / "LAB-1").rglob("*"))
    r = client.post("/reports/LAB-1/cost-estimate", headers=AUTH, json={})
    res = client.get(r.json()["status_url"], headers=AUTH).json()["result"]
    assert res["retrieval"] == "bm25" and res["batches"] >= 1 and res["uoc_tinh_chi_phi"]
    assert sorted(p.name for p in (settings.reports_root / "LAB-1").rglob("*")) == before
    assert client.post("/reports/LAB-1/cost-estimate", headers=AUTH, json={"retrieval": "x"}).status_code == 422


def test_community_rules_needs_a_completed_extraction(env):
    client, _ = env
    ingest(client)
    r = client.post("/reports/LAB-1/community-rules", headers=AUTH,
                    json={"extraction_id": "extract_khong_co", "dataset_id": "otrf-gia"})
    job = client.get(r.json()["status_url"], headers=AUTH).json()
    assert job["status"] == "failed" and job["error"]


def test_technique_lookup_bm25_and_hybrid(env):
    client, _ = env
    bm = client.get("/techniques", headers=AUTH, params={"q": "WMI execute process", "k": 1}).json()
    assert bm["results"][0]["technique_id"] == "T1047"
    lai = client.get("/techniques", headers=AUTH, params={"q": "communicate over web", "mode": "lai"}).json()
    assert lai["results"][0]["technique_id"] == "T1071" and len(lai["results"]) == 2
    assert client.get("/techniques", headers=AUTH, params={"q": "x", "k": 31}).status_code == 422
    assert client.get("/techniques", headers=AUTH, params={"q": "x", "mode": "vector"}).status_code == 422


def test_hybrid_without_embed_extra_is_503_not_a_crash(env, stix, monkeypatch, tmp_path):
    from cti_hunt.attack import dense_retrieval as DR

    def missing(key):
        raise ImportError("No module named 'sentence_transformers'")
    monkeypatch.setattr(DR, "load_encoder", missing)
    app = create_app(S.Settings(token=TOKEN, jobs_db=tmp_path / "j3.sqlite", inline_jobs=True),
                     technique_search=S.TechniqueSearch(stix=stix))
    c = TestClient(app)
    r = c.get("/techniques", headers=AUTH, params={"q": "x", "mode": "lai"})
    assert r.status_code == 503 and "[embed]" in r.json()["detail"]
    assert c.get("/techniques", headers=AUTH, params={"q": "WMI process"}).status_code == 200


def test_base_image_without_numpy_answers_503_before_importing(env, stix, monkeypatch, tmp_path):
    # Ảnh Docker cơ bản không có numpy: phải trả 503 trước khi nhập module embedding (bản đầu ra 500 trong container).
    monkeypatch.setattr(S, "embed_available", lambda: False)
    client, _ = env
    ingest(client)
    r = client.post("/reports/LAB-1/cost-estimate", headers=AUTH, json={"retrieval": "lai"})
    assert r.status_code == 503 and "[embed]" in r.json()["detail"]
    c = TestClient(create_app(S.Settings(token=TOKEN, jobs_db=tmp_path / "j4.sqlite", inline_jobs=True),
                              technique_search=S.TechniqueSearch(stix=stix)))
    assert c.get("/techniques", headers=AUTH, params={"q": "x", "mode": "lai"}).status_code == 503


def test_fresh_clone_without_attack_data_answers_503(tmp_path, monkeypatch):
    # Repo công khai không kèm dữ liệu: thiếu ATT&CK thì báo tên tệp thiếu, không 500, không lộ đường dẫn máy.
    def missing():
        raise FileNotFoundError(2, "No such file", str(tmp_path / "data/attack/enterprise-attack-19.2.json"))
    monkeypatch.setattr(S, "_stix", missing)
    c = TestClient(create_app(S.Settings(token=TOKEN, jobs_db=tmp_path / "j5.sqlite", inline_jobs=True)))
    r = c.get("/techniques", headers=AUTH, params={"q": "x"})
    assert r.status_code == 503 and r.json()["detail"] == "Thiếu dữ liệu cục bộ: enterprise-attack-19.2.json"


def test_records_are_read_only_lookups(env):
    client, _ = env
    assert client.get("/records", headers=AUTH, params={"technique": "T1047"}).json()[0]["record_id"] == "r1"
    assert client.get("/records", headers=AUTH, params={"technique": "abc"}).status_code == 400
    assert client.get("/records/r1", headers=AUTH).json()["markdown"] == "# Hunt record"
    assert client.get("/records/r2", headers=AUTH).status_code == 404


def test_job_store_thread_failure_and_restart(tmp_path):
    store = JobStore(tmp_path / "j.sqlite")
    ok = store.submit("demo", {"a": 1}, lambda: {"x": 1})
    bad = store.submit("demo", {}, lambda: 1 / 0)
    for _ in range(200):
        if store.get(ok)["status"] in ("done", "failed") and store.get(bad)["status"] in ("done", "failed"):
            break
        time.sleep(0.02)
    assert store.get(ok)["status"] == "done" and store.get(ok)["result"] == {"x": 1}
    assert store.get(bad)["status"] == "failed" and store.get(bad)["error"].startswith("ZeroDivisionError")
    assert [j["id"] for j in store.list()] == [bad, ok] and store.list()[0]["result"] is None
    store.shutdown()
    with sqlite3.connect(tmp_path / "j.sqlite") as c:            # mô phỏng máy chủ tắt khi việc đang chạy
        c.execute("INSERT INTO jobs (id, kind, params, status, created_at) VALUES ('z', 'demo', '{}', 'running', 'x')")
    again = JobStore(tmp_path / "j.sqlite", inline=True)
    assert again.get("z")["status"] == "interrupted" and again.get(ok)["status"] == "done"
    assert json.loads(json.dumps(again.list(5)))
