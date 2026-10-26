"""Mốc cố định E1: graph chỉ chạy trên APT29 day 2 khi prompt, cấu hình và mã khớp mốc đã commit."""
import json
import shutil
import subprocess

import pytest

from cti_hunt.agent import moc, session
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import ContractA, SourceSpan, TTP


def test_filter_v2_milestones_have_independent_namespace(repo):
    first = moc.create('pipeline', 'fixture reviewer', root=repo)
    original = first.read_bytes()
    commit(repo)
    assert moc.latest('pipeline', repo, version='v2') == (None, None)
    second = moc.create('pipeline', 'fixture reviewer', root=repo, version='v2')
    assert second.relative_to(repo).as_posix() == 'configs/moc_co_dinh/v2/pipeline_v1.json'
    manifest = json.loads(second.read_text(encoding='utf-8'))
    assert manifest['filter_policy'] == 'duyet_loc_khau5_v2'
    cfg = load_cfg('agent_v2', repo)
    assert {'configs/agent_v2.yaml', 'configs/chinh_sach_loc_v2.yaml',
            cfg['prompt_khau4'], cfg['prompt_khau4_pivot'], cfg['prompt_khau5']} <= set(manifest['tep'])
    assert 'configs/agent.yaml' not in manifest['tep']
    commit(repo)
    assert moc.verify('pipeline', repo, version='v2')['tep'].startswith('configs/moc_co_dinh/v2/')
    assert first.read_bytes() == original
    assert moc.latest('pipeline', repo)[0] == first


def git(root, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "core.autocrlf=false", *args],
                   cwd=root, check=True, capture_output=True)


def commit(root, msg="x"):
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", msg)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "configs", root / "configs", ignore=shutil.ignore_patterns("moc_co_dinh"))
    shutil.copytree(ROOT / "prompts", root / "prompts")
    (root / "src").mkdir()
    (root / "src" / "ma.py").write_text("X = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text("data/\n", encoding="utf-8")
    git(root, "init", "-q")
    commit(root, "goc")
    return root


def dev_dir(tmp_path, name="otrf-thu"):
    d = tmp_path / name
    d.mkdir()
    (d / "ingest_manifest.json").write_text(json.dumps({"dataset_kind": "otrf_dev", "dataset_id": name,
                                                        "source_sha256": "a" * 64, "rows": 3}), encoding="utf-8")
    return d


def append(path, text):
    path.write_bytes(path.read_bytes() + text.encode("utf-8"))


def test_freeze_needs_committed_state_and_records_versions(repo):
    p4 = load_cfg("agent", repo)["prompt_khau4"]
    append(repo / p4, "\n<!-- sửa chưa commit -->\n")
    with pytest.raises(moc.MilestoneError, match="chưa commit.*" + p4):
        moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    path = moc.create("pipeline", "người vận hành", root=repo)
    m = json.loads(path.read_text(encoding="utf-8"))
    assert path.name == "pipeline_v1.json" and m["nguoi_chot"] == "người vận hành" and m["phien_ban"] == 1
    assert {"configs/llm_hunt.yaml", p4, "prompts/khau5_sigma_v1.md"} <= set(m["tep"])
    assert "configs/llm.yaml" not in m["tep"]  # cấu hình ② không còn điều khiển ④⑤
    assert "prompts/agent_plan_v1.md" not in m["tep"]                  # pipeline không dùng planner
    assert m["mo_hinh"]["khau4_5"] == {"model": "claude-sonnet-5", "effort": "high"}
    assert len(m["ma_nguon"]["src_tree"]) == 40
    commit(repo)
    assert moc.create("pipeline", "người vận hành", root=repo).name == "pipeline_v2.json"   # mốc cũ giữ nguyên


def test_verify_blocks_until_state_matches_committed_milestone(repo):
    with pytest.raises(moc.MilestoneError, match="chưa có mốc"):
        moc.verify("pipeline", repo)
    moc.create("pipeline", "người vận hành", root=repo)
    with pytest.raises(moc.MilestoneError, match="chưa commit"):                # tệp mốc cũng phải commit
        moc.verify("pipeline", repo)
    commit(repo)
    assert moc.verify("pipeline", repo)["phien_ban"] == 1
    append(repo / "prompts" / "khau5_sigma_v1.md", "\n<!-- đổi sau mốc -->\n")
    commit(repo)
    with pytest.raises(moc.MilestoneError, match="khác mốc pipeline_v1.json: prompts/khau5_sigma_v1.md"):
        moc.verify("pipeline", repo)
    git(repo, "revert", "--no-edit", "HEAD")
    (repo / "src" / "ma.py").write_text("X = 2\n", encoding="utf-8")
    commit(repo)
    with pytest.raises(moc.MilestoneError, match="src/"):
        moc.verify("pipeline", repo)


def test_agent_milestone_must_share_pipeline_prompts_and_code(repo, tmp_path):
    with pytest.raises(moc.MilestoneError, match="dữ liệu OTRF phát triển"):
        moc.create("agent", "người vận hành", root=repo)
    with pytest.raises(moc.MilestoneError, match="chưa có mốc chế độ pipeline"):
        moc.create("agent", "người vận hành", [dev_dir(tmp_path)], root=repo)
    moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    p4 = load_cfg("agent", repo)["prompt_khau4"]
    append(repo / p4, "\n<!-- lệch pipeline -->\n")
    commit(repo)
    with pytest.raises(moc.MilestoneError, match="trùng mốc pipeline.*" + p4):
        moc.create("agent", "người vận hành", [tmp_path / "otrf-thu"], root=repo)
    git(repo, "revert", "--no-edit", "HEAD")
    append(repo / "prompts" / "agent_plan_v1.md", "\n<!-- chỉnh planner trên dữ liệu phát triển -->\n")
    commit(repo)
    m = json.loads(moc.create("agent", "người vận hành", [tmp_path / "otrf-thu"], root=repo).read_text(encoding="utf-8"))
    assert m["du_lieu_phat_trien"] == [{"id": "otrf-thu", "source_sha256": "a" * 64, "rows": 3}]
    assert "prompts/agent_plan_v2.md" in m["tep"] and m["mo_hinh"]["planner"]["effort"] == "medium"
    assert m["mo_hinh"]["planner"]["model"] == "claude-sonnet-5"


def test_changed_hunt_model_invalidates_the_milestone(repo):
    moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    path = repo / "configs" / "llm_hunt.yaml"
    path.write_bytes(path.read_bytes().replace(b"claude-sonnet-5", b"claude-opus-5-5"))
    commit(repo)
    with pytest.raises(moc.MilestoneError, match="khác mốc.*llm_hunt.yaml"):
        moc.verify("pipeline", repo)


def test_switching_catalog_pointer_invalidates_the_milestone(repo):
    """N2 §4: danh mục ③ theo con trỏ trong dataset.yaml; trỏ sang v2 (tuyến B) thì mốc tuyến A không còn khớp."""
    assert moc.catalog_files(repo) == ["configs/telemetry_catalog.yaml", "configs/logsource_catalog.yaml"]
    moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    ds = repo / "configs" / "dataset.yaml"
    ds.write_bytes(ds.read_bytes().replace(b"telemetry_catalog: configs/telemetry_catalog.yaml",
                                           b"telemetry_catalog: configs/telemetry_catalog_v2.yaml"))
    commit(repo)
    assert "configs/telemetry_catalog_v2.yaml" in session.tracked_files(repo)
    assert "configs/telemetry_catalog.yaml" not in session.tracked_files(repo)
    with pytest.raises(moc.MilestoneError, match="khác mốc.*telemetry_catalog"):
        moc.verify("pipeline", repo)


def test_start_on_evaluation_data_goes_through_the_milestone(repo, work, monkeypatch):
    (repo / "data" / "work").mkdir(parents=True)
    shutil.copy(work / "events.parquet", repo / "data" / "work" / "events.parquet")
    ca = repo / "ca.json"
    ca.write_text(ContractA(report_id="TU", ttps=[TTP(tactic="Lateral Movement", technique_id="T1047",
                  source_span=SourceSpan(segment_id="TU-001"), confidence=0.9)]).model_dump_json(), encoding="utf-8")
    events, run = repo / "data" / "work", repo / "luot"
    with pytest.raises(session.SessionError, match="E1: .*danh_gia"):              # đường cũ vẫn bị chặn
        session.start("pipeline", ca, events, run, dataset_kind="fixture", dataset_id="TU", root=repo)
    with pytest.raises(moc.MilestoneError, match="chưa có mốc"):
        session.start("pipeline", ca, events, run, dataset_kind="danh_gia", root=repo)
    moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    with pytest.raises(moc.MilestoneError, match="chưa có mốc cố định cho chế độ agent"):
        session.start("agent", ca, events, run, dataset_kind="danh_gia", root=repo)

    seen = {}

    def stop_before_graph(meta, run_dir, root):
        seen.update(meta)
        raise RuntimeError("đã qua cổng mốc")
    monkeypatch.setattr(session, "_build", stop_before_graph)
    with pytest.raises(RuntimeError, match="đã qua cổng mốc"):
        session.start("pipeline", ca, events, run, dataset_kind="danh_gia", root=repo)
    assert seen["dataset"] == {"kind": "danh_gia", "id": "apt29_day2",
                               "sha256": "fd4043c9ad2382f57da882476acb541332d2d19b60ad538572a8d4a070d59a89"}
    assert seen["moc_co_dinh"]["tep"] == "configs/moc_co_dinh/pipeline_v1.json" and not run.exists()
    with pytest.raises(session.SessionError, match="chỉ dùng cho events.parquet của APT29"):
        session.start("pipeline", ca, repo / "khac", run, dataset_kind="danh_gia", root=repo)


def test_v2_catalog_pointer_is_separate_and_keeps_route_a_milestone(repo):
    """02/10: con trỏ ③ tách theo phiên bản; khóa/sửa danh mục v2 không làm lệch mốc tuyến A."""
    assert moc.catalog_files(repo) == ["configs/telemetry_catalog.yaml", "configs/logsource_catalog.yaml"]
    assert moc.catalog_files(repo, "v2") == ["configs/telemetry_catalog_v2_2.yaml", "configs/logsource_catalog.yaml"]
    moc.create("pipeline", "người vận hành", root=repo)
    commit(repo)
    v2 = moc.create("pipeline", "người vận hành", root=repo, version="v2")
    commit(repo)
    tep = json.loads(v2.read_text(encoding="utf-8"))["tep"]
    assert "configs/telemetry_catalog_v2_2.yaml" in tep and "configs/telemetry_catalog.yaml" not in tep
    assert "configs/telemetry_catalog_v2_2.yaml" in session.tracked_files(repo, "v2")
    assert "configs/telemetry_catalog_v2_2.yaml" not in session.tracked_files(repo)
    moc.verify("pipeline", repo)
    moc.verify("pipeline", repo, version="v2")
    append(repo / "configs" / "telemetry_catalog_v2_2.yaml", "# sua danh muc v2\n")
    commit(repo)
    moc.verify("pipeline", repo)
    with pytest.raises(moc.MilestoneError, match="khác mốc.*telemetry_catalog_v2_2"):
        moc.verify("pipeline", repo, version="v2")
