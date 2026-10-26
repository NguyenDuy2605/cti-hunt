"""Chế độ pipeline chạy toàn trình ④→⑨ trên graph D10 qua lệnh `agent`, trên fixture tổng hợp (E1), không nhãn."""
import json
from pathlib import Path

import pytest
import yaml

from cti_hunt import approval, cli
from cti_hunt.agent import session
from cti_hunt.agent.graph import PipelinePlanner
from cti_hunt.config import ROOT, load as load_cfg
from cti_hunt.contracts import IOC, ContractA, SourceSpan, TTP
from cti_hunt.data.store import connect
from cti_hunt.hunt import runner
from cti_hunt.hunt.observe import unlabeled_result
from cti_hunt.llm import providers
from cti_hunt.stages import s3_telemetry, s9_record

SYS = "microsoft-windows-sysmon/operational"
RULE = (ROOT / "hunts" / "sigma" / "H-03.yml").read_text(encoding="utf-8")
LIMITS = {"hypotheses_per_round": 10, "max_pivot_depth": 2, "pivots_per_round": 3, "queries_total": 20}


def _view(**kw):
    base = {"remaining_refs": [], "eligible_pivots": [], "pivot_depth": 0, "queries_reserved": 0,
            "prior_decisions": [], "last_round_executed": None, "limits": LIMITS}
    return {**base, **kw}


def _cand(value, depth=1):
    return {"loai": "may", "gia_tri": value, "pivot_depth": depth, "tu_gia_thuyet": ["TU-H01", "TU-H02"],
            "ly_do": "khớp 2 giả thuyết"}


def test_pipeline_planner_follows_fixed_order_and_caps():
    plan = PipelinePlanner()
    d = plan(_view(remaining_refs=list(range(12))))
    assert d["action"] == "hunt" and d["ttp_refs"] == list(range(10))          # trần 10 giả thuyết/vòng
    hunted = [{"action": "hunt", "ttp_refs": list(range(12)), "pivot_targets": []}]
    four = [_cand("A"), _cand("B"), _cand("C"), _cand("D")]
    d = plan(_view(eligible_pivots=four, prior_decisions=hunted, last_round_executed=True))
    assert [t["gia_tri"] for t in d["pivot_targets"]] == ["A", "B", "C"]       # đầu bảng, trần 3/vòng
    d = plan(_view(eligible_pivots=four, queries_reserved=19, prior_decisions=hunted, last_round_executed=True))
    assert [t["gia_tri"] for t in d["pivot_targets"]] == ["A"]                 # còn 1 suất trong 20
    assert plan(_view(eligible_pivots=four, queries_reserved=20))["reason"].endswith("hết suất truy vấn pivot")
    assert "trần độ sâu" in plan(_view(pivot_depth=2, eligible_pivots=[_cand("A", 3)]))["reason"]
    assert plan(_view())["reason"].endswith("không còn thực thể vượt ngưỡng")
    # Vòng pivot không có giả thuyết nào được duyệt để chạy: dừng như lệnh `pivot`, không lấy tiếp ứng viên cũ.
    pivoted = hunted + [{"action": "pivot", "ttp_refs": [], "pivot_targets": [{"loai": "may", "gia_tri": "A"}]}]
    d = plan(_view(eligible_pivots=four, prior_decisions=pivoted, last_round_executed=False))
    assert d["action"] == "stop" and "không có giả thuyết" in d["reason"]


class Scripted:
    """Mô hình giả cho ④ và ⑤, chọn phản hồi theo lược đồ. Chế độ pipeline không gọi mô hình để lập kế hoạch."""
    model_id = "mock"

    def __init__(self, calls):
        self.calls = calls

    def complete_json(self, system, user, json_schema, log=None):
        self.calls.append(json_schema.get("title"))
        if json_schema.get("title") == "LLMRule":
            return {"rule_yaml": RULE}
        assert json_schema.get("title") == "LLMHypothesisBatch"
        return {"items": [{"ttp_refs": [0], "behavior": "Tiến trình con lạ của nhóm thực thi từ xa",
                           "scope": "mọi máy", "timeframe": "toàn bộ log", "data_source": SYS, "event_ids": [1],
                           "key_fields": ["ParentImage", "Image"], "extra_techniques": [], "priority": "cao"}]}

    def describe(self):
        return {"model": self.model_id, "kieu_api": "mock"}


def _approve_all(review_dir):
    f = review_dir / approval.REVIEW_FILE
    form = yaml.safe_load(f.read_text(encoding="utf-8"))
    form["nguoi_duyet"] = "tester"
    for g in form["gia_thuyet"]:
        g["quyet_dinh"] = "approved"
    f.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")


@pytest.fixture
def contract_a(tmp_path):
    """11 TTP huntable: nhiều hơn trần 10 giả thuyết/vòng, pipeline phải chia hai lô."""
    ca = ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", behavior_description=f"Thực thi từ xa, mô tả tự soạn {i}",
        source_span=SourceSpan(segment_id=f"TU-{i:03d}", text="Câu tự soạn."), confidence=0.9) for i in range(11)])
    path = tmp_path / "contract_a_TU.json"
    path.write_text(ca.model_dump_json(), encoding="utf-8")
    return path


@pytest.fixture
def scripted(monkeypatch):
    calls = []
    monkeypatch.setattr(providers, "from_config", lambda cfg: Scripted(calls))
    return calls


def test_pipeline_runs_end_to_end_via_cli(work, contract_a, tmp_path, scripted, capsys):
    run = tmp_path / "luot_1"
    assert cli.main(["agent", "start", "--mode", "pipeline", "--contract-a", str(contract_a), "--events", str(work),
                     "--dataset-kind", "fixture", "--dataset-id", "TU-pipeline-v1", "--out", str(run)]) == 0
    for rd in ("round_01", "round_02", "round_03"):         # săn lô 1 · săn lô 2 · pivot
        assert (run / rd / approval.REVIEW_FILE).exists(), rd
        _approve_all(run / rd)
        assert cli.main(["agent", "resume", str(run)]) == 0
    assert "Xong." in capsys.readouterr().out

    rec = json.loads((run / "agent_dev_record.json").read_text(encoding="utf-8"))
    hist = rec["history"]
    assert [h["decision"]["action"] for h in hist] == ["hunt", "hunt", "pivot", "stop"]
    assert hist[0]["decision"]["ttp_refs"] == list(range(10)) and hist[1]["decision"]["ttp_refs"] == [10]
    # H01 (lô 1) và H02 (lô 2) chỉ gặp nhau khi ⑧ gom mọi hunt cùng độ sâu; ưu tiên máy ít sự kiện hơn.
    assert [(p["loai"], p["gia_tri"]) for p in hist[2]["decision"]["pivot_targets"]] == [
        ("may", "NEWYORK"), ("may", "UTICA")]
    assert hist[2]["selected"][0]["tu_gia_thuyet"] == ["TU-H01", "TU-H02"]
    assert hist[2]["generated_ids"] == ["TU-H03", "TU-H04"]
    assert hist[3]["decision"]["reason"].endswith("không còn thực thể vượt ngưỡng")
    assert rec["planner"]["mode"] == "pipeline" and "Decision" not in scripted
    pivots = approval.load_hypotheses(run / "round_03" / approval.APPROVED_FILE)
    assert {(h.origin, h.pivot_depth, h.pivot_value) for h in pivots} == {("pivot", 1, "NEWYORK"), ("pivot", 1, "UTICA")}
    assert len(rec["executed_specs"]) == 4

    md = (run / "hunt_record.md").read_text(encoding="utf-8")
    assert md == (Path(rec["hunt_record"])).read_text(encoding="utf-8")
    assert [line for line in md.splitlines() if line.startswith("## ")] == [
        "## Learn", "## Observe", "## Check", "## Keep"]
    assert "Pivot đã chạy:** may `NEWYORK` (vòng 3)" in md and "Điểm độ hiếm:** cao nhất" in md
    assert "pipeline: 2/2 ứng viên đầu bảng" in md
    assert "-- phạm vi: microsoft-windows-sysmon/operational EID [1] · máy NEWYORK" in md   # ràng buộc pivot
    assert "buoc" not in md and "mau_so_fpr" not in json.dumps(rec)
    meta = json.loads((run / session.META_FILE).read_text(encoding="utf-8"))
    assert meta["mode"] == "pipeline" and meta["dataset"]["id"] == "TU-pipeline-v1"
    assert {"configs/agent.yaml", "configs/llm_hunt.yaml", load_cfg("agent")["prompt_khau4"],
            "prompts/khau5_sigma_v1.md"} <= set(meta["tep"])


def test_record_includes_ioc_sweep_when_contract_has_iocs(work, tmp_path, scripted):
    """Khâu quét IOC (14/10): Contract A có IOC thì hunt record thêm mục Quét IOC sau bốn mục LOCK, record JSON có kết quả."""
    ca = ContractA(report_id="TU", iocs=[
        IOC(type="hash", value="a" * 64, source_span=SourceSpan(segment_id="TU-001", text="sha256 " + "a" * 64)),
        IOC(type="ip", value="10.0.0.5", source_span=SourceSpan(segment_id="TU-001"))],
        ttps=[TTP(tactic="Lateral Movement", technique_id="T1047", behavior_description="Thực thi từ xa, tự soạn",
                  source_span=SourceSpan(segment_id="TU-001", text="Câu tự soạn."), confidence=0.9)])
    path = tmp_path / "contract_a_TU_ioc.json"
    path.write_text(ca.model_dump_json(), encoding="utf-8")
    run = tmp_path / "luot_ioc"
    assert cli.main(["agent", "start", "--mode", "pipeline", "--contract-a", str(path), "--events", str(work),
                     "--dataset-kind", "fixture", "--dataset-id", "TU-ioc-v1", "--out", str(run)]) == 0
    for _ in range(5):
        if (run / "hunt_record.md").exists():
            break
        pending = sorted(p for p in run.glob("round_*") if (p / approval.REVIEW_FILE).exists())
        _approve_all(pending[-1])
        assert cli.main(["agent", "resume", str(run)]) == 0
    md = (run / "hunt_record.md").read_text(encoding="utf-8")
    heads = [line for line in md.splitlines() if line.startswith("## ")]
    assert heads == ["## Learn", "## Observe", "## Check", "## Keep"]       # D13: mục thêm là mục con của Keep
    assert "### Quét IOC (ioc_sweep_v1)" in md.splitlines()
    rec = json.loads((run / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert isinstance(rec["bien_the_rule"], list)       # biến thể rule (14/10): chỉ đếm, không chạy trong lượt
    by = {m["gia_tri"]: m for m in rec["ioc_sweep"]["muc"]}
    # Log mẫu không có cột Hashes: IOC mạnh vẫn được xét, khâu báo "không có trường" chứ không ghi 0 sự kiện
    assert by["a" * 64]["muc"] == "manh" and by["a" * 64]["trang_thai"] == "khong_co_truong"
    assert by["10.0.0.5"]["muc"] == "yeu" and by["10.0.0.5"]["trang_thai"] == "khong_quet"


@pytest.mark.parametrize("changed_config", ["configs/agent.yaml", "configs/llm_hunt.yaml",
                                           load_cfg("agent")["prompt_khau4"]])
def test_resume_refuses_blank_form_changed_version_and_reused_dir(work, contract_a, tmp_path, scripted, changed_config):
    run = tmp_path / "luot"
    out = session.start("pipeline", contract_a, work, run, dataset_kind="fixture", dataset_id="TU")
    assert out["trang_thai"] == "cho_duyet"
    with pytest.raises(session.SessionError, match="chưa có quyết định"):
        session.resume(run)                                   # phiếu trống không được coi là "không duyệt gì"
    meta = json.loads((run / session.META_FILE).read_text(encoding="utf-8"))
    meta["tep"][changed_config] = "0" * 64
    (run / session.META_FILE).write_text(json.dumps(meta), encoding="utf-8")
    _approve_all(run / "round_01")
    with pytest.raises(session.SessionError, match="E2.*" + changed_config):
        session.resume(run)
    with pytest.raises(session.SessionError, match="thư mục mới"):
        session.start("pipeline", contract_a, work, run, dataset_kind="fixture", dataset_id="TU")


class TwoHypotheses(Scripted):
    def complete_json(self, system, user, json_schema, log=None):
        out = super().complete_json(system, user, json_schema, log)
        if json_schema.get("title") == "LLMHypothesisBatch":
            out["items"].append({**out["items"][0], "behavior": "Tiến trình con lạ thứ hai, mô tả tự soạn"})
        return out


def test_resume_refuses_partly_blank_form_and_names_the_blank_items(work, contract_a, tmp_path, monkeypatch):
    monkeypatch.setattr(providers, "from_config", lambda cfg: TwoHypotheses([]))
    run = tmp_path / "luot"
    out = session.start("pipeline", contract_a, work, run, dataset_kind="fixture", dataset_id="TU")
    f = Path(out["review_dir"]) / approval.REVIEW_FILE
    form = yaml.safe_load(f.read_text(encoding="utf-8"))
    assert len(form["gia_thuyet"]) >= 2
    form["nguoi_duyet"] = "tester"
    for g in form["gia_thuyet"][:-1]:
        g["quyet_dinh"] = "approved"
    last = form["gia_thuyet"][-1]["id"]
    f.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    with pytest.raises(session.SessionError, match=f"còn 1 giả thuyết chưa có quyết định \\({last}\\)"):
        session.resume(run)                     # mục trống sẽ thành pending_review và bị bỏ không lý do
    assert not (run / "round_01" / "approval_log.json").exists()
    form["gia_thuyet"][-1].update(quyet_dinh="rejected", ly_do="tự soạn: bỏ có lý do")
    f.write_text(yaml.safe_dump(form, allow_unicode=True), encoding="utf-8")
    assert session.resume(run)["trang_thai"] in ("cho_duyet", "xong")
    log = json.loads((run / "round_01" / "approval_log.json").read_text(encoding="utf-8"))
    assert log["dem"]["pending_review"] == 0 and log["quyet_dinh"][last]["quyet_dinh"] == "rejected"


@pytest.mark.parametrize("dry_run", [False, True])
def test_refuses_evaluation_dataset_and_unidentified_otrf(work, contract_a, tmp_path, scripted, dry_run):
    ds = load_cfg("dataset")
    with pytest.raises(session.SessionError, match="E1"):
        session.check_dataset(ROOT / ds["work_dir"])
    copy = tmp_path / "ban_sao"
    copy.mkdir()
    (copy / "events.parquet").write_bytes(b"")
    (copy / "ingest_manifest.json").write_text(json.dumps({"source": "C:/khac/" + Path(ds["raw"]["path"]).name}),
                                               encoding="utf-8")
    with pytest.raises(session.SessionError, match="E1"):
        session.check_dataset(copy)
    run = tmp_path / "otrf"
    assert cli.main(["agent", "start", "--mode", "agent", "--contract-a", str(contract_a), "--events", str(work),
                     "--dataset-kind", "otrf_dev", "--dataset-id", "otrf-x", "--out", str(run)]
                    + (["--dry-run"] if dry_run else [])) == 1
    assert not run.exists()                                   # lỗi E1 dừng trước khi tạo thư mục lượt


@pytest.mark.parametrize("mode", ["pipeline", "agent"])
def test_dry_run_uses_hunt_models_without_api_or_creating_a_run(work, contract_a, tmp_path, monkeypatch, capsys, mode):
    def forbidden(*args, **kwargs):
        pytest.fail("dry-run không được gọi API hay mở graph/checkpoint")

    monkeypatch.setattr(providers.AnthropicClient, "complete_json", forbidden)
    monkeypatch.setattr(session, "_graph", forbidden)
    run = tmp_path / "dry_run"
    assert cli.main(["agent", "start", "--mode", mode, "--contract-a", str(contract_a), "--events", str(work),
                     "--dataset-kind", "fixture", "--dataset-id", "TU", "--out", str(run), "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["trang_thai"] == "dry_run" and out["goi_api"] is False
    assert out["so_ttp_vao_khau4"] == 11 and out["so_ttp_not_huntable"] == 0
    for stage in ("khau4", "khau5"):
        assert out[stage]["model"] == "claude-sonnet-5" and out[stage]["effort"] == "high"
    assert out["planner"]["model"] == ("claude-sonnet-5" if mode == "agent" else None)
    if mode == "agent":
        assert out["planner"]["llm_parameters"]["effort"] == "medium"
    assert "configs/llm_hunt.yaml" in out["tep"] and "configs/llm.yaml" not in out["tep"]
    assert load_cfg("llm")["model"] == "claude-opus-5-5"
    assert not run.exists()


def test_uninitialized_budget_stops_before_creating_a_run(work, contract_a, tmp_path, monkeypatch):
    from cti_hunt.llm.budget import BudgetError
    original = providers.from_config

    def isolated(cfg):
        llm = original(cfg)
        llm.budget_ledger = str(tmp_path / "missing-budget.sqlite")
        return llm

    monkeypatch.setattr(providers, "from_config", isolated)
    run = tmp_path / "no_budget"
    with pytest.raises(BudgetError, match="Chưa đặt ngân sách"):
        session.start("pipeline", contract_a, work, run, dataset_kind="fixture", dataset_id="TU")
    assert not run.exists()


def test_unlabeled_result_feeds_operational_record_but_not_eval(work):
    con = connect(work)
    spec = runner.load_spec(ROOT / "eval" / "reference" / "H-03_truoc_F02.yaml")
    res = unlabeled_result(con, spec)
    assert res["pham_vi"] == {"su_kien_trong_pham_vi": 5}
    assert [(g["stage"], g["hits"], g["removed"]) for g in res["giai_doan"]] == [("ung_vien", 4, 0), ("sau_F-01", 3, 1)]
    assert len(res["ket_qua_cuoi"]) == 3 and "buoc" not in json.dumps(res, default=str)
    ca = ContractA(report_id="TU")
    telemetry = s3_telemetry.load_catalog(ROOT / "configs" / "telemetry_catalog.yaml")
    md = s9_record.render(ca, telemetry, [], [res])
    assert "4 ứng viên → loại 1 → **3 cần xem xét**" in md and "5 sự kiện trong phạm vi" in md
    with pytest.raises(ValueError, match="--eval"):
        s9_record.render(ca, telemetry, [], [res], eval_mode=True)


def test_run_meta_pins_dataset_profile_and_resume_refuses_a_changed_one(work, tmp_path, scripted, monkeypatch):
    """đã chốt (PA-1): hồ sơ bộ dữ liệu ghi trong thư mục lượt, SHA256 vào run_meta; prompt ④ và ⑨ dùng nó."""
    from cti_hunt import integrity
    ca = ContractA(report_id="TU", ttps=[TTP(
        tactic="Lateral Movement", technique_id="T1047", technique_name="Windows Management Instrumentation",
        behavior_description="Thực thi từ xa, mô tả tự soạn",
        source_span=SourceSpan(segment_id="TU-000", text="Câu tự soạn."), confidence=0.9)])
    path = tmp_path / "ca.json"
    path.write_text(ca.model_dump_json(), encoding="utf-8")
    run = tmp_path / "luot"
    assert session.start("pipeline", path, work, run, dataset_kind="fixture", dataset_id="TU")["trang_thai"] == "cho_duyet"
    meta = json.loads((run / session.META_FILE).read_text(encoding="utf-8"))
    profile_file = run / s3_telemetry.PROFILE_FILE
    assert meta["ho_so"]["sha256"] == integrity.sha256_file(profile_file)
    assert meta["ho_so"]["dataset_id"] == "TU" and meta["ho_so"]["kenh"][SYS] == 5   # số đếm chỉ ở hồ sơ/run_meta
    user = json.loads((run / "round_01" / "request.json").read_text(encoding="utf-8"))["user"]
    assert "không thu thập microsoft-windows-wmi-activity/operational (bỏ nguồn này)" in user
    assert '"CommandLine"' not in user and '"User"' not in user  # G0(b), trường rỗng trên fixture
    _approve_all(run / "round_01")

    original = profile_file.read_bytes()
    profile_file.write_bytes(original.replace(b'"TU"', b'"TU-sua"'))
    with pytest.raises(session.SessionError, match="hồ sơ bộ dữ liệu.*ho_so_du_lieu.json"):
        session.resume(run)
    profile_file.write_bytes(original)
    real = s3_telemetry.build_profile
    with monkeypatch.context() as m:           # cùng events nhưng mã lập hồ sơ cho kết quả khác
        m.setattr(s3_telemetry, "build_profile", lambda con, cat, ds: {**real(con, cat, ds), "dataset_id": "khac"})
        with pytest.raises(session.SessionError, match="hồ sơ lập lại từ events"):
            session.resume(run)

    assert session.resume(run)["trang_thai"] == "xong"
    md = (run / "hunt_record.md").read_text(encoding="utf-8")
    row = next(line for line in md.splitlines() if line.startswith("| T1047 |"))
    assert f"| huntable | {SYS} [1] |" in row and "không thu thập microsoft-windows-wmi-activity/operational" in row
