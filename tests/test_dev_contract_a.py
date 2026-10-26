"""Contract A phát triển v1 (E1) và lệnh chạy thử pipeline bằng mock trên bộ OTRF phát triển."""
import importlib.util
import json
import zipfile

import pytest
import yaml

from cti_hunt import approval, integrity
from cti_hunt.agent import dev_data
from cti_hunt.config import ROOT, load as load_cfg, resolve
from cti_hunt.contracts import ContractA, SourceSpan, TTP
from cti_hunt.llm import providers
from cti_hunt.stages import s3_telemetry

DEV = ROOT / "dev"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _load(version):
    return {f.stem.removeprefix("contract_a_"): ContractA.model_validate_json(f.read_text(encoding="utf-8"))
            for f in sorted((DEV / f"contract_a_{version}").glob("contract_a_*.json"))}


@pytest.mark.parametrize("version, n_files", [("v1", 7), ("v2", 8)])
def test_contract_a_versions_are_frozen_and_self_contained(version, n_files):
    d = DEV / f"contract_a_{version}"
    assert all(r["ok"] for r in integrity.verify_dir(d, d / integrity.MANIFEST_NAME))    # sửa thì tạo bản mới
    cas = _load(version)
    assert len(cas) == n_files
    eval_reports = set(load_cfg("reports")["eval_reports"])
    for rid, ca in cas.items():
        assert rid == ca.report_id and ca.report_id.startswith("DEV-") and ca.report_id not in eval_reports
        assert "OTRF/Security-Datasets" in ca.source_url
        for t in ca.ttps:
            assert t.source_span.text and t.source_span.segment_id.startswith(f"{ca.report_id}-")
            assert not s3_telemetry.STEP_ID.search(t.model_dump_json())


def test_contract_a_v2_context_comes_only_from_the_description():
    """Lỗi của v1: account_type lấy từ permissions_required, tool lấy chữ từ tags."""
    for ca in _load("v2").values():
        for t in ca.ttps:
            assert t.context.account_type == "" and t.context.command_example == ""
            assert t.context.tool.lower() in t.source_span.text.lower(), (ca.report_id, t.context.tool)


def test_composite_contract_a_keeps_every_mechanism_row():
    cas = _load("v2")
    mix = cas.pop("DEV-TONGHOP")
    rows = [(t.technique_id, t.source_span.text) for ca in cas.values() for t in ca.ttps]
    assert sorted((t.technique_id, t.source_span.text) for t in mix.ttps) == sorted(rows)
    assert len({t.source_span.segment_id for t in mix.ttps}) == 7                     # bảy đoạn, một mô tả mỗi đoạn


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_contract_a_techniques_exist_in_attack_v19(version):
    stix = resolve(load_cfg("reports")["attack"]["stix_path"])
    if not stix.exists():
        pytest.skip("chưa có file STIX v19.2 trong data/attack")
    from cti_hunt.attack.catalog import AttackCatalog
    cat = AttackCatalog.from_stix(stix)
    for ca in _load(version).values():
        for t in ca.ttps:
            r = cat.resolve(t.technique_id)
            assert (r.status, r.name) == ("ok", t.technique_name), t.technique_id


def _script():
    spec = importlib.util.spec_from_file_location("chay_thu_mock", ROOT / "scripts" / "chay_thu_mock.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mock_dry_run_goes_through_every_stage_without_api(tmp_path):
    rows = [{"Hostname": "WS5.lab.local", "Channel": SYSMON, "EventID": 1, "RecordNumber": 100 + i,
             "EventTime": f"2020-09-20 20:00:0{i}", "UtcTime": f"2020-09-21 00:00:0{i}.000",
             "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe", "Image": r"C:\Windows\System32\cmd.exe",
             "User": "LAB\\alice"} for i in range(3)]
    src = tmp_path / "bo.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("bo.json", "\n".join(json.dumps(r) for r in rows) + "\n")
    events = tmp_path / "dev"
    dev_data.ingest_dev(src, "otrf-mock", events)
    ca = tmp_path / "ca.json"
    ca.write_text(ContractA(report_id="DEV-T", ttps=[TTP(tactic="Lateral Movement", technique_id="T1047",
                  source_span=SourceSpan(segment_id="DEV-T-001", text="x"), confidence=0.9)]).model_dump_json(),
                  encoding="utf-8")
    original = providers.from_config
    res = _script().run(ca, events, tmp_path / "luot")
    assert providers.from_config is original                        # trả lại provider thật sau khi chạy thử
    assert res["trang_thai"] == "xong" and res["so_phieu"] == 1
    form = yaml.safe_load((tmp_path / "luot" / "round_01" / approval.REVIEW_FILE).read_text(encoding="utf-8"))
    assert "KHÔNG phải duyệt" in form["nguoi_duyet"]
    rec = json.loads((tmp_path / "luot" / "agent_dev_record.json").read_text(encoding="utf-8"))
    assert [o["stages"] for o in rec["observations"]] == [[{"stage": "pham_vi", "hits": 3},
                                                             {"stage": "ung_vien", "hits": 3}]]
    assert "## Check" in (tmp_path / "luot" / "hunt_record.md").read_text(encoding="utf-8")
