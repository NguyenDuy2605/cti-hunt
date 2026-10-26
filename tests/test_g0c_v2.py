"""G0(c) v2: thu EID của chuẩn về EID hunt sinh khi là tập con cùng channel; v1 giữ nguyên và là mặc định."""
import json

import pytest
import yaml

from cti_hunt import cli
from cti_hunt.eval import g0c

SYS = "microsoft-windows-sysmon/operational"


def spec(hid, eids, channel=SYS, hosts=None, where="TRUE"):
    scope = {"channel": channel, "event_ids": eids, **({"hosts": hosts} if hosts else {})}
    return {"id": hid, "scope": scope, "candidates": where, "filters": []}


def test_v1_requires_exact_scope_and_is_default():
    gen = spec("g", [13])
    assert g0c.narrow_reference(spec("r", [12, 13, 14]), gen) is None
    assert g0c.narrow_reference(spec("r", [13]), gen)["scope"]["event_ids"] == [13]


@pytest.mark.parametrize("ref_eids", [[12, 13, 14], []])
def test_v2_narrows_only_scope_and_records_original(ref_eids):
    ref = spec("r", ref_eids, where="TargetObject ILIKE '%run%'")
    out = g0c.narrow_reference(ref, spec("g", [13]), "v2")
    assert out["scope"]["event_ids"] == [13]
    assert out["candidates"] == ref["candidates"] and out["filters"] == ref["filters"]
    assert out["g0c_v2_thu_hep_eid"] == {"chuan_goc": ref_eids or "mọi EID", "theo_hunt_sinh": [13]}
    assert ref["scope"]["event_ids"] == ref_eids          # không sửa chuẩn gốc


@pytest.mark.parametrize("gen", [spec("g", [13, 15]), spec("g", [13], channel="security"),
                                 spec("g", [13], hosts=["UTICA"]), spec("g", [])])
def test_v2_never_widens_or_crosses_channel_or_hosts(gen):
    assert g0c.narrow_reference(spec("r", [12, 13, 14]), gen, "v2") is None


def test_unknown_rule_version_rejected():
    with pytest.raises(ValueError, match="v1 hoặc v2"):
        g0c.narrow_reference(spec("r", [1]), spec("g", [1]), "v3")


def test_cli_v2_scores_narrowed_reference_while_v1_does_not(work, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_ds", lambda: {"work_dir": str(work)})
    ref, gen = tmp_path / "ref.yaml", tmp_path / "gen.yaml"
    ref.write_text(yaml.safe_dump(spec("ref", [1, 5], where="ev_host = 'UTICA'")), encoding="utf-8")
    gen.write_text(yaml.safe_dump(spec("gen", [1], where="ev_rec = 11")), encoding="utf-8")
    out1, out2 = tmp_path / "v1.json", tmp_path / "v2.json"
    assert cli.main(["exec-acc", str(ref), str(gen), "--out", str(out1)]) == 1
    assert cli.main(["exec-acc", str(ref), str(gen), "--out", str(out2), "--quy-tac", "v2"]) == 0
    r1, = json.loads(out1.read_text(encoding="utf-8"))
    r2, = json.loads(out2.read_text(encoding="utf-8"))
    assert r1["so_duoc"] is False and r1["quy_tac_g0c"] == "v1"
    assert r2["so_duoc"] is True and r2["quy_tac_g0c"] == "v2"
    assert r2["bo_chuan"][0]["thu_hep_eid"] == [{"chuan_goc": [1, 5], "theo_hunt_sinh": [1]}]
    assert r2["giai_doan"]["ung_vien"]["chuan"] == 3      # 3 sự kiện Sysmon EID 1 của UTICA trong fixture
