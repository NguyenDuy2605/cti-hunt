"""Khảo sát ứng viên lọc trên OTRF: fixture tổng hợp, không đọc dữ liệu thật, không tạo phiếu."""
import importlib.util
import sys

import pytest

from cti_hunt import config
from cti_hunt.data.store import connect


@pytest.fixture
def mod(monkeypatch):
    monkeypatch.syspath_prepend(str(config.ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("ra_ung_vien_loc_otrf_test", config.ROOT / "scripts/ra_ung_vien_loc_otrf.py")
    m = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ra_ung_vien_loc_otrf_test", m)
    spec.loader.exec_module(m)
    return m


def test_survey_counts_whole_source_and_groups_by_available_key_fields(mod, work):
    con = connect(work)
    try:
        out = mod.survey_source(con, {"channel": "microsoft-windows-sysmon/operational", "event_ids": [1]})
    finally:
        con.close()
    assert out["so_su_kien"] == 5 and out["so_nhom"] == 5
    assert sum(g["so_su_kien"] for g in out["nhom_lon_nhat"]) == 5
    assert out["gom_theo"][:2] == ["ParentImage", "Image"]


def test_proposals_are_single_line_and_never_create_review_forms(mod):
    import yaml
    for eids, rule in mod.PROPOSALS.values():
        det = yaml.safe_load(rule)["detection"]
        values = [v for k, block in det.items() if k.startswith("filter_") for v in block.values()]
        assert all("\r" not in str(v) and "\n" not in str(v) for v in values)
        assert det["condition"].startswith("selection and not ")
    source = (config.ROOT / "scripts/ra_ung_vien_loc_otrf.py").read_text(encoding="utf-8")
    assert not any(call in source for call in ("F.prepare", "F.finalize", "save_decisions", "F.receipt", "F.FORM"))


@pytest.mark.parametrize("relative", ["data/dev", "data/work/x", "runs/x"])
def test_output_must_be_new_dir_under_data_dev(mod, relative):
    with pytest.raises(ValueError, match="data/dev"):
        mod.run(config.ROOT / relative)
