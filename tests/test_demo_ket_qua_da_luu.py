import importlib.util
import json
from pathlib import Path
import socket
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ra_ho_so_tuyen_a.py"
spec = importlib.util.spec_from_file_location("ra_ho_so_tuyen_a", SCRIPT)
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def package(tmp_path):
    source = tmp_path / "data/dev/saved/approval_log.json"
    source.parent.mkdir(parents=True)
    source.write_text('{"approved": true}', encoding="utf-8")
    folder = tmp_path / "data/dev/demo"
    folder.mkdir()
    data = {"source_hashes": {source.relative_to(tmp_path).as_posix(): audit.sha(source)}}
    def write(value):
        path = folder / "demo.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        (folder / "demo.sha256").write_text(audit.sha(path), encoding="ascii")
    write(data)
    return folder, source, data, write


def test_saved_package_has_no_network_or_writes(tmp_path, monkeypatch):
    folder, source, data, _ = package(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    def forbidden(*args, **kwargs):
        pytest.fail("Đọc demo không được kết nối hoặc ghi tệp")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    assert audit.load_demo(folder, tmp_path) == data
    assert all(p.read_bytes() == content for p, content in before.items())


@pytest.mark.parametrize("relative", ["runs/EVAL.json", "data/labels/a.json", "data/dev/../../labels/a.json", "../outside.json"])
def test_manifest_cannot_read_forbidden_sources(tmp_path, relative):
    folder, _, data, write = package(tmp_path)
    data["source_hashes"] = {relative: "0" * 64}
    write(data)
    with pytest.raises(ValueError):
        audit.load_demo(folder, tmp_path)


def test_changed_review_stops_demo(tmp_path):
    folder, source, _, _ = package(tmp_path)
    source.write_text('{"approved": false}', encoding="utf-8")
    with pytest.raises(ValueError, match="Nguồn demo đã đổi"):
        audit.load_demo(folder, tmp_path)


def test_changed_snapshot_stops_demo(tmp_path):
    folder, _, _, _ = package(tmp_path)
    (folder / "demo.json").write_text('{}', encoding="utf-8")
    with pytest.raises(ValueError, match="Gói demo đã đổi"):
        audit.load_demo(folder, tmp_path)


def test_viewer_switches_cases_without_api(monkeypatch):
    from streamlit.testing.v1 import AppTest
    def forbidden(*args, **kwargs):
        pytest.fail("Viewer không được gọi API")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    cases = [{"hypothesis": {"hypothesis_id": f"H0{i}", "source_spans": [], "status": "approved"},
              "review": {"nguoi_duyet": "User"}, "rule": "title: saved", "specs": [],
              "observations": [{"stages": [{"stage": "ung_vien", "hits": i}], "sample": []}]}
             for i in (1, 2)]
    monkeypatch.setattr(audit, "load_demo", lambda _: {
        "report": {}, "contract_a": {}, "cases": cases, "verified_summary": {},
        "hunt_record": "Kết quả gốc", "agent_history": [{"decision": {"action": "stop"}}],
        "source_hashes": {}, "filter_demo": {
            "executed_at_utc": "2026-10-02T01:46:50Z", "hypothesis": {"behavior": "Synthetic scheduled task"},
            "stages": [{"stage": stage, "duck_count": n, "splunk_count": n, "jaccard": 1.0}
                       for stage, n in (("ung_vien", 3), ("sau_S-01", 2), ("sau_S-02", 1))],
            "review": {"quyet_dinh": [{"id": "SYNTHETIC__S-01", "quyet_dinh": "approved", "ly_do": "Fixture",
                "nguoi_chiu_trach_nhiem": "synthetic tester", "hieu_luc_den_utc": "2026-01-01T00:00:00Z", "can_cu": "Fixture only"}]},
            "rule": "title: mock", "receipt": {}, "hunt_record": "Synthetic record"},
        "real_v2": {
            "bat_dau": "2026-10-02T14:50:21", "commit": "0" * 40, "dataset": {"id": "otrf-fixture"},
            "planner": [{"action": "hunt", "ttp": ["T0001"], "ly_do": "fixture"}],
            "cong_loc": {"nguoi_duyet": "synthetic tester", "thoi_diem_utc": "2026-10-02T08:10:15+00:00",
                         "so_spec_hieu_luc": 1, "rule_co_muc_loc": {"FX-H01": "title: fixture"},
                         "preview": [{"hunt_id": "FX-H01__h", "candidates": 1,
                                      "filters": [{"id": "S-01", "matched": 0}]}],
                         "muc_loc": [{"id": "FX-H01__h__S-01", "hunt_id": "FX-H01__h", "hypothesis_id": "FX-H01",
                                      "bieu_thuc_sigma": "filter_x", "where": "1=1", "quyet_dinh": "rejected",
                                      "ly_do": "fixture"}]},
            "vong": [{"dem": {"approved": 1}, "rule_hop_le": ["FX-H01"],
                      "gia_thuyet": [{"id": "FX-H01", "hanh_vi": "fixture", "nguon": "fixture", "eid": [1]}],
                      "rule": [{"hypothesis_id": "FX-H01", "hop_le": True, "so_lan_sua": 0, "loi": ""}],
                      "ket_qua": [{"hypothesis_id": "FX-H01", "stages": [{"stage": "pham_vi", "hits": 2},
                                                                        {"stage": "ung_vien", "hits": 1}],
                                   "mau": [{"ev_host": "H", "ev_ts": "t", "Image": "x.exe", "User": "u"}]}]}],
            "su_co": {"ly_do": "fixture"}, "chi_phi": {"loi_goi": 1, "usd": "0.000001"},
            "hunt_record": "Synthetic real record"}})
    app = AppTest.from_file(str(SCRIPT.with_name("demo_ket_qua_da_luu.py"))).run()
    assert not app.exception
    assert not app.button
    assert len(app.tabs) == 7
    assert any(list(table.value["Quyết định"]) == ["rejected"] for table in app.table if "Quyết định" in table.value)
    assert any("rule mock" in warning.value for warning in app.warning)
    assert any(list(table.value["DuckDB"]) == [3, 2, 1] for table in app.table if "DuckDB" in table.value)
    order = [getattr(node, "type", None) for node in app.main.children.values()]
    assert order.index("selectbox") < order.index("tab_container")
    assert app.selectbox[0].value == "H02"
    app.selectbox[0].select("H01").run()
    assert not app.exception
    assert app.selectbox[0].value == "H01"


def test_viewer_hides_empty_sample_columns_and_names_stages():
    viewer_path = SCRIPT.with_name("demo_ket_qua_da_luu.py")
    viewer_spec = importlib.util.spec_from_file_location("demo_ket_qua_da_luu", viewer_path)
    viewer = importlib.util.module_from_spec(viewer_spec)
    viewer_spec.loader.exec_module(viewer)
    rows, hidden = viewer.visible_sample([{"ev_host": "A", "Image": "", "User": None},
                                          {"ev_host": "B", "Image": "x.exe", "User": ""}])
    assert hidden == ["User"]
    assert rows == [{"ev_host": "A", "Image": ""}, {"ev_host": "B", "Image": "x.exe"}]
    assert viewer.visible_sample([]) == ([], [])
    assert [viewer.stage_label(s) for s in ("pham_vi", "ung_vien", "sau_S-02", "khac")] == [
        "Phạm vi nguồn log", "Ứng viên khớp rule", "Sau mục lọc S-02", "khac"]
    assert viewer.utc_text("2026-10-02T01:46:50.720970+00:00") == "02/10/2026 01:46:50 UTC"
    assert viewer.utc_text("2026-10-02T08:46:50+07:00") == "02/10/2026 01:46:50 UTC"
    assert viewer.utc_text("không phải thời gian") == "không phải thời gian"
