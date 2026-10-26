"""Hunt memory của agent tuyến A: kho rỗng, ghi vào run_meta, resume từ chối nếu kho đổi giữa lượt."""
import pytest

from cti_hunt import integrity
from cti_hunt.agent import session
from cti_hunt.config import ROOT


def test_evaluation_memory_store_is_empty():
    """Kho cũ data/reports/moi có record của report đánh giá MS; agent tuyến A phải thấy kho rỗng."""
    snap = session.hunt_memory()
    assert snap["root"] != "data/reports/moi" and snap["records"] == []


def test_resume_refuses_when_the_memory_store_changes(work, tmp_path, monkeypatch):
    ca = tmp_path / "ca.json"
    ca.write_text('{"report_id": "TU", "ttps": []}', encoding="utf-8")
    meta = {"mode": "agent", "tep": session.tracked_files(ROOT),
            "contract_a": {"path": str(ca), "sha256": integrity.sha256_file(ca)},
            "events": {"dir": str(work), "parquet_sha256": integrity.sha256_file(work / "events.parquet")},
            "git": {"commit": None}, "moc_co_dinh": None, "hunt_memory": session.hunt_memory()}
    session._check_unchanged(meta, ROOT)                                   # cùng kho: qua
    monkeypatch.setattr(session, "hunt_memory", lambda root=ROOT: {"root": meta["hunt_memory"]["root"],
                                                                    "records": ["record-moi"]})
    with pytest.raises(session.SessionError, match="kho hunt memory"):
        session._check_unchanged(meta, ROOT)
    del meta["hunt_memory"]                                               # run_meta cũ không có khóa: bỏ qua
    session._check_unchanged(meta, ROOT)
