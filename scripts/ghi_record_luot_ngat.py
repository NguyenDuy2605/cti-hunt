"""Dựng hunt record bản vận hành (không nhãn) cho lượt graph bị ngắt giữa một node, không gọi API.

Dùng khi một lời gọi mô hình thất bại ngoài cổng ◆ (vd mô hình từ chối ở ⑤) và lượt không được gọi lại (D11).
Kiểm cổng E2, hồ sơ và mốc như `agent resume`. Chỉ đọc BẢN SAO checkpoint; không sửa checkpoint, phiếu hay tệp của
các vòng. Chỉ thêm hunt_record.md, agent_dev_record.json (StageTools.record — cùng mã với node record) và su_co.json.
Giả thuyết đã duyệt nhưng chưa thực thi được liệt kê riêng, không ghi là 0 kết quả.

    .venv/Scripts/python.exe -X utf8 scripts/ghi_record_luot_ngat.py --run <thư mục lượt> --ly-do "<mô tả sự cố>"
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import tempfile

from cti_hunt import approval, config, integrity
from cti_hunt.agent import moc, session
from cti_hunt.agent.graph import open_sqlite_graph

OUTPUTS = ("hunt_record.md", "agent_dev_record.json", "su_co.json")


def not_executed(state: dict) -> list[dict]:
    """Giả thuyết approved ở các vòng chưa có agent_execute.json (vòng bị ngắt trước khi thực thi xong).

    `co_rule_hop_le`: ⑤ đã ghi rule hợp lệ (v1 `rules/`, v2 `rules_draft/`) nhưng rule chưa được truy vấn."""
    out = []
    for p in state.get("approved_files") or []:
        path = Path(p)
        if not (path.parent / "agent_execute.json").exists():
            out += [{"vong": path.parent.name, "hypothesis_id": h.hypothesis_id,
                     "co_rule_hop_le": any((path.parent / d / f"{h.hypothesis_id}.yml").exists()
                                           for d in ("rules", "rules_draft"))}
                    for h in approval.load_hypotheses(path) if h.status == "approved"]
    return out


def record_interrupted(run_dir: Path, reason: str, root: Path = config.ROOT) -> dict:
    run_dir = Path(run_dir)
    if not str(reason or "").strip():
        raise session.SessionError("cần ghi lý do sự cố")
    meta = json.loads((run_dir / session.META_FILE).read_text(encoding="utf-8"))
    session._check_unchanged(meta, root)
    if meta.get("moc_co_dinh") and moc.verify(meta["mode"], root, version=meta.get("phien_ban", "v1"))["sha256"] \
            != meta["moc_co_dinh"]["sha256"]:
        raise session.SessionError("mốc hiện tại khác mốc của lượt")
    existing = [n for n in OUTPUTS if (run_dir / n).exists()]
    if existing:
        raise session.SessionError(f"{', '.join(existing)} đã tồn tại trong lượt; không ghi đè")
    checkpoint = run_dir / session.CHECKPOINT_FILE
    before = integrity.sha256_file(checkpoint)
    planner, tools, cfg, profile = session._build(meta, run_dir, root)
    try:
        session._check_profile(meta, run_dir, profile)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / session.CHECKPOINT_FILE
            shutil.copy2(checkpoint, copy)
            with open_sqlite_graph(planner, tools, cfg, run_dir, copy) as graph:
                snap = graph.get_state(session._thread(meta))
        pending = list(snap.next or ())
        if not pending or "review" in pending:
            raise session.SessionError("chỉ dùng cho lượt bị ngắt ngoài cổng duyệt; lượt này "
                                       + ("đang chờ phiếu ◆" if pending else "đã xong hoặc chưa bắt đầu"))
        state = snap.values
        missing = not_executed(state)
        tools.record(state)                  # chạy lại hunt đã thực thi trên events, không gọi mô hình
    finally:
        tools.con.close()
    if integrity.sha256_file(checkpoint) != before:
        raise session.SessionError("checkpoint gốc bị đổi trong lúc dựng record")
    incident = {"loai": "luot_ngat_ngoai_cong_duyet", "ly_do": reason.strip(), "node_dang_cho": pending,
                "gia_thuyet_da_duyet_chua_thuc_thi": missing,
                "so_hunt_da_thuc_thi": len(state.get("executed_specs") or []),
                "checkpoint_sha256": before, "khong_goi_api": True, "moc_co_dinh": meta.get("moc_co_dinh"),
                "thoi_diem": datetime.now().isoformat(timespec="seconds"),
                "cong_cu": "scripts/ghi_record_luot_ngat.py", "cong_cu_sha256": integrity.sha256_file(Path(__file__))}
    lines = ["", "", "### Sự cố: lượt dừng giữa chừng", "",
             f"{incident['ly_do']} Lượt không được gọi lại sau sự cố. Hunt record này dựng từ checkpoint sau sự cố, "
             "không gọi mô hình, chỉ gồm các hunt đã thực thi.", ""]
    if missing:
        lines += ["Giả thuyết đã duyệt nhưng chưa truy vấn — chưa được kiểm chứng, "
                  "không phải kết quả 0 sự kiện:", ""]
        lines += [f"- {m['vong']}: {m['hypothesis_id']}"
                  + (" (đã có rule hợp lệ, chưa truy vấn)" if m["co_rule_hop_le"] else " (chưa có rule)")
                  for m in missing]
    md = run_dir / "hunt_record.md"
    md.write_text(md.read_text(encoding="utf-8").rstrip("\n") + "\n".join(lines) + "\n", encoding="utf-8")
    (run_dir / "su_co.json").write_text(json.dumps(incident, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return incident


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--ly-do", required=True, help="mô tả sự cố, ghi nguyên văn vào record")
    args = parser.parse_args(argv)
    out = record_interrupted(args.run, args.ly_do)
    print(json.dumps({k: out[k] for k in ("node_dang_cho", "gia_thuyet_da_duyet_chua_thuc_thi",
                                         "so_hunt_da_thuc_thi", "khong_goi_api")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
