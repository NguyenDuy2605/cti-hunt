"""Exercise the saved, already-approved legacy demo through Streamlit without API calls."""
import argparse
import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

from cti_hunt import config, demo_app, integrity


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--accept-partial", action="store_true", help="Chấp nhận giới hạn nguồn đã biết cho replay; không duyệt OCR/TTP mới")
    args = p.parse_args()
    if args.out.exists():
        raise ValueError("Dùng file bằng chứng mới")
    bundle, events = args.bundle.resolve(), args.events.resolve()
    extraction = bundle / "extraction"
    before = set((extraction / "replays").glob("replay_*"))
    def no_api():
        raise RuntimeError("Kiểm replay không được gọi API")
    demo_app.api_key = no_api
    app = AppTest.from_file(str(config.ROOT / "app/streamlit_app.py"), default_timeout=60).run()
    def field(kind, label):
        return next(x for x in getattr(app, kind) if x.label == label)
    field("selectbox", "Mở report đã lưu").select(bundle).run()
    field("selectbox", "Lượt trích").select(extraction).run()
    if args.accept_partial:
        field("checkbox", "Tôi đã rà và chấp nhận phần chưa đọc/cảnh báo").check().run()
    field("selectbox", "Bộ log phát triển").select(events).run()
    field("button", "Kiểm và thực thi rule cũ").click().run()
    if app.exception or app.error:
        raise RuntimeError([x.value for x in [*app.exception, *app.error]])
    created = set((extraction / "replays").glob("replay_*")) - before
    if len(created) != 1:
        raise RuntimeError("Không tạo được đúng một lượt replay")
    run = created.pop()
    field("selectbox", "Kết quả chạy lại").select(run).run()
    if app.exception or app.error:
        raise RuntimeError([x.value for x in [*app.exception, *app.error]])
    record = json.loads((run / "agent_dev_record.json").read_text(encoding="utf-8"))
    shown = any("Observe" in x.value and "Check" in x.value for x in app.markdown)
    if not shown:
        raise RuntimeError("UI không hiển thị Hunt Record")
    proof = {"kind": "streamlit_approved_rule_replay", "run": str(run), "api_called": False,
             "new_approvals": False, "partial_source_acknowledged_for_replay": args.accept_partial,
             "rules": record["rules"], "executed_specs": len(record["executed_specs"]),
             "hunt_record_displayed": shown, "sql_displayed": sum("SELECT * FROM events" in x.value for x in app.code),
             "record_sha256": integrity.sha256_file(run / "hunt_record.md")}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
    print(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
