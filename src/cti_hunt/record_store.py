"""Read-only hunt memory over completed unlabeled records. No mock data or arbitrary paths."""
import json
import re
from pathlib import Path

from . import config, demo


class RecordStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        allowed = [config.ROOT / "data/reports/moi", config.ROOT / "data/dev"]
        if not any(self.root == p.resolve() or self.root.is_relative_to(p.resolve()) for p in allowed):
            raise ValueError("Kho chỉ được nằm trong report mới hoặc data/dev")

    def read(self, record_id: str) -> dict:
        folder = demo.inside(self.root / record_id, self.root)
        path = demo.inside(folder / "agent_dev_record.json", self.root)
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("kind") != "development_only_unlabeled":
            raise ValueError("Không phải hunt record vận hành không nhãn")
        md = demo.inside(folder / "hunt_record.md", self.root)
        return {"record_id": record_id, "record": record, "markdown": md.read_text(encoding="utf-8")}

    def find(self, technique: str = "", report: str = "") -> list[dict]:
        technique = technique.strip().upper()
        if technique and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            raise ValueError("Cần mã ATT&CK dạng T1047 hoặc T1059.001")
        result = []
        for path in sorted(self.root.rglob("agent_dev_record.json")):
            try:
                rid = path.parent.relative_to(self.root).as_posix()
                item = self.read(rid)
            except (ValueError, OSError):
                continue
            rec = item["record"]
            # IDs are from existing records, never invented results or untrusted absolute paths.
            techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", item["markdown"])
            if (not report or rec.get("report_id") == report) and (not technique or technique in techniques):
                result.append({"record_id": rid, "report_id": rec.get("report_id"),
                               "dataset": rec.get("dataset"), "executed_hunts": len(rec.get("executed_specs", []))})
        return result
