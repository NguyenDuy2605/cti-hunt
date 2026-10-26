"""Explicit engine comparison DuckDB vs local Splunk. Preview is the default, no server writes."""
import argparse
import json
from pathlib import Path

from . import config, demo, integrity
from .adapters import duckdb_sigma
from .adapters.splunk import SplunkConnection
from .data.store import connect
from .eval import splunk_compare
from .stages.s1_ingest import write_json


def dataset(events: Path) -> dict:
    """APT29 day 2 đúng thư mục làm việc (dữ liệu không nhãn, D14 §11.2) hoặc bộ OTRF phát triển đã kiểm E1."""
    work = config.resolve(config.load("dataset")["work_dir"]).resolve()
    if events.resolve() == work:
        if not (work / "events.parquet").exists():
            raise ValueError(f"Chưa có {work / 'events.parquet'}")
        return {"dataset_id": "apt29_day2", "dataset_kind": "danh_gia"}
    return demo.dataset(events)


def rule_files(paths: list[Path]) -> list[Path]:
    """Giữ thứ tự tham số; thư mục lấy mọi *.yml theo thứ tự tên; bỏ tệp trùng."""
    files = []
    for path in paths:
        path = config.resolve(path)
        for f in (sorted([*path.rglob("*.yml"), *path.rglob("*.yaml")]) if path.is_dir() else [path]):
            if f not in files:
                files.append(f)
    if not files:
        raise ValueError("Không tìm thấy tệp rule .yml nào")
    return files


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rules", nargs="+", type=Path, help="tệp rule Sigma hoặc thư mục (lấy mọi *.yml bên trong)")
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--index", required=True)
    p.add_argument("--time-from", required=True, help="ISO8601 có múi giờ; đầu cửa sổ bao gồm")
    p.add_argument("--time-to", required=True, help="ISO8601 có múi giờ; cuối cửa sổ loại trừ")
    p.add_argument("--import-manifest", type=Path)
    p.add_argument("--send", action="store_true")
    p.add_argument("--export-events", action="store_true",
                   help="Xuất JSONL chuẩn hóa (chỉ các channel/EID mà rule truy vấn) và manifest nháp để nạp thủ công")
    p.add_argument("--exclude-source", action="append", default=[], metavar="CHANNEL:EID",
                   help="Bỏ một nguồn khỏi gói xuất; stage của nguồn đó ghi not_imported khi so")
    p.add_argument("--exclude-reason", default="", help="Lý do loại trừ, bắt buộc khi có --exclude-source")
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args(argv)
    con = None
    try:
        if a.out.exists():
            raise ValueError("Thư mục kết quả đã tồn tại; dùng tên mới")
        if a.send and a.export_events:
            raise ValueError("Xuất gói và so là hai lượt riêng: nạp và xác nhận manifest ở giữa")
        if a.exclude_source and not a.export_events:
            raise ValueError("--exclude-source chỉ dùng khi --export-events; lúc so, phạm vi lấy từ manifest")
        if a.exclude_source and not a.exclude_reason.strip():
            raise ValueError("Cần --exclude-reason cho nguồn bị loại trừ")
        excluded = [splunk_compare.parse_source(s) for s in a.exclude_source]
        events = config.resolve(a.events)
        ds = dataset(events)
        con = connect(events)
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        catalog_path = config.resolve(config.load("dataset")["logsource_catalog"])
        catalog = duckdb_sigma.load_catalog(catalog_path)
        events_sha256 = integrity.sha256_file(events / "events.parquet")
        catalog_sha256 = integrity.sha256_file(catalog_path)
        plans, blocked = [], []
        for rule in rule_files(a.rules):
            try:
                import yaml
                from .hunt import runner
                from .filter_approval import path_policy
                doc = yaml.safe_load(rule.read_text(encoding="utf-8"))
                if isinstance(doc, dict) and "detection" not in doc and (doc.get("filter_policy") or path_policy(rule)):
                    plan = splunk_compare.plans_effective(runner.load_spec(rule), con, a.index, a.time_from, a.time_to)
                else:
                    plan = splunk_compare.plans(rule, catalog, cols, a.index, a.time_from, a.time_to)
                for stage in plan["stages"]:
                    con.execute("EXPLAIN " + stage["sql"])
            except Exception as e:  # một rule lỗi không làm mất cả lượt; lý do được ghi nguyên văn
                blocked.append({"rule": str(rule), "error": f"{type(e).__name__}: {e}"})
                continue
            plan.update(rule=str(rule), events_sha256=events_sha256, catalog_sha256=catalog_sha256)
            plans.append(plan)
        if not plans:
            raise ValueError("Không rule nào lập được kế hoạch so: " + "; ".join(b["error"] for b in blocked[:3]))
        a.out.mkdir(parents=True, exist_ok=False)
        write_json(a.out / "plan.json", {"dataset": ds, "events_sha256": events_sha256,
                                         "catalog_sha256": catalog_sha256, "plans": plans, "blocked": blocked})
        print(f"Lập kế hoạch {len(plans)} rule, chặn {len(blocked)} rule (lý do trong plan.json)")
        if a.export_events:
            scope = splunk_compare.import_scope(plans, excluded)
            records = [{"channel": ch, "event_id": eid, "reason": a.exclude_reason.strip()} for ch, eid in excluded]
            m = splunk_compare.export_events(con, a.out / "import", events_sha256, a.index,
                                             scope=scope, excluded=records, omit_null=True)
            print(f"Đã xuất {m['rows']} sự kiện, {m['bytes']} byte ({m['bytes'] / 1e6:.1f} MB) "
                  f"vào {a.out / 'import'}; manifest nháp chưa xác nhận")
        if not a.send:
            print(f"Đã kiểm SQL và ghi {a.out / 'plan.json'}; chưa kết nối Splunk")
            return 0
        if not a.import_manifest:
            raise ValueError("--send cần manifest nạp cùng dataset/index, xác nhận thời gian/giấy phép")
        imported = json.loads(a.import_manifest.read_text(encoding="utf-8"))
        result = splunk_compare.compare_suite(con, SplunkConnection("127.0.0.1"), plans, imported, events_sha256)
        result["blocked"] = blocked
        write_json(a.out / "comparison.json", result)
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
        print(f"Chi tiết khóa lệch trong {a.out / 'comparison.json'}")
        return 0
    except Exception as e:
        print(f"Chưa hoàn tất đối chiếu: {e}")
        return 1
    finally:
        if con is not None:
            con.close()
