"""Prepare explicit rule comparisons on an E1 development dataset; no Splunk/API calls."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from cti_hunt import config, demo, integrity
from cti_hunt.adapters import duckdb_sigma
from cti_hunt.data.store import connect
from cti_hunt.eval import splunk_compare as compare
from cti_hunt.stages.s1_ingest import write_json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--import-dir", required=True, type=Path)
    p.add_argument("--rules", required=True, nargs="+", type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    if a.out.exists():
        raise ValueError("Dùng thư mục mới, không ghi đè kết quả")
    dataset = demo.dataset(a.events.resolve())
    imported = json.loads((a.import_dir / "import_manifest.draft.json").read_text(encoding="utf-8"))
    events_hash = integrity.sha256_file(a.events / "events.parquet")
    exported = demo.inside(a.import_dir / imported["export_file"], a.import_dir)
    if imported["events_sha256"] != events_hash or integrity.sha256_file(exported) != imported["export_sha256"]:
        raise ValueError("Gói xuất không khớp hash dataset hoặc JSONL")
    con = connect(a.events)
    try:
        cur = con.execute("SELECT * FROM events")
        columns = [x[0] for x in cur.description]
        expected = [dict(zip(columns, row)) for row in cur.fetchall()]
        lines = exported.read_bytes().splitlines()
        rows = [json.loads(line) for line in lines]
        # This checks the LOCAL export, never pretends to be a Splunk response.
        actual = [{**{k: row[k] for k in compare.KEYS}, "_raw": line.decode("utf-8"),
                   "cti_indexed_epoch": str(datetime.fromisoformat(row["ev_ts"].replace("Z", "+00:00")).timestamp())}
                  for row, line in zip(rows, lines)]
        compare.verify_payload(expected, actual)
        lo, hi = con.execute("SELECT min(ev_ts), max(ev_ts) FROM events").fetchone()
        start = lo.replace(tzinfo=timezone.utc).isoformat()
        end = (hi + timedelta(microseconds=1)).replace(tzinfo=timezone.utc).isoformat()
        catalog_path = config.resolve(config.load("dataset")["logsource_catalog"])
        catalog = duckdb_sigma.load_catalog(catalog_path)
        a.out.mkdir(parents=True, exist_ok=False)
        plans = []
        for number, rule in enumerate(a.rules):
            try:
                plan = compare.plans(rule, catalog, set(columns), imported["index"], start, end)
                plan.update(events_sha256=events_hash, catalog_sha256=integrity.sha256_file(catalog_path))
                for stage in plan["stages"]:
                    stage["duckdb_preview_count"] = len(con.execute(stage["sql"]).fetchall())
                path = a.out / f"{number:02d}_{rule.stem}.json"
                write_json(path, plan)
                plans.append({"rule": str(rule), "status": "prepared", "plan": str(path),
                              "counts": [s["duckdb_preview_count"] for s in plan["stages"]],
                              "skipped_sources": plan["skipped_sources"]})
            except ValueError as e:
                plans.append({"rule": str(rule), "status": "blocked", "error": str(e)})
        proof = {"kind": "splunk_suite_preparation_only", "splunk_called": False,
                 "dataset_id": dataset["dataset_id"], "events_sha256": events_hash,
                 "import_dir": str(a.import_dir), "rows": len(rows), "bytes": exported.stat().st_size,
                 "local_payload_verified": True, "max_event_bytes": max(map(len, lines)),
                 "events_over_default_10000_bytes": sum(len(line) > 10000 for line in lines),
                 "time_from": start, "time_to_exclusive": end, "rules": plans}
        write_json(a.out / "preflight.json", proof)
        print(json.dumps(proof, ensure_ascii=False, indent=2))
    finally:
        con.close()


if __name__ == "__main__":
    main()
