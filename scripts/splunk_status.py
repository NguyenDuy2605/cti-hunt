"""Read local Splunk readiness/license/index state through the search endpoint only."""
import argparse
import json
import os
import re
from pathlib import Path

from cti_hunt.adapters.splunk import SplunkConnection, SplunkError


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--index", default="cti_wmi_dev")
    args = p.parse_args()
    if args.out.exists():
        raise ValueError("Dùng tệp trạng thái mới")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", args.index):
        raise ValueError("Tên index không hợp lệ")
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as registry:
            for name in ("SPLUNK_USER", "SPLUNK_PASS"):
                if not os.environ.get(name):
                    try:
                        os.environ[name] = winreg.QueryValueEx(registry, name)[0]
                    except FileNotFoundError:
                        pass
    client = SplunkConnection("127.0.0.1")
    queries = {
        "server": "| rest splunk_server=local /services/server/info | table version build serverName",
        "licenses": "| rest count=0 splunk_server=local /services/licenser/licenses | table label type quota expiration_time status",
        "license_groups": "| rest count=0 splunk_server=local /services/licenser/groups | table title is_active",
        "dev_index": f"| rest splunk_server=local /services/data/indexes/{args.index} | table title totalEventCount currentDBSizeMB frozenTimePeriodInSecs maxTotalDataSizeMB",
        "usage_today": "search index=_internal source=*license_usage.log type=Usage | stats sum(b) AS indexed_bytes_today",
        "search_smoke": "| makeresults | eval cti_readiness=1 | table cti_readiness",
    }
    proof = {"kind": "local_splunk_readiness_only", "cti_imported_by_script": False, "results": {}}
    for name, query in queries.items():
        proof["results"][name] = client.search(query, earliest_time="@d", latest_time="now")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
    print(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (SplunkError, ValueError, OSError) as exc:
        print(f"Chưa hoàn tất kiểm tra Splunk: {exc}")
        raise SystemExit(1)
