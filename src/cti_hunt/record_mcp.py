"""Minimal MCP stdio 2025-11-25, read-only completed records. No approvals or execution tools."""
import argparse
import json
import sys
from pathlib import Path

from . import config
from .record_store import RecordStore

VERSION = "2025-11-25"
TOOLS = [
    {"name": "tra_hunt_memory", "description": "Tìm hunt record không nhãn đã hoàn tất theo mã ATT&CK/report",
     "inputSchema": {"type": "object", "properties": {"technique": {"type": "string"}, "report": {"type": "string"}},
                     "additionalProperties": False}},
    {"name": "doc_hunt_record", "description": "Đọc record_id từ kết quả tra_hunt_memory",
     "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}},
                     "required": ["record_id"], "additionalProperties": False}},
]
for tool in TOOLS:
    tool["annotations"] = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


def handle(req, store):
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None,
                "error": {"code": -32600, "message": "Invalid request"}}
    if "id" not in req:
        return None
    reply = {"jsonrpc": "2.0", "id": req["id"]}
    method = req.get("method")
    if method == "initialize":
        reply["result"] = {"protocolVersion": VERSION, "serverInfo": {"name": "cti-hunt-records", "version": "1.0"},
                           "capabilities": {"tools": {"listChanged": False}}}
    elif method == "ping":
        reply["result"] = {}
    elif method == "tools/list":
        reply["result"] = {"tools": TOOLS}
    elif method == "tools/call":
        try:
            params = req.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("Params phải là object")
            name, args = params.get("name"), params.get("arguments", {})
            if not isinstance(args, dict) or any(not isinstance(v, str) for v in args.values()):
                raise ValueError("Arguments phải là chuỗi")
            if name == "tra_hunt_memory" and set(args) <= {"technique", "report"}:
                value = store.find(**args)
            elif name == "doc_hunt_record" and set(args) == {"record_id"}:
                value = store.read(args["record_id"])
            else:
                raise ValueError("Tool/arguments không hỗ trợ; server không duyệt hoặc chạy hunt")
            reply["result"] = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": False}
        except (ValueError, OSError) as e:
            reply["result"] = {"content": [{"type": "text", "text": str(e)}], "isError": True}
    else:
        reply["error"] = {"code": -32601, "message": "Method not found"}
    return reply


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=config.ROOT / "data/reports/moi")
    store = RecordStore(p.parse_args().root)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            reply = handle(json.loads(line), store)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if reply is not None:
            print(json.dumps(reply, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
