"""Pilot 0 USD: mô hình mở chạy cục bộ (Ollama, CPU) thay Claude ở khâu ② và ⑤ trên dữ liệu phát triển.

Không gọi API Claude: chặn dựng client Anthropic/OpenAI và mọi kết nối mạng ngoài 127.0.0.1. Không đổi cấu hình,
prompt, mốc hay sổ ngân sách (kiểm hash trước/sau). Không đọc nhãn, `runs/` hay dữ liệu APT29.

- ②: đúng 20 câu phát triển N3 và đúng prompt đã đo Sonnet 5 (N3 §11); kiểm prompt gửi đi trùng byte với
  `requests.jsonl` của lượt Sonnet; chấm bằng chính `score_dev` và so từng câu.
- ⑤: 16 giả thuyết người vận hành đã duyệt trên OTRF phát triển, đã có rule Sonnet 5 sinh với cùng prompt ⑤ v1; đo tính hợp lệ
  (cùng kiểm tĩnh và vòng sửa) và so tập sự kiện của rule cục bộ với rule Sonnet bằng exec-acc (không nhãn).

    python scripts/pilot_llm_cuc_bo.py khau2 --model qwen2.5:7b-instruct --phien-ban v1 --out data/dev/pilot_llm_cuc_bo/<mới>
    python scripts/pilot_llm_cuc_bo.py khau5 --model qwen2.5:7b-instruct --out data/dev/pilot_llm_cuc_bo/<mới>
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
from unittest.mock import patch

from cti_hunt import approval, config, integrity
from cti_hunt.llm import providers

OLLAMA = "http://127.0.0.1:11434"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
SONNET_KHAU2 = {"v1": "data/dev/n3/dev_ttp_v1_chinh_20261001-110837",
                "v2": "data/dev/n3/dev_ttp_v2_chinh_20261001-110955"}
KHAU5_ROUNDS = ["data/dev/sonnet5_pipeline_03/round_01", "data/dev/sonnet5_pipeline_04/round_01",
                *[f"data/dev/report_emotet_28-9/case/handoff_send/hunt_v3/round_0{i}" for i in range(1, 5)]]
KHAU5_PROMPT = "prompts/khau5_sigma_v1.md"
PINNED = ["configs/llm.yaml", "configs/llm_v2.yaml", "configs/llm_hunt.yaml", "configs/agent.yaml",
          "configs/agent_v2.yaml", "prompts/khau2_ttp_v1.md", "prompts/khau2_ttp_v2.md", "prompts/khau2_kiem_v2.md",
          KHAU5_PROMPT, "data/dev/api_budget.sqlite"]


def _local_only(address) -> None:
    host = address[0] if isinstance(address, tuple) else address
    if str(host) not in LOCAL_HOSTS:
        raise RuntimeError(f"pilot chỉ kết nối 127.0.0.1; chặn kết nối tới {host}")


@contextmanager
def guard():
    """Chặn client API thật và mọi kết nối mạng ngoài máy, suốt thời gian pilot."""
    real_create, real_connect = socket.create_connection, socket.socket.connect

    def create_connection(address, *args, **kwargs):
        _local_only(address)
        return real_create(address, *args, **kwargs)

    def connect(sock, address):
        _local_only(address)
        return real_connect(sock, address)

    def forbidden(*args, **kwargs):
        raise RuntimeError("pilot cấm dựng client API Claude/OpenAI")

    with ExitStack() as stack:
        stack.enter_context(patch("socket.create_connection", create_connection))
        stack.enter_context(patch.object(socket.socket, "connect", connect))
        for target in ("cti_hunt.llm.providers.AnthropicClient", "cti_hunt.llm.providers.OpenAICompatibleClient",
                       "cti_hunt.llm.providers.from_config"):
            stack.enter_context(patch(target, side_effect=forbidden))
        yield


def _get(path: str, body: dict | None = None, timeout: int = 30) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(f"{OLLAMA}{path}", data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def model_info(model: str) -> dict:
    """Mô hình phải có sẵn cục bộ (không phải mô hình cloud); ghi digest/kích thước/lượng tử hóa."""
    tags = {m["name"]: m for m in _get("/api/tags")["models"]}
    if model not in tags:
        raise ValueError(f"chưa có mô hình cục bộ {model}; tải bằng `ollama pull {model}`")
    show = _get("/api/show", {"model": model})
    if show.get("remote_host") or show.get("remote_model"):
        raise ValueError("mô hình trỏ tới máy chủ từ xa; pilot chỉ dùng mô hình cục bộ")
    tag = tags[model]
    return {"name": model, "digest": tag.get("digest"), "size_bytes": tag.get("size"),
            "details": show.get("details") or {}, "ollama_version": _get("/api/version").get("version")}


class LocalOllama:
    """Cùng giao diện `complete_json` của providers; gọi API gốc Ollama để đặt rõ num_ctx (không cắt prompt)."""

    def __init__(self, model: str, num_ctx: int, max_output_tokens: int, timeout: int):
        self.model, self.num_ctx, self.max_output_tokens, self.timeout = model, num_ctx, max_output_tokens, timeout
        self.model_id = f"ollama/{model}"
        self.calls: list[dict] = []

    def describe(self) -> dict:
        return {"model": self.model_id, "kieu_api": "ollama_cuc_bo", "base_url": OLLAMA, "num_ctx": self.num_ctx,
                "num_predict": self.max_output_tokens, "temperature": 0, "seed": 0, "timeout_giay": self.timeout,
                "json_schema": "providers.strict_schema"}

    def complete_json(self, system: str, user: str, json_schema: dict, log=None) -> dict:
        record = log or (lambda _: None)
        payload = {"model": self.model, "stream": False, "keep_alive": "30m",
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   "format": providers.strict_schema(json_schema),
                   "options": {"num_ctx": self.num_ctx, "num_predict": self.max_output_tokens,
                               "temperature": 0, "seed": 0}}
        t0 = time.monotonic()
        try:
            data = _get("/api/chat", payload, timeout=self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            event = {"http": None, "loi": str(e)[:300], "giay": round(time.monotonic() - t0, 1)}
            self.calls.append(event)
            record(event)
            raise providers.TransportError(f"Ollama cục bộ lỗi: {e}") from e
        ns = lambda k: round((data.get(k) or 0) / 1e9, 1)
        event = {"stop_reason": data.get("done_reason"), "input_tokens": data.get("prompt_eval_count"),
                 "output_tokens": data.get("eval_count"), "max_tokens": self.max_output_tokens,
                 "giay": round(time.monotonic() - t0, 1), "giay_doc_prompt": ns("prompt_eval_duration"),
                 "giay_sinh": ns("eval_duration")}
        self.calls.append(event)
        record(event)
        if (data.get("prompt_eval_count") or 0) >= self.num_ctx - 32:
            raise providers.BadOutputError("prompt chạm num_ctx; có thể đã bị cắt, không dùng kết quả")
        if data.get("done_reason") == "length":
            raise providers.BadOutputError("hết num_predict trước khi xong JSON")
        return providers._parse_json(data["message"]["content"])


def _sha(path: Path) -> str:
    return integrity.sha256_file(path)


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _write(path: Path, data) -> None:
    path.write_bytes(json.dumps(data, ensure_ascii=False, indent=2, default=str).encode("utf-8"))


def _totals(calls: list[dict]) -> dict:
    ok = [c for c in calls if c.get("input_tokens") is not None]
    return {"loi_goi": len(calls), "loi_goi_loi_mang": len(calls) - len(ok),
            "input_tokens": sum(c["input_tokens"] or 0 for c in ok),
            "output_tokens": sum(c["output_tokens"] or 0 for c in ok),
            "giay": round(sum(c.get("giay") or 0 for c in calls), 1)}


def run_khau2(llm: LocalOllama, phien_ban: str, out: Path, root: Path) -> dict:
    from cti_hunt.attack.catalog import AttackCatalog
    from cti_hunt.cli import dev_ttp_config
    from cti_hunt.eval import proc_examples as D
    from cti_hunt.stages import s2_ttp, s2_v2
    cfg2 = config.load("llm_v2", root)
    options, dev, manifest = s2_v2.build(cfg2)
    items = [i for i in dev if i["tap"] == "chinh"][:20]
    cfg = dev_ttp_config(phien_ban, cfg2)
    v2 = options if phien_ban == "v2" else None
    prompt = s2_ttp.load_prompt(config.resolve(cfg["prompt_file"], root))
    segments, batch = D.dev_segments(items), int(cfg2["dev_batch_size"])
    sonnet = root / SONNET_KHAU2[phien_ban]
    smeta = json.loads((sonnet / "meta.json").read_text(encoding="utf-8"))
    if (smeta["prompt_sha256"], smeta["so_cau"], smeta["tap_phat_trien"]) != (prompt["sha256"], 20, manifest):
        raise ValueError("lượt Sonnet đối chứng khác prompt/số câu/tập phát triển; không so được")
    catalog = AttackCatalog.from_stix(config.resolve(config.load("reports", root)["attack"]["stix_path"], root))
    out.mkdir(parents=True)
    meta = {"kind": "pilot_llm_cuc_bo_khau2", "phien_ban": phien_ban, "so_cau": len(items), "lo": batch,
            "prompt": prompt["path"], "prompt_sha256": prompt["sha256"], "mo_hinh": llm.describe(),
            "doi_chung_sonnet": str(sonnet), "tap_phat_trien": manifest, "v2": v2.describe() if v2 else None,
            "bat_dau_utc": datetime.now(timezone.utc).isoformat()}
    _write(out / "meta.json", meta)
    ttps, log = s2_ttp.extract_report("DEV", segments, llm, catalog, prompt, batch, out, v2=v2)
    score = D.score_dev(items, segments, ttps)
    ours = [r for r in _jsonl(out / "requests.jsonl") if "user" in r and "segment_ids" in r]
    theirs = [r for r in _jsonl(sonnet / "requests.jsonl") if "user" in r and "segment_ids" in r]
    same_input = len(ours) == len(theirs) and all((a["segment_ids"], a["user"]) == (b["segment_ids"], b["user"])
                                                  for a, b in zip(ours, theirs))
    sscore = json.loads((sonnet / "ket_qua.json").read_text(encoding="utf-8"))["diem"]
    sonnet_ok = {r["id"]: r["dung_ma"] for r in sscore["theo_cau"]}
    local_ok = {r["id"]: r["dung_ma"] for r in score["theo_cau"]}
    compare = {"ca_hai_dung": sum(local_ok[i] and sonnet_ok[i] for i in local_ok),
               "chi_cuc_bo_dung": sum(local_ok[i] and not sonnet_ok[i] for i in local_ok),
               "chi_sonnet_dung": sum(sonnet_ok[i] and not local_ok[i] for i in local_ok),
               "ca_hai_sai": sum(not local_ok[i] and not sonnet_ok[i] for i in local_ok)}
    result = {"diem": score, "diem_sonnet": {k: sscore[k] for k in ("tat_ca", "khong_link_ma")},
              "so_sanh_theo_cau": compare, "dau_vao_trung_byte_voi_sonnet": same_input,
              "su_co": {"lo_that_bai": log["su_co"]["lo_that_bai"], "lo_goi_lai": log["su_co"]["lo_goi_lai"],
                        "kiem_that_bai": log["su_co"].get("kiem_that_bai", [])},
              "loi_goi": llm.calls, "tong": _totals(llm.calls), "ket_thuc_utc": datetime.now(timezone.utc).isoformat()}
    _write(out / "ket_qua.json", {"log": log, **result})
    if not same_input:
        raise ValueError("đầu vào ② khác lượt Sonnet đối chứng; không dùng số so sánh")
    return result


def run_khau5(llm: LocalOllama, out: Path, root: Path) -> dict:
    from cti_hunt.adapters import duckdb_sigma
    from cti_hunt.agent.session import check_dataset
    from cti_hunt.data.store import connect
    from cti_hunt.eval import exec_accuracy as ea
    from cti_hunt.llm.prompting import load_sections
    from cti_hunt.stages import s5_rule
    cfg = config.agent_config("v1", root)
    if cfg["prompt_khau5"] != KHAU5_PROMPT:
        raise ValueError("prompt ⑤ của cấu hình v1 không còn là bản Sonnet đã dùng")
    prompt_sha = _sha(root / KHAU5_PROMPT)
    prompt = load_sections(root / KHAU5_PROMPT, ("SYSTEM", "USER", "REPAIR"))
    catalog = duckdb_sigma.load_catalog(config.resolve(config.load("dataset", root)["logsource_catalog"], root))
    max_repair = int(cfg["max_repair_attempts"])
    out.mkdir(parents=True)
    _write(out / "meta.json", {"kind": "pilot_llm_cuc_bo_khau5", "prompt": KHAU5_PROMPT, "prompt_sha256": prompt_sha,
                               "max_repair_attempts": max_repair, "mo_hinh": llm.describe(), "vong": KHAU5_ROUNDS,
                               "bat_dau_utc": datetime.now(timezone.utc).isoformat()})
    rows = []
    for rel in KHAU5_ROUNDS:
        rd = root / rel
        meta = json.loads((rd.parent / "run_meta.json").read_text(encoding="utf-8"))
        events = Path(meta["events"]["dir"])
        check_dataset(events, root)
        if (meta["tep"].get(KHAU5_PROMPT) != prompt_sha
                or _sha(events / "events.parquet") != meta["events"]["parquet_sha256"]):
            raise ValueError(f"{rel}: prompt ⑤ hoặc parquet khác lượt Sonnet; không so được")
        approval.verify_saved_review(rd)
        baseline = {r["hypothesis_id"]: r for r in
                    json.loads((rd / "agent_execute.json").read_text(encoding="utf-8")).get("rules", [])}
        con = connect(events)
        try:
            columns = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
            for h in [h for h in approval.load_hypotheses(rd / approval.APPROVED_FILE) if h.status == "approved"]:
                tag = f"{rd.parent.name}__{rd.name}__{h.hypothesis_id}"
                before = len(llm.calls)
                res = s5_rule.generate_rule(h, llm, prompt, catalog, max_repair, columns, con, out / tag)
                sonnet_text = (rd / "rules" / f"{h.hypothesis_id}.yml").read_text(encoding="utf-8")
                s_errors, s_specs = s5_rule.validate_rule(sonnet_text, h, catalog, columns, con)
                comparisons = []
                for spec in res.get("hunt_specs") or []:
                    ref = next((s for s in s_specs if ea.same_scope(s, spec)), None)
                    if ref is None:
                        comparisons.append({"sinh": spec["id"], "so_duoc": False, "ly_do": "rule Sonnet không có hunt cùng phạm vi"})
                        continue
                    r = ea.evaluate(con, ref, spec)
                    comparisons.append({"sinh": spec["id"], "chuan_sonnet": ref["id"], "so_duoc": r["so_duoc"],
                                        "giai_doan": {st: {k: c[k] for k in ("chuan", "sinh", "chung", "jaccard")}
                                                      for st, c in r.get("giai_doan", {}).items()}})
                rows.append({"vong": rel, "hypothesis_id": h.hypothesis_id, "dataset": meta["dataset"]["id"],
                             "nguon": h.evidence.data_source, "event_ids": h.evidence.event_ids,
                             "cuc_bo": {k: res.get(k) for k in ("hop_le", "hop_le_lan_dau", "so_lan_sua")}
                                       | {"bo_qua": bool(res["lan_thu"]) and res["lan_thu"][0].get("loai") == "bo_qua",
                                          "loi_cuoi": [str(x)[:200] for x in (res["lan_thu"][-1].get("loi") or [])][:5]},
                             "sonnet": {"hop_le": baseline.get(h.hypothesis_id, {}).get("hop_le"),
                                        "so_lan_sua": baseline.get(h.hypothesis_id, {}).get("so_lan_sua"),
                                        "kiem_tinh_lai_hien_tai": not s_errors},
                             "so_sanh_su_kien": comparisons, "loi_goi": llm.calls[before:]})
                _write(out / "tung_gia_thuyet.json", rows)
        finally:
            con.close()
    summary = {"so_gia_thuyet": len(rows),
               "cuc_bo_hop_le": sum(bool(r["cuc_bo"]["hop_le"]) for r in rows),
               "cuc_bo_hop_le_lan_dau": sum(bool(r["cuc_bo"]["hop_le_lan_dau"]) for r in rows),
               "cuc_bo_bo_qua": sum(r["cuc_bo"]["bo_qua"] for r in rows),
               "sonnet_hop_le": sum(bool(r["sonnet"]["hop_le"]) for r in rows),
               "so_duoc_voi_sonnet": sum(any(c["so_duoc"] for c in r["so_sanh_su_kien"]) for r in rows),
               "trung_hoan_toan_ung_vien": sum(any(c.get("giai_doan", {}).get("ung_vien", {}).get("jaccard") == 1
                                                   for c in r["so_sanh_su_kien"]) for r in rows),
               "trung_hoan_toan_cuoi": sum(any(c.get("giai_doan", {}).get("cuoi", {}).get("jaccard") == 1
                                              for c in r["so_sanh_su_kien"]) for r in rows),
               "tong": _totals(llm.calls), "ket_thuc_utc": datetime.now(timezone.utc).isoformat()}
    _write(out / "ket_qua.json", {"tom_tat": summary, "tung_gia_thuyet": rows})
    return summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("khau", choices=("khau2", "khau5"))
    p.add_argument("--model", required=True, help="tên mô hình Ollama đã tải cục bộ, vd qwen2.5:7b-instruct")
    p.add_argument("--phien-ban", choices=("v1", "v2"), default="v1", help="chỉ cho khau2")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--num-ctx", type=int, default=16384)
    p.add_argument("--num-predict", type=int, default=8192)
    p.add_argument("--timeout", type=int, default=3600, help="giây chờ tối đa mỗi lời gọi (CPU chậm)")
    a = p.parse_args(argv)
    root, out = config.ROOT.resolve(), a.out.resolve()
    if not out.is_relative_to(root / "data/dev") or out == root / "data/dev" or out.exists():
        raise SystemExit("cần thư mục mới trong data/dev; không ghi đè")
    pinned = {k: _sha(root / k) for k in PINNED}
    try:
        with guard():
            info = model_info(a.model)
            llm = LocalOllama(a.model, a.num_ctx, a.num_predict, a.timeout)
            started = time.monotonic()
            result = (run_khau2(llm, a.phien_ban, out, root) if a.khau == "khau2" else run_khau5(llm, out, root))
    finally:
        if {k: _sha(root / k) for k in PINNED} != pinned:
            raise SystemExit("cấu hình/prompt/sổ ngân sách đổi trong lúc pilot")
    _write(out / "moi_truong.json", {"mo_hinh_ollama": info, "git_commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root).decode().strip(), "api_claude": 0, "ket_noi_ngoai_may": "chặn",
        "hash_ghim_khong_doi": pinned, "tong_giay": round(time.monotonic() - started, 1)})
    print(json.dumps({k: v for k, v in result.items() if k not in ("loi_goi", "su_co")}, ensure_ascii=False,
                     indent=2, default=str)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
