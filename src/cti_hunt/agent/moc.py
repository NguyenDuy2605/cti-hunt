"""Mốc cố định trước khi chạy graph D10 trên tập đánh giá APT29 day 2 (E1; v3.2 §3.3–3.4, §8.1 tuần 4–5).

người vận hành chạy `agent freeze` khi đã chốt thời điểm cố định; mã không tự tạo mốc. Theo bản ghi E1, mốc lưu: SHA256 của cấu
hình và prompt mà chế độ đó dùng, phiên bản mã (commit và cây `src/`), mô hình, danh sách dữ liệu phát triển.

`agent start --dataset-kind danh_gia` chỉ chạy khi trạng thái hiện tại khớp đúng mốc mới nhất của chế độ đó, và mốc
đã được commit (bản ghi nằm trong lịch sử git). Đổi sau mốc thì tạo mốc phiên bản mới (`<mode>_v<N+1>.json`), mốc cũ
giữ nguyên; kết quả của phiên bản mới báo riêng.

Chế độ agent được so với chế độ pipeline trên cùng graph, công cụ, rào chắn và trần (v3.2 §4.1, §6.4): mốc agent phải
trùng mốc pipeline mới nhất ở mọi tệp dùng chung và ở cây mã `src/`.
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

from .. import config, integrity

MOC_DIR = "configs/moc_co_dinh"
MODES = ("pipeline", "agent")
PIPELINE_CONFIGS = ("configs/agent.yaml", "configs/llm_hunt.yaml")
PIPELINE_PROMPTS = ("prompt_khau4", "prompt_khau4_pivot", "prompt_khau5")
AGENT_CONFIGS = ("configs/agent_planner.yaml",)
AGENT_PROMPTS = ("prompt_agent_plan",)
WATCHED = ("src", "configs", "prompts")         # phải sạch (đã commit) khi tạo mốc và khi chạy trên tập đánh giá


class MilestoneError(ValueError):
    pass


def catalog_files(root: Path = config.ROOT, version: str = "v1") -> list[str]:
    """Danh mục ③ và ⑤ đang dùng, theo con trỏ trong configs/dataset.yaml (N2 §4: tuyến A giữ danh mục 18 mục,
    tuyến B trỏ sang v2). Con trỏ ③ tách theo phiên bản (config.telemetry_catalog); danh mục ⑤ dùng chung.
    Đổi con trỏ là đổi tên tệp trong mốc và run_meta, nên mốc/lượt cũ không còn khớp."""
    base = Path(root).resolve()
    paths = [config.telemetry_catalog(version, base), config.resolve(config.load("dataset", base)["logsource_catalog"], base)]
    return [p.resolve().relative_to(base).as_posix() for p in paths]


def files_for(mode: str, root: Path = config.ROOT, *, version: str = "v1") -> dict[str, str]:
    """SHA256 của cấu hình và prompt mà chế độ này phụ thuộc."""
    if mode not in MODES:
        raise MilestoneError(f"chế độ phải là {' | '.join(MODES)}")
    cfg = config.agent_config(version, root)
    paths = list(PIPELINE_CONFIGS) + catalog_files(root, version) + [cfg[k] for k in PIPELINE_PROMPTS]
    if version == "v2":
        paths = [p for p in paths if p != "configs/agent.yaml"] + ["configs/agent_v2.yaml", cfg["filter_policy"]]
    if mode == "agent":
        paths += list(AGENT_CONFIGS) + [cfg[k] for k in AGENT_PROMPTS]
    return {p: integrity.sha256_file(config.resolve(p, root)) for p in paths}


def code_state(root: Path = config.ROOT) -> dict:
    """Commit, cây `src/` ở HEAD và danh sách thay đổi chưa commit trong src/, configs/, prompts/."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout
    try:
        return {"commit": git("rev-parse", "HEAD").strip(), "src_tree": git("rev-parse", "HEAD:src").strip(),
                "chua_commit": [line[3:].strip() for line in git("status", "--porcelain", "--", *WATCHED).splitlines()
                                if line.strip()]}
    except (OSError, subprocess.CalledProcessError) as e:
        raise MilestoneError(f"không đọc được trạng thái git của {root}: mốc cố định cần repo git") from e


def _models(mode: str, root: Path) -> dict:
    llm = config.load("llm_hunt", root)
    out = {"khau4_5": {"model": llm.get("model"), "effort": llm.get("effort")}}
    if mode == "agent":
        planner = config.load("agent_planner", root)
        out["planner"] = {"model": planner.get("model"), "effort": planner.get("effort")}
    return out


def _dev_data(dirs: list[Path]) -> list[dict]:
    out = []
    for d in dirs:
        path = Path(d) / "ingest_manifest.json"
        m = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if m.get("dataset_kind") != "otrf_dev":
            raise MilestoneError(f"{d}: không phải bộ OTRF phát triển do `ingest-dev` nạp")
        out.append({"id": m["dataset_id"], "source_sha256": m["source_sha256"], "rows": m.get("rows")})
    return out


def _versions(mode: str, root: Path, version: str = "v1") -> list[tuple[int, Path]]:
    if version not in ("v1", "v2"):
        raise MilestoneError("phiên bản phải là v1 hoặc v2")
    d = config.resolve(MOC_DIR + ("/v2" if version == "v2" else ""), root)
    found = []
    for p in d.glob(f"{mode}_v*.json") if d.exists() else []:
        m = re.fullmatch(rf"{mode}_v(\d+)\.json", p.name)
        if m:
            found.append((int(m.group(1)), p))
    return sorted(found)


def latest(mode: str, root: Path = config.ROOT, *, version: str = "v1") -> tuple[Path | None, dict | None]:
    found = _versions(mode, root, version)
    if not found:
        return None, None
    path = found[-1][1]
    return path, json.loads(path.read_text(encoding="utf-8"))


def _diff(frozen: dict[str, str], now: dict[str, str]) -> list[str]:
    return sorted(k for k in set(frozen) | set(now) if frozen.get(k) != now.get(k))


def create(mode: str, nguoi_chot: str, dev_dirs: list[Path] | None = None, root: Path = config.ROOT, *, version: str = "v1") -> Path:
    if not str(nguoi_chot or "").strip():
        raise MilestoneError("thiếu người chốt mốc")
    files = files_for(mode, root, version=version)
    code = code_state(root)
    if code["chua_commit"]:
        raise MilestoneError("mốc phải là phiên bản đã commit; còn thay đổi chưa commit: "
                             + ", ".join(code["chua_commit"]))
    dev = _dev_data(list(dev_dirs or []))
    if mode == "agent":
        if not dev:
            raise MilestoneError("E1: mốc chế độ agent phải ghi danh sách dữ liệu OTRF phát triển (--dev-data)")
        _, pipe = latest("pipeline", root, version=version)
        if pipe is None:
            raise MilestoneError("chưa có mốc chế độ pipeline: agent được so với pipeline trên cùng công cụ và trần")
        shared = {k: v for k, v in files.items() if k in pipe["tep"]}
        changed = _diff(pipe["tep"], shared)
        if pipe["ma_nguon"]["src_tree"] != code["src_tree"]:
            changed.append("src/")
        if changed:
            raise MilestoneError("mốc agent phải trùng mốc pipeline mới nhất ở tệp dùng chung và mã nguồn; khác: "
                                 + ", ".join(changed) + ". Tạo mốc pipeline mới (và chạy lại pipeline) trước.")
    serial = (_versions(mode, root, version)[-1][0] + 1) if _versions(mode, root, version) else 1
    manifest = {"che_do": mode, "phien_ban": serial, "nguoi_chot": nguoi_chot.strip(),
                "thoi_diem": datetime.now().isoformat(timespec="seconds"),
                "tep": files, "ma_nguon": {"commit": code["commit"], "src_tree": code["src_tree"]},
                "mo_hinh": _models(mode, root), "du_lieu_phat_trien": dev}
    if version == "v2":
        manifest["filter_policy"] = config.agent_config(version, root)["filter_policy_id"]
    out = config.resolve(MOC_DIR + ("/v2" if version == "v2" else ""), root) / f"{mode}_v{serial}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return out


def verify(mode: str, root: Path = config.ROOT, *, version: str = "v1") -> dict:
    """Trạng thái hiện tại khớp mốc mới nhất của chế độ này; trả tham chiếu mốc để ghi vào run_meta."""
    path, manifest = latest(mode, root, version=version)
    if manifest is None:
        raise MilestoneError(f"E1: chưa có mốc cố định cho chế độ {mode} — chưa chạy graph trên APT29 day 2 "
                             "(người vận hành chạy `agent freeze` khi chốt thời điểm)")
    code = code_state(root)
    if code["chua_commit"]:
        raise MilestoneError("E1: còn thay đổi chưa commit trong src/, configs/, prompts/ (kể cả tệp mốc): "
                             + ", ".join(code["chua_commit"]))
    changed = _diff(manifest["tep"], files_for(mode, root, version=version))
    if manifest["ma_nguon"]["src_tree"] != code["src_tree"]:
        changed.append("src/")
    if changed:
        raise MilestoneError(f"E1: khác mốc {path.name}: " + ", ".join(changed)
                             + ". Muốn dùng phiên bản mới thì tạo mốc mới và báo kết quả riêng.")
    return {"tep": path.relative_to(Path(root)).as_posix(), "sha256": integrity.sha256_file(path),
            "phien_ban": manifest["phien_ban"]}
