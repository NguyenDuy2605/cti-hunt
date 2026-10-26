"""Chạy graph D10 từ dòng lệnh: bắt đầu một lượt, dừng ở phiếu ◆, tiếp tục sau khi duyệt.

Một lượt = một thư mục + một thread_id + một checkpoint SQLite (E2). Lúc bắt đầu ghi `run_meta.json`: chế độ, dữ
liệu, SHA256 của Contract A, events.parquet, cấu hình, prompt và commit mã (E1). Lúc tiếp tục kiểm lại các hash đó:
đổi giữa chừng thì từ chối, vì một lượt phải chạy trọn trên một phiên bản.

Hồ sơ bộ dữ liệu của khâu ③: lập từ events của chính bộ đang chạy, ghi `ho_so_du_lieu.json`
trong thư mục lượt, SHA256 và số sự kiện từng kênh vào run_meta. Resume lập lại hồ sơ và từ chối nếu khác.

E1: graph chỉ chạy trên APT29 day 2 với `--dataset-kind danh_gia`, và chỉ khi trạng thái hiện tại khớp mốc cố định
mới nhất của chế độ đó (`agent/moc.py`, người vận hành tạo bằng `agent freeze`). Ngoài đường đó, mã chặn thư mục dữ liệu làm
việc của tập đánh giá và mọi events.parquet nạp từ tệp nguồn của nó. Bộ `otrf_dev` phải do lệnh `ingest-dev` nạp
(`agent/dev_data.py`), đúng mã và SHA256 khai báo.
"""
from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import yaml

from .. import approval, config, integrity
from ..contracts import ContractA
from ..llm import providers
from ..llm.prompting import load_sections
from ..stages import s3_telemetry
from . import moc

META_FILE, CHECKPOINT_FILE = "run_meta.json", "checkpoint.sqlite"
MODES = ("pipeline", "agent")
EVAL_DATASET_ID = "apt29_day2"
CONFIG_FILES = ("configs/agent.yaml", "configs/agent_planner.yaml", "configs/llm_hunt.yaml")
PROMPT_KEYS = ("prompt_khau4", "prompt_khau4_pivot", "prompt_khau5", "prompt_agent_plan")


class SessionError(ValueError):
    pass


def tracked_files(root: Path = config.ROOT, version: str = "v1") -> dict[str, str]:
    """SHA256 của cấu hình và prompt mà một lượt phụ thuộc — cố định suốt lượt (E2)."""
    cfg = config.agent_config(version, root)
    paths = list(CONFIG_FILES) + moc.catalog_files(root, version) + [cfg[k] for k in PROMPT_KEYS]
    if version == "v2":
        paths = [p for p in paths if p != "configs/agent.yaml"] + ["configs/agent_v2.yaml", cfg["filter_policy"]]
    paths += [p.relative_to(root).as_posix() for p in sorted((root / "src/cti_hunt").rglob("*.py"))]
    return {p: integrity.sha256_file(config.resolve(p, root)) for p in paths}


def hunt_memory(root: Path = config.ROOT, version: str = "v1") -> dict:
    """Kho hunt memory mà planner đọc được lúc này (N5): đường dẫn cấu hình và mã các record. Ghi vào run_meta của
    lượt agent để kiểm được lượt nào thấy memory gì; resume từ chối nếu kho đổi giữa lượt (E2)."""
    from ..record_store import RecordStore
    rel = config.agent_config(version, root).get("memory_root", "data/reports/moi")
    return {"root": rel, "records": sorted(r["record_id"] for r in RecordStore(config.resolve(rel, root)).find())}


def git_state(root: Path = config.ROOT) -> dict:
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    try:
        return {"commit": git("rev-parse", "HEAD"), "co_thay_doi_chua_commit": bool(git("status", "--porcelain"))}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "co_thay_doi_chua_commit": None}


def is_eval_dataset(events_dir: Path, root: Path = config.ROOT) -> bool:
    """Thư mục làm việc của tập đánh giá, hoặc bất kỳ events.parquet nào nạp từ tệp nguồn APT29 day 2."""
    ds = config.load("dataset", root)
    d = Path(events_dir).resolve()
    if d == config.resolve(ds["work_dir"], root).resolve():
        return True
    manifest = d / "ingest_manifest.json"
    if manifest.exists():
        src = str(json.loads(manifest.read_text(encoding="utf-8")).get("source") or "")
        raw = config.resolve(ds["raw"]["path"], root)
        return bool(src) and (Path(src).name.lower() == raw.name.lower() or Path(src).resolve() == raw.resolve())
    return False


def check_dataset(events_dir: Path, root: Path = config.ROOT) -> None:
    """E1: ngoài `--dataset-kind danh_gia` (có mốc cố định), graph chỉ chạy trên fixture/OTRF phát triển."""
    if is_eval_dataset(events_dir, root):
        raise SessionError("E1: dữ liệu APT29 day 2 chỉ chạy bằng --dataset-kind danh_gia, sau mốc cố định "
                           "(`agent freeze`) của đúng chế độ đó")
    d = Path(events_dir).resolve()
    if not (d / "events.parquet").exists():
        raise SessionError(f"Không có {d / 'events.parquet'}")


def _build(meta: dict, run_dir: Path, root: Path):
    """Công cụ của graph trên danh mục ③ hiệu lực (danh mục chung + hồ sơ của bộ dữ liệu). Trả thêm hồ sơ."""
    if meta.get('runner'):
        raise SessionError('Lượt có runner riêng; dùng script đã ghim của gói, không agent resume/start thường')
    from ..adapters import duckdb_sigma
    from ..attack.catalog import AttackCatalog
    from ..data.store import connect
    from .graph import PipelinePlanner, configured_planner
    from .stage_tools import StageTools

    version = meta.get("phien_ban", "v1")
    ds, cfg = config.load("dataset", root), config.agent_config(version, root)
    ca = ContractA.model_validate_json(Path(meta["contract_a"]["path"]).read_text(encoding="utf-8"))
    stix = config.resolve(config.load("reports", root)["attack"]["stix_path"], root)
    llm_cfg = config.load("llm_hunt", root)
    if llm_cfg.get("budget_ledger"):
        llm_cfg["budget_ledger"] = str(config.resolve(llm_cfg["budget_ledger"], root))
    con = connect(Path(meta["events"]["dir"]))
    catalog = s3_telemetry.load_catalog(config.telemetry_catalog(version, root))
    profile = s3_telemetry.build_profile(con, catalog, meta["dataset"]["id"])
    tools = StageTools(
        ca, s3_telemetry.apply_profile(catalog, profile),
        duckdb_sigma.load_catalog(config.resolve(ds["logsource_catalog"], root)),
        con, cfg,
        providers.from_config(llm_cfg), providers.from_config(llm_cfg),
        load_sections(config.resolve(cfg["prompt_khau4"], root)),
        load_sections(config.resolve(cfg["prompt_khau4_pivot"], root)),
        load_sections(config.resolve(cfg["prompt_khau5"], root), ("SYSTEM", "USER", "REPAIR")),
        run_dir, dataset_kind=meta["dataset"]["kind"], dataset_id=meta["dataset"]["id"],
        dataset_sha256=meta["dataset"]["sha256"],
        attack_catalog=AttackCatalog.from_stix(stix) if stix.exists() else None,
        filter_dependencies=[config.resolve(p, root) for p in meta["tep"]] + [Path(meta["contract_a"]["path"])]
        if version == "v2" else ())
    planner = PipelinePlanner() if meta["mode"] == "pipeline" else configured_planner(
        run_dir, root=root, **({"version": version} if version == "v2" else {}))
    return planner, tools, cfg, profile


@contextmanager
def _graph(built, run_dir: Path):
    from .graph import open_sqlite_graph
    planner, tools, cfg, _ = built
    try:
        with open_sqlite_graph(planner, tools, cfg, run_dir, run_dir / CHECKPOINT_FILE) as graph:
            yield graph, tools
    finally:
        tools.con.close()


def _thread(meta: dict) -> dict:
    return {"configurable": {"thread_id": meta["thread_id"]}}


def _summary(out: dict, run_dir: Path) -> dict:
    if "__interrupt__" in out:
        value = out["__interrupt__"][0].value
        result = {"trang_thai": "cho_duyet", "review_dir": value["review_dir"]}
        if value.get("review_kind"):
            result["review_kind"] = value["review_kind"]
        return result
    return {"trang_thai": "xong", "record": out["record"], "hunt_record": str(run_dir / "hunt_record.md")}


def start(mode: str, contract_a: Path, events_dir: Path, run_dir: Path, *, dataset_kind: str, dataset_id: str = "",
          dataset_sha256: str = "", root: Path = config.ROOT, dry_run: bool = False, version: str = "v1") -> dict:
    if mode not in MODES:
        raise SessionError(f"chế độ phải là {' | '.join(MODES)}")
    config.agent_config(version, root)
    run_dir = Path(run_dir)
    if run_dir.exists() and any(run_dir.iterdir()):
        raise SessionError(f"{run_dir} đã có nội dung — mỗi lượt một thư mục mới (E2)")
    milestone = None
    if dataset_kind == "danh_gia":
        if not is_eval_dataset(events_dir, root) or not (Path(events_dir) / "events.parquet").exists():
            raise SessionError("--dataset-kind danh_gia chỉ dùng cho events.parquet của APT29 day 2 (data/work)")
        milestone = moc.verify(mode, root, version=version) if version == "v2" else moc.verify(mode, root)
        dataset_id, dataset_sha256 = EVAL_DATASET_ID, str(config.load("dataset", root)["raw"]["sha256"]).lower()
    else:
        check_dataset(events_dir, root)
        if dataset_kind == "otrf_dev":
            from .dev_data import check_manifest
            check_manifest(Path(events_dir), dataset_id, dataset_sha256, root)
    contract_a = Path(contract_a).resolve()
    report_id = ContractA.model_validate_json(contract_a.read_text(encoding="utf-8")).report_id
    events_dir = Path(events_dir).resolve()
    meta = {"mode": mode, "thread_id": f"{report_id}-{mode}-{datetime.now():%Y%m%d-%H%M%S}",
            "bat_dau": datetime.now().isoformat(timespec="seconds"),
            "contract_a": {"path": str(contract_a), "sha256": integrity.sha256_file(contract_a)},
            "events": {"dir": str(events_dir), "parquet_sha256": integrity.sha256_file(events_dir / "events.parquet")},
            "dataset": {"kind": dataset_kind, "id": dataset_id, "sha256": dataset_sha256},
            "tep": tracked_files(root, version) if version == "v2" else tracked_files(root),
            "git": git_state(root), "moc_co_dinh": milestone}
    if version == "v2":
        meta["phien_ban"] = "v2"
    if mode == "agent":
        meta["hunt_memory"] = hunt_memory(root, version) if version == "v2" else hunt_memory(root)
    built = _build(meta, run_dir, root)     # lỗi E1/cấu hình dừng ở đây, trước khi tạo thư mục lượt
    profile = built[3]
    if dry_run:
        planner, tools, _, _ = built
        try:
            state = tools.initial_state()
            return {"trang_thai": "dry_run", "goi_api": False, "mode": mode, "report_id": report_id,
                    "dataset": meta["dataset"], "so_ttp_vao_khau4": len(state["remaining_refs"]),
                    "so_ttp_not_huntable": len(tools.ca.ttps) - len(state["remaining_refs"]),
                    "khau4": tools.llm_hypotheses.describe(), "khau5": tools.llm_rules.describe(),
                    "planner": planner.metadata(), "tep": meta["tep"],
                    "hunt_memory": meta.get("hunt_memory")}
        finally:
            tools.con.close()
    # Chưa đặt hạn mức hoặc có yêu cầu chưa rõ chi phí: dừng trước khi tạo lượt/checkpoint.
    try:
        _ledgers_ready(built)
    except BaseException:
        built[1].con.close()
        raise
    run_dir.mkdir(parents=True, exist_ok=True)
    _, sha = s3_telemetry.write_profile(profile, run_dir)
    meta["ho_so"] = {"tep": s3_telemetry.PROFILE_FILE, "sha256": sha, "dataset_id": profile["dataset_id"],
                     "kenh": profile["kenh"]}
    (run_dir / META_FILE).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    with _graph(built, run_dir) as (graph, tools):
        return _summary(graph.invoke(tools.initial_state(), _thread(meta)), run_dir)


def _ledgers_ready(built) -> None:
    """Sổ của mọi client có gọi API đã đặt hạn mức và không còn yêu cầu chưa rõ chi phí (không gọi mạng)."""
    from ..llm.budget import Ledger
    for client in (built[1].llm_hypotheses, built[1].llm_rules, getattr(built[0], "llm", None)):
        if getattr(client, "budget_ledger", None):
            Ledger(client.budget_ledger).require_ready()


def _pending(snap) -> tuple[str, ...]:
    """Node đang chờ của checkpoint. Khi một node lỗi sau lúc tiếp tục từ interrupt (vd lỗi trong cổng lọc), LangGraph trả
    `next` rỗng dù tác vụ còn giữ interrupt chưa xong; coi tác vụ ấy là node đang chờ để lượt vẫn ở cổng và resume chạy
    lại đúng node đó (kiểm thật 10/10: lượt kẹt vì phiên tưởng lượt chưa bắt đầu)."""
    return tuple(snap.next or ()) or tuple(t.name for t in snap.tasks if getattr(t, "interrupts", ()))


def _interruption(meta: dict, snap) -> dict:
    """R2 (09/10): lượt dừng NGOÀI cổng duyệt — lỗi đã ghi trong checkpoint và có phục hồi được không.

    Chỉ phục hồi khi mọi lỗi là TransportError (yêu cầu không nhận được phản hồi) và node đang dở là `plan`: planner
    chỉ ghi thêm dòng vào `agent_plan_requests.jsonl`, chạy lại không đè tệp nào. Các node khác đã ghi một phần tệp của
    vòng (④ tạo thư mục vòng trước lời gọi, rào chống ghi đè sẽ chặn). Lỗi rào chặn (AgentGuardError) hay lỗi khác:
    gọi lại là để mô hình quyết định lại, không làm. Không có lỗi ghi lại (tiến trình bị tắt giữa chừng): lời gọi có
    thể đã chạy xong mà chưa kịp ghi, không tự phục hồi. Lượt đánh giá theo quy tắc sự cố: thay lượt mới."""
    errors = [t.error for t in snap.tasks if getattr(t, "error", None)]
    labels = [e if isinstance(e, str) else repr(e) for e in errors]
    record_hint = "dựng record bằng scripts/ghi_record_luot_ngat.py"
    nodes = sorted(_pending(snap))
    if meta["dataset"]["kind"] == "danh_gia":
        why = f"Lượt đánh giá bị ngắt không phục hồi: theo quy tắc sự cố thay bằng lượt mới; {record_hint}"
    elif not labels:
        why = ("Checkpoint không ghi lỗi (tiến trình có thể bị tắt giữa lời gọi); không tự phục hồi — kiểm chi phí "
               f"trên Console, {record_hint}")
    elif not all(label.startswith("TransportError(") for label in labels):
        why = f"Lỗi không phải lỗi mạng; không gọi lại để mô hình quyết định lại — {record_hint}"
    elif nodes != ["plan"]:
        why = (f"Lỗi mạng ở bước {', '.join(nodes)}: vòng đã ghi một phần tệp, chạy lại sẽ bị rào chống ghi đè; "
               f"{record_hint}")
    else:
        why = ""
    return {"loi": labels, "phuc_hoi_duoc": not why, "ly_do_khong_phuc_hoi": why}


def recover(run_dir: Path, root: Path = config.ROOT) -> dict:
    """R2 (09/10): tiếp tục lượt phát triển dừng ngoài cổng duyệt vì lỗi mạng, chạy lại đúng node đang dở (có thể gọi
    API). Giữ mọi kiểm của resume (E2: mã, cấu hình, dữ liệu, hồ sơ không đổi) và kiểm sổ: còn yêu cầu chưa rõ chi phí
    thì người vận hành đối soát trên Console trước."""
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / META_FILE).read_text(encoding="utf-8"))
    _check_unchanged(meta, root)
    built = _build(meta, run_dir, root)
    with _graph(built, run_dir) as (graph, _):
        _check_profile(meta, run_dir, built[3])
        snap = graph.get_state(_thread(meta))
        if not _pending(snap) or {"review", "review_filters"} & set(_pending(snap)):
            raise SessionError("Lượt không bị ngắt ngoài cổng duyệt; dùng agent resume (đang chờ phiếu) hoặc lượt đã xong")
        info = _interruption(meta, snap)
        if not info["phuc_hoi_duoc"]:
            raise SessionError(info["ly_do_khong_phuc_hoi"])
        _ledgers_ready(built)
        return _summary(graph.invoke(None, _thread(meta)), run_dir)


def _check_unchanged(meta: dict, root: Path) -> None:
    if meta.get('runner'):
        raise SessionError('Lượt có runner riêng; dùng script đã ghim của gói, không agent resume thường')
    version = meta.get("phien_ban", "v1")
    now = tracked_files(root, version) if version == "v2" else tracked_files(root)
    if ("configs/agent_v2.yaml" in meta["tep"]) != (version == "v2"):
        raise SessionError("phiên bản lượt và cấu hình ghim không khớp")
    changed = sorted(k for k in set(meta["tep"]) | set(now) if meta["tep"].get(k) != now.get(k))
    if integrity.sha256_file(Path(meta["contract_a"]["path"])) != meta["contract_a"]["sha256"]:
        changed.append("Contract A")
    if integrity.sha256_file(Path(meta["events"]["dir"]) / "events.parquet") != meta["events"]["parquet_sha256"]:
        changed.append("events.parquet")
    commit = git_state(root)["commit"]
    if meta["git"]["commit"] and commit and commit != meta["git"]["commit"]:
        changed.append(f"commit mã ({meta['git']['commit'][:8]} → {commit[:8]})")
    if meta.get("moc_co_dinh") and moc.verify(meta["mode"], root, version=version)["sha256"] != meta["moc_co_dinh"]["sha256"]:
        changed.append("mốc cố định")
    if "hunt_memory" in meta:
        memory = hunt_memory(root, version) if version == "v2" else hunt_memory(root)
        if memory != meta["hunt_memory"]:
            changed.append("kho hunt memory")
    if changed:
        raise SessionError("E2: một lượt phải chạy trọn trên một phiên bản; đã đổi sau khi bắt đầu: "
                           + ", ".join(changed) + ". Bắt đầu lượt mới ở thư mục khác.")


def _check_profile(meta: dict, run_dir: Path, profile: dict) -> None:
    """Hồ sơ lập lại lúc resume phải trùng hồ sơ lúc bắt đầu (SHA256 trong run_meta), và tệp hồ sơ chưa bị sửa."""
    saved = (meta.get("ho_so") or {}).get("sha256")
    path = run_dir / s3_telemetry.PROFILE_FILE
    changed = []
    if not saved:
        changed.append("run_meta không có SHA256 hồ sơ")
    else:
        if s3_telemetry.profile_sha256(profile) != saved:
            changed.append("hồ sơ lập lại từ events")
        if not path.exists() or integrity.sha256_file(path) != saved:
            changed.append(f"tệp {s3_telemetry.PROFILE_FILE}")
    if changed:
        raise SessionError("E2: hồ sơ bộ dữ liệu khác lúc bắt đầu lượt: " + ", ".join(changed)
                           + ". Bắt đầu lượt mới ở thư mục khác.")


def resume(run_dir: Path, root: Path = config.ROOT) -> dict:
    from langgraph.types import Command
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / META_FILE).read_text(encoding="utf-8"))
    _check_unchanged(meta, root)
    built = _build(meta, run_dir, root)
    with _graph(built, run_dir) as (graph, _):
        _check_profile(meta, run_dir, built[3])
        snap = graph.get_state(_thread(meta))
        if snap.values.get("record") and Path(snap.values["record"]).name == "cancellation.json":
            return _cancelled_review(Path(snap.values["record"]).parent, snap.values)
        if "review_filters" in _pending(snap):
            from .. import filter_approval as filters
            rd = Path(snap.values["filter_review_dir"])
            if (rd / filters.CANCEL).exists():
                stopped = _cancelled_review(rd, snap.values)
                graph.update_state(_thread(meta), {"record": str(rd / filters.CANCEL)}, as_node="record")
                return stopped
            filters.validate_form(rd, con=built[1].con)
            if filters.revision_requested(rd):
                filters.check_revision(rd, built[1].con)     # rút gọn không làm được: báo ngay, lượt vẫn ở cổng
            return _summary(graph.invoke(Command(resume=True), _thread(meta)), run_dir)
        if "review" not in _pending(snap):
            raise SessionError("Lượt này không dừng ở phiếu ◆ nào (đã xong hoặc chưa bắt đầu)")
        review_dir = Path(snap.values["review_dir"])
        form = yaml.safe_load((review_dir / approval.REVIEW_FILE).read_text(encoding="utf-8")) or {}
        blank = [str(g.get("id")) for g in form.get("gia_thuyet") or [] if not str(g.get("quyet_dinh") or "").strip()]
        if blank:
            # Mục trống thành pending_review, không vòng nào xét lại: chạy tiếp là bỏ giả thuyết mà không có lý do.
            raise SessionError(f"Phiếu {review_dir / approval.REVIEW_FILE} còn {len(blank)} giả thuyết chưa có quyết định "
                               f"({', '.join(blank)}) — điền approved, hoặc rejected kèm lý do, rồi chạy lại")
        return _summary(graph.invoke(Command(resume=True), _thread(meta)), run_dir)


def inspect(run_dir: Path, root: Path = config.ROOT) -> dict:
    """Read checkpoint without a model call or changing approval decisions."""
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / META_FILE).read_text(encoding="utf-8"))
    _check_unchanged(meta, root)
    built = _build(meta, run_dir, root)
    with _graph(built, run_dir) as (graph, _):
        _check_profile(meta, run_dir, built[3])
        snap = graph.get_state(_thread(meta))
        if snap.values.get("record") and Path(snap.values["record"]).name == "cancellation.json":
            return _cancelled_review(Path(snap.values["record"]).parent, snap.values)
        if "review_filters" in _pending(snap):
            review = Path(snap.values["filter_review_dir"]).resolve()
            if not review.is_relative_to(run_dir.resolve()):
                raise SessionError("Phiếu lọc ngoài thư mục lượt")
            from .. import filter_approval as filters
            if (review / filters.CANCEL).exists():
                return _cancelled_review(review, snap.values)
            return {"trang_thai": "cho_duyet", "review_kind": "filter", "review_dir": str(review)}
        if "review" in _pending(snap):
            review = Path(snap.values["review_dir"]).resolve()
            if not review.is_relative_to(run_dir.resolve()):
                raise SessionError("Phiếu ngoài thư mục lượt")
            return {"trang_thai": "cho_duyet", "review_dir": str(review),
                    **({"review_kind": "hypothesis"} if meta.get("phien_ban") == "v2" else {})}
        if _pending(snap):
            return {"trang_thai": "chua_hoan_tat", "pending_nodes": list(_pending(snap)),
                    "note": "Lượt bị ngắt ngoài cổng duyệt; kiểm lỗi và chi phí trước khi phục hồi",
                    **_interruption(meta, snap)}
        return {"trang_thai": "xong" if snap.values.get("record") else "chua_bat_dau",
                "record": snap.values.get("record")}


def _cancelled_review(rd: Path, state: dict) -> dict:
    from .. import filter_approval as filters
    record = filters._read(rd / filters.CANCEL)
    if record.get("manifest_sha256") != filters._sha(rd / filters.MANIFEST):
        raise SessionError("record hủy không khớp gói lọc")
    return {"trang_thai": "da_huy", "record": str(rd / filters.CANCEL),
            "note": "Dừng trước thực thi lô này; không phải kết quả 0 sự kiện",
            "executed_specs": state.get("executed_specs") or []}
