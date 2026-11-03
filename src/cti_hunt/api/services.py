"""Việc của 6 cửa API. Chỉ gọi lại các hàm hệ thống đã có (``demo``, ``s2_report``, ``s2_ioc_sweep``, ``community_rules``,
``RecordStore``); không có lời gọi LLM nào, không đọc nhãn sự kiện.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .. import config, demo, integrity
from ..contracts import ContractA
from ..stages import s1_ingest, s2_report

class Unavailable(RuntimeError):
    """Chức năng cần thư viện tùy chọn chưa cài (API trả 503)."""


EMBED_MISSING = "Chế độ lai cần nhóm cài [embed] (numpy, sentence-transformers); bản này chỉ có bm25"


def embed_available() -> bool:
    """Có đủ thư viện cho chế độ lai không; kiểm trước khi nhập module embedding (module này nhập numpy ngay đầu tệp)."""
    import importlib.util
    return all(importlib.util.find_spec(m) is not None for m in ("numpy", "sentence_transformers"))


ALLOWED_UPLOAD = (".html", ".htm", ".pdf", ".png", ".jpg", ".jpeg")
DATASET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")


@dataclass
class Settings:
    token: str
    reports_root: Path = field(default_factory=lambda: config.ROOT / "data/reports/moi")
    dev_root: Path = field(default_factory=lambda: config.ROOT / "data/dev")
    jobs_db: Path = field(default_factory=lambda: config.ROOT / "data/work/api_jobs.sqlite")
    max_upload_bytes: int = s1_ingest.MAX_BYTES          # cùng trần 25 MiB của bộ đọc
    # Kiểm bộ log: mặc định đúng phép kiểm E1 của giao diện (chỉ bộ OTRF phát triển, khớp mã băm nguồn).
    dataset_check: Callable[[Path], dict] = demo.dataset
    sigmahq_root: str | Path | None = None
    inline_jobs: bool = False

    @property
    def uploads_dir(self) -> Path:
        return self.reports_root.parent / "tmp_uploads"


# ---------- kiểm đầu vào ----------

def check_url(url: str) -> None:
    """Từ chối sớm (trả 400 ngay, không tạo việc) URL không phải http/https công khai. Dùng lại đúng phép kiểm của bộ đọc
    (``s1_ingest.public_address``); bộ tải còn kiểm lại ở mỗi lần chuyển hướng và ghim kết nối vào địa chỉ đã kiểm."""
    try:
        s1_ingest.public_address(url)
    except OSError as e:                      # không phân giải được tên máy
        raise ValueError("Không phân giải được tên máy trong URL") from e


def save_upload(settings: Settings, filename: str, data: bytes) -> Path:
    suffix = Path(filename or "").suffix.lower()
    if suffix not in ALLOWED_UPLOAD:
        raise ValueError("Chỉ nhận HTML, PDF, PNG, JPEG")
    if len(data) > settings.max_upload_bytes:
        raise ValueError("Tệp vượt giới hạn cỡ")
    folder = demo.new_run(settings.uploads_dir, "upload")
    folder.mkdir(parents=True)
    path = folder / ("input" + suffix)
    path.write_bytes(data)
    return path


def bundle(settings: Settings, report_id: str) -> Path:
    folder = demo.report_folder(report_id, settings.reports_root)
    if not (folder / "manifest.json").is_file():
        raise LookupError("Không có report này")
    return folder


def dataset(settings: Settings, dataset_id: str) -> Path:
    if not DATASET_ID.fullmatch(dataset_id or ""):
        raise ValueError("Mã bộ log không hợp lệ")
    folder = demo.inside(settings.dev_root / dataset_id, settings.dev_root)
    if not (folder / "events.parquet").is_file():
        raise LookupError("Không có bộ log này")
    settings.dataset_check(folder)
    return folder


def datasets(settings: Settings) -> list[dict]:
    out = []
    for m in sorted(settings.dev_root.glob("*/ingest_manifest.json")):
        try:
            d = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if d.get("dataset_kind") == "otrf_dev" and (m.parent / "events.parquet").is_file():
            out.append({"dataset_id": m.parent.name, "events": d.get("events") or d.get("so_su_kien")})
    return out


# ---------- tóm tắt ----------

def report_summary(folder: Path) -> dict:
    manifest, segments, provenance = s1_ingest.load_bundle(folder)
    extractions = []
    for meta_path in sorted((folder / "extractions").glob("*/meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        extractions.append({"extraction_id": meta_path.parent.name, "status": meta.get("status"),
                            "ttp": meta.get("accepted_ttp"), "iocs": meta.get("iocs"),
                            "retrieval": "lai" if meta.get("retrieval_dense") else "bm25"})
    return {"report_id": manifest["report_id"], "title": manifest["title"], "format": manifest["format"],
            "source": s2_report.source_url(manifest) or Path(manifest["resolved_source"]).name,
            "status": manifest["status"], "warnings": manifest["warnings"], "segments": manifest["segments"],
            "readable_segments": manifest["readable_segments"], "unread_blocks": manifest["unread_blocks"],
            "extractions": extractions}


# ---------- 6 việc ----------

def ingest(settings: Settings, report_id: str, source: str, selector: str = "") -> dict:
    """Cửa 1: nạp report (tệp đã lưu hoặc URL đã qua ``check_url``)."""
    return report_summary(demo.ingest(source, report_id, selector, root=settings.reports_root))


def _stix() -> Path:
    rp = config.load("reports")
    stix = config.resolve(rp["attack"]["stix_path"])
    if integrity.sha256_file(stix) != rp["attack"]["stix_sha256"]:
        raise ValueError("ATT&CK khác bản đã ghim")
    return stix


def cost_estimate(settings: Settings, report_id: str, retrieval: str = "bm25") -> dict:
    """Cửa 2: dựng đúng các yêu cầu khâu ② sẽ gửi rồi ước tính tiền. Không gọi LLM, không ghi tệp, không mở sổ."""
    folder = bundle(settings, report_id)
    llm_config = config.load("llm_hunt")
    meta, requests = s2_report.prepare(folder, _stix(), config.resolve("prompts/report_extract_v1.md"), llm_config,
                                       retrieval=retrieval)
    return {"report_id": report_id, "retrieval": retrieval, "target_units": meta["target_units"],
            "batches": meta["batches"], "requests_sha256": meta["requests_sha256"],
            "uoc_tinh_chi_phi": s2_report.estimate_cost(requests, llm_config),
            "khong_gui_khau2": s2_report.noise_summary(meta.get("khong_gui_khau2"))}


def ioc_sweep(settings: Settings, report_id: str, dataset_id: str) -> dict:
    """Cửa 3: IOC rút bằng regex từ report (không cần LLM), xếp mạnh/yếu/bỏ, quét trên bộ log."""
    import yaml
    from ..stages import s2_ioc, s2_ioc_sweep
    folder = bundle(settings, report_id)
    events = dataset(settings, dataset_id)
    manifest, segments, provenance = s1_ingest.load_bundle(folder)
    rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
    contract = ContractA(report_id=manifest["report_id"], title=manifest["title"], source_url=s2_report.source_url(manifest),
                         iocs=s2_report.bundle_iocs(segments, provenance, rules))
    excl = (yaml.safe_load(config.resolve("configs/agent.yaml").read_text(encoding="utf-8")) or {}).get(
        "triage", {}).get("exclude_accounts")
    result = s2_ioc_sweep.sweep_dir(s2_ioc_sweep.plan(contract, rules), events, exclude_accounts=excl)
    result["bo_log"] = dataset_id                      # không trả đường dẫn máy
    return {"report_id": report_id, "dataset_id": dataset_id, "so_ioc_rut_duoc": len(contract.iocs),
            "bang": demo.ioc_table(result), "ket_qua": result}


def community_rules(settings: Settings, report_id: str, extraction_id: str, dataset_id: str,
                    levels: tuple[str, ...] | None = ("high", "critical")) -> dict:
    """Cửa 4: rule SigmaHQ theo TTP của một lượt trích đã hoàn tất (Contract A đã kiểm nguồn)."""
    from ..data.store import connect
    from ..stages import community_rules as cr
    folder = bundle(settings, report_id)
    extraction = demo.inside(folder / "extractions" / extraction_id, folder / "extractions")
    contract = ContractA.model_validate_json(demo.verified_contract(folder, extraction).read_text(encoding="utf-8"))
    events = dataset(settings, dataset_id)
    result = cr.run(connect(events), contract, **({"root": settings.sigmahq_root} if settings.sigmahq_root else {}),
                    levels=levels)
    return {"report_id": report_id, "extraction_id": extraction_id, "dataset_id": dataset_id,
            "muc": list(levels) if levels else "tat_ca", "bang": demo.community_table(result), "ket_qua": result}


class TechniqueSearch:
    """Cửa 5: tra kỹ thuật ATT&CK. Kho BM25 dựng một lần; kho embedding chỉ dựng khi có người hỏi chế độ ``lai``."""

    def __init__(self, stix: Path | None = None, encoder=None):
        from ..attack.retrieval import TechniqueIndex
        self.bm25 = TechniqueIndex.from_stix(stix or _stix())
        self._encoder, self._dense = encoder, None

    def dense(self):
        if self._dense is None:
            if self._encoder is None and not embed_available():
                raise Unavailable(EMBED_MISSING)
            from ..attack import dense_retrieval as dr
            if self._encoder is None:
                try:
                    self._encoder = dr.load_encoder(dr.LAI_MODEL)
                except ImportError as e:
                    raise Unavailable(EMBED_MISSING) from e
            self._dense = dr.DenseIndex(self.bm25.documents, self._encoder,
                                        dr.LAI_MODEL, dr.LAI_CHUNK, cache_dir=dr.default_cache_dir())
        return self._dense

    def search(self, q: str, mode: str = "bm25", k: int = 8) -> list[dict]:
        if not q.strip():
            raise ValueError("Câu tra rỗng")
        if mode == "bm25":
            hits = self.bm25.search(q, k)
        elif mode == "lai":
            dense = self.dense()
            from ..attack import dense_retrieval as dr
            names = {d["technique_id"]: d for d in self.bm25.documents}
            fused = dr.rrf([[c["technique_id"] for c in self.bm25.search(q, dr.RRF_DEPTH)],
                            [c["technique_id"] for c in dense.search(q, dr.RRF_DEPTH)]], k=k)
            hits = [{**names[c["technique_id"]], "retrieval_score": c["retrieval_score"]} for c in fused]
        else:
            raise ValueError("mode phải là bm25 hoặc lai")
        return [{"technique_id": h["technique_id"], "name": h["name"], "tactics": h.get("tactics", []),
                 "score": h["retrieval_score"]} for h in hits]
