"""API HTTP của cti-hunt, đợt 1: 6 cửa, không cửa nào gọi LLM.

| Cửa | Cách chạy |
|---|---|
| ``POST /reports`` nạp report (tệp hoặc URL) | việc nền |
| ``POST /reports/{id}/cost-estimate`` dự toán khâu ② | việc nền |
| ``POST /reports/{id}/ioc-sweep`` quét IOC trên bộ log | việc nền |
| ``POST /reports/{id}/community-rules`` rule SigmaHQ theo TTP | việc nền |
| ``GET /techniques`` tra kỹ thuật ATT&CK (bm25 hoặc lai) | trả ngay |
| ``GET /records``, ``GET /records/{id}`` hunt record đã lưu | trả ngay |

Việc nền trả ``202`` kèm ``job_id``; hỏi ``GET /jobs/{job_id}``. Mọi cửa trừ ``/health`` cần ``Authorization: Bearer <token>``.
Chạy: ``python -m cti_hunt api`` (mặc định chỉ nghe 127.0.0.1; token lấy từ biến ``CTI_API_TOKEN``).
"""
from __future__ import annotations

import secrets
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import services as S
from .jobs import JobStore

VERSION = "api_v1"


class CostRequest(BaseModel):
    retrieval: Literal["bm25", "lai"] = "bm25"


class SweepRequest(BaseModel):
    dataset_id: str = Field(min_length=1)


class CommunityRequest(BaseModel):
    extraction_id: str = Field(min_length=1)
    dataset_id: str = Field(min_length=1)
    muc: Literal["cao", "tat_ca"] = "cao"


def create_app(settings: S.Settings, *, technique_search: S.TechniqueSearch | None = None, record_store=None) -> FastAPI:
    if not settings.token or len(settings.token) < 16:
        raise ValueError("Cần token dài ít nhất 16 ký tự (biến CTI_API_TOKEN); không chạy API không khóa")
    jobs = JobStore(settings.jobs_db, inline=settings.inline_jobs)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        jobs.shutdown(wait=False)

    app = FastAPI(title="cti-hunt API", version=VERSION, lifespan=lifespan,
                  description="Đọc CTI report, quét IOC, bật rule cộng đồng, tra ATT&CK. Không cửa nào gọi LLM.")
    state = {"search": technique_search}

    def auth(authorization: str = Header(default="")) -> None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(token.encode(), settings.token.encode()):
            raise HTTPException(status_code=401, detail="Thiếu hoặc sai token", headers={"WWW-Authenticate": "Bearer"})

    def run_sync(fn, *args, **kw):
        try:
            return fn(*args, **kw)
        except S.Unavailable as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        except FileNotFoundError as e:       # repo vừa clone, chưa tải dữ liệu; chỉ báo tên tệp, không lộ đường dẫn máy
            name = Path(e.filename).name if e.filename else "?"
            raise HTTPException(status_code=503, detail=f"Thiếu dữ liệu cục bộ: {name}") from e
        except LookupError as e:
            raise HTTPException(status_code=404, detail=str(e).strip("'")) from e
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def accepted(kind: str, params: dict, fn) -> JSONResponse:
        job_id = jobs.submit(kind, params, fn)
        return JSONResponse(status_code=202, content={"job_id": job_id, "status_url": f"/jobs/{job_id}"})

    @app.get("/health")
    def health():
        return {"status": "ok", "version": VERSION}

    @app.get("/datasets", dependencies=[Depends(auth)])
    def list_datasets():
        return S.datasets(settings)

    @app.post("/reports", status_code=202, dependencies=[Depends(auth)])
    async def create_report(report_id: str = Form(...), url: str = Form(""), selector: str = Form(""),
                            file: UploadFile | None = File(None)):
        if bool(url.strip()) == bool(file and file.filename):
            raise HTTPException(status_code=400, detail="Gửi đúng một trong hai: url hoặc file")
        run_sync(S.demo.report_folder, report_id, settings.reports_root)
        if (settings.reports_root / report_id).exists():
            raise HTTPException(status_code=409, detail="Mã report đã tồn tại; dữ liệu cũ được giữ nguyên")
        if file and file.filename:
            data = await file.read(settings.max_upload_bytes + 1)
            source = str(run_sync(S.save_upload, settings, file.filename, data))
            params = {"report_id": report_id, "file": file.filename, "selector": selector}
        else:
            run_sync(S.check_url, url.strip())
            source, params = url.strip(), {"report_id": report_id, "url": url.strip(), "selector": selector}
        return accepted("ingest", params, lambda: S.ingest(settings, report_id, source, selector))

    @app.get("/reports/{report_id}", dependencies=[Depends(auth)])
    def get_report(report_id: str):
        return run_sync(lambda: S.report_summary(S.bundle(settings, report_id)))

    @app.post("/reports/{report_id}/cost-estimate", status_code=202, dependencies=[Depends(auth)])
    def cost(report_id: str, body: CostRequest = CostRequest()):
        run_sync(S.bundle, settings, report_id)
        if body.retrieval == "lai" and not S.embed_available():
            raise HTTPException(status_code=503, detail=S.EMBED_MISSING)
        return accepted("cost_estimate", {"report_id": report_id, **body.model_dump()},
                        lambda: S.cost_estimate(settings, report_id, body.retrieval))

    @app.post("/reports/{report_id}/ioc-sweep", status_code=202, dependencies=[Depends(auth)])
    def ioc(report_id: str, body: SweepRequest):
        run_sync(S.bundle, settings, report_id)
        run_sync(S.dataset, settings, body.dataset_id)
        return accepted("ioc_sweep", {"report_id": report_id, **body.model_dump()},
                        lambda: S.ioc_sweep(settings, report_id, body.dataset_id))

    @app.post("/reports/{report_id}/community-rules", status_code=202, dependencies=[Depends(auth)])
    def community(report_id: str, body: CommunityRequest):
        run_sync(S.bundle, settings, report_id)
        run_sync(S.dataset, settings, body.dataset_id)
        levels = ("high", "critical") if body.muc == "cao" else None
        return accepted("community_rules", {"report_id": report_id, **body.model_dump()},
                        lambda: S.community_rules(settings, report_id, body.extraction_id, body.dataset_id, levels))

    @app.get("/techniques", dependencies=[Depends(auth)])
    def techniques(q: str = Query(min_length=1, max_length=4000), mode: Literal["bm25", "lai"] = "bm25",
                   k: int = Query(8, ge=1, le=30)):
        if state["search"] is None:
            state["search"] = run_sync(S.TechniqueSearch)
        return {"q": q, "mode": mode, "results": run_sync(state["search"].search, q, mode, k)}

    def store():
        if record_store is not None:
            return record_store
        from ..record_store import RecordStore
        return RecordStore(settings.reports_root)

    @app.get("/records", dependencies=[Depends(auth)])
    def find_records(technique: str = "", report: str = ""):
        return run_sync(store().find, technique, report)

    @app.get("/records/{record_id:path}", dependencies=[Depends(auth)])
    def read_record(record_id: str):
        try:
            return store().read(record_id)
        except (OSError, ValueError) as e:
            raise HTTPException(status_code=404, detail="Không có hunt record này") from e

    @app.get("/jobs", dependencies=[Depends(auth)])
    def list_jobs(limit: int = Query(20, ge=1, le=200)):
        return jobs.list(limit)

    @app.get("/jobs/{job_id}", dependencies=[Depends(auth)])
    def get_job(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Không có việc này")
        return job

    app.state.jobs = jobs
    return app
