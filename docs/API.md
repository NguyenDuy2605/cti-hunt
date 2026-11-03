# HTTP API (phase 1)

Six system functions exposed over HTTP so that other tools can call them. **No endpoint calls an LLM**, so no endpoint
costs money. The agent part (from TTPs to a hunt record, with human review) has no endpoint yet; it still runs through the
Streamlit interface or the `agent` command.

## Running

```bash
pip install -e ".[api,ingest,sigma]"          # add ,embed for hybrid technique lookup
export CTI_API_TOKEN="<random string, ≥ 16 characters>"
python -m cti_hunt api                         # listens on 127.0.0.1:8000; OpenAPI docs at http://127.0.0.1:8000/docs
```

With Docker:

```bash
export CTI_API_TOKEN="<random string>"
docker compose up --build                                                         # base image (416 MB)
EXTRAS=api,ingest,sigma,embed EXTRAS_TAG=embed docker compose up --build          # with hybrid retrieval (2.24 GB)
```

The host `data/` folder is mounted into the container. `CTI_API_REPORTS_ROOT` and `CTI_API_JOBS_DB` move the report store
and the job table (defaults `data/reports/moi`, `data/work/api_jobs.sqlite`).

## Endpoints

Every endpoint except `/health` requires `Authorization: Bearer <token>`.

| Endpoint | Input | Output | Runs as |
|---|---|---|---|
| `POST /reports` | form: `report_id` and **one** of `file` (HTML/PDF/PNG/JPEG ≤ 25 MiB) or `url`; optional `selector` | job → report summary (blocks, readable, unread, warnings) | background job |
| `GET /reports/{id}` | | report summary and its extraction runs | immediate |
| `POST /reports/{id}/cost-estimate` | `{"retrieval": "bm25" \| "lai"}` | batches, segments, tokens and estimated USD for stage ② | background job |
| `POST /reports/{id}/ioc-sweep` | `{"dataset_id": "otrf-wmi-exec"}` | regex IOCs, strong / weak / drop class, matching events | background job |
| `POST /reports/{id}/community-rules` | `{"extraction_id", "dataset_id", "muc": "cao" \| "tat_ca"}` | SigmaHQ rules selected by the techniques of a completed extraction, events kept per rule | background job |
| `GET /techniques?q=…&mode=bm25\|lai&k=8` | | suggested ATT&CK techniques with scores | immediate |
| `GET /records?technique=T1047&report=…`, `GET /records/{id}` | | saved hunt records (read-only) | immediate |
| `GET /datasets` | | verified OTRF log sets | immediate |
| `GET /jobs/{job_id}`, `GET /jobs` | | job state: `queued`, `running`, `done`, `failed`, `interrupted` | immediate |

```bash
curl -H "Authorization: Bearer $TOKEN" -F report_id=VOLT-1 -F "file=@volt.html" http://127.0.0.1:8000/reports
# {"job_id": "9ae0…", "status_url": "/jobs/9ae0…"}
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/jobs/9ae0…
```

## Design choices

| Problem | Choice | Alternatives considered |
|---|---|---|
| Avoid a second copy of the logic | The API is a thin layer over the functions the Streamlit interface already uses | Rewriting for the API: two copies drift apart |
| IOC sweep should not need a paid extraction | IOC regex extraction moved into `s2_report.bundle_iocs`; the sweep runs right after ingest | Requiring a completed LLM extraction first |
| Long jobs (large PDFs, SigmaHQ ~40 s; LLM extraction ~10 min in a later phase) | `202` + job id at once; one worker thread runs jobs in order; state in SQLite; jobs cut off by a restart become `interrupted` | FastAPI `BackgroundTasks` (lost on restart); Celery/RQ + Redis (worth it only with several machines) |
| One worker, no parallelism | Two jobs loading large logs into DuckDB at once ran out of memory earlier in the project | A worker pool |
| Fetching caller-supplied URLs (SSRF) | Reuse the reader's `s1_ingest.public_address` for an early 400; the fetcher re-checks every redirect and pins the connection to the checked IP | A second, separate check (written first, then removed) |

## Default safety

- Listens on `127.0.0.1` only. In Docker the container listens on `0.0.0.0` but compose publishes the port on the host's
  `127.0.0.1`.
- The server refuses to start without a token of at least 16 characters; tokens are compared with `secrets.compare_digest`
  and never taken from the command line.
- No endpoint calls an LLM or opens the cost ledger.
- URLs: public http/https, ports 80/443 only.
- Uploads: HTML/PDF/PNG/JPEG, ≤ 25 MiB. Report and dataset IDs are checked against strict patterns and paths must stay
  inside the allowed folders. An existing report returns 409 and is never overwritten.
- Log sets are the verified OTRF development sets (same check as the interface). Event labels are never read.
- Hybrid mode on an image without the `embed` extra returns 503 with a clear message; so does any endpoint whose local data
  (ATT&CK, log sets) has not been downloaded yet — it names the missing file, never a host path.
- Verified on a fresh clone: the public image with an empty `data/` starts, `/health` is 200 and `/techniques` answers
  503 naming the missing ATT&CK file.

## Verified

- `tests/test_api.py` (18 cases), on synthetic fixtures.
- Real data: the Volt Typhoon report ingested to 111 blocks / 91 readable / 6 unread; cost estimate 23 batches, request hash
  identical to the saved extraction run; 20 IOCs; SigmaHQ high/critical on the saved extraction: 258 rules, 290 hunts, 4 with
  results.
- Container: runs as a non-root user (uid 10001), health check `healthy`, the same numbers as on the host; a
  `docker restart` during a running job leaves it `interrupted` with a reason.

Limits: one machine, one worker, no rate limiting; a single shared token without users or roles; no endpoint for the agent
or for paid extraction yet; finished job results are kept in SQLite without clean-up.
