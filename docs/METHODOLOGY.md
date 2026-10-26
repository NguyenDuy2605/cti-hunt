# Methodology

This document describes how the system works, what data it was evaluated on, how the reference labels were built, which
controls keep the evaluation honest, and how every metric is computed. Results are summarised in the
[report](../report/cti-hunt-report.pdf) and in the [README](../README.md).

Code comments, configuration keys and CLI help are written in Vietnamese (the project's working language). Identifiers in
this document are given exactly as they appear in the code.

## 1. Research question

> Where do large language models (LLMs) help, and where do they not, on the path from a prose CTI report to a verified
> threat hunt on Windows logs?

Every stage that uses an LLM is compared against a method that does not use one, on the same data:

| # | Question | Non-LLM comparison |
|---|---|---|
| RQ1 | How accurately are IOCs and ATT&CK techniques (TTPs) extracted from a report? | IOC: the system's regular-expression extractor, `iocsearcher`, `iocextract`. TTP: BM25 retrieval over ATT&CK descriptions; rcATT (classical ML, retrained) |
| RQ2 | How many attack steps or techniques do LLM-generated hunts detect, and at what false-positive cost? | SigmaHQ community rules selected by the report's techniques |
| RQ3 | How many LLM errors do the control layers (static checks, field-shape check, breadth gate, human review) catch? | No control layer |

## 2. System

### 2.1. Pipeline

Nine stages. LLMs are used only in ②, ④ and ⑤; everything else is deterministic code.

| Stage | Module | What it does | LLM |
|---|---|---|---|
| ① Ingest | `stages/s1_ingest`, `s1_layout`, `s1_ocr`, `s1_segments` | HTML / PDF / image → numbered text segments with provenance hashes; warns about unread regions; local OCR (RapidOCR) whose output must be reviewed before use | no |
| ② Extract | `stages/s2_ioc`, `s2_ioc_sweep`, `s2_report` | IOCs by regex with defang handling, classified strong / weak / drop before sweeping logs; TTPs plus context by LLM with strict tool use, 8 BM25 candidate techniques per segment, verbatim-quote check | TTP only |
| ③ Telemetry | `stages/s3_telemetry` | Maps each technique to log sources (`configs/telemetry_catalog_v2_2.yaml`, 475 techniques generated from ATT&CK v19.2) and profiles which sources and fields really exist in the dataset | no |
| ④ Hypothesis | `stages/s4_hypothesis` | LOCK-style hunt hypotheses grounded in the report quote, with optional multi-event constraints (distinct count, absence, anchor) enforced by code | yes |
| ◆ Review gate | `approval.py` | A human approves or rejects each hypothesis in a YAML form bound to the SHA-256 of its content; ⑤ refuses unapproved hypotheses | no |
| ⑤ Rule | `stages/s5_rule` | One Sigma rule per approved hypothesis; static checks; at most 2 repair rounds that receive static errors only, never result counts or labels | yes |
| ⑥ Execute | `adapters/duckdb_sigma.py`, `hunt/runner.py` | Sigma → DuckDB SQL through pySigma; the runner rejects any query that references a label column | no |
| ⑦ Filter and rarity | `filter_approval.py`, `stages/s7_rarity` | Exclusion blocks proposed by ⑤ apply only after human approval; a rarity score ranks results and never removes them | no |
| ⑧ Pivot | `stages/s8_triage`, `s8_pivot` | Correlates by host, account and time; pivots on entities matched by ≥ 2 hypotheses, with capped depth and count | no |
| ⑨ Record | `stages/s9_record` | Hunt record in four LOCK sections (Learn / Observe / Check / Keep), built by code without a model | no |

Two run modes share the same stage tools:

- **Pipeline mode:** fixed order ④ → ◆ → ⑤ → ⑥ → ⑦ → ⑧ → ⑨.
- **Agent mode** (`agent/graph.py`, LangGraph): a planner model chooses which TTPs to hunt next, whether to pivot (only
  among candidates the code has already filtered) and when to stop. Every round, pivot rounds included, passes the review
  gate. Budget stops are decided by code, not by the planner.

A Streamlit interface (`app/streamlit_app.py`) drives the same functions: import a report, estimate cost, extract, check
telemetry coverage, run and review a hunt, and read the hunt record. A read-only MCP server (`app/mcp_server.py`) exposes
saved hunt records.

### 2.2. Hybrid mode with community rules

`stages/community_rules.py` selects pinned SigmaHQ rules (status stable or test, level high or critical) whose ATT&CK tag
exactly matches a technique of the report, compiles them through the same adapter (keeping each rule's own filters) and
runs them in every hunt. `coverage()` labels each technique `cao` (a high-level rule that can run), `thap` (low-level rules
only) or `khong_co_rule` (no rule). With `chi_san_khoang_trong: true`, techniques already covered by a high-level community
rule are not sent to ④; on six reports this cut the TTPs sent to ④ from 220 to 37.

### 2.3. Control layers

| Control | Where | Behaviour |
|---|---|---|
| Static checks | `stages/s5_rule` | Sigma syntax; field exists in the log source; log source in the catalogue; no duplicate YAML keys; no regex repetition counts invented by the model; no encoded-command flag pattern placed on script content; no account condition when the code already binds the account |
| Condition fidelity | `stages/rule_fidelity.py` | Rule values are compared with the approved hypothesis; mismatches go to a keep / drop / shorten form |
| Field-shape check | `stages/field_shape.py` (`hinh_dang_truong_v1`) | Compares each SQL condition with the shape of real, unlabelled field values on the same channel and event ID: empty field, numeric field, closed value set, path field, impossible first character, regex syntax inside an equality. Warning only |
| Breadth gate | `configs/do_rong_rule.yaml` | A rule that keeps ≥ 50 % of a high-volume source is flagged; the reviewer must keep it with a reason or drop it. The model never sees this count |
| Grounding warning | `stages/hypothesis_grounding.py` | Flags technical strings in a hypothesis that do not appear in its source quote. Warning only |
| Cost ledger | `llm/budget.py` | SQLite ledger shared by every paid call; a call reserves its maximum cost before sending and is settled from the returned usage |

## 3. Data and ground truth

### 3.1. Datasets

No dataset is redistributed in this repository. Each one is public and pinned by hash or commit.

| Dataset | Content | Used for |
|---|---|---|
| OTRF Security-Datasets, APT29 day 2 | 587,286 Windows events, 4 hosts, 07:50–08:29 UTC | RQ2 multi-step scenario |
| OTRF technique datasets (7 sets) | WMI execution, WMI subscription, WinRM, PsExec, DCOM, run keys, scheduled tasks | Agent development (kept separate from the evaluation data); RQ2 secondary evaluation |
| Splunk `attack_data` (commit `aafa53e`) | 2,291,981 events, 232 techniques (list in `eval/inputs/attack_data_danh_sach_aafa53e.json`) | RQ2 per-technique evaluation; RQ3 |
| SigmaHQ (commit `d1c16224`) | Community Sigma rules | RQ2 baseline; hybrid mode |
| MITRE ATT&CK Enterprise v19.2 (STIX) | Techniques; `uses` relations with citations | TTP answer key; telemetry catalogue; BM25 index |
| CTI reports | 3 scenario reports (Microsoft Solorigate, Symantec Raindrop, FireEye POSHSPY) plus Microsoft Volt Typhoon; 19 reports from 17 publishers for IOC; a pre-registered random set of 30 reports for TTP | RQ1 |

Event conventions: derived columns `ev_host`, `ev_channel` (lower case), `ev_eid`, `ev_rec`, `ev_ts` (UTC); the event key is
`(ev_host, ev_channel, ev_rec)`. Original fields keep their names and are stored as VARCHAR.

### 3.2. Reference labels

| Labels | How they were built | Checks |
|---|---|---|
| APT29 scenario steps | 24 sub-steps (11.A–20.B) of the public scenario text; 5 steps in the Living-off-the-Land scope (15.A, 16.C, 16.D, 20.A, 20.B). 64,972 events attributed to the attacker. 17 steps can be labelled per step; the other 7 only per frame | Frozen with SHA-256 before any hunt was run |
| OTRF process lineage (v1, v2) | Root = the Empire stager command. A process is an attack process if it descends from a root; processes are identified by host, PID and lifetime because PIDs are reused within minutes; WMI and task objects are joined by name. v2 adds processes that read registry values written by an attack process, and classic PowerShell events whose host application matches a live attack process | Blind audit 1: 21/21 decided items agree. Blind audit 2 (stratified, 40 items): 31/36; the 5 disagreements were label errors confirmed on raw events, fixed in v2 (36/36, in-sample) |
| `attack_data` L1 (v1 → v4) | Roots: WinRM host processes and Invoke-AtomicTest. Descendants are attack processes unless filtered: F1 command shared by ≥ 5 technique folders; F2 Splunk agent; F3 Atomic pre-check; F4 Atomic setup and cleanup; F5 compiler children of automation PowerShell; F6 Ansible. Sysmon events only. v4: 70 datasets, 57 techniques, 1,380 processes, 6,945 attack events | Three blind audits: 25/28 (v1), 30/31 (v2, out-of-sample), 9/9 (v4, in-sample) |
| TTP answer key | ATT&CK v19.2 `uses` relations whose citation points to the same report, compared by exact code and by parent technique | Independent of every system output |
| IOC answer key | The IOC section published by the report author; boundaries checked by eye; strings that are not IOCs removed by hand with a recorded reason | — |

An earlier reference set for stage ② (39 report–technique pairs) was generated by GPT-5. It is a silver label, not a gold
standard; it is kept read-only and reported only next to the MITRE-based key.

## 4. Leakage and validity controls

### 4.1. Reference labels for extraction

- The extraction LLM is not from the OpenAI model family, because the silver labels were generated by an OpenAI model.
- Stage-② prompts are never written or tuned from the content of a reference label.
- Reference files are read-only and their SHA-256 is checked on every use (`cli._labels_gate`); a changed file blocks the
  command. A correction becomes a new versioned label set.
- ATT&CK Enterprise is fixed at v19.2. Revoked codes returned by a model are mapped to the current code through
  `revoked-by` (`AttackCatalog.resolve`).

### 4.2. The hunting system never sees event labels

- Hunt queries and stages ④–⑧ never reference label columns (`buoc`, `labeled`, `attack_labels`); the runner rejects any
  query that does.
- The planner sees unlabelled query results only and chooses among pivot candidates that the code has filtered.
- The repair loop of ⑤ receives static errors only, never result counts or labels.
- Configuration text that flows into prompts (catalogue notes) is checked by code for step identifiers, dataset counts and
  references to results (`s3_telemetry.load_catalog`).
- Commands that print labelled results (`labels`, `hunt`, `sigma … --run`, `record … --eval`) were run in a separate
  session; design decisions were not made from labelled numbers.

### 4.3. Pre-registration

- Each labelled measurement made after 16 October 2026 has a protocol written and hashed **before** any labelled number was
  seen: definitions, inputs with SHA-256, comparisons, sensitivity analyses. Deviations are recorded as deviations.
- A result is marked **in-sample** when a rule or label was revised after looking at the same data, and **out-of-sample**
  when the data was untouched at the time of the revision.
- Random samples use fixed seeds (`20261016` for the order of the 232 techniques, `20261019` for the 25-technique sample).

### 4.4. Extraction-stage rules

- The official stage-② run on the three scenario reports was executed once (25 September 2026) and never re-run to improve
  the result. Retried and failed batches are reported (0 and 0).
- Claude 5 models do not accept sampling parameters, so `temperature: 0` cannot be pinned; raw responses are stored and all
  post-processing is deterministic.
- A model refusal is a failure of that call: no retry, no fallback to another model. The affected hypothesis is recorded as
  "not executed" and counts as not detected.
- Only public report text is sent to the API for ②. For ④ and ⑤: extracted TTPs, the log-source catalogue and unlabelled,
  field-limited query results from public datasets.

### 4.5. Caps and thresholds

Fixed before any labelled run (`configs/agent.yaml`): 10 hypotheses per round; pivot depth 2; at most 2 repair rounds per
rule; pivot threshold = an entity matched by ≥ 2 hypotheses; 10-minute time clusters on the same host; 3 pivots per round
and 20 pivot queries in total; built-in service and machine accounts excluded from pivots.

## 5. Metrics and statistics

| Metric | Definition |
|---|---|
| Step recall (APT29) | Steps with ≥ 1 labelled event left in the final stage of ≥ 1 hunt, divided by a denominator. Three denominators: all in-scope steps; steps described in the report; steps described and present in the log. Reported as counts (e.g. 5/5) |
| Technique recall (`attack_data`) | Techniques X with ≥ 1 hunt of X matching an attack event in X's own datasets, divided by the evaluable techniques; Wilson 95 % interval |
| False positives (FP) | Events in the labelled scope matched by a hunt but not labelled as attack, deduplicated across the hunts of one method |
| FPR per hunt | FP ÷ non-attack events of the same channel and event ID as the hunt. Reported as the maximum and the number of hunts above 1 %; the median is 0 % for every method |
| Precision | Matched attack events ÷ all matched events in the labelled scope |
| IOC recall / precision | Author IOCs extracted ÷ author IOCs; author IOCs ÷ everything extracted (hash, IP, domain, URL) |
| TTP recall / precision | Answer-key techniques extracted ÷ answer-key techniques. Precision is a lower bound, because MITRE maps only part of what each report describes |
| Never-match rule | A valid rule that matches 0 events on every available dataset (APT29, 7 OTRF sets, 664 `attack_data` sets). Each one is read by hand and classified (behaviour absent / semantic error / unclear), and the classification is hashed before the field-shape check is run |

Paired comparisons use the exact McNemar test on per-technique outcomes. Differences that rest on fewer than 3 discordant
techniques are not interpreted. Matches outside the labelled scope (other channels, unlabelled datasets) are reported
separately and are not counted as false positives. Small samples are reported as counts rather than percentages.

## 6. Reproducing

```bash
python -m venv .venv
.venv\Scripts\activate                     # Windows; source .venv/bin/activate elsewhere
pip install -e ".[dev,splunk,demo]"
python -m pytest -q                        # synthetic fixtures; no dataset or API key needed
```

With the APT29 day 2 JSON in `data/raw/` and ATT&CK v19.2 STIX in `data/attack/`:

```bash
python -m cti_hunt verify --skip-raw
python -m cti_hunt ingest                                  # -> data/work/events.parquet (587,286 events)
python -m cti_hunt telemetry --check
python -m cti_hunt ingest-report <url-or-file> --id <ID>   # report -> bundle with provenance
python -m cti_hunt extract-report <bundle> --out <dir>     # dry run by default: prompts and cost estimate, no API call
python -m cti_hunt community-rules ...                     # SigmaHQ rules for the report's TTPs
python -m cti_hunt agent start --help                      # full hunt; stops at every review form
```

The interface starts with `run_demo.bat` (Windows) or `streamlit run app/streamlit_app.py`.

Paid model calls need the environment variable `LLM_API_KEY` and go through the cost ledger (`api-budget`). Open models run
through a local Ollama server. The scripts that produced each reported number are in `scripts/`, for example
`do_ttp_mitre.py` (TTP vs MITRE), `do_ioc_tac_gia.py` (IOC vs author lists), `huong2_cham.py` (grading on `attack_data`),
`do_rule_khong_khop.py` and `do_hinh_dang_truong.py` (RQ3), `nhan_otrf.py` and `nhan_attack_data.py` (label builders).
The pre-registered inputs for `attack_data` grading are in `eval/inputs/`.

## 7. Limitations

- One labelled multi-step scenario (APT29 day 2: 4 hosts, 40 minutes). `attack_data` and OTRF are single-technique lab
  recordings. False-positive rates are lower bounds for a real environment.
- Event labels were built by the author from process lineage and checked by blind audits, not by an independent security
  analyst.
- LLM TTP extraction with Claude was measured on 4 reports; the 30-report set was measured with BM25, rcATT and
  `qwen2.5:7b` only.
- The human review gate was not independent: across 258 review decisions in the main evaluation, none differed from the
  assistant's proposal.
- IOC rules were tuned on the same reports that were measured; only the figures marked out-of-sample are unbiased.
