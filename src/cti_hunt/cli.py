"""Dòng lệnh: python -m cti_hunt <lệnh>. Chạy `python -m cti_hunt -h` để xem danh sách."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config, integrity


def _ds():
    return config.load("dataset")


def _rp():
    return config.load("reports")


EVAL_DATASET_ID = "apt29_day2"      # trùng agent.session.EVAL_DATASET_ID; lệnh thủ công ④/⑧/⑨ chạy trên data/work


def _telemetry(con, dataset_id: str, out_dir: Path | None = None, profile_file: str | None = None):
    """Danh mục ③ hiệu lực: danh mục chung + hồ sơ của bộ dữ liệu. Hồ sơ lập từ events, hoặc
    đọc tệp hồ sơ đã ghi (để ⑨ dùng đúng hồ sơ của ④); có out_dir thì ghi ho_so_du_lieu.json vào đó."""
    from .stages import s3_telemetry
    catalog = s3_telemetry.load_catalog(config.resolve(_ds()["telemetry_catalog"]))
    if profile_file:
        profile = json.loads(Path(profile_file).read_text(encoding="utf-8"))
    else:
        profile = s3_telemetry.build_profile(con, catalog, dataset_id)
    sha = s3_telemetry.profile_sha256(profile)
    if out_dir is not None:
        _, sha = s3_telemetry.write_profile(profile, out_dir)
    return s3_telemetry.apply_profile(catalog, profile), {"tep": s3_telemetry.PROFILE_FILE, "sha256": sha,
                                                          "dataset_id": profile["dataset_id"]}


def _labels_ready(con, ds) -> dict:
    from .labels import events
    lv = ds["labels_v1"]
    d = config.resolve(lv["dir"])
    return events.attach(con, d / lv["events_csv"], lv["key_columns"], lv["step_column"], lv.get("expected_rows"))


def _frozen_labels(rp: dict) -> Path:
    return config.resolve(rp["labels_frozen_dir"]) / rp["labels_frozen_xlsx"]


def _labels_gate(rp: dict) -> None:
    """Cổng cho mọi lệnh sinh đầu ra hệ thống trên report đánh giá: thư mục đóng băng có MANIFEST khớp, VÀ file nhãn
    bên trong đúng SHA256 khai trong configs/reports.yaml — tức đúng bộ đã chốt, không phải một bản nào khác."""
    d = config.resolve(rp["labels_frozen_dir"])
    integrity.require_frozen(d)
    f = d / rp["labels_frozen_xlsx"]
    if not f.exists():
        raise integrity.NotFrozenError(f"Thiếu {f} trong thư mục đóng băng")
    want = rp.get("labels_frozen_sha256")
    if want and integrity.sha256_file(f) != want:
        raise integrity.NotFrozenError(f"{f.name} không đúng SHA256 khai trong configs/reports.yaml — "
                                       f"không phải bộ {rp.get('labels_kind', '?')} đã chốt")


def _labels_info(rp: dict) -> dict:
    """Ghi vào meta của mỗi lần chạy: đo so với bộ nhãn nào."""
    return {"loai": rp.get("labels_kind", "?"), "thu_muc": rp["labels_frozen_dir"], "file": rp["labels_frozen_xlsx"],
            "sha256": rp.get("labels_frozen_sha256")}


def _labels_xlsx_default(rp: dict) -> Path:
    f = _frozen_labels(rp)
    return f if f.exists() else config.resolve(rp["labels_xlsx_working"])


def cmd_verify(a) -> int:
    ds, rp = _ds(), _rp()
    ok = True
    raw = config.resolve(ds["raw"]["path"])
    if a.skip_raw:
        print("[bỏ qua] SHA256 dataset gốc")
    elif not raw.exists():
        print(f"[THIẾU] {raw}"); ok = False
    else:
        h = integrity.sha256_file(raw)
        good = h == ds["raw"]["sha256"]
        ok &= good
        print(f"[{'OK' if good else 'SAI'}] dataset gốc {raw.name}" + ("" if good else f"\n       thực tế {h}"))

    lv = ds["labels_v1"]
    d = config.resolve(lv["dir"])
    man = d / lv["manifest"]
    if not man.exists():
        print(f"[THIẾU] {man}"); ok = False
    else:
        for r in integrity.verify_dir(d, man):
            st = "OK" if r["ok"] else ("THIẾU" if r["missing"] else "SAI")
            ok &= r["ok"]
            print(f"[{st}] nhan_v1/{r['file']}")

    stix = config.resolve(rp["attack"]["stix_path"])
    if not stix.exists():
        print(f"[THIẾU] {stix} (cần cho check-labels và khâu ②)")
    else:
        good = integrity.sha256_file(stix) == rp["attack"]["stix_sha256"]
        ok &= good
        print(f"[{'OK' if good else 'SAI'}] ATT&CK STIX {stix.name}")

    name = f"{rp['labels_frozen_dir']} ({rp.get('labels_kind', '?')})"
    try:
        _labels_gate(rp)
        print(f"[OK] {name} đã đóng băng, đúng SHA256 — khâu ② được chạy trên report đánh giá")
        if rp.get("labels_kind") != "gold":
            print("     lưu ý: bộ tham chiếu KHÔNG phải gold — mọi P/R phải ghi rõ (configs/reports.yaml)")
    except integrity.NotFrozenError as e:
        print(f"[CHƯA] {name}: {e}")
    return 0 if ok else 1


def cmd_ingest(a) -> int:
    from .data.ingest import ingest
    ds = _ds()
    src = config.resolve(ds["raw"]["path"])
    m = ingest(src, config.resolve(ds["work_dir"]), sysmon_channel=ds["sysmon_channel"], time_cfg=ds["time"],
               event_key=ds["event_key"], expected_rows=ds["raw"].get("expected_rows"),
               threads=ds.get("ingest_threads", 2))
    print(json.dumps({k: m[k] for k in ("rows", "fields", "hosts", "ev_ts_src", "ev_ts_range_utc",
                                        "renamed_fields")}, ensure_ascii=False, indent=2))
    for p in m["problems"]:
        print(f"[VẤN ĐỀ] {p}")
    print(f"Đã ghi {ds['work_dir']}/events.parquet, event_counts.csv, ingest_manifest.json")
    return 1 if m["problems"] else 0


def cmd_ingest_dev(a) -> int:
    """E1: nạp một bộ OTRF phát triển (không phải APT29 day 2) cho graph D10."""
    from .agent.dev_data import DevDatasetError, ingest_dev
    out = Path(a.out) if a.out else config.resolve(_ds()["dev_dir"]) / a.dataset_id
    try:
        m = ingest_dev(Path(a.src), a.dataset_id, out, offset_hours=a.offset_hours)
    except DevDatasetError as e:
        print(f"[TỪ CHỐI] {e}")
        return 1
    print(json.dumps({k: m[k] for k in ("rows", "hosts", "ev_ts_range_utc", "source_sha256", "e1")},
                     ensure_ascii=False, indent=2))
    print(f"Đã ghi {out}/events.parquet, event_counts.csv, ingest_manifest.json")
    print("Chạy graph: python -m cti_hunt agent start --mode pipeline --contract-a <contract_a.json> "
          f"--events {out} --dataset-kind otrf_dev --dataset-id {a.dataset_id} "
          f"--dataset-sha256 {m['source_sha256']} --out <thư mục lượt mới>")
    return 0


def cmd_labels(a) -> int:
    from .data.store import connect
    ds = _ds()
    con = connect(config.resolve(ds["work_dir"]))
    s = _labels_ready(con, ds)
    print(f"Nhãn v1: {s['rows']} dòng, khóa trùng {s['duplicate_keys']}, không khớp sự kiện {s['unmatched']}")
    print(f"Số bước có sự kiện: {len(s['per_step'])}")
    for k, v in s["per_step"].items():
        print(f"  {k:<6}{v:>8}")
    by_src = con.execute("""SELECT ev_channel, ev_eid, count(*) n FROM attack_labels l
                            JOIN events e USING (ev_host, ev_channel, ev_rec) GROUP BY 1, 2 ORDER BY n DESC LIMIT 12""").fetchall()
    print("Nguồn log của sự kiện tấn công (top 12):")
    for ch, eid, n in by_src:
        print(f"  {n:>8}  EID {eid:<6} {ch}")
    for p in s["problems"]:
        print(f"[VẤN ĐỀ] {p}")
    return 1 if s["problems"] else 0


def cmd_hunt(a) -> int:
    from .data.store import connect
    from .hunt import runner
    from .labels import ground_truth
    ds, rp = _ds(), _rp()
    con = connect(config.resolve(ds["work_dir"]))
    s = _labels_ready(con, ds)
    if s["problems"] and not a.force:
        print("Nhãn chưa join sạch, không tính chỉ số (xem lệnh `labels`, hoặc --force):")
        for p in s["problems"]:
            print(f"  {p}")
        return 1
    lv = ds["labels_v1"]
    steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
    independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
    rc = 0
    files = []
    for x in map(Path, a.hunt_files):     # PowerShell không mở rộng *.yaml cho lệnh python: cho phép truyền thư mục
        files += sorted(x.glob("*.yaml")) + sorted(x.glob("*.yml")) if x.is_dir() else [x]
    for path in files:
        spec = runner.load_spec(Path(path))
        res = runner.run(con, spec, steps, independent)
        out = runner.save(res, config.resolve("runs"))
        print(runner.format_summary(res))
        print(f"Kết quả đầy đủ: {out}\n")
        if any(g["removed_attacker"] for g in res["giai_doan"]):
            print("[CẢNH BÁO] Có mục lọc loại nhầm sự kiện tấn công (v3 §6.2: mục tiêu bằng 0)")
            rc = 2
    return rc


def cmd_sigma(a) -> int:
    from .adapters import duckdb_sigma as adapter
    from .data.store import connect
    from . import filter_approval as filters
    version = getattr(a, "phien_ban", "v1")
    if a.run and (version == "v2" or any(filters.path_policy(Path(p)) for p in a.rule_files)):
        print("Rule v2 phải qua phiếu lọc; chạy hunt hiệu lực sau duyệt, không dùng sigma --run trên draft.")
        return 1
    ds, rp = _ds(), _rp()
    catalog = adapter.load_catalog(config.resolve(ds["logsource_catalog"]))
    parquet = config.resolve(ds["work_dir"]) / "events.parquet"
    con = connect(config.resolve(ds["work_dir"])) if parquet.exists() else None
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()} if con else None

    all_hunts = []
    for path in a.rule_files:
        policy = filters.POLICY if version == "v2" else filters.path_policy(Path(path))
        hunts, skipped = adapter.compile_rule(Path(path), catalog, cols, **({"filter_policy": policy} if policy else {}))
        print(f"== {path}")
        for h in hunts:
            print(f"  [{h.source}] channel={h.scope['channel']} eid={h.scope['event_ids']} "
                  f"ttp={','.join(h.linked_ttps) or '-'}")
            print(f"     ứng viên: {h.candidates}")
            for f in h.filters:
                print(f"     lọc {f['id']} ({f['mo_ta']}): {f['where']}")
            if h.ghi_chu:
                print(f"     ghi chú: {h.ghi_chu}")
        for sk in skipped:
            print(f"  [bỏ {sk.source}] {sk.ly_do}")
        if not hunts:
            print("  không săn được bằng nguồn log hiện có (khoảng trống quan sát)")
        all_hunts += hunts

    if not a.run:
        return 0
    if con is None:
        print("Chưa có events.parquet, không chạy được. Chạy `ingest` trước.")
        return 1
    from .hunt import runner
    from .labels import ground_truth
    s = _labels_ready(con, ds)
    if s["problems"] and not a.force:
        print("Nhãn chưa join sạch, không tính chỉ số (xem lệnh `labels`, hoặc --force):")
        for p_ in s["problems"]:
            print(f"  {p_}")
        return 1
    lv = ds["labels_v1"]
    steps = ground_truth.load(config.resolve(lv["dir"]) / lv["ground_truth_csv"])
    independent = [k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")]
    for h in all_hunts:
        spec = h.to_hunt_spec()
        runner.validate(spec)
        res = runner.run(con, spec, steps, independent)
        out = runner.save(res, config.resolve("runs"))
        print()
        print(runner.format_summary(res))
        print(f"Kết quả đầy đủ: {out}")
    return 0


def _load_hunts(path: Path, con, *, issues: list[dict] | None = None) -> list[dict]:
    """File hunt YAML (nhánh A) hoặc rule Sigma -> danh sách hunt spec. Rule Sigma: một spec cho mỗi nguồn log."""
    import hashlib
    import yaml
    from .adapters import duckdb_sigma as adapter
    from .hunt import runner
    from .filter_approval import path_policy
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise runner.HuntSpecError("File hunt/rule phải là một YAML mapping")
    if "detection" not in doc:
        return [runner.load_spec(path)]
    ds = _ds()
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    catalog = adapter.load_catalog(config.resolve(ds["logsource_catalog"]))
    policy = path_policy(path)
    hunts, skipped = adapter.compile_rule(path, catalog, cols, **({"filter_policy": policy} if policy else {}))
    scopes = {src["name"]: {"channel": src["channel"], "event_ids": src.get("event_ids") or []}
              for sources in catalog.values() for src in sources}
    for sk in skipped:
        print(f"  [bỏ {sk.source}] {path.name}: {sk.ly_do}")
        if issues is not None:
            issues.append({"giai_doan": "bien_dich", "source": sk.source,
                           "scope": scopes.get(sk.source), "ly_do": sk.ly_do})
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    out = []
    for h in hunts:
        spec = h.to_hunt_spec()
        spec["_path"], spec["_sha256"] = path.as_posix(), sha
        try:
            runner.validate(spec, con=con)
        except runner.HuntSpecError as exc:
            if issues is None:
                raise
            issues.append({"giai_doan": "kiem_hunt", "source": h.source,
                           "scope": spec["scope"], "hunt_id": spec["id"], "ly_do": str(exc)})
            continue
        out.append(spec)
    return out


def _exec_acc_input(path: Path, con) -> dict:
    """Giữ hash và lỗi đầu vào để exec-acc không mất bản ghi khi một rule chuẩn hỏng."""
    import yaml
    result = {"file": str(path), "sha256": None, "hunts": [], "loi": []}
    try:
        result["sha256"] = integrity.sha256_file(path)
        result["hunts"] = _load_hunts(path, con, issues=result["loi"])
    except (OSError, ValueError, yaml.YAMLError, NotImplementedError) as exc:
        result["loi"].append({"giai_doan": "nap_hunt", "scope": None,
                              "loai_loi": type(exc).__name__, "ly_do": str(exc)})
    return result


def _issue_affects_scope(issue: dict, scope: dict) -> bool:
    """Lỗi toàn tệp hoặc cùng nguồn/EID ngăn đo tập con; lỗi ở nguồn khác vẫn được ghi riêng."""
    other = issue.get("scope")
    if not other:
        return True
    if str(other.get("channel", "")).lower() != str(scope["channel"]).lower():
        return False
    eids = set(other.get("event_ids") or [])
    return not eids or bool(eids & set(scope["event_ids"]))


def cmd_exec_acc(a) -> int:
    from datetime import datetime
    import duckdb
    from .data.store import connect
    from .eval import exec_accuracy as ea
    ds = _ds()
    events_dir = config.resolve(a.events or ds["work_dir"])
    parquet = events_dir / "events.parquet"
    if not parquet.exists():
        print("Chưa có events.parquet. Chạy `ingest` trước.")
        return 1
    con = connect(events_dir)
    ref_files = list(dict.fromkeys([a.ref, *a.ref_extra]))
    refs_by_file = [_exec_acc_input(Path(path), con) for path in ref_files]
    gen_input = _exec_acc_input(Path(a.gen), con)
    gens = gen_input["hunts"]
    results = []
    reference_name = " ∪ ".join(Path(path).name for path in ref_files)
    if gen_input["loi"] or not gens:
        results.append({"chuan": reference_name, "sinh": a.gen, "so_duoc": False,
                        "ly_do": "file sinh có lỗi hoặc không có hunt hợp lệ",
                        "loi_sinh": gen_input["loi"],
                        "bo_chuan": [{k: v for k, v in r.items() if k != "hunts"} for r in refs_by_file]})
    from .eval import g0c
    for g in gens:
        # v1: chuẩn cùng đúng phạm vi; v2: thu EID của chuẩn về EID của hunt sinh khi là tập con (g0c.narrow_reference).
        groups = [(entry, [n for r in entry["hunts"] if (n := g0c.narrow_reference(r, g, a.quy_tac)) is not None])
                  for entry in refs_by_file]
        missing = [entry["file"] for entry, refs in groups
                   if not refs or any(_issue_affects_scope(e, g["scope"]) for e in entry["loi"])]
        refs = [r for _, group in groups for r in group]
        if missing or any(_issue_affects_scope(e, g["scope"]) for e in gen_input["loi"]):
            # Không bỏ một file chuẩn đã chọn để tính điểm trên phần còn lại.
            res = ea.evaluate_union(con, [], g)
            res["chuan"] = reference_name
            res["ly_do"] = ("file chuẩn có lỗi hoặc không có hunt cùng phạm vi: " + ", ".join(missing)
                            if missing else "file sinh có lỗi trong phạm vi đang đo")
        else:
            try:
                res = ea.evaluate(con, refs[0], g) if len(refs) == 1 else ea.evaluate_union(con, refs, g)
            except duckdb.Error as exc:
                res = ea.evaluate_union(con, [], g)
                res.update(chuan=reference_name, ly_do=f"lỗi truy vấn khi so: {exc}",
                           loi_do={"loai_loi": type(exc).__name__, "ly_do": str(exc)})
        res["quy_tac_g0c"] = a.quy_tac
        res["bo_chuan"] = [{"file": entry["file"], "sha256": entry["sha256"], "loi": entry["loi"],
                            "hunt_ids": [r["id"] for r in group],
                            "thu_hep_eid": [r["g0c_v2_thu_hep_eid"] for r in group if "g0c_v2_thu_hep_eid" in r],
                            "pham_vi_hunts": [{"id": r["id"], "scope": r["scope"]} for r in entry["hunts"]]}
                           for entry, group in groups]
        if len(refs) == 1 and res["so_duoc"]:
            res["file_chuan"], res["sha256_chuan"] = refs[0].get("_path"), refs[0].get("_sha256")
        res["file_sinh"], res["sha256_sinh"] = g.get("_path"), g.get("_sha256")
        results.append(res)
    con.close()
    for res in results:
        res.setdefault("file_sinh", Path(a.gen).as_posix())
        res.setdefault("sha256_sinh", gen_input["sha256"])
        res["events_dir"] = events_dir.as_posix()
        print(ea.format_summary(res) + "\n")
    out = Path(a.out) if a.out else config.resolve("runs") / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_exec_acc.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"Đã ghi {out}")
    return 0 if results and all(r["so_duoc"] for r in results) else 1


def _agent_cfg() -> dict:
    return config.load("agent")


def cmd_hypotheses(a) -> int:
    from datetime import datetime
    from . import approval
    from .contracts import ContractA
    from .data.store import connect
    from .llm import providers
    from .llm.prompting import load_sections
    from .stages import s4_hypothesis
    ds, rp, cfg = _ds(), _rp(), _agent_cfg()
    ca = ContractA.model_validate_json(Path(a.contract_a).read_text(encoding="utf-8"))
    if ca.report_id in rp["eval_reports"]:       # cổng đóng băng: đầu ra hệ thống trên report đánh giá
        try:
            _labels_gate(rp)
        except integrity.NotFrozenError as e:
            print(e)
            return 1
    try:
        con = connect(config.resolve(ds["work_dir"]))
    except FileNotFoundError as e:
        print(f"{e}\nKhâu ④ cần events để lập hồ sơ bộ dữ liệu của danh mục ③.")
        return 1
    run_dir = Path(a.out) if a.out else config.resolve("runs") / f"khau4_{datetime.now().strftime('%Y%m%d-%H%M%S')}_{ca.report_id}"
    telemetry, ho_so = _telemetry(con, EVAL_DATASET_ID, out_dir=run_dir)
    stix = config.resolve(rp["attack"]["stix_path"])
    attack = None
    if stix.exists():
        from .attack.catalog import AttackCatalog
        attack = AttackCatalog.from_stix(stix)
    else:
        print(f"[lưu ý] chưa có {stix.name}: extra_techniques chỉ được kiểm định dạng, không kiểm với v19.2")
    prompt = load_sections(config.resolve(cfg["prompt_khau4"]))
    llm = providers.from_config(config.load("llm_hunt"))
    res = s4_hypothesis.generate(ca, telemetry, llm, prompt, cfg, attack, run_dir)
    form = approval.write_review(res["hypotheses"], run_dir, telemetry=telemetry)
    (run_dir / "khau4_log.json").write_text(json.dumps({**res["log"], "khoang_trong": res["khoang_trong"],
                                                        "ho_so": ho_so},
                                                       ensure_ascii=False, indent=2), encoding="utf-8")
    lg = res["log"]
    print(f"{ca.report_id}: {lg['so_ttp_dau_vao']} TTP vào khâu ④, {lg['so_ttp_not_huntable']} not_huntable · "
          f"{lg['so_muc_tho']} thô -> {lg['so_gia_thuyet']} giả thuyết · mã sửa: {lg['ma_sua'] or 'không'}")
    print(f"Phiếu duyệt: {form}\nĐiền xong chạy: python -m cti_hunt approve {run_dir}")
    return 0


def cmd_approve(a) -> int:
    from . import approval
    try:
        log = approval.apply_review(Path(a.run_dir))
    except approval.ReviewError as e:
        print(e)
        return 1
    print(f"Người duyệt {log['nguoi_duyet'] or '-'}: {log['dem']}")
    print(f"Đã ghi {Path(a.run_dir) / approval.APPROVED_FILE}")
    return 0


def cmd_rules(a) -> int:
    from .filter_approval import path_policy
    if getattr(a, "phien_ban", "v1") == "v2":
        return _cmd_rules_v2(a)
    if path_policy(Path(a.run_dir) / "rules"):
        print("Lượt v2 không được gọi rules theo v1; dùng --phien-ban v2 hoặc agent resume.")
        return 1
    import yaml as _yaml
    from . import approval
    from .adapters import duckdb_sigma as adapter
    from .data.store import connect
    from .llm import providers
    from .llm.prompting import load_sections
    from .stages import s5_rule
    ds, cfg = _ds(), _agent_cfg()
    run_dir = Path(a.run_dir)
    approved_file = run_dir / approval.APPROVED_FILE
    if not approved_file.exists():
        print(f"Chưa có {approved_file}. Chạy `approve {run_dir}` trước.")
        return 1
    hyps = [h for h in approval.load_hypotheses(approved_file) if h.status == "approved"]
    if not hyps:
        print("Không có giả thuyết nào đã duyệt.")
        return 1
    ls_catalog = adapter.load_catalog(config.resolve(ds["logsource_catalog"]))
    parquet = config.resolve(ds["work_dir"]) / "events.parquet"
    con = connect(config.resolve(ds["work_dir"])) if parquet.exists() else None
    cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()} if con else None
    if con is None:
        print("[lưu ý] chưa có events.parquet: bỏ qua kiểm tra tên cột và EXPLAIN")
    prompt = load_sections(config.resolve(cfg["prompt_khau5"]), ("SYSTEM", "USER", "REPAIR"))
    llm = providers.from_config(config.load("llm_hunt"))
    (run_dir / "rules").mkdir(exist_ok=True)
    (run_dir / "hunts").mkdir(exist_ok=True)
    results = []
    for h in hyps:
        r = s5_rule.generate_rule(h, llm, prompt, ls_catalog, int(cfg["max_repair_attempts"]), cols, con, run_dir)
        results.append(r)
        state = "hợp lệ" + (" ngay lần đầu" if r["hop_le_lan_dau"] else f" sau {r['so_lan_sua']} lần sửa") if r["hop_le"] \
            else f"KHÔNG hợp lệ sau {r['so_lan_sua']} lần sửa: " + "; ".join(i["kind"] for i in r["lan_thu"][-1]["loi"])
        print(f"{h.hypothesis_id}: {state}")
        if r["hop_le"]:
            (run_dir / "rules" / f"{h.hypothesis_id}.yml").write_text(r["rule_yaml"], encoding="utf-8")
            for spec in r["hunt_specs"]:
                (run_dir / "hunts" / f"{h.hypothesis_id}__{spec['id'].split('__')[-1]}.yaml").write_text(
                    _yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8")
    summ = s5_rule.summarize(results)
    summ.update(prompt=prompt["path"], prompt_sha256=prompt["sha256"], model=getattr(llm, "model_id", "?"))
    (run_dir / "khau5_log.json").write_text(json.dumps({"tong_hop": summ, "chi_tiet": results}, ensure_ascii=False,
                                                       indent=2, default=str), encoding="utf-8")
    print(f"Hợp lệ cú pháp: lần đầu {summ['hop_le_lan_dau']}/{summ['so_gia_thuyet']}, "
          f"sau sửa {summ['hop_le_sau_sua']}/{summ['so_gia_thuyet']} · lỗi lần đầu: {summ['loi_lan_dau_theo_loai'] or '-'}")
    print(f"Chạy: python -m cti_hunt hunt {run_dir / 'hunts'}")
    return 0


def _cmd_rules_v2(a) -> int:
    """Shared prepare phase for standalone ⑤; repeated calls reuse a complete packet."""
    from . import approval, filter_approval as filters
    from .adapters import duckdb_sigma
    from .agent import session
    from .agent.stage_tools import StageTools
    from .data.store import connect
    from .llm import providers
    from .llm.prompting import load_sections
    con = None
    try:
        root = Path(a.run_dir).resolve()
        if (root / session.META_FILE).exists():
            raise ValueError("Lượt graph dùng agent resume để giữ đúng checkpoint; không chạy rules độc lập")
        if not a.events or not a.dataset_kind or not a.dataset_id:
            raise ValueError("rules v2 cần --events, --dataset-kind và --dataset-id")
        session.check_dataset(a.events)
        if a.dataset_kind == "otrf_dev":
            from .agent.dev_data import check_manifest
            check_manifest(a.events, a.dataset_id, a.dataset_sha256)
        approval.verify_saved_review(root)
        hyps = [h for h in approval.load_hypotheses(root / approval.APPROVED_FILE) if h.status == "approved"]
        if not hyps or len({h.pivot_depth for h in hyps}) != 1:
            raise ValueError("cần lô giả thuyết đã duyệt cùng độ sâu")
        con = connect(a.events)
        rd = root / "filter_review/r01"
        if (rd / filters.MANIFEST).exists():
            filters.verify_packet(rd, con=con)
        else:
            if (root / filters.CONTEXT).exists() or (root / "rules_draft").exists():
                raise ValueError("⑤ xuất dở; giữ log và dùng revision/lượt mới, không tự gọi lại")
            cfg = config.agent_config("v2")
            deps = [config.resolve(p) for p in session.tracked_files(version="v2")]
            # Pin the policy before any generation, so a partial request cannot fall back to v1.
            filters.bind(con, root, dependencies=deps)
            filters._write(root / filters.CONTEXT, filters._context(con, root))
            ds = _ds()
            tools = StageTools(None, {}, duckdb_sigma.load_catalog(config.resolve(ds["logsource_catalog"])),
                               con, cfg, None, providers.from_config(config.load("llm_hunt")), {}, {},
                               load_sections(config.resolve(cfg["prompt_khau5"]), ("SYSTEM", "USER", "REPAIR")),
                               root, dataset_kind=a.dataset_kind, dataset_id=a.dataset_id,
                               dataset_sha256=a.dataset_sha256, filter_dependencies=deps)
            tools.prepare_rules({"review_dir": str(root)}, hyps)
        print(f"Phiếu lọc: {rd / filters.FORM}\nChưa thực thi; điền phiếu rồi chạy filter-review finalize.")
        if (rd / filters.RULE_FORM).exists():
            print(f"Phiếu giữ/bỏ rule: {rd / filters.RULE_FORM}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Chặn rules v2: {exc}")
        return 1
    finally:
        if con is not None:
            con.close()


def cmd_record(a) -> int:
    from datetime import datetime
    from .contracts import ContractA
    from .data.store import connect
    from .stages import s9_record
    ds = _ds()
    ca = ContractA.model_validate_json(Path(a.contract_a).read_text(encoding="utf-8"))
    hyps = _load_hypotheses_many(a.hypotheses)
    results = []
    for x in map(Path, a.results):
        for f in (sorted(x.glob("*.json")) if x.is_dir() else [x]):
            d = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(d, dict) and "giai_doan" in d and "hunt" in d:
                results.append(d)
    ids = {h.hypothesis_id for h in hyps}
    results = [r for r in results if r["hunt"].get("hypothesis_id") in ids]
    try:
        con = None if a.ho_so else connect(config.resolve(ds["work_dir"]))
    except FileNotFoundError as e:
        print(f"{e}\nKhâu ⑨ cần events để lập hồ sơ bộ dữ liệu, hoặc --ho-so <ho_so_du_lieu.json của lượt ④>.")
        return 1
    telemetry, ho_so = _telemetry(con, EVAL_DATASET_ID, profile_file=a.ho_so)
    print(f"Hồ sơ bộ dữ liệu {ho_so['dataset_id']} · sha256 {ho_so['sha256'][:16]}")
    tri = json.loads(Path(a.triage).read_text(encoding="utf-8")) if a.triage else None
    rarity = json.loads(Path(a.rarity).read_text(encoding="utf-8")) if a.rarity else None
    pivot_rounds = [json.loads(Path(p).read_text(encoding="utf-8")) for p in a.pivot_rounds]
    pivot_log = [{**p["nhat_ky_vong"], "selected": p["selected"]} for p in pivot_rounds]
    md = s9_record.render(ca, telemetry, hyps, results, pivot_log=pivot_log,
                          eval_mode=a.eval, triage=tri, rarity=rarity)
    out = Path(a.out) if a.out else config.resolve("runs") / (
        f"hunt_record_{ca.report_id}_{datetime.now().strftime('%Y%m%d-%H%M%S')}{'_EVAL' if a.eval else ''}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"{len(results)} kết quả hunt khớp giả thuyết · đã ghi {out}")
    return 0


def cmd_score_ttp(a) -> int:
    """P/R khâu ② của một lần chạy, so với bộ nhãn tham chiếu đã đóng băng: bản đủ và bản bỏ mã có sẵn."""
    from .attack.catalog import AttackCatalog
    from .contracts import ContractA
    from .eval import extraction_metrics as em
    from .labels import reports
    rp = _rp()
    try:
        _labels_gate(rp)
    except integrity.NotFrozenError as e:
        print(e)
        return 1
    run_dir = Path(a.run_dir)
    files = sorted(run_dir.glob("contract_a_*.json"))
    if not files:
        print(f"Không có contract_a_*.json trong {run_dir}")
        return 1
    pred = set()
    pred_ctx: dict[tuple[str, str], dict] = {}
    thieu_ma_doan = trung_khoa = 0
    for f in files:
        ca = ContractA.model_validate_json(f.read_text(encoding="utf-8"))
        pred |= {(ca.report_id, t.technique_id.strip().upper()) for t in ca.ttps}
        for t in ca.ttps:                       # ghép context theo (đoạn, mã kỹ thuật) — D2, chốt 23/9
            seg = (t.source_span.segment_id or "").strip()
            if not seg:
                thieu_ma_doan += 1
                continue
            key = (seg, t.technique_id.strip().upper())
            if key in pred_ctx:
                trung_khoa += 1
                continue
            pred_ctx[key] = {"report": ca.report_id, **t.context.model_dump()}
    catalog = AttackCatalog.from_stix(config.resolve(rp["attack"]["stix_path"]))
    data = reports.load(_frozen_labels(rp))
    texts: dict[str, list[str]] = {}
    for sgm in data["segments"]:
        texts.setdefault(sgm.report, []).append(sgm.van_ban)
    independent = {k for k, v in rp["eval_reports"].items() if v.get("doc_lap_voi_kich_ban")}
    res = em.score(reports.gold_pairs(data["nhan"]), reports.gold_pairs(data["nhan"], in_scope_only=True), pred,
                   catalog, em.literal_pairs(texts, catalog), independent)
    res["context"] = em.score_context(reports.gold_context(data["nhan"]), pred_ctx, catalog,
                                      em.literal_pairs(texts, catalog), thieu_ma_doan, trung_khoa)
    res["bo_nhan_tham_chieu"] = _labels_info(rp)
    res["report_doc_lap"] = sorted(independent)
    # Cảnh báo đi theo FILE, không chỉ in ra màn hình: ai mở score_ttp.json về sau cũng phải thấy.
    if rp.get("labels_kind") != "gold":
        res["canh_bao"] = (f"Bộ tham chiếu là {rp.get('labels_kind', '?')}, KHÔNG phải gold và không phải nhãn tay: "
                           "mọi P/R ở đây phải ghi rõ điều đó khi báo cáo. Danh sách 'lech' của từng trường là giá "
                           "trị nhãn tham chiếu, dùng để đọc định tính, không phải đáp án đúng. "
                           "Không dùng danh sách này để soạn hoặc sửa prompt khâu ② (docs/METHODOLOGY.md §4.1).")
    print(f"So với {rp.get('labels_kind', '?')} ({rp['labels_frozen_xlsx']}) · report độc lập: {sorted(independent)}"
          f" · mã có sẵn trong văn bản: {res['ma_co_san']['so_cap']} cặp\n")
    print(em.format_score(res))
    print("\nBối cảnh từng trường (khớp chặt sau chuẩn hóa — giới hạn dưới; 'trống2' = hai bên cùng trống,\n"
          "'chứa' = cặp lệch mà một bên chứa bên kia; danh sách cặp lệch ở score_ttp.json):")
    print(em.format_context(res["context"]))
    if res["ma_tho"]["khong_ton_tai"] or res["ma_tho"]["bi_thu_hoi"]:
        print(f"\nMã thô: không tồn tại {res['ma_tho']['khong_ton_tai']} · bị thu hồi {res['ma_tho']['bi_thu_hoi']}")
    if rp.get("labels_kind") != "gold":
        print("\nLưu ý: bộ tham chiếu không phải gold — ghi rõ khi báo cáo (configs/reports.yaml).")
    out = run_dir / "score_ttp.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=2, default=list), encoding="utf-8")
    print(f"Đã ghi {out}")
    return 0


def cmd_sigma_check(a) -> int:
    """Chạy hàng loạt rule Sigma qua adapter. Có events.parquet thì kiểm trên dữ liệu thật (tên cột + EXPLAIN)."""
    from datetime import datetime
    from .adapters import duckdb_sigma as adapter, sigma_check
    from .data.store import connect
    ds = _ds()
    catalog = adapter.load_catalog(config.resolve(ds["logsource_catalog"]))
    parquet = config.resolve(ds["work_dir"]) / "events.parquet"
    con = cols = None
    if parquet.exists() and not a.synthetic:
        con = connect(config.resolve(ds["work_dir"]))
        cols = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
        print("Chế độ dữ liệu thật: kiểm tên cột và EXPLAIN trên events")
    else:
        print("Chế độ tổng hợp: chỉ kiểm cú pháp SQL")
    res = sigma_check.check_dir(Path(a.rules_dir), catalog, con, cols)
    print(f"{res['tong']} rule: {res['nhom']}")
    for g in ("loi_sql", "loi_backend", "loi_sigma", "thieu_truong", "ngoai_danh_muc"):
        rows = res["ly_do"].get(g, [])
        if rows:
            print(f"\n[{g}]")
            for x in rows[:a.top]:
                print(f"  {x['so_rule']:>5}  {x['ly_do'][:110]}   (vd {x['vi_du']})")
    out = config.resolve("runs") / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_sigma_check.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nDanh sách rule chạy được và chi tiết từng rule: {out}")
    return 1 if res["nhom"].get("loi_sql") else 0


def _load_results(paths) -> list[dict]:
    out = []
    for x in map(Path, paths):
        for f in (sorted(x.glob("*.json")) if x.is_dir() else [x]):
            d = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(d, dict) and "giai_doan" in d and "hunt" in d:
                out.append(d)
    return out


def _load_hypotheses_many(paths):
    from . import approval
    out = []
    seen = set()
    for path in paths:
        for h in approval.load_hypotheses(Path(path)):
            if h.hypothesis_id in seen:
                raise ValueError(f"hypothesis_id trùng giữa các vòng: {h.hypothesis_id}")
            seen.add(h.hypothesis_id)
            out.append(h)
    return out


def cmd_pivot(a) -> int:
    """Khâu ⑧ → ④: tính lại pivot không nhãn, sinh giả thuyết và phiếu duyệt ◆."""
    from datetime import datetime
    from . import approval
    from .attack.catalog import AttackCatalog
    from .contracts import ContractA
    from .data.store import connect
    from .llm import providers
    from .llm.prompting import load_sections
    from .stages import s8_pivot, s8_triage

    ds, rp, cfg = _ds(), _rp(), _agent_cfg()
    ca = ContractA.model_validate_json(Path(a.contract_a).read_text(encoding="utf-8"))
    if ca.report_id in rp["eval_reports"]:
        try:
            _labels_gate(rp)
        except integrity.NotFrozenError as e:
            print(e)
            return 1
    hyps = _load_hypotheses_many(a.hypotheses)
    results = _load_results(a.results)
    if not results or any(not r.get("truy_van") for r in results):
        print("Cần kết quả `hunt` có `truy_van` cho toàn bộ giả thuyết của vòng hiện tại.")
        return 1
    specs = [s8_triage.spec_from_result(r) for r in results]
    history = [json.loads(Path(p).read_text(encoding="utf-8")) for p in a.history]
    con = connect(config.resolve(ds["work_dir"]))
    try:
        plan = s8_pivot.plan_round(con, specs, hyps, cfg, history)
    except s8_pivot.PivotError as e:
        print(e)
        return 1
    run_dir = Path(a.out) if a.out else config.resolve("runs") / f"pivot_{datetime.now().strftime('%Y%m%d-%H%M%S')}_{ca.report_id}"
    if run_dir.exists() and any(run_dir.iterdir()):
        print(f"Thư mục vòng pivot đã có nội dung: {run_dir}")
        return 1
    selected = plan["selected"]
    generated = {"hypotheses": [], "log": {"so_pivot": 0, "so_gia_thuyet": 0}}
    telemetry = ho_so = None
    if selected:
        telemetry, ho_so = _telemetry(con, EVAL_DATASET_ID, out_dir=run_dir)
        stix = config.resolve(rp["attack"]["stix_path"])
        attack = AttackCatalog.from_stix(stix) if stix.exists() else None
        prompt = load_sections(config.resolve(cfg["prompt_khau4_pivot"]))
        llm = providers.from_config(config.load("llm_hunt"))
        generated = s8_pivot.generate_round(ca, telemetry, hyps, plan, llm, prompt, cfg, attack, run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    round_log = dict(plan["triage"]["nhat_ky_vong"])
    if selected and not generated["hypotheses"]:
        round_log["ly_do_dung"] = "mô hình không sinh giả thuyết pivot hợp lệ"
    record = {"selected": selected, "source_depth": plan["source_depth"],
              "queries_reserved_before": plan["queries_reserved_before"],
              "queries_reserved_after": plan["queries_reserved_after"],
              "nhat_ky_vong": round_log, "pivot": plan["triage"]["pivot"],
              "generated_ids": [h.hypothesis_id for h in generated["hypotheses"]], "khau4": generated["log"],
              "ho_so": ho_so}
    (run_dir / "pivot_round.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    if generated["hypotheses"]:
        form = approval.write_review(generated["hypotheses"], run_dir, telemetry=telemetry)
        print(f"{len(selected)} pivot → {len(generated['hypotheses'])} giả thuyết chờ duyệt ◆: {form}")
        print(f"Điền phiếu rồi chạy: python -m cti_hunt approve {run_dir}")
    else:
        print(f"Không có giả thuyết pivot mới; lý do dừng: {plan['triage']['pivot']['ly_do_dung'] or 'mô hình không sinh giả thuyết hợp lệ'}")
    print(f"Nhật ký vòng: {run_dir / 'pivot_round.json'}")
    return 0


def cmd_agent(a) -> int:
    """Graph D10 toàn trình ④→⑨: chế độ pipeline (mốc) hoặc agent; dừng ở mỗi phiếu ◆, tiếp tục bằng `resume`."""
    from .agent import moc, session
    from .contracts import ContractA
    try:
        if a.agent_cmd == "chi-phi":
            from .agent.chi_phi import run_cost
            print(json.dumps(run_cost(Path(a.run_dir)), ensure_ascii=False, indent=2))
            return 0
        if a.agent_cmd == "freeze":
            path = moc.create(a.mode, a.nguoi_chot, [Path(d) for d in a.dev_data],
                              **({"version": a.phien_ban} if getattr(a, "phien_ban", "v1") == "v2" else {}))
            print(f"Đã ghi mốc {path}. Commit tệp này rồi mới chạy `agent start --dataset-kind danh_gia`.")
            return 0
        if a.agent_cmd == "start":
            rp = _rp()
            ca = ContractA.model_validate_json(Path(a.contract_a).read_text(encoding="utf-8"))
            if ca.report_id in rp["eval_reports"]:
                _labels_gate(rp)
            run_dir = Path(a.out)
            out = session.start(a.mode, Path(a.contract_a), Path(a.events), run_dir, dataset_kind=a.dataset_kind,
                                dataset_id=a.dataset_id, dataset_sha256=a.dataset_sha256 or "",
                                dry_run=a.dry_run,
                                **({"version": a.phien_ban} if getattr(a, "phien_ban", "v1") == "v2" else {}))
        else:
            run_dir = Path(a.run_dir)
            out = session.recover(run_dir) if a.agent_cmd == "phuc-hoi" else session.resume(run_dir)
    except (ValueError, RuntimeError, integrity.NotFrozenError) as e:
        print(f"[{type(e).__name__}] {e}")
        return 1
    if out["trang_thai"] == "dry_run":
        print(json.dumps(out, ensure_ascii=False, indent=2))
    elif out["trang_thai"] == "da_huy":
        print(f"Đã hủy trước thực thi lô lọc: {out['record']}")
    elif out["trang_thai"] == "cho_duyet":
        filename = "duyet_loc.yaml" if out.get("review_kind") == "filter" else "duyet.yaml"
        print(f"Chờ duyệt ◆: {Path(out['review_dir']) / filename}")
        if out.get("review_kind") == "filter" and (Path(out["review_dir"]) / "duyet_rule.yaml").exists():
            print(f"Phiếu giữ/bỏ rule: {Path(out['review_dir']) / 'duyet_rule.yaml'}")
        print(f"Điền xong chạy: python -m cti_hunt agent resume {run_dir}")
    else:
        print(f"Xong. Hunt record (bản vận hành, không nhãn): {out['hunt_record']}")
        print(f"Nhật ký lượt: {out['record']}")
    return 0


def cmd_triage(a) -> int:
    """Khâu ⑧ phần xác định: gom nhóm, tương quan, đề xuất pivot. Chạy lại truy vấn trên `events`, không nhìn nhãn."""
    from datetime import datetime
    from .data.store import connect
    from .stages import s8_triage
    ds, cfg = _ds(), _agent_cfg()
    results = [r for r in _load_results(a.results) if r.get("truy_van")]
    if not results:
        print("Không có kết quả hunt nào có `truy_van` (chạy lại `hunt` bằng bản mới).")
        return 1
    con = connect(config.resolve(ds["work_dir"]))
    tr = s8_triage.triage(con, [s8_triage.spec_from_result(r) for r in results], cfg, a.depth, a.queries_used)
    for h in tr["hunts"]:
        print(f"  {h['hypothesis_id']:<14} {h['nguon_log']:<45} {h['so_su_kien']} sự kiện")
    print("\nThực thể khớp ≥2 giả thuyết:")
    for e in [e for e in tr["thuc_the"] if e["so_gia_thuyet"] >= 2] or []:
        print(f"  {e['loai']:<10} {e['gia_tri']:<20} {e['so_gia_thuyet']} gt · {e['so_nguon_log']} nguồn · {e['so_su_kien']} sk")
    for e in tr["loai_tru"]:
        print(f"  [loại] {e['gia_tri']}: {e['ly_do']}")
    print(f"\nĐề xuất pivot (chờ duyệt ◆): {len(tr['pivot']['de_xuat'])} · lý do dừng: {tr['pivot']['ly_do_dung'] or '-'}")
    for p in tr["pivot"]["de_xuat"]:
        print(f"  {p['loai']} {p['gia_tri']} — {p['ly_do']}")
    out = Path(a.out) if a.out else config.resolve("runs") / f"triage_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(tr, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"Đã ghi {out}")
    return 0


def cmd_rarity(a) -> int:
    """Khâu ⑦: chấm điểm sau lọc trên events, không đọc nhãn hay kết quả hunt."""
    from datetime import datetime
    from .data.store import connect
    from .stages import s7_rarity

    ds = _ds()
    con = connect(config.resolve(ds["work_dir"]))
    specs = []
    for path in map(Path, a.hunt_files):
        files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")) if path.is_dir() else [path]
        for file in files:
            specs.extend(_load_hunts(file, con))
    if not specs:
        print("Không có hunt spec nào để chấm điểm.")
        return 1
    cfg = config.load("agent")["rarity"]
    result = s7_rarity.score(con, specs, window_seconds=int(cfg["recon_window_seconds"]),
                             entropy_threshold=float(cfg["entropy_threshold"]))
    result["tham_so"]["agent_config_sha256"] = integrity.sha256_file(config.resolve("configs/agent.yaml"))
    if a.confirmed_benign:
        feedback = json.loads(Path(a.confirmed_benign).read_text(encoding="utf-8"))
        if not isinstance(feedback, list):
            raise ValueError("--confirmed-benign cần JSON array")
        result["de_xuat_loai_tru"] = [s7_rarity.propose_exclusion(
            item["sample"], reason=item["reason"], owner=item["owner"], expires=item["expires"])
            for item in feedback]
    print(f"{len(specs)} hunt · {result['so_su_kien']} sự kiện sau mục lọc đã duyệt; điểm chỉ để xếp hạng")
    for row in result["su_kien"][:a.top]:
        print(f"  {row['score']:.4f}  {row['hunt_id']}  {row['ev_host']}  {row['ev_rec']}")
    out = Path(a.out) if a.out else config.resolve("runs") / f"rarity_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Đã ghi {out}")
    return 0


def cmd_ioc(a) -> int:
    from .stages import s2_ioc
    ds, rp = _ds(), _rp()
    rules = s2_ioc.load_rules(config.resolve(ds["ioc_rules"]))
    if a.eval_set:
        out = config.resolve("runs") / "ioc_eval_set.json"
        try:
            _labels_gate(rp)
            result = s2_ioc.run_on_eval_set(config.resolve(rp["segments_jsonl"]),
                                            config.resolve(rp["labels_frozen_dir"]), rules, out)
        except Exception as e:
            print(e)
            return 1
        for report, iocs in sorted(result.items()):
            print(f"{report}: {len(iocs)} IOC")
            for i in iocs:
                print(f"  {i.type:<10} {i.value}   [{i.source_span.segment_id}]")
        print(f"Đã ghi {out}")
        from .labels import reports
        ref = reports.load(_frozen_labels(rp))["ioc"]
        if ref and all(str(r.get("nguon_de_xuat") or "").lower().startswith("regex") for r in ref):
            print("\n[CẢNH BÁO] IOC tham chiếu trong bộ nhãn đóng băng đều sinh bằng regex — cùng phương pháp với nhánh "
                  "IOC này. So hai bên sẽ ra P = R = 100% bất kể regex đúng hay sai. KHÔNG báo P/R IOC trên bộ này.")
        return 0
    for path in a.files:
        text = Path(path).read_text(encoding="utf-8")
        print(f"== {path}")
        for i in s2_ioc.extract(text, rules):
            print(f"  {i.type:<10} {i.value}")
    return 0


def cmd_telemetry(a) -> int:
    from .data.store import connect
    from .stages import s3_telemetry
    ds = _ds()
    catalog = s3_telemetry.load_catalog(config.telemetry_catalog(a.phien_ban))
    for tid, e in sorted(catalog.items()):
        srcs = "; ".join(f"{s['channel']} {s.get('event_ids') or 'mọi EID'}" for s in e.get("sources") or []) or "-"
        print(f"{tid:<12}{e['status']:<14}{srcs}")
    if not a.check:
        return 0
    events_dir = Path(a.events) if a.events else config.resolve(ds["work_dir"])
    if not (events_dir / "events.parquet").exists():
        print(f"Chưa có {events_dir / 'events.parquet'}, bỏ qua phần đối chiếu dữ liệu.")
        return 0
    manifest = events_dir / "ingest_manifest.json"
    dataset_id = (json.loads(manifest.read_text(encoding="utf-8")).get("dataset_id") if manifest.exists() else None) \
        or (EVAL_DATASET_ID if events_dir.resolve() == config.resolve(ds["work_dir"]).resolve() else events_dir.name)
    profile = s3_telemetry.build_profile(connect(events_dir), catalog, dataset_id)
    print(f"\nHồ sơ bộ dữ liệu {dataset_id} (sha256 {s3_telemetry.profile_sha256(profile)[:16]}); "
          "M1: bỏ nguồn khi kênh vắng hoặc thiếu trường bắt buộc")
    dropped = 0
    for tid, p in profile["ky_thuat"].items():
        mark = p["trang_thai"] if p["trang_thai"] == p["trang_thai_danh_muc"] else \
            f"{p['trang_thai_danh_muc']} -> {p['trang_thai']}"
        print(f"{tid:<12}{mark}")
        for r in p["nguon"]:
            label = f"{r['channel']} {r['event_ids']}"
            if not r["giu"]:
                dropped += 1
                why = "kênh không được thu thập" if r["ly_do_bo"] == "kenh_khong_thu_thap" else \
                    "thiếu trường bắt buộc " + ", ".join(r["truong_khong_co_gia_tri"])
                print(f"   [BỎ] {label}: {why}")
            elif r["truong_khong_co_gia_tri"]:
                print(f"   [TRƯỜNG] {label}: không có giá trị ở {', '.join(r['truong_khong_co_gia_tri'])}")
            elif not r["da_kiem_truong"]:
                print(f"   [GIỮ, 0 sự kiện] {label}: kênh đã thu thập, chưa kiểm được trường")
    print(f"{dropped} nguồn bị bỏ" if dropped else "Không nguồn nào bị bỏ.")
    return 1 if dropped else 0


def cmd_ttp(a) -> int:
    import json as _json
    from datetime import datetime
    from .attack.catalog import AttackCatalog
    from .llm import providers
    from .stages import s2_ttp
    rp = _rp()
    phien_ban = getattr(a, "phien_ban", "v1") or "v1"
    cfg = config.load("llm_v2" if phien_ban == "v2" else "llm")
    prompt = s2_ttp.load_prompt(config.resolve(a.prompt or cfg["prompt_file"]))
    v2 = None
    if phien_ban == "v2":
        from .stages import s2_v2
        if not a.dry_run and not config.resolve("docs/giao_thuc_khau2_v2.md").exists():
            print("Chưa khóa v2: cần giao thức docs/giao_thuc_khau2_v2.md trước khi chạy trên 3 report (N3 §3.3).")
            return 1
        try:
            v2 = s2_v2.build(cfg)[0]
        except (OSError, ValueError, KeyError) as e:
            print(f"Chưa dựng được v2: {e}")
            return 1
    segs_path = config.resolve(a.segments or rp["segments_jsonl"])
    if not segs_path.exists():
        print(f"Chưa có {segs_path}. Chạy `segments` trước.")
        return 1
    segments = [_json.loads(line) for line in segs_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    batch_size = int(a.batch_size or cfg.get("batch_size", 8))

    if a.dry_run:
        report = a.report or segments[0]["report"]
        batch = [s for s in segments if s["report"] == report][:batch_size]
        candidates = s2_ttp.render_candidates(s2_ttp.candidates_for_batch(v2.index, batch, v2.per_segment),
                                              v2.desc_chars) if v2 else None
        user = s2_ttp.render_batch(prompt, report, batch, candidates)
        system = prompt["system"]
        llm = providers.from_config(cfg)          # chỉ dựng đối tượng, KHÔNG gọi API
        print(f"# prompt {prompt['path']} sha256={prompt['sha256'][:16]} | mô hình {cfg.get('model') or '(chưa chốt)'}"
              f" | batch {batch_size} đoạn")
        if hasattr(llm, "build_payload"):         # in đúng thứ sẽ gửi, kể cả phần adapter tự thêm
            payload = llm.build_payload(system, user, s2_ttp.ExtractionBatch.model_json_schema())
            system = payload["system"]
            tham_so = {k: v for k, v in payload.items() if k not in ("system", "messages", "tools")}
            tool = payload["tools"][0]
            print(f"# tham số: {_json.dumps(tham_so, ensure_ascii=False)}")
            print(f"# công cụ: {tool['name']} · strict={tool.get('strict', False)}")
        print()
        print("===== SYSTEM =====")
        print(system)
        print("\n===== USER (lô đầu tiên) =====")
        print(user)
        return 0

    try:
        _labels_gate(rp)
    except integrity.NotFrozenError as e:
        print(e)
        return 1
    catalog = AttackCatalog.from_stix(config.resolve(rp["attack"]["stix_path"]))
    llm = providers.from_config(cfg)
    resume = bool(a.resume)
    run_dir = Path(a.resume) if resume else \
        config.resolve("runs") / f"khau2{'_v2' if v2 else ''}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    try:
        result = s2_ttp.run_on_eval_set(segs_path, config.resolve(rp["labels_frozen_dir"]), llm, catalog,
                                        prompt, batch_size, run_dir, resume=resume, v2=v2)
    except providers.TransportError as e:
        # Lỗi mạng đã thử lại đủ lượt: giữ nguyên lô đã xong, chạy tiếp bằng --resume
        print(f"Dừng vì lỗi mạng: {e}")
        print(f"Các lô đã xong được giữ nguyên. Chạy tiếp (cùng cấu hình):\n"
              f"  python -m cti_hunt ttp --resume {run_dir}{' --phien-ban v2' if v2 else ''}")
        return 1
    except Exception as e:
        print(e)
        return 1
    goi_lai = that_bai = 0
    for report, r in sorted(result.items()):
        sc = r["log"].get("su_co", {})
        goi_lai += len(sc.get("lo_goi_lai", []))
        that_bai += len(sc.get("lo_that_bai", []))
        print(f"{report}: {r['log']['so_muc_giu']} TTP giữ lại / {r['log']['so_muc_tho']} thô"
              f" · mã sửa: {r['log']['ma_sua'] or 'không'}")
    print(f"Sự cố: {goi_lai} lô phải gọi lại · {that_bai} lô thất bại"
          + (" (chi tiết lô nào ở meta.json)" if goi_lai or that_bai else ""))
    for report, r in sorted(result.items()):
        for lo in r["log"].get("su_co", {}).get("lo_that_bai", []):
            print(f"  [THẤT BẠI] {report} lô {lo['lo']} ({', '.join(lo['segment_ids'])}): {lo['ly_do'][:120]}")
    # Bị cắt vì max_tokens là lô hỏng; mục tiêu là không để xảy ra, nên báo sớm cả lô mới tiệm cận trần.
    sat_tran = [x for r in result.values() for x in r["log"].get("su_co", {}).get("stop_reason_theo_lo", [])
                if (x.get("output_tokens") or 0) >= 0.8 * (x.get("max_tokens") or 1)]
    if sat_tran:
        print(f"[CẢNH BÁO] {len(sat_tran)} lô dùng quá 80% max_tokens — nới max_output_tokens trước lần sau:")
        for x in sat_tran[:5]:
            print(f"  {x['report']} lô {x['lo']}: {x['output_tokens']}/{x['max_tokens']} token"
                  f" (stop_reason={x.get('stop_reason')!r})")
    meta = run_dir / "meta.json"
    if meta.exists():
        m = _json.loads(meta.read_text(encoding="utf-8"))
        m["bo_nhan_tham_chieu"] = _labels_info(rp)
        meta.write_text(_json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Đã ghi {run_dir}")
    return 0


def dev_ttp_config(phien_ban: str, cfg2: dict, effort: str | None = None) -> dict:
    """Trên tập phát triển, v1 và v2 dùng CÙNG cấu hình mô hình và sổ ngân sách của llm_v2; chỉ khác prompt.
    `effort` (nếu có) ghi đè cho cả hai bản như nhau, để đo chi phí/chất lượng mà không sửa cấu hình v2."""
    out = dict(cfg2) if phien_ban == "v2" else {**cfg2, "prompt_file": config.load("llm")["prompt_file"]}
    if effort:
        out["effort"] = effort
    return out


def cmd_dev_ttp(a) -> int:
    """Khâu ② trên tập phát triển procedure example (N3 §3.3): v1 làm mốc, v2 để chỉnh. Không dùng Silver v1."""
    import json as _json
    from datetime import datetime
    from .attack.catalog import AttackCatalog
    from .eval import proc_examples as D
    from .llm import providers
    from .stages import s2_ttp, s2_v2
    rp = _rp()
    cfg2 = config.load("llm_v2")
    if a.tap == "giu_lai" and not a.cho_phep_giu_lai:
        print("Tập giữ lại chỉ chạy sau khi khóa v2 (N3 §3.3). Khi đã khóa, thêm --cho-phep-giu-lai.")
        return 1
    try:
        options, dev, manifest = s2_v2.build(cfg2)
    except (OSError, ValueError, KeyError) as e:
        print(f"Chưa dựng được v2: {e}")
        return 1
    items = [i for i in dev if i["tap"] == a.tap][: a.gioi_han or None]
    cfg = dev_ttp_config(a.phien_ban, cfg2, a.effort)
    v2 = options if a.phien_ban == "v2" else None
    prompt = s2_ttp.load_prompt(config.resolve(cfg["prompt_file"]))
    segments, batch = D.dev_segments(items), int(cfg2["dev_batch_size"])

    if a.dry_run:
        users = []
        for s in range(0, len(segments), batch):
            part = segments[s:s + batch]
            cand = s2_ttp.render_candidates(s2_ttp.candidates_for_batch(v2.index, part, v2.per_segment),
                                            v2.desc_chars) if v2 else None
            users.append(s2_ttp.render_batch(prompt, "DEV", part, cand))
        print(f"# {a.phien_ban} · tập {a.tap} · {len(items)} câu · {len(users)} lô × {batch} câu"
              f" · prompt {prompt['path']} sha256={prompt['sha256'][:16]} · mô hình {cfg.get('model')}")
        print(f"# ký tự SYSTEM + USER của lượt rút, cộng mọi lô: {sum(len(prompt['system']) + len(u) for u in users)}"
              + (" · cộng thêm một lượt kiểm mỗi lô có mục" if v2 else ""))
        print("\n===== USER (lô đầu tiên) =====")
        print(users[0] if users else "(không có câu)")
        return 0

    catalog = AttackCatalog.from_stix(config.resolve(rp["attack"]["stix_path"]))
    llm = providers.from_config(cfg)
    out = Path(a.out) if a.out else \
        config.resolve("data/dev/n3") / f"dev_ttp_{a.phien_ban}_{a.tap}_{datetime.now():%Y%m%d-%H%M%S}"
    if out.exists() and any(out.iterdir()):
        print(f"{out} đã có nội dung; dùng thư mục mới")
        return 1
    out.mkdir(parents=True, exist_ok=True)
    meta = {"chay_luc": datetime.now().isoformat(timespec="seconds"), "phien_ban": a.phien_ban, "tap": a.tap,
            "so_cau": len(items), "gioi_han": a.gioi_han, "prompt": prompt["path"], "prompt_sha256": prompt["sha256"],
            "model": getattr(llm, "model_id", "?"), "cau_hinh_mo_hinh": llm.describe() if hasattr(llm, "describe") else {},
            "lo": batch, "tap_phat_trien": manifest, "v2": v2.describe() if v2 else None,
            "attack_version": catalog.version}
    (out / "meta.json").write_text(_json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        ttps, log = s2_ttp.extract_report("DEV", segments, llm, catalog, prompt, batch, out, v2=v2)
    except Exception as e:                        # lỗi mạng/ngân sách: giữ mọi bản ghi đã có, không gọi lại
        print(f"Dừng: {type(e).__name__}: {e}. Bản ghi đã có ở {out}")
        return 1
    score = D.score_dev(items, segments, ttps)
    (out / "ket_qua.json").write_text(_json.dumps({"log": log, "diem": score}, ensure_ascii=False, indent=2,
                                                  default=str), encoding="utf-8")
    for part in ("tat_ca", "khong_link_ma"):
        s = score[part]
        print(f"{part}: đúng mã {s['dung_ma']}/{s['so_cau']} · cùng cha {s['cung_ky_thuat_cha']}"
              f" · precision (giới hạn dưới) {s['precision_gioi_han_duoi']}")
    print(f"Sự cố: {len(log['su_co']['lo_that_bai'])} lô thất bại"
          + (f" · {len(log['su_co'].get('kiem_that_bai', []))} lượt kiểm thất bại" if v2 else "")
          + f" · đã ghi {out}")
    return 0


def cmd_segments(a) -> int:
    from .stages import s1_segments
    rp = _rp()
    xlsx = Path(a.xlsx) if a.xlsx else _labels_xlsx_default(rp)
    print(f"Đọc {xlsx}")
    only = set(a.reports.split(",")) if a.reports else set(rp["eval_reports"])
    counts = s1_segments.export(xlsx, config.resolve(rp["segments_jsonl"]), only)
    print(f"Đã xuất {sum(counts.values())} đoạn {counts} -> {rp['segments_jsonl']}")
    return 0


def cmd_check_labels(a) -> int:
    from .attack.catalog import AttackCatalog
    from .labels import reports
    rp = _rp()
    xlsx = Path(a.xlsx) if a.xlsx else _labels_xlsx_default(rp)
    print(f"Đọc {xlsx}")
    catalog = AttackCatalog.from_stix(config.resolve(rp["attack"]["stix_path"]))
    data = reports.load(xlsx)
    if a.report:
        keep = set(a.report.split(","))
        data = {"segments": [s for s in data["segments"] if s.report in keep],
                "nhan": [r for r in data["nhan"] if r["report"] in keep],
                "ioc": [r for r in data["ioc"] if r["report"] in keep]}
    print(f"ATT&CK v{catalog.version}: {len(catalog.techniques)} mã kỹ thuật")
    for rep, d in sorted(reports.progress(data).items()):
        print(f"  {rep}: {d['da_xem']}/{d['doan']} đoạn đã xem · {d['dong_nhan']} dòng nhãn · {d['ioc']} IOC")
    issues = reports.check(data, catalog)
    for i in issues:
        loc = f"{i['sheet']}" + (f" dòng {i['dong']}" if i["dong"] else "") + f" {i['ma_doan']}"
        print(f"[{'LỖI' if i['muc'] == 'loi' else 'lưu ý'}] {loc}: {i['noi_dung']}")
    n_err = sum(1 for i in issues if i["muc"] == "loi")
    print(f"{n_err} lỗi, {len(issues) - n_err} lưu ý")
    return 1 if n_err else 0


def cmd_freeze(a) -> int:
    d = Path(a.directory)
    rp = _rp()
    if d.resolve() == config.resolve(rp["labels_frozen_dir"]).resolve():
        f = d / rp["labels_frozen_xlsx"]
        if not f.exists():
            print(f"Thiếu {f}. Chép file nhãn vào thư mục này trước khi đóng băng.")
            return 1
        want = rp.get("labels_frozen_sha256")
        if want and integrity.sha256_file(f) != want:
            print(f"{f.name} không đúng SHA256 khai trong configs/reports.yaml ({want[:16]}…). Không đóng băng.")
            return 1
        extra = sorted(x.name for x in d.iterdir() if x.is_file() and x.name not in (f.name, integrity.MANIFEST_NAME))
        if extra:
            print(f"Thư mục có file lạ {extra} — chỉ để đúng file nhãn rồi đóng băng.")
            return 1
        print(f"Bộ nhãn: {rp.get('labels_kind', '?')} — {f.name}")
    if (d / integrity.MANIFEST_NAME).exists() and not a.overwrite:
        print(f"{d} đã có {integrity.MANIFEST_NAME}. Đã đóng băng thì không ghi đè; cần sửa nhãn thì tạo bản mới.")
        return 1
    out = integrity.write_manifest(d)
    print(out.read_text(encoding="utf-8"))
    return 0


def cmd_api_budget(a) -> int:
    from .llm.budget import BudgetError, Ledger, configured_path
    try:
        ledger = Ledger(configured_path())
        if a.budget_cmd == "init":
            out = ledger.init(a.usd)
        elif a.budget_cmd == "set-limit":
            out = ledger.set_limit(a.usd)
        elif a.budget_cmd == "resolve":
            out = ledger.resolve(a.request_id, a.cost_usd, a.note)
        else:
            out = ledger.status()
    except (BudgetError, OSError, KeyError) as e:
        print(f"[Ngân sách] {e}")
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="cti_hunt", description="Topic 5 — Threat Hunting từ CTI report")
    sub = p.add_subparsers(dest="cmd", required=True)
    from .report_cli import register as register_report_commands
    register_report_commands(sub)
    s = sub.add_parser("api-budget", help="Hạn mức USD dùng chung cho ④⑤/pivot/planner, không nạp tiền hay gọi API")
    bs = s.add_subparsers(dest="budget_cmd", required=True)
    for action in ("init", "set-limit"):
        b = bs.add_parser(action, help="đặt tổng hạn mức cục bộ (không phải số dư tài khoản)")
        b.add_argument("--usd", required=True, help="tổng USD cho phép, bao gồm số đã dùng trong sổ")
    bs.add_parser("status", help="xem chi phí đã ghi, khoản đang giữ và phần còn lại")
    b = bs.add_parser("resolve", help="người vận hành đối soát yêu cầu chưa rõ chi phí từ Console; không chạy khi yêu cầu còn đang gửi")
    b.add_argument("request_id")
    b.add_argument("--cost-usd", required=True)
    b.add_argument("--note", required=True, help="căn cứ đối soát từ Console")
    s.set_defaults(fn=cmd_api_budget)

    s = sub.add_parser("verify", help="Kiểm tra SHA256 dataset, nhãn v1, STIX; trạng thái đóng băng")
    s.add_argument("--skip-raw", action="store_true", help="Bỏ qua hash file JSON 1,7 GB")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("ingest", help="JSON OTRF -> data/work/events.parquet")
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("ingest-dev", help="E1: nạp một bộ OTRF phát triển (zip/tar.gz/json) -> data/dev/<mã>/events.parquet")
    s.add_argument("src", help="gói OTRF đã tải (không phải tệp APT29 day 2)")
    s.add_argument("--id", required=True, dest="dataset_id", help="mã bộ dữ liệu, vd otrf-empire-psexec")
    s.add_argument("--out", help="thư mục đích mới (mặc định data/dev/<mã>)")
    s.add_argument("--offset-hours", type=int,
                   help="lệch EventTime -> UTC nếu khác cấu hình (vd 5 cho bộ ghi mùa đông); luôn kiểm lại trên Sysmon")
    s.set_defaults(fn=cmd_ingest_dev)

    s = sub.add_parser("labels", help="Join nhãn sự kiện v1 với events, in thống kê theo bước")
    s.set_defaults(fn=cmd_labels)

    s = sub.add_parser("hunt", help="Chạy hunt YAML, in chỉ số theo giai đoạn, ghi runs/*.json")
    s.add_argument("hunt_files", nargs="+")
    s.add_argument("--force", action="store_true", help="Vẫn chạy khi join nhãn có vấn đề")
    s.set_defaults(fn=cmd_hunt)

    s = sub.add_parser("sigma", help="Biên dịch rule Sigma sang truy vấn DuckDB (một hunt cho mỗi nguồn log)")
    s.add_argument("rule_files", nargs="+")
    s.add_argument("--phien-ban", choices=["v1", "v2"], default="v1")
    s.add_argument("--run", action="store_true", help="Chạy luôn và đo như nhánh B")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_sigma)

    s = sub.add_parser("exec-acc", help="Execution accuracy khâu ⑤: so tập kết quả rule sinh với rule chuẩn (không dùng nhãn)")
    s.add_argument("ref", help="rule chuẩn: hunt YAML nhánh A hoặc rule Sigma (vd SigmaHQ)")
    s.add_argument("gen", help="rule sinh ra: rule Sigma hoặc hunt YAML")
    s.add_argument("--ref-extra", action="append", default=[], help="file chuẩn bổ sung đã chọn theo G0(c); hợp tập kết quả, có thể lặp")
    s.add_argument("--events", help="thư mục events.parquet để đo không nhãn (mặc định dataset.work_dir)")
    s.add_argument("--out", help="file JSON kết quả (mặc định runs/<thời điểm>_exec_acc.json)")
    s.add_argument("--quy-tac", choices=["v1", "v2"], default="v1",
                   help="G0(c) v1: chuẩn cùng đúng phạm vi; v2: thu EID chuẩn về EID hunt sinh khi là tập con cùng channel")
    s.set_defaults(fn=cmd_exec_acc)

    s = sub.add_parser("hypotheses", help="Khâu ④: sinh giả thuyết từ Contract A, ghi phiếu duyệt")
    s.add_argument("contract_a", help="file contract_a_<report>.json")
    s.add_argument("--out", help="thư mục chạy (mặc định runs/khau4_<thời điểm>_<report>)")
    s.set_defaults(fn=cmd_hypotheses)

    s = sub.add_parser("approve", help="Điểm dừng ◆: áp phiếu duyet.yaml đã điền")
    s.add_argument("run_dir")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("rules", help="Khâu ⑤: sinh rule Sigma cho giả thuyết đã duyệt, kiểm tra tĩnh, tự sửa")
    s.add_argument("run_dir")
    s.add_argument("--phien-ban", choices=["v1", "v2"], default="v1")
    s.add_argument("--events", type=Path, help="v2: bộ events không nhãn để phát phiếu lọc")
    s.add_argument("--dataset-kind", choices=["fixture", "otrf_dev"])
    s.add_argument("--dataset-id")
    s.add_argument("--dataset-sha256", default="")
    s.set_defaults(fn=cmd_rules)

    from .filter_cli import register as register_filter_commands
    register_filter_commands(sub)

    s = sub.add_parser("record", help="Khâu ⑨: hunt record Markdown; --eval thêm số liệu ground truth")
    s.add_argument("--contract-a", required=True)
    s.add_argument("--hypotheses", nargs="+", required=True, help="một hoặc nhiều hypotheses_da_duyet.json")
    s.add_argument("--results", nargs="+", required=True, help="file runs/*.json của lệnh hunt, hoặc thư mục")
    s.add_argument("--eval", action="store_true", help="thêm mục 9 theo ground truth — không đưa người duyệt")
    s.add_argument("--triage", help="file triage_*.json của lệnh triage (mục 4–5 và pivot từng phát hiện)")
    s.add_argument("--pivot-rounds", nargs="*", default=[], help="các pivot_round.json để ghi nhật ký vòng lặp")
    s.add_argument("--rarity", help="file rarity_*.json của khâu ⑦ (điểm độ hiếm từng phát hiện)")
    s.add_argument("--ho-so", help="ho_so_du_lieu.json của lượt ④ (mặc định: lập lại từ events của data/work)")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_record)

    s = sub.add_parser("rarity", help="Khâu ⑦: xếp hạng sự kiện sau lọc trên events (không nhãn)")
    s.add_argument("hunt_files", nargs="+", help="hunt YAML, rule Sigma hoặc thư mục")
    s.add_argument("--top", type=int, default=10, help="số sự kiện đứng đầu in ra")
    s.add_argument("--confirmed-benign", help="JSON phản hồi chuyên viên để tạo phiếu loại trừ chờ duyệt")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_rarity)

    s = sub.add_parser("triage", help="Khâu ⑧: gom nhóm, tương quan chéo, đề xuất pivot (không nhìn nhãn)")
    s.add_argument("--results", nargs="+", required=True, help="file runs/*.json của lệnh hunt, hoặc thư mục")
    s.add_argument("--depth", type=int, default=0, help="pivot_depth của các hunt này (0 = từ report)")
    s.add_argument("--queries-used", type=int, default=0, help="số truy vấn pivot đã dùng trong cuộc săn")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("pivot", help="Khâu ⑧ → ④: chọn pivot D7, sinh giả thuyết và phiếu duyệt ◆")
    s.add_argument("--contract-a", required=True)
    s.add_argument("--hypotheses", nargs="+", required=True, help="mọi file hypotheses_da_duyet.json đến vòng này")
    s.add_argument("--results", nargs="+", required=True, help="kết quả hunt của CHỈ vòng hiện tại, có truy_van")
    s.add_argument("--history", nargs="*", default=[], help="pivot_round.json của các vòng trước (nếu có)")
    s.add_argument("--out", help="thư mục vòng pivot mới; không ghi đè")
    s.set_defaults(fn=cmd_pivot)

    s = sub.add_parser("agent", help="Graph D10 toàn trình ④→⑨ (pipeline | agent), dừng ở phiếu ◆; "
                                     "APT29 day 2 chỉ sau mốc cố định (E1)")
    agent_sub = s.add_subparsers(dest="agent_cmd", required=True)
    t = agent_sub.add_parser("freeze", help="người vận hành chạy: ghi mốc cố định của một chế độ (hash prompt/cấu hình, mã, "
                                            "mô hình, dữ liệu phát triển) vào configs/moc_co_dinh/")
    t.add_argument("--mode", choices=["pipeline", "agent"], required=True)
    t.add_argument("--phien-ban", choices=["v1", "v2"], default="v1")
    t.add_argument("--nguoi-chot", required=True)
    t.add_argument("--dev-data", nargs="*", default=[], help="thư mục OTRF phát triển (ingest-dev); bắt buộc với agent")
    t = agent_sub.add_parser("start", help="bắt đầu một lượt trong thư mục mới")
    t.add_argument("--mode", choices=["pipeline", "agent"], required=True)
    t.add_argument("--phien-ban", choices=["v1", "v2"], default="v1")
    t.add_argument("--contract-a", required=True)
    t.add_argument("--events", required=True, help="thư mục có events.parquet (data/work chỉ với danh_gia)")
    t.add_argument("--dataset-kind", choices=["fixture", "otrf_dev", "danh_gia"], required=True,
                   help="danh_gia = APT29 day 2, chỉ chạy khi khớp mốc cố định của chế độ")
    t.add_argument("--dataset-id", default="", help="bắt buộc với fixture/otrf_dev")
    t.add_argument("--dataset-sha256", help="bắt buộc với otrf_dev: SHA256 tệp OTRF gốc")
    t.add_argument("--out", required=True, help="thư mục lượt mới (chưa có nội dung)")
    t.add_argument("--dry-run", action="store_true", help="kiểm dữ liệu/cấu hình/model, không gọi API hay tạo lượt")
    t = agent_sub.add_parser("resume", help="tiếp tục sau khi đã điền phiếu duyet.yaml")
    t.add_argument("run_dir")
    t = agent_sub.add_parser("phuc-hoi", help="lượt phát triển dừng ngoài cổng duyệt vì lỗi mạng: chạy lại đúng bước "
                                              "bị ngắt (có thể gọi API); lỗi khác hoặc lượt đánh giá bị từ chối")
    t.add_argument("run_dir")
    t = agent_sub.add_parser("chi-phi", help="chi phí API của một lượt, tính từ nhật ký API của chính lượt (không gọi API)")
    t.add_argument("run_dir")
    s.set_defaults(fn=cmd_agent)

    s = sub.add_parser("sigma-check", help="Chạy hàng loạt rule Sigma (vd SigmaHQ rules/windows) qua adapter, phân loại lỗi")
    s.add_argument("rules_dir")
    s.add_argument("--synthetic", action="store_true", help="bỏ qua dữ liệu thật, chỉ kiểm cú pháp SQL")
    s.add_argument("--top", type=int, default=10, help="số lý do in ra mỗi nhóm")
    s.set_defaults(fn=cmd_sigma_check)

    s = sub.add_parser("score-ttp", help="P/R khâu ② của một lần chạy: bản đủ và bản bỏ mã có sẵn trong văn bản")
    s.add_argument("run_dir", help="thư mục runs/khau2_<thời điểm>")
    s.set_defaults(fn=cmd_score_ttp)

    s = sub.add_parser("ioc", help="Trích IOC bằng regex; --eval-set chạy trên 3 report (cần nhãn đã đóng băng)")
    s.add_argument("files", nargs="*", help="tệp văn bản để thử")
    s.add_argument("--eval-set", action="store_true")
    s.set_defaults(fn=cmd_ioc)

    s = sub.add_parser("telemetry", help="In danh mục nguồn log khâu ③; --check lập hồ sơ bộ dữ liệu (không nhãn)")
    s.add_argument("--check", action="store_true")
    s.add_argument("--events", help="thư mục có events.parquet (mặc định data/work; vd data/dev/otrf-psexec)")
    s.add_argument("--phien-ban", choices=["v1", "v2"], default="v1",
                   help="v1 = danh mục tuyến A (18 mục); v2 = danh mục tuyến B (configs/dataset.yaml telemetry_catalog_v2)")
    s.set_defaults(fn=cmd_telemetry)

    s = sub.add_parser("ttp", help="Khâu ② rút TTP bằng mô hình ngôn ngữ; --dry-run chỉ in prompt")
    s.add_argument("--dry-run", action="store_true", help="In prompt của lô đầu tiên, không gọi API")
    s.add_argument("--segments")
    s.add_argument("--prompt")
    s.add_argument("--report")
    s.add_argument("--batch-size", type=int)
    s.add_argument("--resume", metavar="RUN_DIR",
                   help="chạy tiếp lần chạy đã dừng vì lỗi mạng; lô đã xong không gọi lại")
    s.add_argument("--phien-ban", choices=["v1", "v2"], default="v1",
                   help="v2 = N3 (ứng viên BM25 + lượt kiểm); chạy thật bị chặn tới khi có giao thức v2")
    s.set_defaults(fn=cmd_ttp)

    s = sub.add_parser("dev-ttp", help="Khâu ② trên tập phát triển procedure example (N3); --dry-run không gọi API")
    s.add_argument("--tap", choices=["chinh", "giu_lai"], default="chinh")
    s.add_argument("--phien-ban", choices=["v1", "v2"], default="v2")
    s.add_argument("--gioi-han", type=int, help="chỉ N câu đầu (đo token thật trước khi chạy hết, N3 §7)")
    s.add_argument("--dry-run", action="store_true", help="In prompt lô đầu và tổng ký tự, không gọi API")
    s.add_argument("--cho-phep-giu-lai", action="store_true", help="chỉ dùng sau khi khóa v2 (N3 §3.3)")
    s.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"],
                   help="ghi đè effort cho cả v1 và v2 khi đo (mặc định theo configs/llm_v2.yaml)")
    s.add_argument("--out", help="thư mục kết quả (mặc định data/dev/n3/dev_ttp_<bản>_<tập>_<thời điểm>)")
    s.set_defaults(fn=cmd_dev_ttp)

    s = sub.add_parser("segments", help="Xuất đoạn văn DoanVan -> segments.jsonl (đầu vào khâu ②)")
    s.add_argument("--xlsx")
    s.add_argument("--reports", help="vd SY,PS")
    s.set_defaults(fn=cmd_segments)

    s = sub.add_parser("check-labels", help="Kiểm tra hình thức file gán nhãn report theo R1–R14 và v19.2")
    s.add_argument("--xlsx")
    s.add_argument("--report", help="chỉ kiểm tra report này, vd SY")
    s.set_defaults(fn=cmd_check_labels)

    s = sub.add_parser("freeze", help="Ghi MANIFEST.sha256 cho một thư mục (đóng băng)")
    s.add_argument("directory")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(fn=cmd_freeze)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
