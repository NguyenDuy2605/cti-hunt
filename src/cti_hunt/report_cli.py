"""Commands for new reports, independent of frozen evaluation labels."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from . import config, integrity
from .contracts import ContractA
from .stages import s1_ingest, s2_ioc, s2_report, s3_telemetry


def cmd_ingest_report(a) -> int:
    try:
        out = config.resolve(a.out or f"data/reports/moi/{a.id}")
        manifest = s1_ingest.ingest(a.source, a.id, out, a.selector)
        print(f"{a.id}: {manifest['status']} · {manifest['readable_segments']} đoạn có nội dung"
              f" · {manifest['unread_blocks']} khối chưa đọc")
        for warning in manifest["warnings"]:
            print(f"  [{warning['code']}] {warning['detail']}")
        print(f"Xem và đối chiếu nguồn: {out / 'review.html'}")
        return 1 if manifest["status"] == "blocked" else 0
    except Exception as e:
        print(f"Không nhập được report: {e}")
        return 1


def cmd_ocr_report(a) -> int:
    from .stages import s1_ocr
    try:
        result = s1_ocr.enrich(config.resolve(a.bundle), config.resolve(a.out), dpi=a.dpi,
                               allow_network=a.fetch_images, max_targets=0 if a.all else a.max_targets,
                               continue_ocr=a.continue_ocr, retry_failed=a.retry_failed, engine_name=a.engine,
                               progress=lambda sid, n, status: print(f"  {n}: {sid} · {status}", flush=True))
        print(f"OCR cục bộ: {result['ocr_pending_blocks']} đoạn cần rà; {result['unread_blocks']} khối chưa đọc.")
        print(f"Còn {result['ocr']['remaining_unattempted']} vùng chưa thử; "
              f"{result['image_review_pending_blocks']} ảnh/bản chép đang chờ rà.")
        failures = [w for w in result["warnings"] if w["code"] in ("ocr_failed", "ocr_no_text", "ocr_limit")]
        for warning in failures[:5]:
            print(f"  [{warning['code']}] {warning.get('segment_id', '')}: {warning['detail']}")
        if len(failures) > 5:
            print(f"  Còn {len(failures) - 5} cảnh báo; xem manifest.json.")
        print(f"Đối chiếu ảnh/chữ: {config.resolve(a.out) / 'review.html'}")
        print("Chữ chưa rà không vào TTP/IOC. Điền bản sao ocr_review_template.json rồi chạy review-ocr.")
        return 0
    except Exception as e:
        print(f"Không hoàn tất OCR: {e}")
        return 1


def cmd_review_ocr(a) -> int:
    from .stages import s1_ocr
    try:
        result = s1_ocr.apply_review(config.resolve(a.bundle), config.resolve(a.review), config.resolve(a.out))
        print(f"Đã tạo bản sau rà: {result['readable_segments']} đoạn dùng được; {result['ocr_pending_blocks']} đoạn OCR chờ rà; "
              f"{result['ocr_rejected_blocks']} đoạn bị từ chối.")
        return 0
    except Exception as e:
        print(f"Không áp dụng phiếu OCR: {e}")
        return 1


def cmd_extract_report(a) -> int:
    try:
        bundle = config.resolve(a.bundle)
        manifest, _, _ = s1_ingest.load_bundle(bundle)
        if a.send and manifest["status"] != "extracted" and not a.accept_partial:
            raise ValueError("Report có cảnh báo/phần chưa đọc. Rà review.html; dùng --accept-partial nếu chấp nhận giới hạn đã ghi")
        rp = config.load("reports")  # configuration only; never read labels or evaluation output
        stix = config.resolve(rp["attack"]["stix_path"])
        if integrity.sha256_file(stix) != rp["attack"]["stix_sha256"]:
            raise ValueError("ATT&CK không khớp SHA256 đã ghim")
        llm_cfg = yaml.safe_load(config.resolve(a.llm_config).read_text(encoding="utf-8"))
        if a.send:
            # Every real generation uses the existing shared budget guard, no fallback provider.
            if llm_cfg.get("provider") != "anthropic" or not llm_cfg.get("budget_ledger"):
                raise ValueError("--send yêu cầu provider Anthropic có budget_ledger; không bỏ qua kiểm soát chi phí")
            from .llm.budget import Ledger
            Ledger(config.resolve(llm_cfg["budget_ledger"])).require_ready()
        result = s2_report.run(bundle, stix, config.resolve("prompts/report_extract_v1.md"), llm_cfg,
                               config.resolve(a.out), s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml")),
                               send=a.send, resume=a.resume, batch_size=a.batch_size, top_k=a.top_k,
                               accept_partial=a.accept_partial,
                               segments_selected=[x.strip() for x in a.segments.split(",") if x.strip()]
                               if a.segments is not None else None)
        print(f"{result['report_id']}: {result['status']} · {result['target_units']} phần văn bản / {result['batches']} lô")
        estimate = result.get("uoc_tinh_chi_phi")
        if estimate is not None:
            print(s2_report.cost_summary(estimate))
            for warning in estimate["warnings"]:
                print(f"  Cảnh báo: {warning}")
        else:
            print("Chưa có biểu giá cho mô hình này; không ước tính được chi phí khâu ②.")
        noise = s2_report.noise_summary(result.get("khong_gui_khau2"))
        if noise:
            print(noise)
        if result.get("partial_extraction"):
            print(f"Trích một phần: {len(result['selected_segments'])} đoạn đã chọn trên {result['target_units_total']} "
                  "phần đọc được; Contract A chỉ phản ánh các đoạn này.")
        if a.send:
            print(f"Giữ {result['accepted_ttp']} TTP, loại {result['rejected_items']} mục. Chưa đánh giá độ đúng ngữ nghĩa.")
            print(f"Contract A: {config.resolve(a.out) / 'contract_a.json'}")
        else:
            print(f"Chưa gọi API. Xem toàn bộ prompt: {config.resolve(a.out) / 'requests.json'}")
        return 0
    except Exception as e:
        print(f"Không hoàn tất trích report: {e}")
        return 1


def coverage(contract: ContractA, events: Path, *, version: str = "v1") -> dict:
    from .data.store import connect
    catalog_path = config.telemetry_catalog(version)
    catalog = s3_telemetry.load_catalog(catalog_path)
    con = connect(events)
    try:
        profile = s3_telemetry.build_profile(con, catalog, events.name)
    finally:
        con.close()
    effective = s3_telemetry.apply_profile(catalog, profile)
    rows = []
    for tid in sorted({t.technique_id for t in contract.ttps}):
        mapped = s3_telemetry.map_technique(tid, effective)
        exact = tid in catalog
        kind = "exact" if exact else "inherited_mapping" if "sources" in mapped else "catalog_gap"
        rows.append({"technique_id": tid, "status": mapped["status"], "mapping_kind": kind,
                     "sources": mapped.get("sources", []),
                     "reason": mapped.get("ly_do") or mapped.get("ly_do_partial") or mapped.get("ghi_chu", ""),
                     "review_note": "" if exact else "Thiếu ánh xạ chính xác trong danh mục; không suy rằng môi trường không có log",
                     "evidence": [t.source_span.model_dump() for t in contract.ttps if t.technique_id == tid]})
    return {"report_id": contract.report_id, "dataset": str(events.resolve()), "phien_ban": version,
            "events_sha256": integrity.sha256_file(events / "events.parquet"),
            "catalog_sha256": integrity.sha256_file(catalog_path), "techniques": rows, "profile": profile,
            "labels_used": False, "queries_executed": "telemetry profile only; no hunt"}


def cmd_report_coverage(a) -> int:
    try:
        out = config.resolve(a.out)
        if out.exists():
            raise ValueError("Tệp đầu ra đã tồn tại; dùng tên mới")
        path = config.resolve(a.contract_a)
        ca = ContractA.model_validate_json(path.read_text(encoding="utf-8"))
        result = coverage(ca, config.resolve(a.events), version=a.phien_ban)
        result["contract_a_sha256"] = integrity.sha256_file(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        s1_ingest.write_json(out, result)
        for row in result["techniques"]:
            print(f"{row['technique_id']}: {row['status']} ({row['mapping_kind']}) · {row['reason']}")
        print(f"Đã ghi {out}. Contract A dùng được với agent start --contract-a; vẫn qua cổng duyệt hiện có.")
        return 0
    except Exception as e:
        print(f"Không kiểm tra được telemetry: {e}")
        return 1


def cmd_ioc_sweep(a) -> int:
    from .stages import s2_ioc_sweep
    try:
        contract = ContractA.model_validate_json(config.resolve(a.contract_a).read_text(encoding="utf-8"))
        rules = s2_ioc.load_rules(config.resolve("configs/ioc_rules.yaml"))
        excl = (yaml.safe_load(config.resolve("configs/agent.yaml").read_text(encoding="utf-8")) or {}).get(
            "triage", {}).get("exclude_accounts")
        items = s2_ioc_sweep.plan(contract, rules)
        out = config.resolve(a.out)
        out.mkdir(parents=True, exist_ok=True)
        results = []
        for events in a.events:
            r = s2_ioc_sweep.sweep_dir(items, config.resolve(events), include_weak=a.ca_ioc_yeu, exclude_accounts=excl)
            r["contract_a_sha256"] = integrity.sha256_file(config.resolve(a.contract_a))
            results.append(r)
            t = r["tong"]
            print(f"{Path(events).name}: {t['so_muc']} giá trị ({t['manh']} mạnh, {t['yeu']} yếu, {t['bo']} bỏ) · "
                  f"quét {t['da_quet']} · có khớp {t['co_khop']}")
            for row in r["muc"]:
                if row["so_su_kien"]:
                    print(f"  {row['gia_tri']} [{row['loai']}, {row['muc']}] {row['so_su_kien']} sự kiện · máy "
                          f"{', '.join(row['may'])} · tài khoản {', '.join(row['tai_khoan']) or '—'}")
        (out / "ioc_sweep.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "ioc_sweep.md").write_text("\n".join(s2_ioc_sweep.render(r) for r in results), encoding="utf-8")
        print(f"Đã ghi {out / 'ioc_sweep.json'} và ioc_sweep.md. Khớp IOC là đầu mối để kiểm, không phải kết luận.")
        return 0
    except Exception as e:
        print(f"Không quét được IOC: {e}")
        return 1


def cmd_rule_variants(a) -> int:
    from .stages import rule_variant
    from .data.store import connect
    try:
        cfg = rule_variant.load_config()
        specs = []
        for src in a.specs:
            path = config.resolve(src)
            files = [path] if path.is_file() else sorted(path.rglob("*.yaml"))
            for f in files:
                spec = yaml.safe_load(f.read_text(encoding="utf-8"))
                if isinstance(spec, dict) and spec.get("candidates") and spec.get("scope"):
                    specs.append(spec)
        out = config.resolve(a.out)
        (out / "specs").mkdir(parents=True, exist_ok=True)
        results = []
        for events in a.events:
            rows = rule_variant.compare(specs, connect(config.resolve(events)), cfg)
            for r in rows:
                (out / "specs" / f"{r['spec']['id']}.yaml").write_text(
                    yaml.safe_dump(r.pop("spec"), allow_unicode=True, sort_keys=False), encoding="utf-8", newline="\n")
            results.append({"events": str(events), "version": rule_variant.VERSION, "so_hunt": len(specs), "bien_the": rows})
            print(f"{Path(events).name}: {len(specs)} hunt, {len(rows)} có biến thể")
            for r in rows:
                print(f"  {r['hunt']}: phạm vi {r['pham_vi']} · gốc {r['goc']} · biến thể {r['bien_the']} — {r['mo_ta']}")
        (out / "bien_the.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "bien_the.md").write_text("\n\n".join(rule_variant.render(r["bien_the"]) for r in results), encoding="utf-8")
        print(f"Đã ghi {out / 'bien_the.json'}, bien_the.md và hunt spec biến thể trong {out / 'specs'}. "
              "Biến thể là rule mới: chạy và duyệt như rule ⑤, không tự áp.")
        return 0
    except Exception as e:
        print(f"Không dựng được biến thể rule: {e}")
        return 1


def cmd_community_rules(a) -> int:
    from .data.store import connect
    from .stages import community_rules
    try:
        contract = ContractA.model_validate_json(config.resolve(a.contract_a).read_text(encoding="utf-8"))
        out = config.resolve(a.out)
        out.mkdir(parents=True, exist_ok=True)
        results = []
        for events in a.events:
            r = community_rules.run(connect(config.resolve(events)), contract)
            r["events"] = str(events)
            results.append(r)
            print(f"{Path(events).name}: {len(r['ttp'])} TTP · {r['so_rule_chon']} rule SigmaHQ · {r['so_hunt']} hunt dịch được · "
                  f"{r['co_ket_qua']} có kết quả · {len(r['khong_dich_duoc'])} không dịch được")
        (out / "rule_cong_dong.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "rule_cong_dong.md").write_text("\n\n".join(community_rules.render(r) for r in results), encoding="utf-8")
        print(f"Đã ghi {out / 'rule_cong_dong.json'} và rule_cong_dong.md. Số là đếm trên log, không nhãn.")
        return 0
    except Exception as e:
        print(f"Không chạy được rule cộng đồng: {e}")
        return 1

def cmd_review_report(a) -> int:
    from . import report_review
    try:
        packet = report_review.prepare(config.resolve(a.bundle), config.resolve(a.extraction),
                                       config.resolve(a.out), config.resolve(a.reference) if a.reference else None)
        print(f"{packet['report_id']}: trích {packet['extraction_status']}; ngữ nghĩa {packet['semantic_status']}.")
        print(f"Phiếu tách lỗi bóc chữ/hiểu nội dung: {config.resolve(a.out) / 'review.html'}")
        print("Không tự chấm P/R, không tự duyệt TTP hoặc giả thuyết.")
        return 0
    except Exception as e:
        print(f"Không tạo được phiếu rà report: {e}")
        return 1


def register(sub) -> None:
    p = sub.add_parser("review-report", help="Tạo phiếu rà bóc chữ và TTP riêng biệt; không gọi API, không tự chấm điểm")
    p.add_argument("bundle")
    p.add_argument("--extraction", required=True, help="Thư mục extract-report preview hoặc đã chạy")
    p.add_argument("--reference", help="Bản tham chiếu phát triển; chỉ đọc khi tạo phiếu, không đưa vào prompt")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_review_report)
    p = sub.add_parser("ocr-report", help="OCR cục bộ vùng ảnh/trang quét, giữ riêng chờ rà, không API LLM")
    p.add_argument("bundle")
    p.add_argument("--out", required=True)
    p.add_argument("--dpi", type=int, default=200)
    p.add_argument("--fetch-images", action="store_true", help="Cho phép tải ảnh công khai của HTML, không gửi ảnh ra ngoài")
    p.add_argument("--max-targets", type=int, default=60)
    p.add_argument("--all", action="store_true", help="Xử lý toàn bộ vùng chưa thử, vẫn có trần thời gian/kích thước mỗi vùng")
    p.add_argument("--engine", choices=("rapid", "rapid-en", "tesseract"), default="rapid-en")
    p.add_argument("--continue", dest="continue_ocr", action="store_true", help="Tiếp tục từ bundle OCR vào thư mục mới; giữ kết quả/phiếu đã có")
    p.add_argument("--retry-failed", action="store_true", help="Thử lại cả vùng từng lỗi/rỗng; giữ lịch sử artifact")
    p.set_defaults(fn=cmd_ocr_report)
    p = sub.add_parser("review-ocr", help="Áp phiếu transcript đã đối chiếu ảnh vào bundle mới")
    p.add_argument("bundle")
    p.add_argument("--review", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_review_ocr)
    p = sub.add_parser("ingest-report", help="URL/HTML/PDF/PNG/JPEG mới → nội dung có nguồn và cảnh báo phần chưa đọc")
    p.add_argument("source")
    p.add_argument("--id", required=True)
    p.add_argument("--out")
    p.add_argument("--selector", help="CSS selector chọn đúng một khối nội dung HTML")
    p.set_defaults(fn=cmd_ingest_report)
    p = sub.add_parser("extract-report", help="Report bundle → Contract A; mặc định chỉ chuẩn bị prompt, không gọi API")
    p.add_argument("bundle")
    p.add_argument("--out", required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--send", action="store_true", help="Gọi mô hình thật, dùng sổ ngân sách hiện có")
    mode.add_argument("--dry-run", action="store_true", help="Mặc định: lưu mọi prompt, không gọi API")
    p.add_argument("--resume", action="store_true", help="Giữ nguyên đầu vào/cấu hình, dùng lại lô đã có phản hồi")
    p.add_argument("--accept-partial", action="store_true", help="Đã rà và chấp nhận phần chưa đọc/cảnh báo của parser")
    p.add_argument("--llm-config", default="configs/llm_hunt.yaml", help="Cấu hình riêng của lượt phát triển; không sửa llm.yaml v1")
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--top-k", type=int, default=8)
    p.add_argument("--segments", help="Chỉ trích các mã đoạn này (phân cách dấu phẩy); ghi trích một phần vào meta")
    p.set_defaults(fn=cmd_extract_report)
    p = sub.add_parser("report-coverage", help="Contract A mới → độ phủ telemetry trên log, không nhãn, không gọi API")
    p.add_argument("contract_a")
    p.add_argument("--phien-ban", choices=["v1", "v2"], default="v1")
    p.add_argument("--events", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_report_coverage)
    p = sub.add_parser("ioc-sweep", help="IOC của Contract A → phân loại mạnh/yếu, quét đúng trường trên log; không nhãn, không API")
    p.add_argument("contract_a")
    p.add_argument("--events", required=True, nargs="+", help="Một hay nhiều thư mục có events.parquet")
    p.add_argument("--out", required=True, help="Thư mục ghi ioc_sweep.json và ioc_sweep.md")
    p.add_argument("--ca-ioc-yeu", action="store_true", help="Quét cả IOC yếu (IP nội bộ, dịch vụ phổ biến, tên tệp trơn…)")
    p.set_defaults(fn=cmd_ioc_sweep)
    p = sub.add_parser("rule-variants", help="Hunt spec rule ⑤ → biến thể mức kỹ thuật (giữ vết cơ chế, nới phần tải), đếm trên log; không nhãn, không API")
    p.add_argument("specs", nargs="+", help="Tệp hoặc thư mục hunt spec (vd hunts_effective của một lượt v2)")
    p.add_argument("--events", required=True, nargs="+", help="Một hay nhiều thư mục có events.parquet")
    p.add_argument("--out", required=True, help="Thư mục ghi bien_the.json, bien_the.md và specs/")
    p.set_defaults(fn=cmd_rule_variants)
    p = sub.add_parser("community-rules", help="TTP của Contract A → rule SigmaHQ cùng kỹ thuật, đếm trên log; không nhãn, không API")
    p.add_argument("contract_a")
    p.add_argument("--events", required=True, nargs="+", help="Một hay nhiều thư mục có events.parquet")
    p.add_argument("--out", required=True, help="Thư mục ghi rule_cong_dong.json và rule_cong_dong.md")
    p.set_defaults(fn=cmd_community_rules)
