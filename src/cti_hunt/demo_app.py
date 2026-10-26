"""Streamlit view of the shared checkpointed workflow; no parallel S4/S5 implementation."""
import json
import os
from pathlib import Path

import streamlit as st
import yaml

from . import approval, config, demo, integrity
from .agent import session
from .contracts import ContractA
from .report_cli import coverage
from .stages import hypothesis_grounding as grounding, s1_ingest, s2_report

# Q6 (09/10): lượt có thể chạy vài phút; báo rõ để người dùng không tải lại trang giữa chừng.
RUNNING = "Đang chạy lượt (có thể vài phút, mỗi lời gọi mô hình 1–2 phút) — đừng tải lại trang"


def filter_form(review_dir: Path, run: Path):
    from . import filter_approval as filters
    form_path = review_dir / filters.FORM
    _, form = filters.validate_form(review_dir, complete=False)
    form_hash = integrity.sha256_file(form_path)
    st.caption("◆ Duyệt mục lọc sau ⑤. Chưa quyết định thì cả lô chờ; từ chối giữ lại ứng viên.")
    packet = filters.verify_packet(review_dir)
    chain = filters.revision_chain(review_dir)
    if chain:
        st.info("Bản sửa của gói (người duyệt rút gọn rule): " + "; ".join(
            f"{c['hypothesis_id']} bỏ " + ", ".join(f"{i['truong']} = {i['gia_tri']}" for i in c["bo_muc"]) for c in chain)
            + ". Rule dưới đây là bản đã rút gọn; điền lại quyết định lọc và rule của bản sửa rồi tiếp tục.")
    for spec in packet["specs"]:
        with st.expander(f"Rule và ứng viên: {spec['id']}"):
            st.code(yaml.safe_dump(spec["sigma_context"]["rule"], allow_unicode=True, sort_keys=False), language="yaml")
            st.code(spec["candidates"], language="sql")
            st.json(spec["scope"], expanded=False)
    preview = read(review_dir / "preview.json")
    scopes = {s["id"]: s["scope"] for s in packet["specs"]}
    breadth_table([{**row, "source": scopes[row["hunt_id"]]} for row in preview])
    st.json(preview, expanded=False)
    st.caption("Số đếm dùng toàn tập; mẫu tối đa 5 sự kiện/mục. 0 khớp không chứng minh lành tính.")
    with st.form(f"filters_{run.name}_{form_hash}"):
        reviewer = st.text_input("Người duyệt", value=form["nguoi_duyet"])
        choices = {}
        for row in form["muc_loc"]:
            st.write(row["id"], row["bieu_thuc_sigma"])
            st.json({k: row[k] for k in ("hunt_id", "scope", "selectors", "de_xuat")}, expanded=False)
            st.code(row["where"], language="sql")
            values = ["", "approved", "rejected"]
            prefix = f"filter_{run.name}_{form_hash}_{row['id']}"
            choice = {"quyet_dinh": st.selectbox("Quyết định", values, index=values.index(row["quyet_dinh"]), key=prefix)}
            for key, label in (("ly_do", "Lý do"), ("can_cu", "Căn cứ lành tính độc lập"),
                               ("nguoi_chiu_trach_nhiem", "Người chịu trách nhiệm"),
                               ("hieu_luc_den_utc", "Hiệu lực đến UTC (vd 2026-10-02T10:00:00Z)")):
                choice[key] = st.text_input(label, value=row[key], key=f"{prefix}_{key}")
            choices[row["id"]] = choice
        submit = st.form_submit_button("Lưu quyết định lọc")
    if submit:
        filters.save_decisions(review_dir, reviewer, choices, form_hash)
        st.success("Đã lưu phiếu lọc; graph vẫn chờ đến khi tiếp tục")
    rule_form(review_dir, run)
    m = packet
    if m["events"]["path"]:
        from .data.store import connect
        con = connect(Path(m["events"]["path"]).parent)
        try:
            st.json(filters.decision_preview(review_dir, con), expanded=False)
        finally:
            con.close()


def api_key():
    name = config.load("llm_hunt")["api_key_env"]
    if not os.environ.get(name) and os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as registry:
                os.environ[name] = winreg.QueryValueEx(registry, name)[0]
        except FileNotFoundError:
            pass
    if not os.environ.get(name):
        raise ValueError(f"Thiếu biến môi trường {name}")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rule_form(review_dir: Path, run: Path):
    """09/10: giữ hoặc bỏ từng rule có giá trị/regex ⑤ tự thêm (đối chiếu B3) trước khi chạy.
    10/10 (phiếu v2): rút gọn — bỏ đúng các mục chọn khỏi rule, graph phát bản sửa của gói để duyệt lại."""
    from . import filter_approval as filters
    path = review_dir / filters.RULE_FORM
    if not path.exists():
        return
    form = filters.validate_rule_form(review_dir, filters.verify_packet(review_dir), complete=False)
    form_hash = integrity.sha256_file(path)
    v2 = form["quy_tac_duyet"] in (filters.RULE_POLICY, filters.RULE_POLICY_V3)
    st.markdown("**Rule có điều kiện giả thuyết không nêu** — giữ nếu là chi tiết hợp lý (vd tên tệp của ứng dụng được "
                "nêu chung), bỏ nếu ⑤ thêm hoặc đổi điều kiện (vd cổng, ngưỡng, mẫu đặt sai trường). Rule bị bỏ không "
                "chạy và được ghi là chưa thực thi."
                + (" **Rút gọn** (rut_gon): chỉ bỏ các mục chọn ở ô dưới, giữ phần còn lại của rule (chỉ xóa, không thêm); "
                   "hệ thống phát bản sửa của gói để duyệt lại trước khi chạy. Bỏ hết điều kiện sinh ứng viên thì không "
                   "rút gọn được, chỉ còn bỏ cả rule." if v2 else ""))
    with st.form(f"rules_{run.name}_{form_hash}"):
        reviewer = st.text_input("Người duyệt rule", value=form["nguoi_duyet"])
        choices = {}
        for row in form["rule"]:
            st.write(row["id"], "· giả thuyết", row["hypothesis_id"])
            items = row["doi_chieu"]
            wide = row.get("do_rong")
            if wide:
                st.warning(f"Rule rộng: giữ {wide['giu']}/{wide['pham_vi']} sự kiện ({wide['ty_le']:.0%}) của nguồn log "
                           f"khối lượng lớn (ngưỡng {wide['nguong']:.0%}). Gần như là mọi sự kiện của nguồn, không còn là "
                           "giả thuyết cụ thể; giữ thì phải ghi lý do.")
            var = row.get("bien_the")
            if var:
                st.info(f"Biến thể mức kỹ thuật: {var['mo_ta']}. Trên log của lượt: rule gốc giữ {var['goc_giu']}, "
                        f"biến thể giữ {var['bien_the_giu']} trên {var['pham_vi']} sự kiện của nguồn. Chọn bien_the để "
                        "chạy biến thể thay rule gốc (cần lý do).")
            st.dataframe([{"#": n, "Trường": i["truong"], "Loại": "regex ngoài thư viện"
                           if i["kind"] == "regex_ngoai_thu_vien" else "giá trị", "Giá trị": i["gia_tri"]}
                          for n, i in enumerate(items)], hide_index=True)
            values = (["", "giu", "bo", "rut_gon"] if v2 else ["", "giu", "bo"]) + (["bien_the"] if row.get("bien_the") else [])
            prefix = f"rule_{run.name}_{form_hash}_{row['id']}"
            choice = {
                "quyet_dinh": st.selectbox("Giữ/bỏ rule", values, index=values.index(row["quyet_dinh"]), key=prefix),
                "ly_do": st.text_input("Lý do (bắt buộc khi bỏ, rút gọn, giữ rule rộng hoặc chọn biến thể)", value=row["ly_do"], key=f"{prefix}_ly_do")}
            if v2:
                choice["bo_muc"] = [int(n) for n in st.multiselect(
                    "Mục bỏ khi rút gọn", list(range(len(items))), default=row["bo_muc"], key=f"{prefix}_bo_muc",
                    format_func=lambda n, items=items: f"{n}: {items[n]['truong']} = {items[n]['gia_tri']}")]
            choices[row["id"]] = choice
        submit = st.form_submit_button("Lưu quyết định rule")
    if submit:
        filters.save_rule_decisions(review_dir, reviewer, choices, form_hash)
        st.success("Đã lưu phiếu rule; graph vẫn chờ đến khi tiếp tục")


def grounding_note(path: Path):
    """B3: giá trị ứng viên không có trong giả thuyết đã duyệt; chỉ để xem, không chặn hay đổi kết quả."""
    try:
        items = demo.rule_grounding(path)
    except Exception as e:                     # noqa: BLE001 — rule cũ không đọc lại được thì chỉ báo
        st.caption(f"Không đối chiếu được điều kiện với giả thuyết: {e}")
        return
    if items is None:
        return
    if items:
        st.warning("Đối chiếu với giả thuyết đã duyệt (chỉ để xem, không chặn): "
                   + "; ".join(f"{i['truong']} {'regex ngoài thư viện' if i['kind'] == 'regex_ngoai_thu_vien' else 'giá trị'}"
                               f" `{i['gia_tri']}`" for i in items)
                   + ". Không chứng minh rule sai; cần người xem.")
    else:
        st.caption("Đối chiếu với giả thuyết đã duyệt: mọi giá trị ứng viên có trong giả thuyết hoặc thư viện mẫu. "
                   "Không chứng minh rule giữ đủ điều kiện.")
    try:
        missing = demo.rule_missing(path)
    except Exception:                          # noqa: BLE001 — đã báo ở phần đối chiếu phía trên
        return
    if missing:
        st.warning("Chuỗi kỹ thuật của giả thuyết không thấy trong điều kiện sinh ứng viên của rule (chỉ để xem, "
                   "không chặn): " + "; ".join(f"`{m['gia_tri']}` ({grounding.LABELS.get(m['loai'], m['loai'])})"
                                               for m in missing)
                   + ". Rule có thể đã bỏ điều kiện; cũng có thể chuỗi chỉ là ví dụ hoặc ý phủ định trong giả thuyết.")


def breadth_table(rows: list[dict]):
    from .hunt.breadth import summarize
    items = []
    for row in rows:
        summary = summarize(row["scope"], row["candidates"])
        items.append({"Hunt": row["hunt_id"], "Phạm vi": summary["scope"],
                      "Ứng viên": summary["candidates"],
                      "Tỷ lệ": f"{summary['ratio']:.2%}" if summary["ratio"] is not None else "không xác định",
                      **({"Nguồn log": row["source"]["channel"],
                          "Mã sự kiện": ", ".join(str(e) for e in row["source"]["event_ids"])}
                         if row.get("source") else {}),
                      **({"Còn sau lọc": row["remaining"]} if "remaining" in row else {})})
        if summary["broad"]:
            st.warning(f"{row['hunt_id']}: truy vấn khớp {summary['candidates']}/{summary['scope']} sự kiện "
                       "trong phạm vi (≥95%). Cần xem lại điều kiện hành vi và khối lượng cần rà; "
                       "số này chưa chứng minh truy vấn sai hay kết quả là tấn công.")
    if items:
        st.dataframe(items, hide_index=True)
        st.caption("Tỷ lệ là ứng viên/phạm vi cùng nguồn log và thời gian, trước lọc; không phải FPR. "
                   "Cảnh báo chỉ để xem xét, giữ nguyên kết quả. Nguồn ít sự kiện cần đọc cùng số đếm.")


def open_report(folder: Path, notice: str):
    """Mở report vừa tạo và báo kết quả ở lượt chạy kế tiếp. Ô “Mở report đã lưu” và danh sách của nó đã dựng trước khi
    nút được xử lý, nên report mới chỉ vào danh sách sau một lần chạy lại trang (12/10: trước đó người dùng phải tự bấm R)."""
    st.session_state["pending_selected_report"] = folder.name
    st.session_state["report_notice"] = notice
    st.rerun()


def ocr_form(bundle: Path) -> Path | None:
    """H4 (12/10): rà bản chép OCR ngay trên UI; ghi phiếu đúng định dạng `review-ocr`. Không chọn sẵn kết quả nào.
    Trả về thư mục bản sau rà nếu lượt này vừa tạo ra nó."""
    try:
        form = demo.ocr_review(bundle)
    except Exception as e:                     # noqa: BLE001 — bundle lỗi thì chỉ báo, không chặn phần còn lại của tab
        st.error(str(e))
        return None
    if form is None:
        return None
    st.subheader("Rà bản chép OCR")
    st.caption("So từng ảnh với bản chép. Chỉ đoạn approved mới đi vào trích TTP/IOC; chưa chọn thì đoạn vẫn chờ rà.")
    values = ["pending", "approved", "rejected", "no_text"]
    with st.form(f"ocr_{bundle.name}_{form['bundle_manifest_sha256']}"):
        reviewer = st.text_input("Người rà OCR", value=form.get("reviewer") or "")
        choices = {}
        for d in form["decisions"]:
            sid = d["segment_id"]
            st.image(d["image"], caption=sid)
            text = st.text_area("Bản chép (sửa cho khớp ảnh trước khi duyệt)", value=d["text"],
                                key=f"ocr_text_{bundle.name}_{sid}")
            status = st.selectbox("Kết quả rà", values, index=values.index(d.get("status") or "pending"),
                                  key=f"ocr_status_{bundle.name}_{sid}")
            reason = st.text_input("Lý do (bắt buộc khi đã chọn kết quả)", value=d.get("reason") or "",
                                   key=f"ocr_reason_{bundle.name}_{sid}")
            choices[sid] = {"status": status, "text": text, "reason": reason}
        submit = st.form_submit_button("Áp phiếu rà OCR")
    if submit:
        try:
            made = demo.ocr_apply(bundle, reviewer, choices)
            st.success(f"Đã tạo bản sau rà `{made.name}`.")
            return made
        except Exception as e:                 # noqa: BLE001 — lỗi kiểm phiếu của s1_ocr hiện nguyên văn cho người rà
            st.error(str(e))
    return None


def hypothesis_form(review_dir: Path, run: Path):
    form_path = review_dir / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
    form_hash = integrity.sha256_file(form_path)
    with st.form(f"review_{run.name}_{form_hash}"):
        reviewer = st.text_input("Người duyệt", value=form.get("nguoi_duyet") or "")
        decisions = {}
        for row in form["gia_thuyet"]:
            st.write(row["id"], row["hanh_vi"])
            st.write({k: row.get(k) for k in ("pham_vi", "thoi_gian", "bang_chung", "nguon_chi_tiet",
                                             "cua_so_thuc_thi_utc", "phep_toan_yeu_cau")})
            if row.get('loi_kha_nang_thuc_thi'):
                st.warning('Giả thuyết sẽ bị chặn trước thực thi: ' + '; '.join(
                    issue['message'] for issue in row['loi_kha_nang_thuc_thi']))
            # H5: phiếu phát trước khi có phép kiểm không có trường này; không hiện gì để khỏi đọc nhầm là "đã kiểm".
            if row.get('canh_bao_thieu_can_cu'):
                st.warning('Chuỗi kỹ thuật chưa thấy trong câu nguồn hay ghi chú danh mục nguồn log: '
                           + grounding.describe(row['canh_bao_thieu_can_cu'])
                           + '. Chỉ là cảnh báo để rà, không tự chặn giả thuyết; người duyệt quyết định.')
            elif 'canh_bao_thieu_can_cu' in row:
                st.caption('Kiểm chuỗi kỹ thuật (tệp, đường dẫn, cờ lệnh, lớp WMI, cmdlet, cổng): không thấy chuỗi '
                           'nào thiếu căn cứ. Không chứng minh giả thuyết bám đúng câu nguồn.')
            values = ["", "approved", "rejected"]
            decision = st.selectbox("Quyết định", values, index=values.index(row.get("quyet_dinh") or ""),
                                    key=f"decision_{run.name}_{form_hash}_{row['id']}")
            reason = st.text_input("Lý do", value=row.get("ly_do") or "", key=f"reason_{run.name}_{form_hash}_{row['id']}")
            decisions[row["id"]] = {"quyet_dinh": decision, "ly_do": reason}
        submit = st.form_submit_button("Lưu phiếu duyệt")
    if submit:
        approval.save_decisions(review_dir, reviewer, decisions, form_hash)
        st.success("Đã lưu phiếu. Bấm tiếp tục để áp phiếu vào graph")


def main():
    st.set_page_config(page_title="CTI to Hunt", layout="wide")
    st.title("CTI to Hunt — phát triển, không nhãn")
    version = st.selectbox("Phiên bản hệ thống", ["v1", "v2"], index=1,
                           help="Áp cho đối chiếu telemetry và lượt săn mới. v2 có thêm bước duyệt mục lọc.")
    tabs = st.tabs(["1. Đọc report", "2. Trích TTP", "3. Telemetry", "4. Giả thuyết và duyệt",
                    "5. Kết quả săn", "6. Nhật ký"])
    root = config.ROOT / "data/reports/moi"
    with tabs[0]:
        rid = st.text_input("Mã report mới", value="NEW-REPORT-02")
        url = st.text_input("URL report (hoặc tải file bên dưới)")
        upload = st.file_uploader("HTML, PDF hoặc ảnh PNG/JPEG", type=["html", "pdf", "png", "jpg", "jpeg"])
        selector = st.text_input("CSS selector (tùy chọn)")
        if st.button("Nhập report mới"):
            try:
                if demo.report_folder(rid).exists():
                    raise ValueError("Mã đã tồn tại; dùng mã mới hoặc mở bản đã lưu. Không xóa dữ liệu cũ")
                source = url.strip()
                if upload:
                    folder = demo.new_run(config.ROOT / "data/reports/tmp_uploads", "upload")
                    folder.mkdir(parents=True)
                    path = folder / ("input" + Path(upload.name).suffix.lower())
                    path.write_bytes(upload.getvalue())
                    source = str(path)
                if not source:
                    raise ValueError("Cần URL hoặc file")
                imported = demo.ingest(source, rid, selector)
                st.session_state["selected_report"] = imported
                st.success("Đã lưu nguồn và bản bóc nội dung")
            except Exception as e:
                st.error(str(e))
        folders = sorted(p for p in root.glob("*") if p.is_dir() and (p / "manifest.json").is_file())
        if not folders:
            st.info("Nhập report để bắt đầu")
            return
        # Report do bước OCR/rà vừa tạo ở lượt chạy trước: chọn nó trước khi dựng ô chọn (xem `open_report`).
        pending_name = st.session_state.pop("pending_selected_report", None)
        pending_folder = next((f for f in folders if f.name == pending_name), None)
        if pending_folder is not None:
            st.session_state["selected_report"] = pending_folder
        notice = st.session_state.pop("report_notice", None)
        bundle = st.selectbox("Mở report đã lưu", folders, key="selected_report", format_func=demo.report_label)
        if notice:
            st.success(notice)
        try:
            demo.inside(bundle, root)
            manifest, segments, provenance = s1_ingest.load_bundle(bundle)
        except Exception as e:
            st.error(str(e))
            return
        identity = integrity.sha256_file(bundle / "manifest.json")
        st.write(f"Trạng thái: {manifest['status']} · {manifest['unread_blocks']} khối chưa đọc")
        for alert in demo.selection_alerts(manifest):
            st.error("Có thể đã đọc nhầm vùng nội dung của trang. Mở bản đối chiếu nguồn; nếu sai, nhập lại với mã "
                     "mới và CSS selector. " + alert["detail"])
        if manifest["warnings"]:
            st.warning("Có phần chưa đọc/cần rà. OCR chưa rà không đi vào TTP.")
            st.json(manifest["warnings"], expanded=False)
        if manifest["unread_blocks"] and not manifest.get("ocr"):
            st.caption("Report có ảnh hoặc khối chưa đọc. OCR chạy trên máy, không gọi API; có thể mất vài phút.")
            if st.button("Chạy OCR cục bộ cho các khối chưa đọc"):
                try:
                    with st.spinner("Đang OCR trên máy — đừng tải lại trang"):
                        made = demo.ocr_bundle(bundle)
                    open_report(made, f"Đã tạo bản OCR `{made.name}` và đang mở nó. So ảnh với bản chép ở mục "
                                      "“Rà bản chép OCR” bên dưới; chữ chưa rà không đi vào TTP.")
                except Exception as e:
                    st.error(str(e))
        reviewed = ocr_form(bundle)
        if reviewed is not None:
            open_report(reviewed, f"Đã tạo bản sau rà `{reviewed.name}` và đang mở nó. Sang tab 2 để xem dự toán "
                                  "và trích TTP.")
        st.download_button("Tải bản đối chiếu nguồn", (bundle / "review.html").read_bytes(), "review.html", "text/html")
        with st.expander("Nội dung và vị trí nguồn"):
            for seg in segments:
                st.text(f"{seg['ma_doan']} · {seg['loai']}")
                st.text(seg["van_ban"])
                st.caption(json.dumps(provenance[seg["ma_doan"]], ensure_ascii=False))
    with tabs[1]:
        st.caption("Khâu ②: câu trích khớp chưa chứng minh TTP đúng ngữ nghĩa.")
        choices = sorted(p for p in (bundle / "extractions").glob("extract_*") if (p / "meta.json").exists())
        if (bundle / "extraction/meta.json").exists():
            choices.insert(0, bundle / "extraction")
        extraction_key = f"extract_{identity}"
        pending = st.session_state.pop(f"pending_{extraction_key}", None)
        if pending in choices:
            st.session_state[extraction_key] = pending
        extraction = st.selectbox("Lượt trích", [None, *choices], key=extraction_key,
                                  format_func=lambda p: "Tạo lượt mới" if p is None else p.name)
        saved = demo.saved_options_for(manifest["title"])     # Q2: chỉ kết quả của đúng report đang mở
        frozen_report = bool(saved)
        if saved:
            saved_key = st.selectbox("Kết quả trích đã lưu", list(saved),
                                     format_func=lambda key: saved[key]["title"], key=f"saved_{identity}")
            st.caption("Dùng lại nguyên kết quả cũ: kiểm hash và từng câu nguồn với report đang mở, không gọi API trích.")
            if st.button("Dùng kết quả trích đã lưu", key=f"reuse_{identity}"):
                try:
                    out = demo.reuse_saved(bundle, saved[saved_key])
                    st.session_state[f"pending_{extraction_key}"] = out
                    st.rerun()
                except (OSError, ValueError, KeyError, TypeError) as e:
                    st.error(f"Không dùng lại được kết quả trích: {e}")
        selected_meta = {}
        if extraction:
            try:
                selected_meta = read(extraction / "meta.json")
            except (OSError, ValueError):
                pass  # The source validation below displays the error and blocks the next steps.
        reused = selected_meta.get("version") == "saved_contract_v1"
        dry = st.checkbox("Chỉ chuẩn bị prompt, chưa gọi API", value=True, key=f"dry_{identity}")
        partial = st.checkbox("Tôi đã rà và chấp nhận phần chưa đọc/cảnh báo", value=False, key=f"partial_{identity}")
        if frozen_report and not reused:
            st.info("Bài này có kết quả trích đã chốt ngày 25/9. Bấm ‘Dùng kết quả trích đã lưu’ để kiểm nguồn và dùng lại; không trích lại bằng API.")
        if not reused:
            try:
                estimate = demo.extraction_cost(bundle, extraction)
                if estimate is not None:
                    st.info(s2_report.cost_summary(estimate))
                    st.caption("Ước tính cho toàn bộ lượt, chưa trừ lô đã có phản hồi khi tiếp tục. "
                               "Khoản giữ trước tính với toàn bộ trần token đầu ra; số thực tế tùy nội dung và suy luận.")
                    for warning in estimate["warnings"]:
                        st.warning(warning + " Chọn đoạn hiện dùng qua dòng lệnh.")
                else:
                    st.info("Chưa có biểu giá cho mô hình này; không ước tính được chi phí khâu ②.")
                noise = demo.extraction_noise(bundle, extraction)
                if noise:
                    st.caption(noise)
            except (OSError, ValueError, KeyError, TypeError) as e:
                st.warning(f"Không ước tính được chi phí khâu ②: {e}")
        if st.button("Chạy / tiếp tục trích TTP", disabled=reused or (frozen_report and not dry)):
            try:
                if not dry:
                    api_key()
                out = extraction or demo.new_run(bundle / "extractions", "extract")
                result = demo.extract(bundle, out, send=not dry, resume=extraction is not None, accept_partial=partial)
                st.session_state[f"pending_{extraction_key}"] = out
                st.rerun()
            except Exception as e:
                st.error(str(e))
        ca_path = None
        blocked_reason = "Chọn lượt trích hoàn tất hoặc dùng kết quả trích đã lưu ở tab 2 trước khi sang bước này."
        if extraction:
            try:
                demo.inside(extraction, bundle)
                meta = read(extraction / "meta.json")
            except Exception as e:
                st.error(str(e))
                return
            st.write({k: meta.get(k) for k in ("status", "batches", "accepted_ttp", "rejected_items", "semantic_quality")})
            if meta.get("status") == "prepared":
                blocked_reason = ("Tab 2 mới chuẩn bị yêu cầu, chưa gọi API và chưa có TTP. "
                                  "Chọn kết quả trích đã lưu nếu có; report mới cần hoàn tất trích TTP trước.")
                st.info(blocked_reason)
            elif meta.get("status") != "complete":
                blocked_reason = "Trích TTP chưa hoàn tất. Quay lại tab 2 để xem trạng thái và lỗi của lượt này."
                st.info(blocked_reason)
            if meta.get("status") == "complete":
                try:
                    ca_path = demo.verified_contract(bundle, extraction)
                    st.json(read(ca_path), expanded=False)
                    if reused:
                        st.success(f"Đã dùng lại {meta['accepted_ttp']} TTP từ kết quả đã lưu; không gọi API trích.")
                        st.caption("Mã report và mã đoạn của kết quả cũ được giữ nguyên. Vị trí trên HTML đang mở đã kiểm riêng.")
                        with st.expander("Nguồn của kết quả dùng lại"):
                            st.dataframe([{"TTP": row["ttp_ref"], "Đoạn gốc": row["original_segment_id"],
                                           "Đoạn trong report đang mở": ", ".join(row["current_segment_ids"])}
                                          for row in meta["source_bindings"]], hide_index=True)
                    if manifest["status"] != "extracted" and not partial:
                        blocked_reason = ("Report còn phần chưa đọc/cảnh báo. Ở tab 2, chỉ đánh dấu "
                                          "‘Tôi đã rà và chấp nhận phần chưa đọc/cảnh báo’ sau khi đã kiểm nguồn.")
                        st.warning(blocked_reason)
                        ca_path = None
                except Exception as e:
                    ca_path = None
                    blocked_reason = f"Kết quả trích không khớp nguồn: {e}. Quay lại tab 2 để kiểm tra."
                    st.error(str(e))
    with tabs[2]:
        available = sorted(p for p in (config.ROOT / "data/dev").glob("otrf-*") if (p / "ingest_manifest.json").exists())
        if not available:
            st.info("Chưa nạp bộ OTRF phát triển")
            return
        events = st.selectbox("Bộ log phát triển", available, format_func=lambda p: p.name)
        contract_hash = integrity.sha256_file(ca_path) if ca_path else ""
        coverage_key = f"coverage_{identity}_{extraction}_{contract_hash}_{events}_{version}"
        if not ca_path:
            st.info(blocked_reason)
        if st.button("Đối chiếu telemetry", disabled=ca_path is None):
            try:
                if not ca_path:
                    raise ValueError("Cần lượt trích hoàn tất, khớp nguồn")
                demo.dataset(events)
                result = coverage(ContractA.model_validate_json(ca_path.read_text(encoding="utf-8")), events,
                                  version=version)
                st.session_state[coverage_key] = result
            except Exception as e:
                st.error(str(e))
        if ca_path and coverage_key in st.session_state:
            result = st.session_state[coverage_key]
            if (result["events_sha256"] == integrity.sha256_file(events / "events.parquet") and
                    result["catalog_sha256"] == integrity.sha256_file(config.telemetry_catalog(version))):
                st.caption(f"Đối chiếu {version} · bộ log {events.name}")
                st.dataframe(demo.coverage_table(result["techniques"]), hide_index=True)
                st.caption("catalog_gap là thiếu ánh xạ; không kết luận môi trường không có log.")
                with st.expander("Chi tiết nguồn log và câu nguồn (JSON)"):
                    st.json(result["techniques"], expanded=False)
            else:
                st.info("Nguồn log hoặc danh mục đã đổi; bấm đối chiếu telemetry lại.")
        st.subheader("Quét IOC của report trên bộ log này")
        st.caption("Chạy trước săn theo hành vi; không gọi API, không đọc nhãn. Chỉ quét IOC mạnh, đúng trường: mã băm với Hashes, IP với trường địa chỉ… IOC yếu (IP nội bộ, dịch vụ phổ biến, tên tệp trơn, imphash) và link tham khảo chỉ liệt kê.")
        sweep_key = f"iocsweep_{identity}_{extraction}_{contract_hash}_{events}"
        if st.button("Quét IOC", disabled=ca_path is None):
            try:
                st.session_state[sweep_key] = demo.ioc_sweep(
                    ContractA.model_validate_json(ca_path.read_text(encoding="utf-8")), events)
            except Exception as e:
                st.error(str(e))
        if ca_path and sweep_key in st.session_state:
            swept = st.session_state[sweep_key]
            t = swept["tong"]
            st.caption(f"{t['so_muc']} giá trị · {t['manh']} mạnh · {t['yeu']} yếu · {t['bo']} bỏ · đã quét {t['da_quet']} · "
                       f"có khớp {t['co_khop']} · bộ log {swept['so_su_kien_log']} sự kiện")
            st.dataframe(demo.ioc_table(swept), hide_index=True)
            if swept["thuc_the"]["may"] or swept["thuc_the"]["tai_khoan"]:
                st.warning(f"Máy dính IOC: {', '.join(swept['thuc_the']['may']) or '—'} · tài khoản: "
                           f"{', '.join(swept['thuc_the']['tai_khoan']) or '—'}. Đầu mối để kiểm, không phải kết luận.")
            else:
                st.info("Không IOC mạnh nào khớp. Không có nghĩa là sạch: chiến dịch mới thường đổi hạ tầng; săn theo hành vi ở tab 4.")
        st.subheader("Rule cộng đồng SigmaHQ theo TTP của report")
        st.caption("Rule SigmaHQ (stable/test) có tag kỹ thuật trùng TTP của report, chạy trên bộ log này; không gọi API, "
                   "không đọc nhãn. Dùng cạnh hunt hệ thống sinh ở tab 4: rule mức high/critical thường chính xác, "
                   "medium/low hay ồn.")
        community_key = f"community_{identity}_{extraction}_{contract_hash}_{events}"
        if st.button("Chạy rule cộng đồng theo TTP", disabled=ca_path is None):
            try:
                st.session_state[community_key] = demo.community_rules(
                    ContractA.model_validate_json(ca_path.read_text(encoding="utf-8")), events)
            except Exception as e:
                st.error(str(e))
        if ca_path and community_key in st.session_state:
            got = st.session_state[community_key]
            st.caption(f"{got['so_rule_chon']} rule chọn theo {len(got['ttp'])} TTP · {got['so_hunt']} hunt dịch được · "
                       f"{got['co_ket_qua']} có kết quả · {len(got['khong_dich_duoc'])} không dịch được")
            st.dataframe(demo.community_table(got), hide_index=True)
    with tabs[3]:
        mode = st.selectbox("Chế độ", ["pipeline", "agent"])
        st.caption(f"Lượt mới dùng hệ thống {version}; đối chiếu telemetry ở tab 3 dùng cùng phiên bản.")
        preview = st.checkbox("Kiểm tra trước, chưa gọi API sinh giả thuyết", value=True)
        if not ca_path:
            st.info(blocked_reason)
        if st.button("Bắt đầu lượt săn mới", disabled=ca_path is None):
            try:
                if not ca_path:
                    raise ValueError("Cần Contract A đã kiểm nguồn")
                if not preview:
                    api_key()
                run = demo.new_run(extraction / "hunts", "run")
                with st.spinner(RUNNING):
                    result = demo.start(bundle, extraction, events, run, mode=mode, dry_run=preview, version=version)
                st.json(result)
                if (run / session.META_FILE).exists():
                    st.session_state[f"hunt_{identity}_{extraction}"] = run
            except Exception as e:
                st.error(str(e))
        runs = sorted(p for p in (extraction / "hunts").glob("run_*") if (p / session.META_FILE).exists()) if extraction else []
        run = st.selectbox("Lượt săn đã lưu", [None, *runs], key=f"hunt_{identity}_{extraction}",
                           format_func=lambda p: "Chọn lượt" if p is None else p.name)
        if run:
            try:
                demo.inside(run, extraction)
                meta = read(run / session.META_FILE)
                st.caption(f"Lượt đã lưu: {meta.get('phien_ban', 'v1')} · {meta['mode']} "
                           f"· bộ log đã ghim: {meta['dataset']['id']}")
                status = session.inspect(run)
                if status["trang_thai"] == "cho_duyet":
                    review_dir = Path(status["review_dir"])
                    st.info("Đang chờ duyệt mục lọc" if status.get("review_kind") == "filter"
                            else "Đang chờ duyệt giả thuyết")
                    if status.get("review_kind") == "filter":
                        filter_form(review_dir, run)
                    else:
                        hypothesis_form(review_dir, run)
                    resume_label = ("Tiếp tục sau duyệt (có thể gọi API ở bước kế tiếp)" if status.get("review_kind") == "filter"
                                    else "Tiếp tục sau duyệt (có gọi API)")
                    if st.button(resume_label):
                        api_key()
                        demo.verified_contract(bundle, extraction)
                        with st.spinner(RUNNING):
                            st.json(session.resume(run))
                        st.rerun()
                else:
                    st.json(status)
                    if status.get("trang_thai") == "chua_hoan_tat":
                        st.caption("Checkpoint chỉ cập nhật sau mỗi bước: nếu lượt vừa được bấm chạy ở tab hoặc cửa sổ "
                                   "khác, nó có thể vẫn đang chạy — chờ rồi chọn lại lượt trước khi kết luận là bị ngắt.")
                    if status.get("phuc_hoi_duoc"):
                        st.warning("Lượt dừng vì lỗi mạng ngoài cổng duyệt. Phục hồi chạy lại đúng bước bị ngắt "
                                   "và có thể gọi API; kiểm mạng trước khi bấm.")
                        if st.button("Phục hồi sau lỗi mạng (có thể gọi API)"):
                            api_key()
                            demo.verified_contract(bundle, extraction)
                            with st.spinner(RUNNING):
                                st.json(session.recover(run))
                            st.rerun()
                    elif status.get("ly_do_khong_phuc_hoi"):
                        st.info(status["ly_do_khong_phuc_hoi"])
            except Exception as e:
                st.error(str(e))
    with tabs[4]:
        result_run = run
        if extraction and (bundle / "khau3_run" / approval.LOG_FILE).exists():
            with st.expander("Chạy lại rule của demo cũ đã được duyệt"):
                st.caption("Kiểm lại phiếu, nguồn và schema; giữ nguyên rule cũ, không gọi API. Rule lỗi bị chặn.")
                if st.button("Kiểm và thực thi rule cũ"):
                    try:
                        if not ca_path:
                            raise ValueError("Cần Contract A hợp lệ và xác nhận giới hạn nguồn ở tab 2")
                        from .replay import approved_rules
                        replay_out = demo.new_run(extraction / "replays", "replay")
                        result = approved_rules(bundle, extraction, bundle / "khau3_run", events, replay_out)
                        st.json(result["rules"])
                    except Exception as e:
                        st.error(str(e))
                replays = sorted(p for p in (extraction / "replays").glob("replay_*")
                                 if (p / "agent_dev_record.json").exists())
                selected = st.selectbox("Kết quả chạy lại", [None, *replays],
                    key=f"replay_{identity}_{extraction}", format_func=lambda p: "Xem lượt graph ở tab 4" if p is None else p.name)
                if selected:
                    result_run = demo.inside(selected, extraction)
                    st.json(read(result_run / "agent_dev_record.json")["rules"])
        if not result_run:
            st.info("Chọn lượt săn ở tab 4")
        else:
            try:
                summary = demo.result_summary(result_run)
                breadth_table(summary["hunts"])
            except (OSError, ValueError, KeyError, TypeError) as e:
                st.error(f"Không đọc được bảng kết quả đã lưu: {e}")
            record = result_run / "hunt_record.md"
            if record.exists():
                st.markdown(demo.markdown_safe(record.read_text(encoding="utf-8")))
                st.download_button("Tải Hunt Record", record.read_bytes(), "hunt_record.md")
            else:
                st.info("Chưa có Hunt Record; xem phiếu hoặc trạng thái ở tab 4")
            from .hunt import runner
            from .adapters.splunk_sigma import convert_rule, convert_effective
            index = st.text_input("Index Splunk cho hunt đã duyệt", value="cti_dev")
            effective = sorted(result_run.glob("round_*/hunts_effective/*/*.yaml"))
            for path in sorted([*result_run.glob("round_*/hunts/*.yaml"), *result_run.glob("hunts/*.yaml"), *effective]):
                with st.expander(path.relative_to(result_run).as_posix()):     # Q8: tên kèm vòng
                    try:
                        spec = runner.load_spec(path)
                        for stage in demo.sql_stages(spec):
                            st.caption(stage["stage"])
                            st.code(stage["sql"], language="sql")
                        if spec.get("filter_policy"):
                            for stage in convert_effective(spec, index)["stages"]:
                                st.code(stage["spl"])
                            st.caption("SPL từ đúng hunt hiệu lực; chưa kiểm thực thi trên Splunk.")
                    except Exception as e:
                        st.warning(str(e))
            for path in sorted(result_run.glob("round_*/rules_draft/*.yml")):
                with st.expander(f"Sigma do ⑤ sinh: {path.relative_to(result_run).as_posix()}"):
                    st.code(path.read_text(encoding="utf-8"), language="yaml")
                    grounding_note(path)
            for label, text, removed in demo.shortened_rules(result_run):
                with st.expander(f"Sigma người duyệt rút gọn: {label}"):
                    st.code(text, language="yaml")
                    st.caption("Đã bỏ: " + "; ".join(f"{i['truong']} = {i['gia_tri']} (khối {i['khoi']})" for i in removed))
            for path in sorted(result_run.glob("round_*/rules/*.yml")):
                with st.expander(f"Sigma / SPL: {path.relative_to(result_run).as_posix()}"):
                    st.code(path.read_text(encoding="utf-8"), language="yaml")
                    grounding_note(path)
                    try:
                        for spl in convert_rule(path):
                            st.code(spl)
                        st.caption("SPL mới chuyển đổi; chưa kiểm thực thi trên Splunk và cần ghim index/scope/thời gian.")
                    except Exception as e:
                        st.warning(str(e))
    with tabs[5]:
        if result_run:
            try:
                decisions = demo.result_summary(result_run)["decisions"]
                if decisions:
                    st.dataframe([{"Vòng": r["round"], "Hành động": r["action"], "Lý do": r["reason"]}
                                  for r in decisions], hide_index=True)
            except (OSError, ValueError, KeyError, TypeError) as e:
                st.error(f"Không đọc được nhật ký quyết định: {e}")
            for path in [result_run / "agent_dev_record.json", *sorted(result_run.glob("round_*/agent_proposal.json")),
                         *sorted(result_run.glob("round_*/agent_execute.json"))]:
                if path.exists():
                    with st.expander(str(path.relative_to(result_run))):
                        st.json(read(path))
            st.caption("Nhật ký đã lưu của lượt đang xem; replay không tạo lịch sử agent giả.")
        else:
            st.info("Chọn lượt săn để đọc nhật ký")
        from .record_store import RecordStore
        with st.expander("Tra hunt memory — các record đã hoàn tất"):
            st.caption(demo.memory_note(root, version))                    # Q3: kho nào đang tra, planner đọc kho nào
            technique = st.text_input("Mã ATT&CK (để trống để liệt kê)")
            if st.button("Tìm record"):
                try:
                    st.json(RecordStore(root).find(technique=technique))
                except ValueError as e:
                    st.error(str(e))
