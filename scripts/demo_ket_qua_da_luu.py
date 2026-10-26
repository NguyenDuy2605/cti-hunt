"""Streamlit chỉ đọc gói demo đã kiểm; không nhập graph, client, CLI hay API key."""
from datetime import datetime, timezone
from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ra_ho_so_tuyen_a import load_demo
from chuan_bi_demo_v2_that import DEMO_OUTPUT

STAGE_LABELS = {"pham_vi": "Phạm vi nguồn log", "ung_vien": "Ứng viên khớp rule"}


def stage_label(stage: str) -> str:
    if stage.startswith("sau_"):
        return "Sau mục lọc " + stage[len("sau_"):]
    return STAGE_LABELS.get(stage, stage)


def visible_sample(rows: list[dict]) -> tuple[list[dict], list[str]]:
    """Ẩn cột rỗng ở mọi dòng mẫu đã lưu; trả về dòng còn lại và tên cột đã ẩn."""
    empty = [k for k in (rows[0] if rows else {}) if all(r.get(k) in (None, "") for r in rows)]
    return [{k: v for k, v in r.items() if k not in empty} for r in rows], empty


def utc_text(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return str(value)
    if moment.tzinfo:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%d/%m/%Y %H:%M:%S UTC")


def main():
    st.set_page_config(page_title="CTI Hunt — kết quả đã lưu", layout="wide")
    st.title("CTI Hunt — trình diễn kết quả đã lưu")
    st.caption("Chỉ đọc kết quả đã lưu, không gọi API · Tab 1–4: lượt pipeline Emotet trên OTRF (29/09) · "
               "Tab 5: lượt agent SY_02 trên APT29 day 2 (30/09) · Tab 6: cổng lọc v2, rule mock (02/10) · "
               "Tab 7: lượt v2 chạy thật trên OTRF (02/10)")
    try:
        data = load_demo(DEMO_OUTPUT)
    except (ValueError, OSError, KeyError) as exc:
        st.error(f"Không thể xác minh gói demo: {exc}")
        st.stop()
    summary = data["verified_summary"]
    selected = st.selectbox("Giả thuyết Emotet đã duyệt (áp cho tab 1–3)",
                            [c["hypothesis"]["hypothesis_id"] for c in data["cases"]], index=1)
    case = next(c for c in data["cases"] if c["hypothesis"]["hypothesis_id"] == selected)
    h = case["hypothesis"]
    tabs = st.tabs(["1 · Report", "2 · Giả thuyết và duyệt", "3 · Rule và kết quả",
                    "4 · Hunt record", "5 · Quyết định agent", "6 · Cổng lọc v2", "7 · Lượt v2 chạy thật"])
    with tabs[0]:
        st.subheader(data["report"].get("title", "Nguồn CTI đã lưu"))
        st.write(f"Contract A đã trích: {len(data['contract_a'].get('ttps', []))} TTP · {len(data['contract_a'].get('iocs', []))} IOC")
        st.write("Đoạn nguồn gắn với giả thuyết đang chọn")
        for span in h["source_spans"]:
            st.caption(f"{span.get('segment_id', '')} · {span.get('section', '')}")
            st.text(span["text"])
        with st.expander("Manifest và Contract A gốc"):
            st.json(data["report"])
            st.json(data["contract_a"])
    with tabs[1]:
        st.subheader(h.get("behavior", selected))
        st.write("Phạm vi: " + h.get("scope", ""))
        st.write("Thời gian: " + h.get("timeframe", ""))
        evidence = h.get("evidence", {})
        st.write(f"Nguồn log: {evidence.get('data_source', '')} · EID {evidence.get('event_ids', [])}")
        st.write("TTP: " + ", ".join(h.get("linked_ttps", [])))
        review = case["review"]
        decision = review.get("quyet_dinh", {}).get(selected, {}).get("quyet_dinh", h.get("status", ""))
        st.success(f"Quyết định đã lưu: {decision} · người duyệt: {review.get('nguoi_duyet', '')}")
        st.caption("Tên người duyệt giữ nguyên theo log của lượt gốc.")
        with st.expander("Giả thuyết, log và hash phiếu gốc"):
            st.json(h)
            st.json(review)
    with tabs[2]:
        st.info("Số sự kiện khớp truy vấn trên dữ liệu phát triển; chưa phải TP hoặc bằng chứng phát hiện Emotet.")
        st.code(case["rule"], language="yaml")
        for spec in case["specs"]:
            with st.expander("Hunt spec / điều kiện SQL đã lưu"):
                st.code(spec, language="yaml")
        for obs in case["observations"]:
            st.table([{"Giai đoạn": stage_label(s["stage"]), "Số sự kiện": s["hits"]} for s in obs["stages"]])
            if obs["sample"]:
                rows, hidden = visible_sample(obs["sample"])
                st.write("Mẫu sự kiện cuối đã lưu")
                st.table(rows)
                if hidden:
                    st.caption("Mẫu của lượt gốc chỉ lưu một bộ trường cố định; cột rỗng ở nguồn này đã ẩn: "
                               + ", ".join(hidden) + ".")
        if selected.endswith("-H01"):
            st.warning("H01 có 0 ứng viên trên bộ log này; không bỏ kết quả rỗng khỏi demo.")
        elif selected.endswith("-H13"):
            st.warning("H13 chưa kiểm tương quan nhiều IP theo tiến trình, cửa sổ thời gian hoặc vắng DNS; query hẹp hơn yêu cầu của giả thuyết.")
        elif selected.endswith("-H14"):
            st.warning("H14 có bind tài khoản nhưng thiếu mốc neo và điều kiện ‘30 phút sau’. Hợp lệ tĩnh chưa chứng minh đúng ngữ nghĩa.")
    with tabs[3]:
        st.subheader("Kết quả cuối của lượt pipeline Emotet")
        st.info("Số sự kiện khớp truy vấn trên dữ liệu phát triển; chưa phải TP hoặc bằng chứng phát hiện Emotet.")
        cols = st.columns(3)
        cols[0].metric("Giả thuyết đã duyệt", summary.get("approved", len(data["cases"])))
        cols[1].metric("Rule hợp lệ sau sửa", summary.get("valid_final", "—"))
        cols[2].metric("Sự kiện cuối duy nhất", summary.get("unique_final_events", "—"))
        st.write(f"{summary.get('valid_first', '—')} rule hợp lệ lần đầu; {summary.get('valid_final', '—')} sau sửa. Sự kiện trùng giữa rule được khử trùng khi tính tổng duy nhất.")
        st.table([{"Giả thuyết": row["hypothesis_id"], "Sự kiện cuối": row["stages"][-1]["hits"]}
                  for row in summary.get("unlabeled_checks", [])])
        with st.expander("Hunt record gốc"):
            st.markdown(data["hunt_record"])
        with st.expander("Bằng chứng kiểm số đếm và chi phí lượt gốc"):
            st.json(summary)
    with tabs[4]:
        st.write("SY_02 — chế độ agent trên APT29 day 2 (tuyến A): lịch sử planner đã lưu, không chạy lại.")
        st.caption("Lượt Emotet ở các tab trước dùng pipeline; lịch sử sau thuộc một lượt agent riêng.")
        for index, row in enumerate(data["agent_history"], 1):
            decision = row["decision"]
            st.subheader(f"{index}. {decision['action']}")
            facts = []
            if row.get("round_budget"):
                facts.append(f"đã dùng {row['round_budget']['used']}/{row['round_budget']['limit']} vòng")
            if "pivot_depth" in row:
                facts.append(f"độ sâu pivot {row['pivot_depth']}")
            if row.get("api_budget"):
                facts.append(f"sổ ngân sách chung lúc quyết định còn {row['api_budget']['remaining_usd']} USD")
            if row.get("generated_ids"):
                facts.append("giả thuyết sinh: " + ", ".join(row["generated_ids"]))
            if facts:
                st.caption(" · ".join(facts))
            st.write(decision.get("reason", ""))
            if decision.get("ttp_refs"):
                st.caption("Tham chiếu TTP: " + ", ".join(map(str, decision["ttp_refs"])))
            if decision.get("pivot_targets"):
                st.table(decision["pivot_targets"])
    with tabs[5]:
        st.subheader("Scheduled task — cổng duyệt lọc v2")
        st.warning("Kiểm cơ chế: rule mock, log OTRF thật, quyết định người vận hành đã lưu. Chưa đo chất lượng LLM v2 hoặc TP/FPR.")
        gate = data.get("filter_demo")
        if not gate:
            st.info("Gói này chưa có bằng chứng cổng lọc v2.")
        else:
            st.caption(f"Lượt thực thi lịch sử: {utc_text(gate['executed_at_utc'])} · cập nhật ngoài kỳ chốt 01/10")
            st.write(gate["hypothesis"]["behavior"])
            st.table([{"Giai đoạn": stage_label(r["stage"]), "DuckDB": r["duck_count"],
                       "Splunk": r["splunk_count"], "Jaccard": r["jaccard"]} for r in gate["stages"]])
            st.write("Quyết định người duyệt")
            for row in gate["review"]["quyet_dinh"]:
                st.subheader(row["id"].rsplit("__", 1)[-1] + " · " + row["quyet_dinh"])
                st.write(row["ly_do"])
                st.caption(f"Người chịu trách nhiệm: {row['nguoi_chiu_trach_nhiem']} · hạn hiệu lực đã ghi: {row['hieu_luc_den_utc']}")
                with st.expander(row["id"].rsplit("__", 1)[-1] + " — căn cứ và rủi ro người duyệt chấp nhận"):
                    st.write(row["can_cu"])
            st.caption("Chỉ trình bày kết quả lịch sử; không thực thi lại phiếu này hoặc kéo dài thời hạn.")
            with st.expander("Rule mock, biên nhận và Hunt record gốc"):
                st.code(gate["rule"], language="yaml")
                st.json(gate["receipt"])
                st.markdown(gate["hunt_record"])
    with tabs[6]:
        show_real_v2(data.get("real_v2"))
    with st.expander("Nguồn và SHA256 đã kiểm"):
        st.json(data["source_hashes"])


def short(hypothesis_id: str) -> str:
    return hypothesis_id.rsplit("-", 1)[-1]


def show_real_v2(real: dict | None):
    st.subheader("Lượt v2 chạy thật trên OTRF — 02/10")
    st.warning("Mô hình thật (Sonnet 5), log OTRF phát triển, quyết định duyệt của người vận hành. Lượt bị cắt giữa vòng 2 "
               "vì lỗi mạng. Không phải phép đo chất lượng, không phải TP/FPR.")
    if not real:
        st.info("Gói này chưa có lượt v2 chạy thật.")
        return
    st.caption(f"Bắt đầu {real['bat_dau']} · commit {real['commit'][:8]} · dữ liệu {real['dataset']['id']} · "
               "danh mục ③ v2 (475 mục), planner v3, prompt ⑤ v2, chính sách lọc v2")
    st.markdown("**Planner chọn gì**")
    for index, row in enumerate(real["planner"], 1):
        st.write(f"{index}. {row['action']}: {', '.join(row['ttp'])}")
        st.caption(row["ly_do"])
    gate = real["cong_loc"]
    preview = {p["hunt_id"]: p for p in gate["preview"]}

    def matched(item: dict) -> int:
        return next(f["matched"] for f in preview[item["hunt_id"]]["filters"] if item["id"].endswith("__" + f["id"]))
    st.markdown("**Cổng duyệt lọc: mục lọc do mô hình sinh, người duyệt quyết định**")
    st.table([{"Giả thuyết": short(m["hypothesis_id"]), "Mục lọc trong rule": m["bieu_thuc_sigma"],
               "Ứng viên": preview[m["hunt_id"]]["candidates"], "Mục lọc khớp": matched(m),
               "Quyết định": m["quyet_dinh"]} for m in gate["muc_loc"]])
    st.caption(f"Người duyệt: {gate['nguoi_duyet']} · {utc_text(gate['thoi_diem_utc'])} · "
               f"{gate['so_spec_hieu_luc']} hunt hiệu lực, không mục lọc nào được áp")
    for m in gate["muc_loc"]:
        with st.expander(f"{short(m['hypothesis_id'])} — lý do từ chối và rule gốc"):
            st.write(m["ly_do"])
            st.code(gate["rule_co_muc_loc"][m["hypothesis_id"]], language="yaml")
    first = real["vong"][0]
    rules = {r["hypothesis_id"]: r for r in first["rule"]}
    results = {k["hypothesis_id"]: k for k in first["ket_qua"]}
    st.markdown("**Vòng 1: thực thi sau cổng lọc**")
    st.table([{"Giả thuyết": short(g["id"]), "Hành vi": g["hanh_vi"], "Nguồn log": f"{g['nguon']} {g['eid']}",
               "Rule": "hợp lệ" if rules.get(g["id"], {}).get("hop_le") else "không hợp lệ",
               "Phạm vi → ứng viên": " → ".join(str(s["hits"]) for s in results[g["id"]]["stages"])
               if g["id"] in results else "không chạy"} for g in first["gia_thuyet"]])
    for k in first["ket_qua"]:
        for s in k["mau"]:
            st.caption(f"Sự kiện còn lại ({short(k['hypothesis_id'])}): {s['ev_host']} · {s['ev_ts']} · "
                       f"{s['Image']} · {s['User']}. Khớp truy vấn, chưa phải TP.")
    for r in first["rule"]:
        if not r["hop_le"]:
            st.caption(f"{short(r['hypothesis_id'])}: không hợp lệ sau {r['so_lan_sua']} lần sửa — "
                       + "; ".join(e["message"] for e in r["loi"] or []))
    if len(real["vong"]) > 1:
        second = real["vong"][1]
        st.markdown("**Vòng 2: bị cắt giữa khâu ⑤**")
        st.write(f"{second['dem']['approved']} giả thuyết được duyệt; rule hợp lệ đã sinh: "
                 f"{', '.join(short(x) for x in second['rule_hop_le']) or 'không có'}; chưa truy vấn.")
        st.caption(real["su_co"]["ly_do"])
    cost = real["chi_phi"]
    st.write(f"Chi phí theo nhật ký lượt: {cost['loi_goi']} lời gọi, {str(cost['usd']).replace('.', ',')} USD; "
             "cộng 0,012810 USD cho lời gọi bị timeout (1.800 token vào, 921 ra; đối chiếu Console 04/10), "
             "tổng 0,526006 USD.")
    with st.expander("Hunt record gốc của lượt"):
        st.markdown(real["hunt_record"])


if __name__ == "__main__":
    main()
