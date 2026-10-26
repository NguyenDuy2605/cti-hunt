"""Pipeline 9 khâu (v3 §4.1). Mỗi khâu một module, thêm dần theo lịch.

    ① s1_segments      Ingest & Normalize        — dùng đoạn đã tách trong DoanVan cho 3 report đánh giá
    ② s2_ioc / s2_ttp  Extract IOC / TTP+context — T6 25/9 (IOC), T2 28/9 (TTP prompt v1)   [CỔNG ĐÓNG BĂNG]
    ③ s3_telemetry     Telemetry Mapping         — T5 24/9
    ④ s4_hypothesis    Hypothesis Generation     — khung xong (chạy mock); prompts/khau4_gia_thuyet_v1.md
    ◆ approval.py      Điểm dừng phê duyệt       — khung xong, bằng tệp (duyet.yaml), không dùng LangGraph
    ⑤ s5_rule          Query Generation          — khung xong: sinh rule, kiểm tra tĩnh, vòng tự sửa
    ⑥ Validation & Execution (adapter SQL)       — tuần 4; hunt.runner đã là phần thực thi + đo
    ⑦ s7_rarity       Benign Filtering          — điểm độ hiếm + nhật ký lọc không nhãn; loại trừ mới chờ duyệt
    ⑧ s8_triage        Triage & Correlation      — phần xác định xong; phần mô hình (giả thuyết pivot) chưa
    ⑨ s9_record        Hunt Record               — renderer xác định; bản vận hành không chứa nhãn

[CỔNG ĐÓNG BĂNG]: khâu đọc 3 report đánh giá và sinh nhãn phải gọi integrity.require_frozen trước.
"""
