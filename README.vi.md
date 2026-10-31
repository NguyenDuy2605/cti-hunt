# cti-hunt — từ CTI report tới cuộc săn có kiểm chứng, và LLM thực sự giúp ở đâu

[English](README.md) · [Báo cáo (PDF tiếng Anh, 5 trang)](report/cti-hunt-report.pdf) · [Phương pháp](docs/METHODOLOGY.md)

Một đội săn mối đe dọa (threat hunting) đọc một báo cáo tình báo mối đe dọa (CTI report) rồi phải biến phần văn xuôi đó
thành truy vấn chạy trên log Windows của chính mình. **cti-hunt** làm việc này từ đầu đến cuối — report → IOC và kỹ thuật
ATT&CK → giả thuyết săn → người duyệt → rule Sigma → truy vấn → lọc và pivot → hunt record — và được dùng làm bàn thử để
trả lời một câu hỏi:

> **Ở khâu nào LLM tốt hơn cách không dùng LLM, và ở khâu nào thì không?**

Mỗi khâu dùng LLM được so với một cách không dùng LLM (regex, tìm kiếm BM25, rcATT, rule cộng đồng SigmaHQ) trên dữ liệu
công khai có nhãn tới từng sự kiện, theo giao thức viết và băm trước khi đo.

## Kết quả chính

| Câu hỏi | Kết quả |
|---|---|
| **RQ1 · Đọc report** | TTP: Claude tìm được **45/48** kỹ thuật cha mà MITRE gán cho bốn report; mô hình mở `qwen2.5:7b` 25/48; rcATT huấn luyện lại 12/48. Trên bộ 30 report chọn theo giao thức đặt trước, mô hình 7B có recall thấp hơn gợi ý đứng đầu của BM25 (41 % so với 55 %). IOC: bộ rút regex đã đạt recall 484/493 trên 19 report của 17 nhà xuất bản; LLM lọc IOC không hơn luật viết tay |
| **RQ2 · Viết phát hiện** | Trên 25 kỹ thuật chọn ngẫu nhiên có nhãn sự kiện (Splunk `attack_data`): rule Sigma do Claude viết bắt **12/25**, rule SigmaHQ mức cao **10/25** (p = 0,75), báo nhầm 4.439 so với 384. Kết hợp hai bên: 16/25 (p = 0,03 so với SigmaHQ), bằng việc bật mọi rule SigmaHQ mức cao. `qwen2.5:7b` / `14b`: 0/25 |
| **RQ3 · Lớp kiểm soát** | Kiểm tĩnh làm rule của Claude hợp lệ 46/46, nhưng 41 trong 57 rule hợp lệ của mô hình 14B không bao giờ khớp vì sai ngữ nghĩa. **Phép kiểm hình dạng trường** mới bắt 34/41 rule đó trên dữ liệu chưa thấy, không gắn cờ nhầm rule đúng nào (0/61). **Cổng độ rộng** bắt được hunt quá rộng từng thổi kết quả kịch bản lên 17/24 (bỏ nó còn 4–8/24) |

**Rút ra:** dùng LLM để đọc report và đề xuất hunt cho kỹ thuật chưa có rule cộng đồng; với kỹ thuật phổ biến, chọn rule cộng
đồng có sẵn theo kỹ thuật của report — phát hiện như nhau, báo nhầm ít hơn nhiều.

![Số kỹ thuật bắt được trên 25 kỹ thuật chọn ngẫu nhiên](report/figures/fig2_rule_generation.svg)

## Cách hệ thống làm

```
report (HTML/PDF/ảnh)
  ① đọc, chia đoạn, OCR cục bộ chờ người rà
  ② trích     IOC: regex + luật mạnh/yếu              TTP: LLM + gợi ý BM25 + kiểm câu trích nguyên văn
  ③ đối chiếu kỹ thuật → nguồn log, kiểm trên chính bộ dữ liệu
  ④ giả thuyết (LLM)  →  ◆ người duyệt (phiếu gắn SHA-256)
  ⑤ rule Sigma (LLM) + kiểm tĩnh, kiểm hình dạng trường, cổng độ rộng; vòng sửa chỉ nhận lỗi tĩnh
  ⑥ Sigma → SQL DuckDB   ⑦ mục lọc có duyệt, điểm độ hiếm   ⑧ pivot có trần   ⑨ hunt record (LOCK)
        + chế độ lai: rule SigmaHQ chọn theo kỹ thuật của report chạy trong mọi lượt
```

- **Hai chế độ:** pipeline cố định, và agent (LangGraph) có planner tự chọn săn gì, có pivot không, khi nào dừng — luôn dưới
  trần do mã kiểm và qua cổng người duyệt.
- **LLM chỉ ở chỗ cần** (②, ④, ⑤); đọc report, đối chiếu log, thực thi, lọc, pivot và hunt record là mã xác định.
- **Các khâu săn không bao giờ thấy nhãn:** bộ chạy truy vấn từ chối cột nhãn; vòng sửa rule chỉ nhận lỗi tĩnh.

## Phần kỹ thuật dữ liệu

- **Kho sự kiện:** 587.286 sự kiện APT29, 7 bộ OTRF theo kỹ thuật và 2,29 triệu sự kiện Splunk `attack_data`, chuẩn hóa vào
  DuckDB / Parquet với khóa dẫn xuất (`ev_host`, `ev_channel`, `ev_eid`, `ev_rec`, giờ UTC) và các phép kiểm chất lượng.
- **Nhãn theo dòng tiến trình:** lần tiến trình tấn công theo cây tiến trình (GUID của Sysmon; máy + PID + thời gian sống ở
  nơi chỉ có PID, vì PID bị dùng lại), bộ dựng nhãn có phiên bản, kiểm mù (25/28, 30/31 ngoài mẫu, 9/9; OTRF 21/21 và 36/36).
- **Chạy lại được:** mỗi lượt lưu mã băm của đầu vào, prompt, cấu hình và mã; nhãn và đầu vào benchmark ghim SHA-256; giao
  thức được băm trước khi thấy số có nhãn.
- **Đối chiếu hai engine:** rule Sigma chuyển sang SPL và chạy trên Splunk cục bộ: so được 78/111 rule, 0 khác biệt tập kết
  quả so với DuckDB.
- **Kiểm soát chi phí:** sổ SQLite dùng chung cho mọi lời gọi trả tiền, giữ trước chi phí tối đa rồi quyết toán theo usage.
  Cả đề tài: khoảng 44 USD gọi API.

## Cấu trúc repo

```
src/cti_hunt/     stages/ (①–⑨), agent/ (graph LangGraph, phiên), adapters/ (Sigma → DuckDB), llm/ (provider, sổ ngân sách),
                  eval/ (chỉ số, thống kê: Wilson, McNemar chính xác, kiểm định dấu), hunt/, labels/, cli.py
app/              giao diện Streamlit, MCP server chỉ đọc hunt record
configs/          danh mục nguồn log, trần và ngưỡng, cổng độ rộng, cấu hình mô hình
prompts/          prompt có phiên bản (băm ghi trong nhật ký chạy)
scripts/          script đo ra mọi con số đã báo, bộ dựng nhãn
eval/             đầu vào benchmark đã ghim
tests/            hơn 1.400 test trên dữ liệu tổng hợp (không cần dataset hay khóa API)
report/           nguồn báo cáo, hình, PDF
docs/METHODOLOGY.md
```

## Chạy thử

```bash
python -m venv .venv
.venv\Scripts\activate              # Windows; nơi khác: source .venv/bin/activate
pip install -e ".[dev,splunk,demo]"
python -m pytest -q
```

Repo không kèm dữ liệu. Tải OTRF APT29 day 2, các bộ OTRF theo kỹ thuật, Splunk `attack_data` (commit `aafa53e`), SigmaHQ
(commit `d1c16224`) và ATT&CK Enterprise v19.2, rồi làm theo [Phương pháp §6](docs/METHODOLOGY.md#6-reproducing). Lời gọi
mô hình trả tiền cần biến môi trường `LLM_API_KEY`; khâu trích mặc định chỉ chuẩn bị prompt và dự toán, chỉ gọi API khi có
`--send`. Giao diện mở bằng `run_demo.bat` hoặc `streamlit run app/streamlit_app.py`.

## Giới hạn

Chỉ một kịch bản nhiều bước có nhãn (4 máy, 40 phút); các bộ khác là bản ghi lab theo từng kỹ thuật. Nhãn do tác giả dựng
và kiểm bằng kiểm mù, chưa có chuyên viên độc lập kiểm. Claude trích TTP mới đo trên 4 report, sinh rule trên 25/55 kỹ thuật
chọn ngẫu nhiên. Cổng người duyệt chưa độc lập với trợ lý đề xuất quyết định. Xem [báo cáo](report/cti-hunt-report.pdf) §7.

## Lịch sử phát triển

Bắt đầu ngày 19/09/2026, một ngày sau khi nhận việc tại VinSOC, và phát triển trên máy local trong suốt kỳ thực tập
(18/09 – 22/10/2026). Công bố một lần dưới dạng một bản chụp ngày 26/10/2026. Mốc thời gian nằm sẵn trong các tệp của dự
án: lần chạy chính thức khâu ② (25/09), hash của protocol viết trước mỗi phép đo có nhãn (từ 16/10), các seed ngẫu nhiên
cố định, và sổ chi phí của mọi lời gọi trả phí.

## Tác giả và giấy phép

Nguyễn Hoàng Duy — đề tài thực tập tại VinSOC, tháng 9–10/2026.

Đề tài do tác giả tự thiết kế, tự xây dựng và tự đánh giá, chỉ trên dữ liệu công khai (OTRF, Splunk `attack_data`, SigmaHQ,
MITRE ATT&CK, CTI report công khai). Không dùng dữ liệu hay hệ thống của công ty, và không phải sản phẩm của VinSOC.

Phát hành theo [giấy phép MIT](LICENSE).
