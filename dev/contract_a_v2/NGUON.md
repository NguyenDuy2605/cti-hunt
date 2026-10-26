# Contract A phát triển v2 (E1) — nguồn và cách soạn

Soạn 24/09/2026 theo quyết định (2) của Duy: Contract A tự soạn cho từng cơ chế, chỉ từ mô tả công khai của bộ OTRF
tương ứng; không lấy từ Silver v1, ba report đánh giá hay emulation plan. Duy giao triển khai theo nhận xét duyệt v1
(24/9); v2 là bản dùng khi chạy, v1 giữ để truy vết. Trạng thái duyệt ghi ở
`docs/bao_cao_quyet_dinh_E1_du_lieu_agent_24-9.md`. Sửa tiếp thì tạo `contract_a_v3/`, không sửa tại chỗ
(`MANIFEST.sha256`).

## Nguồn

OTRF Security-Datasets, commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`, thư mục `datasets/atomic/_metadata/`.
Chỉ dùng ba trường: `title` (tiêu đề Contract A), `description` (câu trích, hành vi, bối cảnh), `attack_mappings`
(mã kỹ thuật, tactic). **Không** dùng `tags`, `simulation` (kể cả `permissions_required`) và `adversary_view`.

| Contract A | Bộ dữ liệu (`ingest-dev`) | Metadata OTRF | SHA256 tệp metadata |
|---|---|---|---|
| `DEV-DCOM` | `otrf-dcom` | SDWIN-190518211052 | `6081c50588f3a83dc449a15c6a2e86d7cbe2ca41e9e228ed36a8a8dfda86d85d` |
| `DEV-PSREMOTING` | `otrf-psremoting` | SDWIN-190518211456 | `8a5ff6f9f4989f635f8b9f2d730d850ccf390a02e10d15a326891beec7e88a9a` |
| `DEV-WMIEXEC` | `otrf-wmi-exec` | SDWIN-200921001437 | `89e81bb7c4164fed29c206f0b25f2c5da2c23a60b3b1196ae90a4b9e64c29a23` |
| `DEV-PSEXEC` | `otrf-psexec` | SDWIN-190518210652 | `94312e4381c8bed00489ebc76940c6b0a59b6f5806bba09cc093b0f7bd40ece5` |
| `DEV-SCHTASKS` | `otrf-schtasks` | SDWIN-200921175806 | `f76c68841c87c76d3ffea4f9de1f944ff95641d0ba834450176b3dd32fcdcf8d` |
| `DEV-WMISUB` | `otrf-wmi-sub` | SDWIN-190518184306 | `01a40345c774619ee872f68338b37bdcf34ccd7c7438b5e5d9d6edbf2454fd56` |
| `DEV-RUNKEYS` | `otrf-runkeys` | SDWIN-190319023812 | `4f082144cb5c47029ed5d09edb58041e21b8cf92675ccfdcf2b11fda97b3b737` |
| `DEV-TONGHOP` | chạy trên từng bộ ở trên | cả bảy tệp trên | như trên |

## Quy ước soạn

| Trường | Quy ước | Kiểm bằng |
|---|---|---|
| `source_span.text` | nguyên văn toàn bộ `description` | đối chiếu metadata khi soạn: 9/9 dòng |
| `technique_id` | `attack_mappings`; ngoại lệ DEV-PSEXEC bên dưới | ATT&CK v19.2 (`tests/test_dev_contract_a.py`) |
| `technique_name` | tên ở ATT&CK v19.2 | như trên |
| `tactic` | dòng theo mapping OTRF: một tactic OTRF gắn cho mã đó, chọn theo mục đích trong câu mô tả; dòng suy từ mô tả: tactic chính thức ATT&CK của mã | đối chiếu khi soạn |
| `behavior_description` | diễn đạt lại câu mô tả bằng tiếng Việt, không thêm chi tiết | đọc duyệt |
| `context.tool` | đúng cụm chữ trong `description` | test: `tool` nằm trong câu trích |
| `context.execution_path` | "remote/remotely" → remote; "local/locally" → local | đọc duyệt |
| `account_type`, `source_role`, `target_role`, `preceded_by`, `command_example` | để trống — mô tả không nêu (v3.2 §4.5) | test: `account_type` trống |
| `confidence` | 0,9 mã của OTRF; 0,7 mã suy từ mô tả (không đi vào prompt ④) | — |
| `published_date` | `creation_date` của metadata | đối chiếu khi soạn |

**Ngoại lệ DEV-PSEXEC:** OTRF chỉ ghi mã cha `T1021` (khâu ③ xếp not_huntable). Giữ dòng `T1021` đúng như OTRF, thêm
hai dòng **suy từ câu mô tả** "remotely creating and starting a service via RPC methods over TCP": `T1569.002`
(Execution) và `T1543.003` (Persistence — tactic chính thức đầu tiên của mã; câu mô tả không nói về duy trì hiện diện).

**DEV-TONGHOP:** bảy câu mô tả thành bảy đoạn `DEV-TONGHOP-001…007` của một "report" (thứ tự: DCOM, PSRemoting,
WMI, PsExec, Scheduled Tasks, WMI subscriptions, Run keys), giữ nguyên 9 dòng TTP của các Contract A theo cơ chế.
Chạy trên từng bộ dữ liệu: planner phải chọn thứ tự TTP, gặp TTP không có dấu vết trong bộ đó, và có nhiều giả thuyết
để tương quan và pivot — giống một CTI report thật mô tả nhiều kỹ thuật hơn những gì có trong log.

## Khác v1

| # | v1 | v2 | Lý do |
|---|---|---|---|
| 1 | `account_type` lấy từ `permissions_required` | trống | là quyền cần để giả lập, không phải tài khoản của hành vi; prompt ④ dùng nó để thu hẹp phạm vi; metadata tự mâu thuẫn (SCHTASKS: tiêu đề "Elevated", quyền "User") |
| 2 | `tool` của PSEXEC, WMISUB, RUNKEYS lấy chữ từ `tags` | đúng cụm trong `description`; SCHTASKS ghi đủ cụm "local scheduled tasks" | quy ước chỉ lấy bối cảnh từ câu mô tả |
| 3 | `published_date` DEV-RUNKEYS là ngày sửa đổi | ngày tạo 2019/03/19 | thống nhất 7 tệp |
| 4 | — | thêm `DEV-TONGHOP` | để phát triển planner (chế độ agent) có lựa chọn thật |

## Ghi vào báo cáo

- Dữ liệu phát triển **cùng họ kỹ thuật** với tập đánh giá; E1 tách theo dữ liệu (lần ghi, máy, lab), không theo kỹ
  thuật.
- Contract A phát triển có câu mô tả ngắn và sạch hơn một CTI report thật; kết quả trên dữ liệu phát triển không dùng
  làm số đánh giá.
