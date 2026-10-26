# Contract A phát triển v1 (E1) — nguồn và cách soạn

Trạng thái duyệt ghi ở `docs/bao_cao_quyet_dinh_E1_du_lieu_agent_24-9.md` (tệp này nằm trong MANIFEST nên không
ghi trạng thái ở đây). Soạn ngày 24/09/2026 theo quyết định (2) của Duy:
Contract A tự soạn cho từng cơ chế, chỉ dựa trên mô tả công khai của bộ OTRF tương ứng; không lấy từ Silver v1, ba
report đánh giá hay emulation plan. Sửa thì tạo `contract_a_v2/`, không sửa tại chỗ (`MANIFEST.sha256`).

## Nguồn

OTRF Security-Datasets, commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`, thư mục `datasets/atomic/_metadata/`.
Chỉ dùng các trường `title`, `description`, `attack_mappings`, `simulation.permissions_required`. **Không** dùng
`adversary_view` (bản ghi lệnh đã chạy trong bộ dữ liệu): dùng nó thì Contract A biết trước đáp án của dữ liệu phát
triển, dễ hơn một CTI report thật.

| Contract A | Bộ dữ liệu (`ingest-dev`) | Metadata OTRF | SHA256 tệp metadata |
|---|---|---|---|
| `DEV-DCOM` | `otrf-dcom` | SDWIN-190518211052 | `6081c50588f3a83dc449a15c6a2e86d7cbe2ca41e9e228ed36a8a8dfda86d85d` |
| `DEV-PSREMOTING` | `otrf-psremoting` | SDWIN-190518211456 | `8a5ff6f9f4989f635f8b9f2d730d850ccf390a02e10d15a326891beec7e88a9a` |
| `DEV-WMIEXEC` | `otrf-wmi-exec` | SDWIN-200921001437 | `89e81bb7c4164fed29c206f0b25f2c5da2c23a60b3b1196ae90a4b9e64c29a23` |
| `DEV-PSEXEC` | `otrf-psexec` | SDWIN-190518210652 | `94312e4381c8bed00489ebc76940c6b0a59b6f5806bba09cc093b0f7bd40ece5` |
| `DEV-SCHTASKS` | `otrf-schtasks` | SDWIN-200921175806 | `f76c68841c87c76d3ffea4f9de1f944ff95641d0ba834450176b3dd32fcdcf8d` |
| `DEV-WMISUB` | `otrf-wmi-sub` | SDWIN-190518184306 | `01a40345c774619ee872f68338b37bdcf34ccd7c7438b5e5d9d6edbf2454fd56` |
| `DEV-RUNKEYS` | `otrf-runkeys` | SDWIN-190319023812 | `4f082144cb5c47029ed5d09edb58041e21b8cf92675ccfdcf2b11fda97b3b737` |

## Quy ước soạn (để duyệt)

| Trường | Lấy từ | Ghi chú |
|---|---|---|
| `technique_id` | `attack_mappings` của OTRF | Ngoại lệ ở dòng dưới |
| `technique_name` | ATT&CK v19.2 | Tra bằng `AttackCatalog`, không tự đặt |
| `tactic` | tactic trong `attack_mappings`, chọn theo mục đích trong câu mô tả | `T1047` OTRF gắn TA0002 + TA0008; mô tả là "remotely executing code" nên ghi Lateral Movement |
| `source_span.text` | nguyên văn `description` | Đã kiểm: 9/9 dòng trùng toàn văn |
| `behavior_description` | diễn đạt lại câu mô tả bằng tiếng Việt | Không thêm chi tiết ngoài câu mô tả |
| `context.tool` | cơ chế nêu trong câu mô tả | vd "PowerShell Remoting (WinRM)" |
| `context.execution_path` | chữ "remote/remotely" hoặc "local/locally" trong mô tả | |
| `context.account_type` | `simulation.permissions_required` | |
| `command_example`, `source_role`, `target_role`, `preceded_by` | để trống | Mô tả không nêu |
| `confidence` | 0,9 cho mã của OTRF; 0,7 cho mã suy từ câu mô tả | |

**Ngoại lệ — `DEV-PSEXEC`:** OTRF chỉ ghi mã cha `T1021`, mà danh mục khâu ③ không có mục cho mã cha này (bộ sẽ thành
not_huntable). Giữ dòng `T1021` đúng như OTRF, thêm hai dòng **suy từ câu mô tả** "remotely creating and starting a
service via RPC methods over TCP": `T1569.002` (khởi động dịch vụ để thực thi) và `T1543.003` (tạo dịch vụ Windows),
confidence 0,7. Duy duyệt hai dòng này.

## Ghi vào báo cáo

- Dữ liệu phát triển **cùng họ kỹ thuật** với tập đánh giá (scope Living-off-the-Land đã chọn quanh chính các cơ chế
  này); E1 tách theo dữ liệu (lần ghi, máy, lab), không tách theo kỹ thuật.
- Contract A phát triển có câu mô tả ngắn và sạch hơn một CTI report thật; kết quả chạy trên dữ liệu phát triển
  không dùng làm số đánh giá.
