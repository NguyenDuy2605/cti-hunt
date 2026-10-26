"""Sinh danh mục ③ v2.2 = v2.1 + bốn sửa có căn cứ không nhãn. Không ghi đè tệp có sẵn.

Căn cứ là ý nghĩa công khai của mã sự kiện Sysmon/Windows và các lần ④ ghép sai đã ghi khi rà không nhãn (chiến dịch v2
mới 07–08/10, lượt A4 qua UI 09/10); không dùng nhãn hay kết quả có nhãn.

- E1 T1546.012 (IFEO): thêm Sysmon 13. Đặt giá trị Debugger/GlobalFlag là "registry value set" (13); v2.1 chỉ có 12
  (tạo/xóa khóa) nên giả thuyết đặt giá trị bị loại ở kiểm mã sự kiện.
- E2 T1070: thêm Sysmon 12. Xóa khóa/giá trị registry là EID 12 (EventType DeleteKey/DeleteValue); v2.1 chỉ có 13/14.
  EventType không bắt buộc: hồ sơ bỏ trường này ở bộ dữ liệu mà nó rỗng.
- E3 T1012 (Query Registry): bỏ Sysmon 13, 14. Sysmon không ghi việc đọc registry; 13 là đặt giá trị, 14 là đổi tên.
  Kỹ thuật vẫn huntable qua PowerShell 4103/4104 và Sysmon 1.
- E4 T1047: ghi_chu (đi vào prompt ④) nêu WMI-Activity/Operational ghi gì. Kênh này không ghi lời gọi phương thức thành
  công, nên "WMI sinh tiến trình" phải quan sát ở Sysmon 1 (cha WmiPrvSE.exe). Giữ nguyên nguồn và mã sự kiện.

Không đổi T1059.001 (4104 và 4103 là hai nguồn): mỗi nguồn có trường khóa riêng (ScriptBlockText / Payload) và mỗi hunt
một nguồn log (mẫu số FPR); giả thuyết gộp hai mã bị loại là đúng thiết kế, ④ phải tách thành hai giả thuyết.
"""
import argparse
import json
from pathlib import Path

import yaml

from cti_hunt import config
from cti_hunt.stages import s3_telemetry

SOURCE = 'configs/telemetry_catalog_v2_1.yaml'
TARGET = 'configs/telemetry_catalog_v2_2.yaml'
VERSION = '1.4'
SYSMON = s3_telemetry.SYSMON
T1047_NOTE_V21 = 'Lệnh chạy trong bộ nhớ không sinh Sysmon 1, cần đối chiếu thêm log PowerShell.'
T1047_NOTE = (T1047_NOTE_V21 + ' Tiến trình sinh qua WMI thấy ở Sysmon 1 với tiến trình cha WmiPrvSE.exe. '
              'WMI-Activity/Operational không ghi lời gọi phương thức WMI thành công: 5857 ghi provider được nạp, '
              '5858 ghi thao tác WMI bị lỗi, 5860 ghi đăng ký nhận sự kiện tạm, 5861 ghi binding sự kiện thường trú; '
              'chi tiết nằm trong Message.')


def _eids(entry: dict) -> list[tuple]:
    return [(s['channel'], tuple(s['event_ids'])) for s in entry['sources']]


def patch(doc: dict) -> dict:
    """Áp E1–E4 lên bản sao của v2.1; dừng nếu nền không đúng như lúc thiết kế (tránh áp nhầm lên bản đã đổi)."""
    out = json.loads(json.dumps(doc))
    out['phien_ban'] = VERSION
    tech = out['techniques']

    ifeo = tech['T1546.012']
    assert _eids(ifeo) == [(SYSMON, (1,)), (SYSMON, (10,)), (SYSMON, (12,))], 'T1546.012 khác nền v2.1'
    ifeo['sources'].append({'channel': SYSMON, 'event_ids': [13],
                            'key_fields': ['Image', 'TargetObject', 'Details', 'ProcessGuid'],
                            'truong_bat_buoc': ['Image']})

    removal = tech['T1070']
    assert _eids(removal) == [(SYSMON, (13,)), (SYSMON, (14,))], 'T1070 khác nền v2.1'
    removal['sources'].insert(0, {'channel': SYSMON, 'event_ids': [12],
                                  'key_fields': ['Image', 'EventType', 'TargetObject', 'ProcessGuid'],
                                  'truong_bat_buoc': ['Image']})

    query = tech['T1012']
    assert (SYSMON, (13,)) in _eids(query) and (SYSMON, (14,)) in _eids(query), 'T1012 khác nền v2.1'
    query['sources'] = [s for s in query['sources'] if not (s['channel'] == SYSMON and s['event_ids'] in ([13], [14]))]

    wmi = tech['T1047']
    assert wmi.get('ghi_chu') == T1047_NOTE_V21, 'T1047 khác nền v2.1'
    wmi['ghi_chu'] = T1047_NOTE
    return out


def render(root: Path) -> bytes:
    doc = yaml.safe_load((root / SOURCE).read_text(encoding='utf-8'))
    # Cùng cách ghi với v2.1 để diff chỉ còn các dòng sửa.
    return yaml.safe_dump(patch(doc), allow_unicode=True, sort_keys=False).encode('utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=config.ROOT)
    args = parser.parse_args(argv)
    with open(args.root / TARGET, 'xb') as f:
        f.write(render(args.root))
    s3_telemetry.load_catalog(args.root / TARGET)
    print(f'Đã ghi {TARGET}')


if __name__ == '__main__':
    main()
