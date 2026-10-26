"""Gói Emotet một đoạn, trần 1,20 USD. Mặc định chuẩn bị, chỉ --send gọi API."""
import argparse
import json

from cti_hunt.agent import emotet_trial as trial


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--send', action='store_true', help='người vận hành gửi/tiếp tục sau khi điền phiếu')
    group.add_argument('--status', action='store_true', help='Xem trạng thái, không API')
    a = p.parse_args(argv)
    try:
        out = trial.advance() if a.send else trial.status() if a.status else trial.prepare()
    except Exception as e:
        # Never print raw provider error bodies/API keys.
        print(json.dumps({'state': 'blocked_or_failed', 'error_type': type(e).__name__,
                          'message': 'Xem --status và phiếu/log trong tmp/thu_loi_emotet_6-10; không gửi lại pha bị ngắt.'}))
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
