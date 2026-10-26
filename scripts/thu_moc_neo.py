"""Ca mốc neo qua graph, trần gói 0,50 USD. Mặc định chuẩn bị 0 API; --status xem; chỉ người vận hành --send --cap-usd 0.50."""
import argparse
import json

from cti_hunt.agent import neo_trial as trial


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--send', action='store_true', help='người vận hành gửi/tiếp tục sau khi điền phiếu')
    group.add_argument('--status', action='store_true', help='Xem trạng thái, không API')
    p.add_argument('--cap-usd', help='người vận hành xác nhận trần gói; chỉ nhận 0.50')
    a = p.parse_args(argv)
    try:
        if a.send:
            out = trial.advance(cap_usd=a.cap_usd)
        elif a.cap_usd is not None:
            raise ValueError('Chuẩn bị/xem trạng thái không nhận quyền chi tiền')
        else:
            out = trial.status() if a.status else trial.prepare()
    except Exception as e:
        # Never print raw provider error bodies/API keys.
        print(json.dumps({'state': 'blocked_or_failed', 'error_type': type(e).__name__,
                          'message': str(e)[:300] if isinstance(e, ValueError) else
                          'Xem --status và tmp/thu_moc_neo_7-10_lan3; không gửi lại pha bị ngắt.'}, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
