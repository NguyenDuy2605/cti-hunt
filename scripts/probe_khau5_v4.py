"""Mặc định chuẩn bị 0 API; chỉ người vận hành dùng --send --cap-usd 0.40 sau khi chốt chi tiền."""
from cti_hunt.agent.probe_khau5 import main

if __name__ == '__main__':
    raise SystemExit(main())
