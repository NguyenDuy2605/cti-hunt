"""Thống kê cho số đếm nhỏ: khoảng tin cậy Wilson cho một tỷ lệ và kiểm định McNemar chính xác cho hai cách đo trên cùng mục.

Chỉ dùng thư viện chuẩn (môi trường không có scipy). Hai hàm không đọc dữ liệu nào; đầu vào là số đếm.

- ``wilson(x, n)``: khoảng tin cậy 95% cho tỷ lệ x/n. Dùng Wilson thay cho công thức p ± 1,96·sqrt(p(1-p)/n) vì công thức
  đó cho khoảng vượt [0, 1] và sai nhiều khi n nhỏ hoặc p gần 0/1 (vd 8/8).
- ``mcnemar_exact(b, c)``: hai cách A, B chấm trên cùng tập mục; b = mục A đúng mà B sai, c = mục B đúng mà A sai. Mục cả hai
  cùng đúng hay cùng sai không cho thông tin về chênh lệch nên không vào phép thử. Nếu hai cách ngang nhau, mỗi mục bất đồng
  nghiêng về A hay B như tung đồng xu; p hai phía = xác suất gặp lệch ít nhất như quan sát dưới giả định đó (phân phối nhị
  thức, không xấp xỉ chi bình phương vì b + c nhỏ).
"""
from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(x: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Khoảng tin cậy Wilson cho tỷ lệ x/n; n = 0 trả (0, 1)."""
    if n < 0 or x < 0 or x > n:
        raise ValueError(f"cần 0 <= x <= n, nhận x={x}, n={n}")
    if n == 0:
        return 0.0, 1.0
    p = x / n
    z2 = z * z
    den = 1 + z2 / n
    center = (p + z2 / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / den
    return max(0.0, center - half), min(1.0, center + half)


def mcnemar_exact(b: int, c: int) -> float:
    """p hai phía của kiểm định McNemar chính xác (nhị thức, xác suất 1/2) trên b, c mục bất đồng."""
    if b < 0 or c < 0:
        raise ValueError(f"cần b, c >= 0, nhận b={b}, c={c}")
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def sign_test(wins: int, losses: int) -> float:
    """Kiểm định dấu hai phía (ties bỏ ra ngoài): cùng phép tính với McNemar chính xác."""
    return mcnemar_exact(wins, losses)
