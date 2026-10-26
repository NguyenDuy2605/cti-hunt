import math

import pytest

from cti_hunt.eval.thong_ke import mcnemar_exact, sign_test, wilson


def test_wilson_matches_textbook_example():
    # 8/10: khoảng Wilson 95% thường dẫn trong sách là [0,4902; 0,9433]
    lo, hi = wilson(8, 10)
    assert lo == pytest.approx(0.4902, abs=1e-4)
    assert hi == pytest.approx(0.9433, abs=1e-4)


def test_wilson_stays_inside_unit_interval_at_extremes():
    lo, hi = wilson(8, 8)
    assert hi == 1.0 and 0.6 < lo < 0.7  # 8/8 không cho khoảng [1, 1]
    lo, hi = wilson(0, 5)
    assert lo == 0.0 and 0.4 < hi < 0.5
    assert wilson(0, 0) == (0.0, 1.0)


def test_wilson_rejects_bad_counts():
    with pytest.raises(ValueError):
        wilson(3, 2)


def test_mcnemar_exact_known_values():
    assert mcnemar_exact(0, 10) == pytest.approx(2 / 1024)
    assert mcnemar_exact(2, 8) == pytest.approx(2 * (1 + 10 + 45) / 1024)
    assert mcnemar_exact(5, 5) == 1.0
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(10, 0) == mcnemar_exact(0, 10)


def test_sign_test_four_of_four():
    # bốn report, cả bốn nghiêng một phía: p = 2/16, không đủ để kết luận ở mức 0,05
    assert sign_test(4, 0) == pytest.approx(0.125)
    assert math.isclose(sign_test(3, 1), 0.625)
