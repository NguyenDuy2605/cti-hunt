"""Geometric OCR reading order. Never edits recognized characters.

Whitespace columns are read top-to-bottom, then left-to-right. Ruled tables retain
row order. Both the permutation and the raw engine order are preserved for review.
"""
from statistics import median


def ruled_table(image) -> bool:
    import cv2
    import numpy as np
    gray = cv2.cvtColor(np.asarray(image.convert("RGB")), cv2.COLOR_RGB2GRAY)
    scale = min(1, 1400 / max(gray.shape))
    if scale < 1:
        gray = cv2.resize(gray, None, fx=scale, fy=scale)
    ink = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)[1]
    h, w = ink.shape
    horizontal = cv2.morphologyEx(ink, cv2.MORPH_OPEN, np.ones((1, max(25, w // 5)), np.uint8))
    vertical = cv2.morphologyEx(ink, cv2.MORPH_OPEN, np.ones((max(25, h // 10), 1), np.uint8))
    def runs(mask):
        indices = np.flatnonzero(mask)
        return 0 if not len(indices) else 1 + int(np.sum(np.diff(indices) > 2))
    return runs(np.sum(horizontal > 0, axis=1) > w * .25) >= 2 and runs(np.sum(vertical > 0, axis=0) > h * .08) >= 2


def reading_order(lines: list[dict], *, table: bool = False) -> tuple[list[int], dict]:
    if not lines:
        return [], {"mode": "empty", "column_splits": 0}
    boxes = []
    for line in lines:
        points = line["polygon_px"]
        xs, ys = zip(*points)
        boxes.append((min(xs), min(ys), max(xs), max(ys)))
    height = median(max(1, b[3] - b[1]) for b in boxes)
    splits = 0

    def rows(ids):
        pending = sorted(ids, key=lambda i: (boxes[i][1], boxes[i][0]))
        result = []
        while pending:
            top = boxes[pending[0]][1]
            same = [i for i in pending if boxes[i][1] <= top + height * .5]
            pending = [i for i in pending if i not in same]
            result.extend(sorted(same, key=lambda i: boxes[i][0]))
        return result

    def columns(ids):
        nonlocal splits
        if len(ids) < 4:
            return rows(ids)
        intervals = sorted((boxes[i][0], boxes[i][2]) for i in ids)
        right = intervals[0][1]
        gaps = []
        for left, end in intervals[1:]:
            if left - right > height * 1.5:
                gaps.append((left - right, (left + right) / 2))
            right = max(right, end)
        for _, cut in sorted(gaps, reverse=True):
            left = [i for i in ids if boxes[i][2] < cut]
            right = [i for i in ids if boxes[i][0] > cut]
            if min(len(left), len(right)) < 2:
                continue
            overlap = min(max(boxes[i][3] for i in left), max(boxes[i][3] for i in right)) - max(min(boxes[i][1] for i in left), min(boxes[i][1] for i in right))
            if overlap < height:
                continue
            splits += 1
            return columns(left) + columns(right)
        return rows(ids)

    if table:
        ordered = rows(list(range(len(lines))))
    else:
        # Spanning headings/captions separate column bands; within each band use
        # geometric gutters, not a hard-coded page midpoint or a two-column limit.
        ink_width = max(b[2] for b in boxes) - min(b[0] for b in boxes)
        wide = sorted([i for i, b in enumerate(boxes) if b[2] - b[0] >= .72 * ink_width], key=lambda i: boxes[i][1])
        narrow = [i for i in range(len(lines)) if i not in wide]
        ordered = []
        for anchor in [*wide, None]:
            top = boxes[anchor][1] if anchor is not None else float("inf")
            band = [i for i in narrow if boxes[i][1] < top]
            narrow = [i for i in narrow if boxes[i][1] >= top]
            ordered.extend(columns(band))
            if anchor is not None:
                ordered.append(anchor)
    assert sorted(ordered) == list(range(len(lines)))
    return ordered, {"mode": "ruled_table_rows" if table else "whitespace_columns", "column_splits": splits,
                     "heuristic": True, "review_required": True, "line_permutation": ordered}
