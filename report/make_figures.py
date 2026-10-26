"""Draw the two SVG figures of the report. Pure standard library.

The numbers are copied from the result files of the grading scripts (see docs/METHODOLOGY.md §6):
- Figure 1: TTP extraction on the pre-registered 30-report set, parent-technique level, 559 answer-key items.
- Figure 2: rule generation on 25 randomly sampled `attack_data` techniques (seed 20261019), labels v4.
"""
from pathlib import Path

OUT = Path(__file__).with_name("figures")
FONT = "font-family:'Segoe UI',Arial,sans-serif"
BLUE, LIGHT, RED, GRID, TXT, MUTED = "#1f5fbf", "#9bb8e3", "#c8553d", "#d9dee6", "#1b2433", "#5a6372"


def svg(w, h, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
            f'<rect width="{w}" height="{h}" fill="#ffffff"/>{body}</svg>')


def text(x, y, s, size=12, anchor="start", color=TXT, weight="normal"):
    return (f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" fill="{color}" '
            f'font-weight="{weight}" style="{FONT}">{s}</text>')


def fig_ttp():
    # (method, recall, precision lower bound)
    rows = [
        ("BM25, top-1 suggestion", 306 / 559, 0.19),
        ("BM25, top-3 suggestions", 406 / 559, 0.13),
        ("BM25, all 8 suggestions", 474 / 559, 0.11),
        ("rcATT (retrained)", 77 / 559, 0.72),
        ("qwen2.5:7b (open LLM)", 228 / 559, 228 / 781),
    ]
    w, label_w, top, bar_h, gap = 760, 210, 52, 14, 14
    plot_w = w - label_w - 70
    h = top + len(rows) * (2 * bar_h + gap) + 40
    b = [text(label_w, 20, "TTP extraction, 30 reports, 559 answer-key techniques", 14, weight="600"),
         f'<rect x="{label_w}" y="30" width="12" height="10" fill="{BLUE}"/>', text(label_w + 18, 39, "recall", 11),
         f'<rect x="{label_w + 80}" y="30" width="12" height="10" fill="{LIGHT}"/>',
         text(label_w + 98, 39, "precision (lower bound)", 11)]
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        x = label_w + t * plot_w
        b.append(f'<line x1="{x}" y1="{top - 6}" x2="{x}" y2="{h - 30}" stroke="{GRID}"/>')
        b.append(text(x, h - 14, f"{int(t * 100)}%", 10, "middle", MUTED))
    y = top
    for name, r, p in rows:
        b.append(text(label_w - 8, y + bar_h + 4, name, 12, "end"))
        for i, (v, c) in enumerate(((r, BLUE), (p, LIGHT))):
            yy = y + i * bar_h
            b.append(f'<rect x="{label_w}" y="{yy}" width="{v * plot_w:.1f}" height="{bar_h - 2}" fill="{c}"/>')
            b.append(text(label_w + v * plot_w + 5, yy + bar_h - 4, f"{v * 100:.0f}%", 10, color=MUTED))
        y += 2 * bar_h + gap
    return svg(w, h, "".join(b))


def fig_rules():
    # (method, techniques detected of 25, false positives, colour)
    rows = [
        ("Claude Sonnet 5 rules", 12, "4,439", BLUE),
        ("  same, 3 generic hunts removed*", 11, "158", LIGHT),
        ("SigmaHQ high, matched by tag", 10, "384", RED),
        ("Hybrid: SigmaHQ high + Claude", 16, "4,780", BLUE),
        ("  same, 3 generic hunts removed*", 15, "521", LIGHT),
        ("Control: every SigmaHQ high rule", 16, "1,222", RED),
        ("qwen2.5:14b rules", 0, "0", GRID),
        ("qwen2.5:7b rules", 0, "0", GRID),
    ]
    w, label_w, top, bar_h, gap = 760, 240, 56, 16, 8
    plot_w = w - label_w - 150
    h = top + len(rows) * (bar_h + gap) + 34
    b = [text(label_w, 20, "Techniques detected out of 25 (labelled attack_data)", 14, weight="600"),
         text(w - 10, top - 8, "false positives", 11, "end", MUTED)]
    for t in (0, 5, 10, 15, 20, 25):
        x = label_w + t / 25 * plot_w
        b.append(f'<line x1="{x}" y1="{top - 4}" x2="{x}" y2="{h - 28}" stroke="{GRID}"/>')
        b.append(text(x, h - 12, str(t), 10, "middle", MUTED))
    y = top
    for name, n, fp, c in rows:
        b.append(text(label_w - 8, y + bar_h - 4, name, 12, "end"))
        b.append(f'<rect x="{label_w}" y="{y}" width="{max(n / 25 * plot_w, 1):.1f}" height="{bar_h}" fill="{c}"/>')
        b.append(text(label_w + n / 25 * plot_w + 5, y + bar_h - 4, f"{n}/25", 11))
        b.append(text(w - 10, y + bar_h - 4, fp, 11, "end"))
        y += bar_h + gap
    return svg(w, h, "".join(b))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    (OUT / "fig1_ttp_extraction.svg").write_text(fig_ttp(), encoding="utf-8", newline="\n")
    (OUT / "fig2_rule_generation.svg").write_text(fig_rules(), encoding="utf-8", newline="\n")
    print("written to", OUT)
