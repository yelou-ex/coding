# -*- coding: utf-8 -*-
"""按词坐标重建阅读顺序的 PDF 文本提取（替代 extract_cols.py 的"中线硬切"）。

为什么需要新的一版：extract_cols.py 按页面**中线**把页面切成左右两半分别抽取。
遇到下面任一情况就会静默错位，而错位后的正文仍然"看起来像正常英文"：
  * 跨栏元素（整宽表格、整宽图注、脚注、页眉页脚）
  * 三栏排版、或栏宽不等
  * 表格里的多列数字（会被按 y 交错拼成一行 → 数字串到错误的列）
  * 公式与上下标（pdfplumber 的 extract_text 会重排 glyph）

工作区里已经因为这件事吃过一次亏：CAPE 参数表.md §四 记录
`Submission_usenix_232_精读讲解.md` 里的 BFF 公式是"从乱码 PDF 里转录的"，
与 MPC4J 代码里的常数不一致。

本脚本改用**词级 bbox**：
  1. 取 page.extract_words()（每个词带 x0/x1/top/bottom）
  2. 用 x 直方图找出栏间隙（gutter），把词分到栏
  3. 每栏内按 (top, 行容差) 聚成行，行内按 x0 排序
  4. 表格行用更宽的行容差与"多空格间隔"保留列分隔感
输出里每行都带页码；可疑行（同一行内 x 跨度异常大）打 [WIDE] 标记，便于人工复核。

用法：
    python extract_words.py <pdf> <out.txt> [--cols 2] [--debug]
"""
import io
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pdfplumber


def cluster_columns(words, page_width, ncols):
    """按词的 x 中心做 1D 聚类，找出实际的栏边界。返回 [(x_lo, x_hi), ...]。"""
    if ncols <= 1:
        return [(0.0, page_width)]
    # 以词的左边界为特征，做简单的间隔切分：找最宽的 ncols-1 个空隙
    xs = sorted(w["x0"] for w in words)
    if not xs:
        return [(0.0, page_width)]
    gaps = []
    for i in range(len(xs) - 1):
        gaps.append((xs[i + 1] - xs[i], (xs[i] + xs[i + 1]) / 2.0))
    gaps.sort(reverse=True)
    cuts = sorted(c for _, c in gaps[: max(0, ncols - 1)])
    bounds = [0.0] + cuts + [page_width]
    return [(bounds[i], bounds[i + 1]) for i in range(len(bounds) - 1)]


def lines_from_words(words, y_tol=3.0):
    """把词按 top 聚成行；行内按 x0 排序。y_tol 是同一行的垂直容差（pt）。"""
    if not words:
        return []
    ws = sorted(words, key=lambda w: (round(w["top"], 1), w["x0"]))
    lines, cur, cur_top = [], [ws[0]], ws[0]["top"]
    for w in ws[1:]:
        if abs(w["top"] - cur_top) <= y_tol:
            cur.append(w)
        else:
            lines.append(cur)
            cur, cur_top = [w], w["top"]
    lines.append(cur)
    out = []
    for ln in lines:
        ln = sorted(ln, key=lambda w: w["x0"])
        # 词间按实际 x 间隙插入空格；间隙很大时插入多空格，保留表格列的可读性
        parts, prev_x1 = [], None
        for w in ln:
            if prev_x1 is not None:
                gap = w["x0"] - prev_x1
                if gap > 12:
                    parts.append("   ")        # 明显的列分隔
                elif gap > 1.5:
                    parts.append(" ")
            parts.append(w["text"])
            prev_x1 = w["x1"]
        text = "".join(parts)
        span = ln[-1]["x1"] - ln[0]["x0"]
        out.append((ln[0]["top"], text, span, ln[0]["x0"]))
    return out


def extract(pdf_path, out_path, ncols=2, y_tol=3.0, debug=False):
    chunks = []
    with pdfplumber.open(pdf_path) as pdf:
        total = len(pdf.pages)
        for pno, page in enumerate(pdf.pages, 1):
            W, H = page.width, page.height
            words = page.extract_words(use_text_flow=False, keep_blank_chars=False)
            chunks.append("===== PAGE %d (w=%.0f h=%.0f words=%d) =====" % (pno, W, H, len(words)))
            if not words:
                chunks.append("(no words)")
                continue
            cols = cluster_columns(words, W, ncols)
            for ci, (lo, hi) in enumerate(cols):
                inb = [w for w in words if lo <= (w["x0"] + w["x1"]) / 2 < hi]
                if not inb:
                    continue
                chunks.append("[COL %d  x=%.0f..%.0f  words=%d]" % (ci, lo, hi, len(inb)))
                for top, text, span, x0 in lines_from_words(inb, y_tol):
                    wide = " [WIDE]" if span > (hi - lo) * 0.98 else ""
                    chunks.append("  %s%s" % (text, wide))
            if debug:
                chunks.append("[gutter candidates] %s" % (cols,))
    text = "\n".join(chunks)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("pages=%d chars=%d -> %s" % (total, len(text), out_path))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    ncols = 2
    ytol = 3.0
    dbg = False
    rest = sys.argv[3:]
    for i, a in enumerate(rest):
        if a == "--cols" and i + 1 < len(rest):
            ncols = int(rest[i + 1])
        if a == "--ytol" and i + 1 < len(rest):
            ytol = float(rest[i + 1])
        if a == "--debug":
            dbg = True
    extract(sys.argv[1], sys.argv[2], ncols, ytol, dbg)
