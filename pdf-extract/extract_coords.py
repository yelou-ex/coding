# -*- coding: utf-8 -*-
"""按坐标逐行/逐格还原 PDF 里的算法伪代码与表格（用于与源码逐子程序对照）。

动机：extract_cols.py（中线硬切）与 extract_words.py（栏聚类）都会在
**算法伪代码**这种"行号+语句+数学符号混排、且带大缩进"的版面上出问题：
行号被并进上一行、条件分支的缩进层次丢失、上下标被重排。
要做「我们的实现是否符合论文算法」这种逐行核对，必须保留**原始坐标**。

本脚本对每一行输出：y、每个词的 x0 与文本，**不做任何重排**。

用法：
    python extract_coords.py <pdf> <out.txt> --pages 5,6,7 --grep "ANSWER|BlindRotate"

--pages 支持 1-based 页码列表（逗号分隔）或区间 5-8
--grep  只输出含该正则的行的**上下文窗口**（默认 ±6 行）
"""
import io
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pdfplumber


def parse_pages(spec, total):
    if not spec:
        return list(range(1, total + 1))
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return [p for p in out if 1 <= p <= total]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    pdf_path, out_path = sys.argv[1], sys.argv[2]
    pages_spec = None
    grep = None
    ctx = 6
    rest = sys.argv[3:]
    for i, a in enumerate(rest):
        if a == "--pages" and i + 1 < len(rest):
            pages_spec = rest[i + 1]
        if a == "--grep" and i + 1 < len(rest):
            grep = rest[i + 1]
        if a == "--ctx" and i + 1 < len(rest):
            ctx = int(rest[i + 1])

    lines_out = []
    with pdfplumber.open(pdf_path) as pdf:
        total = len(pdf.pages)
        for pno in parse_pages(pages_spec, total):
            page = pdf.pages[pno - 1]
            words = page.extract_words(use_text_flow=False, keep_blank_chars=False)
            # 按 top 聚行（容差 3pt）
            rows = {}
            for w in words:
                key = round(w["top"] / 3.0)
                rows.setdefault(key, []).append(w)
            lines_out.append("===== PAGE %d =====" % pno)
            for key in sorted(rows):
                ws = sorted(rows[key], key=lambda w: w["x0"])
                lines_out.append("y=%6.1f  %s" % (
                    ws[0]["top"],
                    "  ".join("%.0f|%s" % (w["x0"], w["text"]) for w in ws)))
    text = "\n".join(lines_out)

    if grep:
        pat = re.compile(grep, re.I)
        arr = lines_out
        keep = set()
        for i, ln in enumerate(arr):
            if pat.search(ln):
                for j in range(max(0, i - ctx), min(len(arr), i + ctx + 1)):
                    keep.add(j)
        text = "\n".join(arr[i] for i in sorted(keep))
        print("grep=%r  lines=%d" % (grep, len(keep)))

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("-> %s (%d chars)" % (out_path, len(text)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
