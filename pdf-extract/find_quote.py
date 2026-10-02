#!/usr/bin/env python3
"""
在 CAPE 论文的词坐标抽取结果里检索原句，并打印其**阅读顺序**上下文。

## 为什么不能直接 Select-String

`coords_all.txt` 一行是 `y= <基线>  <x1>|片段1  <x2>|片段2 ...`。两个坑：

1. **词间几乎不留空格** —— 原文 "Instead of directly" 抽成 `Insteadofdirectly`。
   带空格的原句搜不到；要搜连写形式，或用本脚本（内部去空格比对）。
2. **一条原始行里可能同时含左右两栏的片段**（如标题行
   `y=138.0 122|CAPE: 169|… 328|Conjunctive 406|Keyword 466|PIR`）。
   所以「按原始行顺序拼成一条流」会造出根本不存在的跨栏邻接，
   必须**先按 x 分栏、栏内按 y 排序**再拼。

本脚本即按 (页, 栏) 分组、栏内按 y 排序建流，再在栏内检索。
栏的分界取 x=308（实测：左栏片段最大 x≈304，右栏最小 x≈309）。

## 用法

    python find_quote.py "<原句或片段>" [--before N] [--after M] [--file coords_all.txt]

例：
    python find_quote.py "The first two operations are used extensively"
    python find_quote.py "Instead of directly sending the RLWE one-hot"
    python find_quote.py "encrypted column selector chooses the column"
"""
import argparse
import re
import sys

LINE_RE = re.compile(r"^y=\s*([\d.]+)\s+(.*)$")
FRAG_RE = re.compile(r"(\d+)\|([^|]*)")
PAGE_RE = re.compile(r"PAGE\s+(\d+)")
COL_SPLIT = 308


def strip_ws(s):
    return re.sub(r"\s+", "", s)


def load(path):
    """-> rows: [{page,y,left:[(x,t)],right:[(x,t)]}]"""
    rows, page = [], 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if "PAGE" in line:
                m = PAGE_RE.search(line)
                if m:
                    page = int(m.group(1))
                continue
            m = LINE_RE.match(line)
            if not m:
                continue
            frags = [(int(x), t) for x, t in FRAG_RE.findall(m.group(2))]
            if not frags:
                continue
            left = sorted([f for f in frags if f[0] < COL_SPLIT])
            right = sorted([f for f in frags if f[0] >= COL_SPLIT])
            rows.append({"page": page, "y": float(m.group(1)),
                         "left": left, "right": right})
    return rows


def build_streams(rows):
    """-> {(page,col): [row_index,...]}(按 y 排序), {(page,col): 去空格文本}"""
    groups = {}
    for i, r in enumerate(rows):
        for col in (0, 1):
            if r["left"] if col == 0 else r["right"]:
                groups.setdefault((r["page"], col), []).append(i)
    streams = {}
    for key, idxs in groups.items():
        idxs.sort(key=lambda i: rows[i]["y"])
        col = key[1]
        segs = []
        for i in idxs:
            frags = rows[i]["left"] if col == 0 else rows[i]["right"]
            segs.append(strip_ws("".join(t for _, t in frags)))
        # ⚠️ 流文本也要转小写：只在 needle 上 lower() 会变成
        #    用 "thefirst…"去找流里的 "Thefirst…"，永远找不到。
        streams[key] = (idxs, segs, "".join(segs).lower())
    return streams


def locate(segs, k):
    """把去空格流里的字符下标 k 映射回行下标。"""
    acc = 0
    for j, seg in enumerate(segs):
        if acc + len(seg) > k:
            return j
        acc += len(seg)
    return max(0, len(segs) - 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("needle")
    ap.add_argument("--file", default="coords_all.txt")
    ap.add_argument("--before", type=int, default=3)
    ap.add_argument("--after", type=int, default=6)
    args = ap.parse_args()

    rows = load(args.file)
    streams = build_streams(rows)
    needle = strip_ws(args.needle).lower()

    found = []
    for key, (idxs, segs, txt) in sorted(streams.items()):
        pos = 0
        while True:
            k = txt.find(needle, pos)
            if k < 0:
                break
            found.append((key, locate(segs, k)))
            pos = k + 1

    if not found:
        print(f"未找到 {args.needle!r}（去空格后 {needle!r}）", file=sys.stderr)
        return 1

    # 去重（同一行可能因多次命中被登记）
    seen, uniq = set(), []
    for key, j in found:
        if (key, j) not in seen:
            seen.add((key, j))
            uniq.append((key, j))

    print(f"=== {args.needle!r}：{len(found)} 处命中，{len(uniq)} 个不同位置 ===\n")
    for (page, col), j in uniq:
        idxs, _, _ = streams[(page, col)]
        lo, hi = max(0, j - args.before), min(len(idxs), j + args.after + 1)
        print(f"--- 第 {page} 页 / {'右栏' if col else '左栏'} ---")
        for t in range(lo, hi):
            i = idxs[t]
            mark = ">>" if t == j else "  "
            body = "".join(x for _, x in (rows[i]["left"] if col == 0 else rows[i]["right"]))
            print(f"{mark} y={rows[i]['y']:6.1f}  {body}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
