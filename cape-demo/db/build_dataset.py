#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build the CAPE demo database from MovieLens (ml-latest-small).

Design goals, in priority order
-------------------------------
1. The query cost must stay affordable.  CAPE's ANSWER cost is

       ANSWER = k * B_pay * d   CMUX
       B_pay  = 2 + maxValues * (1 + l_BF)
       l_BF   = min_h ceil( -h*maxSetSize / ln(1 - eps^(1/h)) )

   so it is driven ONLY by maxValues (values per keyword, max) and
   maxSetSize (keywords per value, max) -- NOT by how many keywords or
   values exist in total.  That is the property the demo exists to show.

2. "Roughly one in three random keyword additions must yield a non-empty
   conjunction."  This is a property of the DATABASE, so it is solved here:
   the builder greedily maximises the number of keyword PAIRS that share at
   least one value, and emits that list as `pool` (curated pairs).

   A hard mathematical note, recorded because it matters: you can NOT get
   (1/3 of all C(128,2) = 8128 pairs non-empty) AND a fast query at once.
   Non-empty pairs scale like e^2/c^3 (e = edges, c = distinct values), while
   cost is ~ linear in maxValues.  Measured ceiling on real MovieLens data at
   affordable settings is single-digit to ~15%, so the demo guarantees the
   1-in-3 behaviour by sampling from `pool` instead of blind-sampling 8128.

3. Keep values (movies) REAL: keyword = MovieLens tag, value = movieId.

Usage
-----
    python build_dataset.py
    python build_dataset.py --max-values 3 --max-set-size 4 --keywords 128
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ML = os.path.join(HERE, "..", "..", "ml-latest-small", "ml-latest-small")


def read_csv(path: str):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            yield row


def best_bloom_length(m: int, eps: float, max_len: int):
    """Mirror of BfGen.choose(): pick h minimising l, return (l, h)."""
    best_len, best_h = None, 1
    for h in range(1, 33):
        p = eps ** (1.0 / h)
        if not (0.0 < p < 1.0):
            continue
        den = math.log(1.0 - p)
        if den >= 0:
            continue
        ln = int(math.ceil(-h * m / den))
        if best_len is None or ln < best_len:
            best_len, best_h = ln, h
    if best_len is None:
        raise SystemExit("[FAIL] no feasible (l,h) for m=%d eps=%g" % (m, eps))
    if best_len > max_len:
        raise SystemExit(
            "[FAIL] l_BF %d exceeds ring dimension %d (maxSetSize=%d, eps=2^%.1f); "
            "lower max-set-size or raise N" % (best_len, max_len, m, math.log2(eps))
        )
    return best_len, best_h


def build(tag_movies, max_values, max_set_size, kw_target, only=None):
    """Greedy: repeatedly add the tag that creates the most new sharing pairs.

    `only` restricts the candidate tags (used by --pool-only to rebuild on the
    set of keywords that actually share a value).
    """
    movie_kws = defaultdict(set)      # movieId -> set(tag)
    kw_movies = {}                    # tag -> [movieId]  (ordered)
    used = set()

    while len(used) < kw_target:
        best_tag, best_pick, best_gain = None, None, -1
        for tag, movies in tag_movies.items():
            if tag in used:
                continue
            if only is not None and tag not in only:
                continue
            gain, pick = 0, []
            for mv in movies:
                if len(pick) >= max_values:
                    break
                if len(movie_kws[mv]) < max_set_size:
                    gain += len(movie_kws[mv])       # each already-there kw makes a pair
                    pick.append(mv)
            if not pick:
                continue
            if gain > best_gain or (gain == best_gain and best_pick is not None
                                    and len(pick) > len(best_pick)):
                best_gain, best_tag, best_pick = gain, tag, pick
        if best_tag is None:
            break
        used.add(best_tag)
        kw_movies[best_tag] = best_pick
        for mv in best_pick:
            movie_kws[mv].add(best_tag)

    return movie_kws, kw_movies


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml", default=DEFAULT_ML, help="MovieLens small dir")
    ap.add_argument("--out", default=os.path.join(HERE, "keywords.json"))
    ap.add_argument("--max-values", type=int, default=3)
    ap.add_argument("--max-set-size", type=int, default=4)
    ap.add_argument("--keywords", type=int, default=128)
    ap.add_argument("--n", type=int, default=8192, help="ring dimension N")
    ap.add_argument("--eps-bf", type=float, default=2.0 ** -6)
    ap.add_argument("--value-space", type=int, default=8192)
    ap.add_argument("--pool-only", action="store_true",
                    help="rebuild keeping only keywords that share a value, so "
                         "the candidate set itself has a high non-empty rate")
    ap.add_argument("--pretty", action="store_true",
                    help="pretty-print the JSON (default is minified)")
    args = ap.parse_args()

    tags_path = os.path.join(args.ml, "tags.csv")
    movies_path = os.path.join(args.ml, "movies.csv")
    for p in (tags_path, movies_path):
        if not os.path.exists(p):
            print("[FAIL] missing %s" % p)
            return 1

    # ---- load ----
    # Merge tags that differ only by case ("Atmospheric"/"atmospheric",
    # "Will Ferrell"/"will ferrell" both occur in MovieLens).  Without this the
    # keyword list has near-duplicates, and any case-insensitive JSON consumer
    # (PowerShell's ConvertFrom-Json, for one) rejects the file outright.
    tag_movies = defaultdict(list)
    canonical = {}                       # lowercased -> display form
    for row in read_csv(tags_path):
        raw = row["tag"]
        mv = row["movieId"]
        key = raw.lower()
        if key not in canonical:
            canonical[key] = raw
        disp = canonical[key]
        if mv not in tag_movies[disp]:
            tag_movies[disp].append(mv)

    titles = {}
    all_ids = []
    for row in read_csv(movies_path):
        titles[row["movieId"]] = row["title"]
        all_ids.append(row["movieId"])

    print("MovieLens: %d distinct tags (case-merged), %d movies"
          % (len(tag_movies), len(titles)))

    kws = args.keywords
    note = ""

    # ---- build (pass 1) ----
    movie_kws, kw_movies = build(tag_movies, args.max_values,
                                 args.max_set_size, kws)

    # ---- pass 2: keep only keywords that share a value with someone ----
    # Without this, the candidate list handed to the user contains many tags
    # that cannot match anything, so a random pick is usually empty.  Dropping
    # them makes "one in three random additions returns a hit" a property of
    # the KEYWORD SET itself, not of a UI-side whitelist.
    if args.pool_only:
        participating = sorted({t for mv in movie_kws.values() for t in mv})
        if len(participating) < kws:
            note = ("pool-only: only %d of %d keywords share a value; "
                    "rebuilt on that set" % (len(participating), kws))
            kws = len(participating)
        movie_kws, kw_movies = build(tag_movies, args.max_values,
                                     args.max_set_size, kws, only=set(participating))
        # one more prune round: rebuilding can orphan a few keywords again
        participating = sorted({t for mv in movie_kws.values() for t in mv})
        if len(participating) < len(kw_movies):
            kws = len(participating)
            movie_kws, kw_movies = build(tag_movies, args.max_values,
                                         args.max_set_size, kws,
                                         only=set(participating))

    keywords = sorted(kw_movies.keys())
    max_values = max((len(v) for v in kw_movies.values()), default=0)
    max_set_size = max((len(v) for v in movie_kws.values()), default=0)
    assoc = sum(len(v) for v in kw_movies.values())
    covered = sorted(movie_kws.keys(), key=lambda s: int(s))

    # ---- non-empty keyword pairs ----
    pair_index = defaultdict(set)     # (tag_a, tag_b) -> movies
    for mv in covered:
        ks = sorted(movie_kws[mv])
        for i in range(len(ks)):
            for j in range(i + 1, len(ks)):
                pair_index[(ks[i], ks[j])].add(mv)

    pool = [
        {"kws": [a, b], "movies": sorted(pair_index[(a, b)], key=lambda s: int(s))}
        for a, b in sorted(pair_index.keys())
    ]
    n_pairs = len(pool)
    total_pairs = len(keywords) * (len(keywords) - 1) // 2
    rate = 100.0 * n_pairs / total_pairs if total_pairs else 0.0

    # ---- CAPE cost ----
    l_bf, h_bf = best_bloom_length(max_set_size, args.eps_bf, args.n)
    b_pay = 2 + max_values * (1 + l_bf)
    units = 3 * b_pay
    per_cmux_ms = 583.0            # measured at N=8192
    answer_ms = units * per_cmux_ms

    # ---- compact value ids into the BFV plaintext field ----
    # MovieLens movieIds reach 193609, which is far above the plaintext modulus
    # t = 65537. Every payload coefficient must be < t, so the raw ids CANNOT be
    # written into the answer -- they have to be remapped to a dense index range
    # and resolved back to a title on the client side.
    value_space = all_ids[: args.value_space]
    if len(value_space) < args.value_space:
        print("[WARN] only %d movies available, value space set to that"
              % len(value_space))
    value_space = sorted(set(value_space) | set(covered), key=lambda s: int(s))

    vid = {mv: i + 1 for i, mv in enumerate(value_space)}     # 1 .. |values|, all < t
    if len(value_space) + 1 >= 65537:
        print("[FAIL] value space %d does not fit t=65537" % len(value_space))
        return 1

    kw_movies_c = {k: [vid[m] for m in v] for k, v in kw_movies.items()}
    pool_c = [
        {"kws": e["kws"], "movies": [vid[m] for m in e["movies"]]}
        for e in pool
    ]
    titles_c = {str(vid[mv]): titles.get(mv, "(unknown)") for mv in value_space}
    raw_c = {str(vid[mv]): mv for mv in value_space}

    # ---- write ----
    db = {
        "meta": {
            "source": "MovieLens ml-latest-small (tags.csv + movies.csv)",
            "keyword_count": len(keywords),
            "value_space": len(value_space),
            "assoc": assoc,
            "covered_values": len(covered),
            "maxValues": max_values,
            "maxSetSize": max_set_size,
            "epsBf": args.eps_bf,
            "lBf": l_bf,
            "bPay": b_pay,
            "unitCount": units,
            "n": args.n,
            "plainModulus": 65537,
            "valuesAreCompactIds": True,
            "pool_size": n_pairs,
            "pool_total_pairs": total_pairs,
            "pool_rate_pct": round(rate, 2),
            "note": note,
        },
        "keywords": keywords,
        "kwToMovies": kw_movies_c,
        "valueSpace": list(range(1, len(value_space) + 1)),
        "titles": titles_c,
        "rawMovieIds": raw_c,
        "pool": pool_c,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        # Minified by default: pretty-printing costs ~25% of the file size and this
        # file is ~480 KB of mostly-numeric arrays that nobody reads by eye.
        # Pass --pretty when you want to inspect it.
        if args.pretty:
            json.dump(db, fh, ensure_ascii=False, indent=1)
        else:
            json.dump(db, fh, ensure_ascii=False, separators=(",", ":"))

    print("")
    print("================ BUILT DATABASE ================")
    if note:
        print("  note                : %s" % note)
    print("  keywords            : %d" % len(keywords))
    print("  associations (edges): %d" % assoc)
    print("  covered values      : %d" % len(covered))
    print("  value space         : %d  (remapped to compact ids 1..%d, all < t=65537)"
          % (len(value_space), len(value_space)))
    print("  maxValues           : %d" % max_values)
    print("  maxSetSize          : %d" % max_set_size)
    print("  l_BF (h)            : %d (%d)" % (l_bf, h_bf))
    print("  B_pay               : %d" % b_pay)
    print("  units (k=3)         : %d" % units)
    print("  predicted ANSWER    : %.0f ms" % answer_ms)
    print("  non-empty pairs     : %d" % n_pairs)
    print("  rate vs all pairs   : %d / %d = %.2f%%"
          % (n_pairs, total_pairs, rate))
    print("  -> wrote %s" % args.out)
    print("================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
