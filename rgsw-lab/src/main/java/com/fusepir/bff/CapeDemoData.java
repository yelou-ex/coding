package com.fusepir.bff;

import com.fusepir.fusepir.*;


import com.fusepir.demo.*;
import com.fusepir.probe.*;
import com.fusepir.common.BfGen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Loads the CAPE demo database produced by {@code cape-demo/db/build_dataset.py} and
 * turns it into the CAPE SETUP artefacts (payload + plaintext tables {@code P}).
 *
 * <p>Contains a small, dependency-free JSON reader: the only JSON library on this
 * lab's classpath is guava, which does not parse JSON, so pulling in one more jar for
 * a single fixed-shape file is not worth it.
 *
 * <p>Geometry note. Each keyword needs exactly one slot in the {@code R x C} grid, and
 * it also needs {@code maxValues} rows inside that slot, so the grid must satisfy
 * {@code R >= maxValues} and {@code R * C >= keywordCount}. The demo DB has 128
 * keywords, so with {@code R = 16} we use {@code C = 8}.
 */
public final class CapeDemoData {

    /** One curated keyword combination that is known to return a non-empty answer. */
    public static final class PoolEntry {
        public final String[] kws;
        public final List<Integer> movies;

        PoolEntry(String[] kws, List<Integer> movies) {
            this.kws = kws;
            this.movies = movies;
        }
    }

    public final Map<String, Object> meta;
    public final List<String> keywords;
    public final Map<String, List<Integer>> kwToMovies;
    public final List<Integer> valueSpace;
    public final Map<Integer, String> titles;
    public final Map<Integer, Integer> rawMovieIds;
    public final List<PoolEntry> pool;

    private CapeDemoData(Map<String, Object> meta, List<String> keywords,
                         Map<String, List<Integer>> kwToMovies, List<Integer> valueSpace,
                         Map<Integer, String> titles, Map<Integer, Integer> rawMovieIds,
                         List<PoolEntry> pool) {
        this.meta = meta;
        this.keywords = keywords;
        this.kwToMovies = kwToMovies;
        this.valueSpace = valueSpace;
        this.titles = titles;
        this.rawMovieIds = rawMovieIds;
        this.pool = pool;
    }

    /**
     * 公开哈希 {@code H: keyword → u ∈ [0, RC)}，论文的 {@code h_a(K)}（A1 L836）。
     *
     * <p><b>⚠️ 这里有一个我踩了很久的坑，写清楚。</b>
     *
     * <p>论文的布局是：数组 {@code D} 长 {@code L_BFF}，补零到 {@code RC}，
     * 再按 {@code P_{c,b}(X) ← Σ_r D[r + cR][b]·X^r} 切成 {@code C} 个多项式。
     * 索引 {@code u} 决定 {@code c = ⌊u/R⌋}、{@code r = u mod R}。
     *
     * <p>第一版我把 {@code u} 取在 {@code [0, n)}（n = 关键词数），
     * 于是**只有前 ⌈n/⌊R/maxValues⌋⌉ 列是"有货"的**，其余列对应的
     * {@code D[r + cR]} 落在 {@code L_BFF} 之外（补零区）⇒ {@code P_{c,b} ≡ 0}
     * ⇒ 载荷恒为 0。症状是「一切看起来都对，但答案是 0」。
     *
     * <p>所以 {@code u} 必须取在 {@code [0, span)} 上，其中
     * <b>{@code span = cellsPerCol × C}</b>（{@code cellsPerCol = ⌊R/maxValues⌋}）。
     * 注意**不是** {@code R×C} —— 我第一版就是这么写的，结果 {@code u = 408} 时
     * {@code col = 408/5 = 81 > C = 26} 直接越界；而且每列只有 {@code cellsPerCol}
     * 个 cell 可放（不是 {@code R} 个），摊到 {@code R×C} 会让同一列挤进
     * {@code R/cellsPerCol} 倍的关键词 ⇒ `cell collision`。
     *
     * <p>映射：{@code col = u / cellsPerCol}、{@code cell = u % cellsPerCol}、
     * {@code rowOf = cell × maxValues}。
     *
     * <p>无碰撞：关键词两两不同槽、槽两两不同 → {@code u} 两两不同 → 列/行对两两不同。
     */
    /**
     * 论文的公开哈希 {@code H} —— <b>实现已搬到 {@link BffEncode#keywordHash}</b>。
     *
     * <p>保留转发只为不动已有调用点。本来 {@code CapeDemoData}（服务端算 {@code b_v}）
     * 与 {@code CapeQuery}（客户端算 {@code b_qry} 与位置）**各有一份逐字重复的实现**，
     * 注释写着"必须逐位一致" —— 那种安排靠人肉维持，迟早会漂。现在只有一份。
     */
    static int[] keywordHash(List<String> keywords, int cellsPerCol, int c) {
        return BffEncode.keywordHash(keywords, cellsPerCol, c);
    }

    public int intMeta(String key, int dflt) {
        Object v = meta.get(key);
        return v instanceof Number ? ((Number) v).intValue() : dflt;
    }

    /**
     * 长整数版：{@code plainModulus} 可以是 2^32，超出 int。
     * 之前只有 {@code intMeta}，所以库里的 {@code plainModulus} 一直没人读得动。
     */
    public long longMeta(String key, long dflt) {
        Object v = meta.get(key);
        return v instanceof Number ? ((Number) v).longValue() : dflt;
    }

    public String title(int movieId) {
        String t = titles.get(movieId);
        return t == null ? ("value#" + movieId) : t;
    }

    /**
     * The original MovieLens movieId behind a compact value id.
     *
     * <p>The value space is remapped to dense ids {@code 1..count} because raw
     * MovieLens ids reach 193609, well above the plaintext modulus t=65537, and every
     * payload coefficient must be &lt; t.
     */
    public int rawMovieId(int valueId) {
        Integer raw = rawMovieIds.get(valueId);
        return raw == null ? valueId : raw;
    }

    // ------------------------------------------------------------------
    //  SETUP artefacts
    // ------------------------------------------------------------------

    /** Payload + plaintext table, in the same layout as {@code CapeEndToEndNative}. */
    public static final class Tables {
        public final int n, c, r, k, bPay, maxValues, lBf;
        public final long t;
        public final long[][][] p;        // [C][B_pay][N]
        public final long[][] payload;    // [keywordCount][B_pay]
        public final int[] colOf;         // [keywordCount]
        public final int[] rowOf;         // [keywordCount]
        public final Map<String, Integer> kwIndex;

        Tables(int n, int c, int r, int k, int bPay, int maxValues, int lBf, long t,
               long[][][] p, long[][] payload, int[] colOf, int[] rowOf,
               Map<String, Integer> kwIndex) {
            this.n = n;
            this.c = c;
            this.r = r;
            this.k = k;
            this.bPay = bPay;
            this.maxValues = maxValues;
            this.lBf = lBf;
            this.t = t;
            this.p = p;
            this.payload = payload;
            this.colOf = colOf;
            this.rowOf = rowOf;
            this.kwIndex = kwIndex;
        }
    }

    /**
     * Builds payload and {@code P}. Deterministic: same DB + same seeds => same tables,
     * which is what lets the service cache SETUP across restarts.
     */
    public Tables buildTables(int n, int c, int r, int k, long t, long seed) {
        int maxValues = intMeta("maxValues", 3);
        int lBf = intMeta("lBf", 35);
        int bPay = 2 + maxValues * (1 + lBf);

        // ---- per-value keyword sets -> Bloom bits (BF.Gen of the CAPE paper) ----
        int maxSetSize = intMeta("maxSetSize", 4);
        BfGen bfGen = BfGen.choose(maxSetSize, epsFromMeta(), n);
        if (bfGen.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch: DB says " + lBf
                + ", recomputed " + bfGen.length() + " (maxSetSize=" + maxSetSize + ")");
        }
        Map<Integer, Set_> kwOfValue = new TreeMap<>();
        for (Map.Entry<String, List<Integer>> e : kwToMovies.entrySet()) {
            for (int mv : e.getValue()) {
                Set_ s = kwOfValue.get(mv);
                if (s == null) {
                    s = new Set_();
                    kwOfValue.put(mv, s);
                }
                s.add(e.getKey());
            }
        }

        int kwCount = keywords.size();
        Random rnd = new Random(seed);

        // ---- grid placement ----
        // CAPE geometry, and the thing that is easy to get wrong: a keyword occupies
        // ONE cell, and its k BFF shares live in that SAME COLUMN at k CONSECUTIVE
        // ROWS (that is why R must be >= maxValues).  So a cell uses maxValues rows,
        // not one, and a column holds R / maxValues cells.
        //
        // Capacities: rows R=16, cells per column = 16/3 = 5, cells per column-group
        // (C columns) = 5*C, keywords per group = 15*C.
        // Grid geometry, done exactly. A keyword needs one cell; the cell's k shares
        // occupy k CONSECUTIVE ROWS of one column (this is why R >= maxValues). So a
        // cell costs maxValues rows, a column holds floor(R/maxValues) cells, and we
        // simply lay the cells out column-major with enough columns to fit them all.
        // ---- grid placement ----
        // CAPE geometry, and the thing that is easy to get wrong: a keyword occupies
        // ONE cell, and its k BFF shares live in that SAME COLUMN at k CONSECUTIVE
        // ROWS (that is why R must be >= maxValues).  So a cell uses maxValues rows,
        // not one, and a column holds R / maxValues cells.
        //
        // 论文 A1 L836 是 `u_a ← h_a(K)`（**哈希**），A1 L837 再
        // `r_a = u_a mod R`、`c_a = ⌊u_a/R⌋`。
        // 早先的版本把 h_a 退化成了「关键词下标」（colOf[i] = i/cellsPerCol），
        // 那篇审计把它记为 D5b：功能上能跑，但**索引与关键词身份一一对应**，
        // 与论文的 u_a 分布不符，也会放大可关联性。
        //
        // 这里换成「均匀分布且无碰撞的 u_i ∈ [0, kwCount)」：
        // 算法本身要求 u_a ∈ [0, n)（Row 索引要落在 R 以内、列号要落在 C 以内），
        // 所以用一个必经查表的公开哈希：先算确定性混合哈希，再用线性探测消解碰撞，
        // 并按 keywords 的顺序做局部交换让它稳定（KEYWORD_HASH 是公开参数 pp 的一部分，
        // 论文 pp 里也含 H，所以这不是「偷偷藏状态」）。
        int cellsPerCol = FusePirSetup.cellsPerCol(r, maxValues);
        int colsNeeded = (kwCount + cellsPerCol - 1) / cellsPerCol;
        if (colsNeeded > c) {
            throw new IllegalStateException("need " + colsNeeded + " columns for "
                + kwCount + " keywords (cells/col=" + cellsPerCol + ") but got c=" + c);
        }
        int[] slotOf = keywordHash(keywords, cellsPerCol, c);
        int[] colOf = new int[kwCount];
        int[] rowOf = new int[kwCount];
        Map<String, Integer> kwIndex = new LinkedHashMap<>();
        for (int i = 0; i < kwCount; i++) {
            // 同一份 u 既决定列也决定 cell（论文 u_a 是单个整数）
            colOf[i] = slotOf[i] / cellsPerCol;
            // 行偏移**对齐到 maxValues 的整数倍**：任意两个关键词的行区间
            // 要么完全相同、要么完全不相交，BFF 的 k 个 share 不会被别人切进去。
            rowOf[i] = (slotOf[i] % cellsPerCol) * maxValues;
            kwIndex.put(keywords.get(i), i);
        }
        // Self-check: no two keywords may share a cell, and every cell must fit the grid.
        boolean[][] used = new boolean[c][cellsPerCol];
        for (int i = 0; i < kwCount; i++) {
            int cell = rowOf[i] / maxValues;
            if (colOf[i] >= c || cell >= cellsPerCol) {
                throw new IllegalStateException("keyword " + i + " maps outside the grid");
            }
            if (used[colOf[i]][cell]) {
                throw new IllegalStateException("cell collision at keyword " + i);
            }
            used[colOf[i]][cell] = true;
            if (rowOf[i] + k > r) {
                throw new IllegalStateException("keyword " + i + " needs rows "
                    + rowOf[i] + ".." + (rowOf[i] + k - 1) + " but R=" + r);
            }
        }

        // ---- payload ----
        long[][] payload = new long[kwCount][bPay];
        for (int i = 0; i < kwCount; i++) {
            String kw = keywords.get(i);
            List<Integer> vals = kwToMovies.get(kw);
            int cnt = Math.min(vals.size(), maxValues);
            payload[i][0] = inField(kw.hashCode(), t);
            payload[i][1] = cnt;
            for (int j = 0; j < cnt; j++) {
                int base = 2 + j * (1 + lBf);
                int mv = vals.get(j);
                if (mv < 0 || mv >= t) {
                    throw new IllegalStateException("movieId " + mv
                        + " does not fit the plaintext field (t=" + t + ")");
                }
                payload[i][base] = mv;
                boolean[] bits = bfGen.bits(kwOfValue.get(mv).asList());
                for (int bi = 0; bi < lBf; bi++) {
                    payload[i][base + 1 + bi] = bits[bi] ? 1 : 0;
                }
            }
            // Every coefficient must live in [0, t); BFV arithmetic is mod t, so a
            // larger value would silently wrap instead of failing.
            for (int b = 0; b < bPay; b++) {
                if (payload[i][b] < 0 || payload[i][b] >= t) {
                    throw new IllegalStateException("payload[" + i + "][" + b + "] = "
                        + payload[i][b] + " is outside the plaintext field (t=" + t + ")");
                }
            }
        }

        // ---- BFF 3-way shares: sum_a D[i][a][b] == payload[i][b] (mod t) ----
        long[][][] share = new long[kwCount][k][bPay];
        for (int i = 0; i < kwCount; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    // nextLong(bound) 而不是 nextInt((int) t)：t 可以大到 2^32，
                    // 强转 int 会溢出成 0，Random.nextInt 直接抛
                    // "bound must be positive"。t=65537 时两者等价。
                    share[i][a][b] = rnd.nextLong(t);
                    sum[b] = (sum[b] + share[i][a][b]) % t;
                }
            }
            for (int b = 0; b < bPay; b++) {
                share[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], t);
            }
        }

        // ---- P_{c,b}(X) ----
        //
        // ⚠️ **这一段我来回改过三次，把依据钉在原文上，别再改第四遍。**
        //
        // 论文里有**两套** Encode，参数化不同，混起来就会改错方向：
        //
        //   (甲) 正文 **Algorithm 1 (FusePIR)**（`coords_all.txt` 671-684 行）：
        //          9: for u = L_BFF to RC − 1 do
        //         10:     D[u] ← 0 ∈ Z_t^{B_pay}.
        //         11: end for
        //         12: for c = 0 to C − 1 do
        //          ...
        //         14:     P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r.
        //        —— `L_BFF = |D|`，表切到 `RC ≥ L_BFF`，**尾部 [L_BFF, RC) 补零**。
        //
        //   (乙) 附录 **Algorithm 3 (Encode)**（`coords_all.txt` 1448/1476-1478）：
        //        3:  L_BFF ← max(0.875 + 0.25·max_i |V_{K_i}|, ⌈1.125n⌉)
        //        12: D[u] ← ⊥.                （u = 0..L_BFF−1，"未填充"标记）
        //         6: D[u] ←$ Z_t^B.           （u = 0..L_BFF−1，**全区间均匀随机**）
        //        —— 正文 §2.4 与附录都写 "initialized (uniformly) in Z_t^B"，指这套。
        //
        // **我们这组参数下两套等价**：槽位 u 的取值范围是 `[0, span)`、
        // `span = cellsPerCol·C`；物理列数就是 `C`、列内只用到
        // `(cellsPerCol−1)·maxValues + k` 行。即 `L_BFF = span` 时
        // `[L_BFF, RC)` 这个尾部**不被任何行掩码寻址**（甲的第 9-11 行永不触发），
        // 于是「随机化 [0, L_BFF)」与「零填充 + 尾部补零」功能同一。
        //
        // 我上一次把它改崩，原因不是选了哪一套，而是**尾部判据的量纲写错了**：
        // 写成 `cc*r + rr >= L_BFF`，把「多项式列号 cc」和「槽位下标 u」当成了同
        // 一个量（u 每列只摊 cellsPerCol 个，cc 却一路数到 C），于是 cc ≥ 8 时
        // `8*16 = 128` 已逼近 130 ⇒ **第 8 列起整列被清空**。老路径要读的是
        // 第 0..25 列，症状就是 col≥8 的关键词三路 share 全 0 ⇒ 载荷 0 ⇒
        // 解密报 "result ciphertext is transparent"。
        //
        // 现在按 (乙) 实现：**槽位 u ∈ [0, L_BFF) 全部均匀随机，再把 BFF 槽覆写**。
        // 选 (乙) 而不是零填充的理由是**语义**而不是正确性：零填充会让「哪些槽没被
        // 用过」在明文表里一眼可见（本 demo 单进程、表在本地；真正的两方部署里服务
        // 器只拿到加密表与盲旋转结果，两者都不可见）。两条路的解密结果完全相同。
        long[][][] p = new long[c][bPay][n];
        final int lBff = cellsPerCol * c;
        // 槽位 u 对应「列 cc = u/cellsPerCol、列内第 cell = u%cellsPerCol 个 cell」，
        // cell 占满 maxValues 行（起始行 cell*maxValues）。按列遍历、逐 cell 填，
        // 每个 cell 恰好填一次，不重复、不遗漏。
        for (int cc = 0; cc < c; cc++) {
            for (int cell = 0; cell < cellsPerCol; cell++) {
                int base = cell * maxValues;
                for (int a = 0; a < maxValues; a++) {
                    for (int b = 0; b < bPay; b++) {
                        p[cc][b][base + a] = rnd.nextLong(t);
                    }
                }
            }
        }
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < k; a++) {
                for (int b = 0; b < bPay; b++) {
                    p[colOf[i]][b][rowOf[i] + a] = share[i][a][b];
                }
            }
        }
        // (3) dataRadius 自检：把「真正会被读到的系数」钉死。
        //     老路径读的是列 c_a = u/cellsPerCol ∈ [0, C)、列内行
        //     (u%cellsPerCol)*maxValues + a（a ∈ [0,k)），所以被读到的系数满足
        //     cc < C 且 rr < (cellsPerCol−1)*maxValues + k。上面随机化 + 覆写只覆盖
        //     了 [0, dataRadius)，其余系数保持数组默认的 0 —— 它们不承载语义。
        //     这条自检就是用来防「半径算错导致整列被清空/载荷被污染」那类事故的：
        //     我上一次改坏表构造，症状正是 col≥8 的整列变成 0。
        int dataRadius = (cellsPerCol - 1) * maxValues + k;
        if (lBff <= kwCount) {
            throw new IllegalStateException("L_BFF = " + lBff + " must exceed the keyword count "
                + kwCount + "; BFF.Encode requires at least one spare slot");
        }
        for (int cc = 0; cc < c; cc++) {
            for (int rr = dataRadius; rr < n; rr++) {
                for (int b = 0; b < bPay; b++) {
                    if (p[cc][b][rr] != 0) {
                        throw new IllegalStateException("column " + cc + " coefficient " + rr
                            + " bit " + b + " is outside the data radius " + dataRadius
                            + " but non-zero");
                    }
                }
            }
        }
        return new Tables(n, c, r, k, bPay, maxValues, lBf, t, p, payload,
            colOf, rowOf, kwIndex);
    }

    private double epsFromMeta() {
        Object v = meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
    }

    /**
     * Maps an arbitrary seed into the BFV plaintext field [1, t-1].
     *
     * <p>Every payload coefficient must be &lt; t, because the answer is computed as
     * ciphertext arithmetic modulo t. Getting this wrong is silent: a coefficient
     * that exceeds t simply wraps, and the only symptom is that one recovered value
     * is off by a multiple of t (the first version used {@code hash % 1_000_000 + 1},
     * so a fingerprint of 661965 came back as 6595 = 661965 - 10*65537).
     */
    public static long inField(long seed, long t) {
        return Math.floorMod(seed, t - 1) + 1;
    }

    /** Tiny ordered string set (avoids dragging in a full Set import ordering concern). */
    private static final class Set_ {
        private final TreeSet<String> inner = new TreeSet<>();

        void add(String s) {
            inner.add(s);
        }

        List<String> asList() {
            return new ArrayList<>(inner);
        }
    }

    // ------------------------------------------------------------------
    //  minimal JSON reader
    // ------------------------------------------------------------------

    public static CapeDemoData load(Path path) throws IOException {
        String text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        JsonValue root = new JsonParser(text).parse();
        Map<String, Object> obj = root.asObject();

        Map<String, Object> meta = castMap(obj.get("meta"));
        List<Object> kws = castList(obj.get("keywords"));
        List<Object> vs = castList(obj.get("valueSpace"));
        List<Object> pl = castList(obj.get("pool"));

        List<String> keywords = new ArrayList<>(kws.size());
        for (Object o : kws) {
            keywords.add((String) o);
        }

        List<Integer> valueSpace = new ArrayList<>(vs.size());
        for (Object o : vs) {
            valueSpace.add(asInt(o));
        }

        Map<String, List<Integer>> kwToMovies = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : castMap(obj.get("kwToMovies")).entrySet()) {
            List<Object> arr = castList(e.getValue());
            List<Integer> ids = new ArrayList<>(arr.size());
            for (Object o : arr) {
                ids.add(asInt(o));
            }
            kwToMovies.put(e.getKey(), ids);
        }

        Map<Integer, String> titles = new TreeMap<>();
        for (Map.Entry<String, Object> e : castMap(obj.get("titles")).entrySet()) {
            titles.put(Integer.parseInt(e.getKey()), (String) e.getValue());
        }

        Map<Integer, Integer> rawMovieIds = new TreeMap<>();
        Object rawObj = obj.get("rawMovieIds");
        if (rawObj instanceof Map) {
            for (Map.Entry<String, Object> e : castMap(rawObj).entrySet()) {
                rawMovieIds.put(Integer.parseInt(e.getKey()), asInt(e.getValue()));
            }
        }

        List<PoolEntry> pool = new ArrayList<>(pl.size());
        for (Object o : pl) {
            Map<String, Object> pe = castMap(o);
            List<Object> kk = castList(pe.get("kws"));
            String[] pair = new String[kk.size()];
            for (int i = 0; i < kk.size(); i++) {
                pair[i] = (String) kk.get(i);
            }
            List<Object> mm = castList(pe.get("movies"));
            List<Integer> ids = new ArrayList<>(mm.size());
            for (Object m : mm) {
                ids.add(asInt(m));
            }
            pool.add(new PoolEntry(pair, ids));
        }

        return new CapeDemoData(meta, keywords, kwToMovies, valueSpace, titles,
            rawMovieIds, pool);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    /**
     * Accepts either a JSON number or a JSON string holding a number. The builder
     * currently writes movie ids as strings (they arrive as strings from the CSV
     * reader), and being tolerant here keeps the loader independent of that choice.
     */
    private static int asInt(Object o) {
        if (o instanceof Number) {
            return (int) ((Number) o).longValue();
        }
        if (o instanceof String) {
            return Integer.parseInt(((String) o).trim());
        }
        throw new IllegalStateException("expected a number, got " + o);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castList(Object o) {
        return (List<Object>) o;
    }

    /** Parsed JSON node: either Map, List, String, Double/Long, Boolean or null. */
    public static final class JsonValue {
        public final Object v;

        public JsonValue(Object v) {
            this.v = v;
        }

        Map<String, Object> asObject() {
            return castMap(v);
        }
    }

    public static final class JsonParser {
        private final String s;
        private int i;

        public JsonParser(String s) {
            this.s = s;
        }

        public JsonValue parse() {
            skipWs();
            Object o = value();
            skipWs();
            if (i != s.length()) {
                throw new IllegalStateException("trailing content at " + i);
            }
            return new JsonValue(o);
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private Object value() {
            char ch = s.charAt(i);
            switch (ch) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return number();
            }
        }

        private void expect(String lit) {
            if (!s.startsWith(lit, i)) {
                throw new IllegalStateException("expected " + lit + " at " + i);
            }
            i += lit.length();
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;                      // '{'
            skipWs();
            if (s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                skipWs();
                String k = string();
                skipWs();
                if (s.charAt(i) != ':') {
                    throw new IllegalStateException("expected ':' at " + i);
                }
                i++;
                skipWs();
                m.put(k, value());
                skipWs();
                char ch = s.charAt(i++);
                if (ch == '}') {
                    return m;
                }
                if (ch != ',') {
                    throw new IllegalStateException("expected ',' or '}' at " + (i - 1));
                }
            }
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++;                      // '['
            skipWs();
            if (s.charAt(i) == ']') {
                i++;
                return l;
            }
            while (true) {
                skipWs();
                l.add(value());
                skipWs();
                char ch = s.charAt(i++);
                if (ch == ']') {
                    return l;
                }
                if (ch != ',') {
                    throw new IllegalStateException("expected ',' or ']' at " + (i - 1));
                }
            }
        }

        private String string() {
            if (s.charAt(i) != '"') {
                throw new IllegalStateException("expected '\"' at " + i);
            }
            i++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                char ch = s.charAt(i++);
                if (ch == '"') {
                    return sb.toString();
                }
                if (ch != '\\') {
                    sb.append(ch);
                    continue;
                }
                char esc = s.charAt(i++);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw new IllegalStateException("bad escape \\" + esc);
                }
            }
        }

        private Object number() {
            int st = i;
            while (i < s.length() && "+-.eE0123456789".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String num = s.substring(st, i);
            if (num.indexOf('.') >= 0 || num.indexOf('e') >= 0 || num.indexOf('E') >= 0) {
                return Double.valueOf(num);
            }
            return Long.valueOf(num);
        }
    }

    // ------------------------------------------------------------------
    //  self-check
    // ------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        Path path = java.nio.file.Paths.get(args.length > 0 ? args[0]
            : "cape-demo/db/keywords.json");
        long t0 = System.nanoTime();
        CapeDemoData db = load(path);
        long loadMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("loaded %s in %d ms%n", path, loadMs);
        System.out.printf("  keywords=%d valueSpace=%d pool=%d assoc=%d%n",
            db.keywords.size(), db.valueSpace.size(), db.pool.size(),
            db.intMeta("assoc", -1));
        System.out.printf("  maxValues=%d maxSetSize=%d lBf=%d bPay=%d%n",
            db.intMeta("maxValues", -1), db.intMeta("maxSetSize", -1),
            db.intMeta("lBf", -1), db.intMeta("bPay", -1));
        if (!db.pool.isEmpty()) {
            PoolEntry e = db.pool.get(0);
            System.out.printf("  pool[0]: %s + %s -> %s%n", e.kws[0], e.kws[1],
                Arrays.toString(e.movies.toArray()));
            System.out.printf("  title: %s%n", db.title(e.movies.get(0)));
        }
    }
}
