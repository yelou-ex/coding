package com.fusepir.bff;

import com.fusepir.bloom.*;

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
     * ⚠️ <b>旧几何的一个坑（保留在此，因为新几何正是为了消掉它）</b>：
     *
     * <p>在"一个关键词一个位置 `u` + 该 cell 的 k 个连续行"那套里，`u` 必须取在
     * {@code [0, span)}、{@code span = cellsPerCol × C}，**不是** `R × C`。
     * 写成 `R × C` 会：① `u = 408` 时 `col = 408/5 = 81 > C` 越界；
     * ② 每列只有 `cellsPerCol` 个 cell 可放（不是 `R` 个），摊到 `R×C` 会让同一列
     * 挤进 `R/cellsPerCol` 倍的关键词 ⇒ `cell collision`。
     *
     * <p>新几何（论文几何）里这套 `span` / `cellsPerCol` 整个不存在了：
     * `u` 直接取在 `[0, L_BFF)`，`c = ⌊u/R⌋`、`r = u mod R`，
     * 见 {@link BffHash#positions} 与 {@link BffSetup.Layout}。
     */
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
        public final int[] colOf;         // [keywordCount] —— 仅旧几何，新几何为 null
        public final int[] rowOf;         // [keywordCount] —— 仅旧几何，新几何为 null
        /** <b>新几何</b>：{@code [keywordCount][k]}，{@code pos[i][a] = h_a(K_i)}。旧几何为 null。 */
        public final int[][] pos;
        /** <b>新几何</b>：A1 SETUP 4 的 {@code (R, C)} 与 A3 SETUP 2/3 的 {@code (s, L_BFF)}。旧几何为 null。 */
        public final BffSetup.Layout layout;
        public final Map<String, Integer> kwIndex;

        Tables(int n, int c, int r, int k, int bPay, int maxValues, int lBf, long t,
               long[][][] p, long[][] payload, int[] colOf, int[] rowOf,
               Map<String, Integer> kwIndex) {
            this(n, c, r, k, bPay, maxValues, lBf, t, p, payload, colOf, rowOf,
                null, null, kwIndex);
        }

        Tables(int n, int c, int r, int k, int bPay, int maxValues, int lBf, long t,
               long[][][] p, long[][] payload, int[] colOf, int[] rowOf,
               int[][] pos, BffSetup.Layout layout, Map<String, Integer> kwIndex) {
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
            this.pos = pos;
            this.layout = layout;
            this.kwIndex = kwIndex;
        }

        /** 走的是不是论文几何（{@code pos} 非 null）。 */
        public boolean isPaperGeometry() {
            return pos != null;
        }

        /**
         * 关键词 {@code i} 的第 {@code a} 路落点 {@code (列 c_a, 行 r_a)}。
         *
         * <p>论文 A1 QUERY 3：{@code r_a = u_a mod R}、{@code c_a = ⌊u_a/R⌋}。
         * 这是**新几何**唯一的落点算法；旧几何的 {@code (colOf, rowOf + a)} 已被它取代。
         */
        public int[] colRow(int i, int a) {
            if (pos == null) {
                return new int[] {colOf[i], rowOf[i] + a};
            }
            final int u = pos[i][a];
            return new int[] {u / layout.r, u % layout.r};
        }
    }

    /**
     * Builds payload and {@code P}. Deterministic: same DB + same seeds => same tables,
     * which is what lets the service cache SETUP across restarts.
     */
    public Tables buildTables(int n, int c, int r, int k, long t, long seed) {
        int maxValues = intMeta("maxValues", 3);
        int lBf = intMeta("lBf", 35);
        int bPay = FusePirSetup.payloadBpay(FusePirSetup.fpSlots(t), maxValues, 1 + lBf);

        // ---- per-value keyword sets -> Bloom bits (A2 SETUP 3-6, 实现已搬到 bloom/BloomSetup) ----
        int maxSetSize = intMeta("maxSetSize", 4);
        BfGen bfGen = BfGen.choose(maxSetSize, epsFromMeta(), n);
        if (bfGen.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch: DB says " + lBf
                + ", recomputed " + bfGen.length() + " (maxSetSize=" + maxSetSize + ")");
        }
        // ⚠️ 2026-10-14 深夜：三项都收口到 bloom/BloomSetup
        //   (a) A2 SETUP 2 `m ← max_i |V_{K_i}|` —— 从 DB **实算**并与 meta 对账。
        //       此前直接信 meta，而载荷构造用 `Math.min(vals.size(), maxValues)`
        //       ⇒ meta 偏小会**静默丢值**；m 还决定网格 cellsPerCol，错了连带错布局。
        //   (b) A2 SETUP 3-4 `S_v` —— 此前这里与 cape/CapeQueryDecode **各写一遍**。
        //   (c) A2 SETUP 5 `b_v ← BF.Gen(0,S_v)`。
        int mDb = BloomSetup.maxValues(kwToMovies);
        BloomSetup.reconcile(mDb, maxValues);
        Map<Integer, List<String>> valueToKeywords = BloomSetup.valueToKeywords(kwToMovies);
        Map<Integer, boolean[]> valueBloom = BloomSetup.valueBloomBits(bfGen, valueToKeywords);

        int kwCount = keywords.size();
        Random rnd = new Random(seed);

        // ---- grid placement (BFF.Encode 的摆放步骤 —— 实现已搬到 BffEncodeLegacy.place) ----
        //
        // 论文 A1 L836 是 `u_a ← h_a(K)`（**哈希**），A1 L837 再
        // `r_a = u_a mod R`、`c_a = ⌊u_a/R⌋`。
        // 早先的版本把 h_a 退化成了「关键词下标」（colOf[i] = i/cellsPerCol），
        // 那篇审计把它记为 D5b：功能上能跑，但**索引与关键词身份一一对应**，
        // 与论文的 u_a 分布不符，也会放大可关联性。
        //
        // 现在走公开哈希 H（`BffEncodeLegacy.keywordHash`，线性探测消解碰撞）：
        // H 是公开参数 pp 的一部分（论文 pp 里也含 H），所以这不是「偷偷藏状态」。
        //
        // ⚠️ 三条自检（越界 / cell 碰撞 / **k ≤ maxValues**）现在都在 `BffEncodeLegacy.place` 里。
        //    其中 k ≤ maxValues 是 2026-10-14 深夜补的：原先只检查 `rowOf + k > R`，
        //    那只保证不出 R —— 出了 cell 照样会静默写进下一个 cell（论文支持 arity 4）。
        int cellsPerCol = FusePirSetup.cellsPerCol(r, maxValues);
        int colsNeeded = FusePirSetup.columns(kwCount, cellsPerCol);
        if (colsNeeded > c) {
            throw new IllegalStateException("need " + colsNeeded + " columns for "
                + kwCount + " keywords (cells/col=" + cellsPerCol + ") but got c=" + c);
        }
        BffEncodeLegacy.Placement place = BffEncodeLegacy.place(keywords, kwCount, cellsPerCol, c, r, maxValues, k);
        int[] colOf = place.colOf;
        int[] rowOf = place.rowOf;
        Map<String, Integer> kwIndex = new LinkedHashMap<>();
        for (int i = 0; i < kwCount; i++) {
            kwIndex.put(keywords.get(i), i);
        }

        // ---- payload（A1 SETUP 6）----
        // ⚠️ 算式只有一份：`buildPayload`。新几何的 buildTablesPaper 也调它
        // —— 载荷布局是论文里定义一次的东西，两条几何各抄一遍就是漂移源。
        long[][] payload = buildPayload(valueBloom, lBf, maxValues, bPay, t);

        // ---- BFF k-way shares: sum_a D[i][a][b] == payload[i][b] (mod t) ----
        // 实现已搬到 `BffEncodeLegacy.splitShares`（伪代码 BFF.Encode 的那一步）。
        // ⚠️ 它消耗 `rnd`（先分享、后表随机化），顺序不能变，否则固定种子下的表不再可复现。
        long[][][] share = BffEncodeLegacy.splitShares(payload, k, t, rnd);

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
        final int lBff = place.lBff;
        // Alg 3 ENCODE 6：D 的 [0, L_BFF) 全区间均匀随机（实现已搬到 BffEncodeLegacy.randomizeD）
        BffEncodeLegacy.randomizeD(p, c, cellsPerCol, maxValues, bPay, t, rnd);
        // Alg 1 SETUP 8 的后半：把 k 路 share 写进 D（BffEncodeLegacy.writeD）
        BffEncodeLegacy.writeD(p, colOf, rowOf, share, kwCount, k, bPay);
        // Alg 1 SETUP 12-16 的半径自检（BffEncode.checkDataRadius）
        int dataRadius = (cellsPerCol - 1) * maxValues + k;
        if (lBff <= kwCount) {
            throw new IllegalStateException("L_BFF = " + lBff + " must exceed the keyword count "
                + kwCount + "; BFF.Encode requires at least one spare slot");
        }
        BffEncode.checkDataRadius(p, c, bPay, n, dataRadius);
        return new Tables(n, c, r, k, bPay, maxValues, lBf, t, p, payload,
            colOf, rowOf, kwIndex);
    }

    /**
     * <b>A1 SETUP 6</b>：{@code y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ … ‖ v_{i,m} ∈ Z_t^{B_pay}}。
     *
     * <p>CAPE 把每个值换成 {@code (v, b_v)}（{@code b_v} 是 ℓ_BF 位的 Bloom 段），
     * 所以一个值占 {@code 1 + ℓ_BF} 项，布局算式全部来自
     * {@link FusePirSetup#perValue}/{@code valueOffset}（全项目唯一一份）。
     *
     * <p>⚠️ 每个系数都必须落在 {@code [0, t)}：答案在同态里按 `mod t` 算，
     * 超了会**静默回绕**，症状只是某个值差一个 `t` 的倍数
     * （早期版本用 {@code hash % 1_000_000 + 1}，指纹 661965 回来变成
     * 6595 = 661965 − 10·65537）。所以这里逐项自检。
     */
    private long[][] buildPayload(Map<Integer, boolean[]> valueBloom,
                                  int lBf, int maxValues, int bPay, long t) {
        final int kwCount = keywords.size();
        final long[][] payload = new long[kwCount][bPay];
        final int fpSlots = FusePirSetup.fpSlots(t);      // μ=40 要几个 Z_t 槽（t=2^32 ⇒ 2）
        for (int i = 0; i < kwCount; i++) {
            final String kw = keywords.get(i);
            final List<Integer> vals = kwToMovies.get(kw);
            final int cnt = Math.min(vals.size(), maxValues);
            // A1 SETUP 6：y ← fp(K) ‖ m_i ‖ v_1 ‖ … ‖ v_m
            // fp 是 **40 bit**（论文 §5.1 μ=40），装不进一个槽 ⇒ 占 fpSlots 个槽。
            final long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);
            for (int s = 0; s < fpSlots; s++) {
                payload[i][s] = fpD[s];
            }
            payload[i][FusePirSetup.countOffset(fpSlots)] = cnt;
            for (int j = 0; j < cnt; j++) {
                final int base = FusePirSetup.valueOffset(fpSlots, j, 1 + lBf);
                final int mv = vals.get(j);
                if (mv < 0 || mv >= t) {
                    throw new IllegalStateException("movieId " + mv
                        + " does not fit the plaintext field (t=" + t + ")");
                }
                payload[i][base] = mv;
                final boolean[] bits = valueBloom.get(mv);   // A2 SETUP 5 的 b_v
                if (bits == null) {
                    throw new IllegalStateException("值 " + mv + " 不在 S_v 里 —— "
                        + "DB 的 values 与 kwToMovies 不一致");
                }
                for (int bi = 0; bi < lBf; bi++) {
                    payload[i][base + 1 + bi] = bits[bi] ? 1 : 0;
                }
            }
            for (int b = 0; b < bPay; b++) {
                if (payload[i][b] < 0 || payload[i][b] >= t) {
                    throw new IllegalStateException("payload[" + i + "][" + b + "] = "
                        + payload[i][b] + " is outside the plaintext field (t=" + t + ")");
                }
            }
            // 自检：写进去的 fpSlots 个槽必须能拼回 40-bit 指纹
            // （构造侧与解析侧用的是同一对 fpDigits/fpFromDigits，这里防的是
            //  "拆的时候用了一个 t、拼的时候用了另一个 t" 这种静默错配）
            if (BffSetup.fpFromDigits(payload[i], 0, fpSlots, t) != BffSetup.fp(kw)) {
                throw new IllegalStateException("指纹往返失败：kw=" + i + "（" + kw + "）");
            }
        }
        return payload;
    }

    /** 新几何建表时最多试几个位置函数种子（A3 ENCODE 2-3 的重试）。 */
    public static final int PAPER_MAX_ATTEMPTS = 64;

    /**
     * <b>论文几何建表</b> —— 与 {@link #buildTables} 并列的那一套。
     *
     * <pre>
     *   A3 SETUP  2/3: s、L_BFF                       ← BffHash.allocate（BFF 参考实现的参数化）
     *   A3 SETUP  9:   H = {h_j} ← BFF.HashGen(ρ_H, L_BFF, s, k) ← BffHash.hashGen(…, ρ_H)
     *                                                              + HashGen.positions(K)
     *   A1 SETUP  4:   Select R, C s.t. RC ≥ L_BFF, R ≤ N ← BffSetup.layout（方格策略，见 MAP §12.7）
     *   A1 SETUP  8:   (D, H) ← BFF.Encode(…)          ← BffEncode.encode（剥皮 + LIFO + 换种子重试）
     *   A1 SETUP  9-11: D[u] ← 0, u ∈ [L_BFF, RC)      ← BffEncode.zeroTail
     *   A1 SETUP 12-16: P_{c,b}(X) ← Σ_r D[r+cR][b]·X^r ← BffEncode.embed
     * </pre>
     *
     * <p><b>与旧几何的区别（这是这次改动的全部意义）</b>：
     * <ul>
     *   <li>旧：一个关键词占 **1 个位置** `u`，k 路分享塞进该 cell 的 **连续 k 行**；
     *       `u → (col = u/cellsPerCol, row = (u%cellsPerCol)·maxValues + a)`。</li>
     *   <li>新：一个关键词占 **k 个分散位置** `{h_a(K)}`（A3 的 BFF 位置函数）；
     *       `u → (c = ⌊u/R⌋, r = u mod R)`，**一个位置占一行**。</li>
     * </ul>
     * ⇒ `cellsPerCol`、`maxValues`-在网格里、线性探测这一整套**整个消失**。
     *
     * @param ringDim  环维度 `N`
     * @param k        arity（论文 3）
     * @param seed     表随机化种子（A3 ENCODE 5-6）
     * @param forceR   强制 `R`（{@code 0} = 方格策略）
     * @param hashSeed 位置函数种子 `ρ_H` 的**初值**（A3 SETUP 8）—— 它交给
     *                 {@code BffEncode.encode} 当 {@code seed0}，重试时每次 +1
     *                 （A3 ENCODE 2-3 的"换新种子重来"）。
     *                 ⚠️ 只有<b>第一次尝试</b>用的是这个数本身。
     */
    public Tables buildTablesPaper(int ringDim, int k, long t, long seed,
                                   int forceR, long hashSeed) {
        final int maxValues = intMeta("maxValues", 3);
        final int lBf = intMeta("lBf", 35);
        final int bPay = FusePirSetup.payloadBpay(FusePirSetup.fpSlots(t), maxValues, 1 + lBf);

        final int maxSetSize = intMeta("maxSetSize", 4);
        final BfGen bfGen = BfGen.choose(maxSetSize, epsFromMeta(), ringDim);
        if (bfGen.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch: DB says " + lBf
                + ", recomputed " + bfGen.length() + " (maxSetSize=" + maxSetSize + ")");
        }
        BloomSetup.reconcile(BloomSetup.maxValues(kwToMovies), maxValues);
        final Map<Integer, List<String>> valueToKeywords = BloomSetup.valueToKeywords(kwToMovies);
        final Map<Integer, boolean[]> valueBloom = BloomSetup.valueBloomBits(bfGen, valueToKeywords);

        final int kwCount = keywords.size();
        final Map<String, Integer> kwIndex = new LinkedHashMap<>();
        for (int i = 0; i < kwCount; i++) {
            kwIndex.put(keywords.get(i), i);
        }

        // ── A1 SETUP 4 + A3 SETUP 2/3 ────────────────────────────────────
        final BffHash.BffParams bp = BffHash.allocate(kwCount, k);
        final BffSetup.Layout lo = BffSetup.layout(bp.arrayLength, bp.segmentLength, ringDim, forceR);

        final long[][] payload = buildPayload(valueBloom, lBf, maxValues, bPay, t);

        // ── A1 SETUP 8：BFF.Encode（剥皮 + LIFO 回填 + 重试） ────────────
        // A3 SETUP 9 的**原签名**：BFF.HashGen(ρ_H, L_BFF, s, k)。
        // ⚠️ 2026-10-15（本轮）：此前这一行是 `s -> BffHash.positions(keywords, s, bp.hashGen())`
        //    —— `HashGen` 只管尺寸（L_BFF, s, k），**ρ_H 另外当参数传给 positions**，
        //    于是伪代码的**一次调用**在代码里是两处（尺寸一处、种子一处）。
        //    现在改走四参入口：`hashGen(L_BFF, s, k, ρ_H)` 拿一个已经把 ρ_H 装进去的
        //    `HashGen`，位置函数由它自己给出 —— **逐位等价**（同一个
        //    `oracleHash`、同一个段结构；`probe/HashGenRhoTest` 对 128 个关键词逐位比对过），
        //    只是签名与伪代码那一行一一对应了。
        // ⚠️ 注意 lambda 里的 `s` 是 **A3 ENCODE 2-3 每次重试换的那个位置函数种子**，
        //    不是 A3 SETUP 8 的 ρ_H；`hashSeed` 只是第一次的初值（encode 里 `seed0 + attempt − 1`）。
        //    所以每次重试**都要新建** `HashGen`（ρ_H 是 final 的，不能改）——
        //    这不是额外开销，原来那一版同样每次重建 `bp.hashGen()`。
        //
        // ⚠️⚠️ **一处行为变化，必须在这里点名**（本轮唯一的一处，不是措辞变化）：
        //    旧写法 `BffHash.positions(keywords, s, bp.hashGen())` 里，段结构来自
        //    `bp.hashGen()`（**那是个不含种子的三参入口**），而位置函数用的是
        //    `positions(…, s, …)` 传进去的 `s` ⇒ 重试第 i 次（`s = hashSeed + i − 1`）
        //    确实会换位置函数。新写法 `hashGen(…, s).positions(...)` 在语义上**完全相同**：
        //    段结构还是那三样（`bp` 的 `arrayLength/segmentLength/k`，一个字节没变），
        //    种子还是同一个 `s`。⇒ 对本 demo 的第一组参数（`ρ_H = 20261014`，第 1 次就成功）
        //    结果**逐位相同**，`FusePirQueryOpsTest`／`CapePaperGeometryTest` 的
        //    128 关键词对表断言可证；重试路径（`attempt ≥ 2`）在本 demo 下**从未触发**，
        //    所以它"没变"这件事是**代码复核**得出的，不是探针验过的（本轮探针只覆盖
        //    单次调用与两次调用在**同一个种子**下的等价性）。
        final BffEncode.PositionFn posFn =
            s -> BffHash.hashGen(bp.arrayLength, bp.segmentLength, k, s).positions(keywords);
        final BffEncode.Table tab = BffEncode.encode(kwCount, k, lo, posFn, hashSeed,
            payload, t, PAPER_MAX_ATTEMPTS, new Random(seed));
        if (tab == null) {
            throw new IllegalStateException("BFF.Encode 失败：试了 " + PAPER_MAX_ATTEMPTS
                + " 个位置函数种子都得不到 |S| = n（n=" + kwCount + ", L_BFF=" + lo.lBff
                + "）—— 说明 L_BFF 余量不够或分段结构不对");
        }

        // ── A1 SETUP 9-11：尾部补零 ─────────────────────────────────────
        // ⚠️ encode 里已经把整张网格先置 0 再随机化 [0, L_BFF)，所以尾部天然是 0。
        //    这里显式再调一次，是为了让论文那一步在**调用图**上看得见，也是自检。
        BffEncode.zeroTail(tab.d, lo, bPay);

        // ── A1 SETUP 12-16：切成 P_{c,b} ───────────────────────────────
        final long[][][] p = BffEncode.embed(tab.d, lo, bPay);
        // 半径自检：只有系数 [0, R) 允许非零
        BffEncode.checkDataRadius(p, lo.c, bPay, ringDim, lo.r);

        return new Tables(ringDim, lo.c, lo.r, k, bPay, maxValues, lBf, t, p, payload,
            null, null, tab.pos, lo, kwIndex);
    }

    private double epsFromMeta() {
        Object v = meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
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
