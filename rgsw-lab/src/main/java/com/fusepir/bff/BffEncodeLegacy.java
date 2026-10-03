package com.fusepir.bff;

import com.fusepir.fusepir.*;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * <b>BFF · 旧几何（降级对照路径）</b> —— 从 {@link BffEncode} 里搬出来的一整套。
 *
 * <h3>⚠️ 这里的东西不是论文的做法，只是为了让旧数字仍可复现</h3>
 * 旧几何 = 「一个关键词**一个**位置 `u`（哈希 + 线性探测），
 * 再把这个位置所在 cell 的 **k 个连续行**当作 k 路」。
 * 它**不是**论文的 BFF：
 * <ul>
 *   <li>论文 A1 QUERY 3 是 `u_a ← h_a(K)`（**k 个分散位置**），
 *       由 {@link BffHash#positions} 提供，不是这里的 {@link #keywordHash}；</li>
 *   <li>论文 A3 ENCODE 8-17 是**剥皮 LIFO 回填**，由 {@link BffEncode#encode} 实现，
 *       不是这里的 {@link #splitShares}（随机拆 k 路）；</li>
 *   <li>论文的落点是 `(⌊u/R⌋, u mod R)`，不是这里的
 *       `(u/cellsPerCol, (u%cellsPerCol)·maxValues + a)`。</li>
 * </ul>
 *
 * <h3>为什么没删掉</h3>
 * `CapeDemoService` 与 `CapeQuery.build(...)` 目前仍走这条路（服务侧是**旧几何默认**，
 * 见 MAP §14.5）。把这些函数删掉会直接编译不过 —— 所以是**搬到明确命名的地方**，
 * 让 {@link BffEncode} 只露论文路径。等服务的默认路径切到论文几何之后，
 * 这个文件可以整个删除。
 *
 * <p>保留它的唯一正当理由是**可复现性**：MAP §14.4 那张"被推翻的旧数字"表
 * （`C=26`、`L_BFF=130`、`dataRadius=15`）要靠这条路重跑出来。
 */
public final class BffEncodeLegacy {

    private BffEncodeLegacy() {
    }
    // ==================================================================
    //  ① 公开哈希 H
    // ==================================================================

    /**
     * 论文的公开哈希 {@code H}：把 {@code n} 个关键词摊到 {@code span = max(n, cellsPerCol·c)}
     * 个槽位上，用**线性探测**解决碰撞，返回「关键词下标 → 槽位 u」的映射。
     *
     * <p>⚠️ 槽数组必须是 {@code span} 长，不是 {@code n} —— 按 {@code u ∈ [0, span)} 索引。
     * 这一点此前踩过：写成 {@code new int[n]} 时 {@code cc ≥ 8} 的列会被静默清空。
     *
     * <p>客户端与服务端**必须**算出同一个位置，所以两边都走这一个实现
     * （此前服务端与客户端各有一份逐字重复的副本，靠注释"必须逐位一致"来约束）。
     *
     * @param cellsPerCol 一列里有多少个 cell（{@code ⌊R/maxValues⌋}）
     * @param c           列数 {@code C}
     */
    public static int[] keywordHash(List<String> keywords, int cellsPerCol, int c) {
        final int n = keywords.size();
        final int span = Math.max(n, FusePirSetup.span(cellsPerCol, c));
        int[] slot = new int[span];
        Arrays.fill(slot, -1);
        for (int i = 0; i < n; i++) {
            int h = mix(keywords.get(i).hashCode()) % span;
            if (h < 0) {
                h += span;
            }
            while (slot[h] != -1) {
                h = (h + 1) % span;
            }
            slot[h] = i;
        }
        // slot[h] = 关键词下标 ⇒ 反查成「关键词下标 → 位置 u」
        int[] out = new int[n];
        for (int h = 0; h < span; h++) {
            if (slot[h] >= 0) {
                out[slot[h]] = h;
            }
        }
        return out;
    }

    /** murmur3 的 finalizer：把 {@code String.hashCode} 的弱分布打散。 */
    public static int mix(int h) {
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;
        return h;
    }

    // ==================================================================
    //  ② 摆放（BFF.Encode 的"把 K_i 放到位置上"）
    // ==================================================================

    /** 关键词在网格里的落点：{@code u → (列 c_i, 列内起始行 r_i)}。 */
    public static final class Placement {
        /** {@code [kwCount]} 每个关键词的列号 {@code c_i = u / cellsPerCol}。 */
        public final int[] colOf;
        /** {@code [kwCount]} 每个关键词的列内起始行 {@code r_i = (u % cellsPerCol)·maxValues}。 */
        public final int[] rowOf;
        /** {@code L_BFF = cellsPerCol · C}（我们的定义，是网格副产品）。 */
        public final int lBff;

        Placement(int[] colOf, int[] rowOf, int lBff) {
            this.colOf = colOf;
            this.rowOf = rowOf;
            this.lBff = lBff;
        }
    }

    /**
     * {@code BFF.Encode} 的摆放那一步：算出 {@code (c_i, r_i)}，并**逐条自检**。
     *
     * <p>三条自检（都抛异常，不静默）：
     * <ol>
     *   <li>每个关键词落在网格内（{@code c_i < C}、{@code cell < cellsPerCol}）；</li>
     *   <li><b>没有两个关键词共用一个 cell</b>（否则两路分享会互相覆盖）；</li>
     *   <li><b>{@code k ≤ maxValues}</b> —— 一个 cell 只有 {@code maxValues} 行，
     *       而一个关键词要写 {@code k} 行分享。<b>这条此前没有检查</b>：原来加的是
     *       {@code rowOf + k > R}，那只保证不出 {@code R} ——
     *       <b>出了 cell 照样会静默写进下一个 cell</b>。论文支持 arity 4
     *       （P1-4 讨论过 k=4），所以这是一条潜伏 bug，不是当前 bug。</li>
     * </ol>
     *
     * @param r 行数 {@code R}
     */
    public static Placement place(List<String> keywords, int kwCount, int cellsPerCol, int c,
                                  int r, int maxValues, int k) {
        if (k > maxValues) {
            throw new IllegalStateException("k=" + k + " > maxValues=" + maxValues
                + "：一个 cell 只有 maxValues 行，k 路分享会溢出到下一个 cell（静默污染）");
        }
        int[] slotOf = keywordHash(keywords, cellsPerCol, c);
        int[] colOf = new int[kwCount];
        int[] rowOf = new int[kwCount];
        for (int i = 0; i < kwCount; i++) {
            // 同一个 u 既决定列也决定 cell（论文 u_a 是单个整数）
            colOf[i] = slotOf[i] / cellsPerCol;
            // 行偏移**对齐到 maxValues 的整数倍**：任意两个关键词的行区间
            // 要么完全相同、要么完全不相交，k 个 share 不会被别人切进去。
            rowOf[i] = (slotOf[i] % cellsPerCol) * maxValues;
        }
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
        return new Placement(colOf, rowOf, FusePirSetup.span(cellsPerCol, c));
    }

    // ==================================================================
    //  ③ 写 D（Alg 1 SETUP 8）与建 P_{c,b}（Alg 1 SETUP 12-16）
    // ==================================================================
    //
    //  ⚠️ 2026-10-14 深夜补：这一段此前**完全没有调用函数** ——
    //  「随机化 D / 把 share 写进 D / 建 P_{c,b} / 半径自检」四件事全内联在
    //  `CapeDemoData.load` 里。于是 `bff` 的 Encode 只覆盖了"算位置 + 算分享"
    //  两半，而论文 SETUP 8 与 12-16 那两半在文件树里看不见。
    //
    //  这里抽成三个函数，语义**一字未改**（只是搬位置），并把事故记录留在旁边。

    /**
     * <b>Alg 3 ENCODE 6 / 正文 Alg 1 SETUP 9-11</b>：把 {@code D} 的
     * {@code [0, L_BFF)} 全区间<b>均匀随机</b>初始化。
     *
     * <p>论文里有两套写法（正文是"零填充 + 尾部补零"，附录 Alg 3 是"全区间均匀随机"），
     * 我们按**附录**实现，理由是**语义**而不是正确性：零填充会让"哪些槽没被用过"
     * 在明文表里一眼可见。两条路的解密结果完全相同（论证见下述"尾部"那段）。
     *
     * <p>⚠️ 它<b>消耗 {@code rnd}</b>，且必须在 {@link #writeD} **之前**调用 ——
     * 顺序变了会让固定种子下的 demo 表不再可复现。
     *
     * @param p {@code [C][B_pay][N]}，原地填
     */
    public static void randomizeD(long[][][] p, int c, int cellsPerCol, int maxValues,
                                  int bPay, long t, Random rnd) {
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
    }

    /**
     * <b>Alg 1 SETUP 8 的后半</b>：把每个关键词的 {@code k} 路 share 写进 {@code D}
     * —— 也就是 {@code P_{c,b}(X) ← Σ_r D[r + cR][b]·X^r} 里那些系数。
     *
     * <p>{@code D[u_a]} 的落点是 {@code p[colOf[i]][b][rowOf[i] + a]}
     * （我们的 u 与 {@code (c,r)} 的对应见 {@link #place}）。
     */
    public static void writeD(long[][][] p, int[] colOf, int[] rowOf,
                              long[][][] share, int kwCount, int k, int bPay) {
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < k; a++) {
                for (int b = 0; b < bPay; b++) {
                    p[colOf[i]][b][rowOf[i] + a] = share[i][a][b];
                }
            }
        }
    }

    // ==================================================================
    //  ④ k 路加性分享（让 Σ_a D[u_a] = y_K 成立）
    // ==================================================================

    /**
     * 把每个关键词的载荷拆成 {@code k} 路加性分享：
     * {@code Σ_a share[i][a][b] ≡ payload[i][b] (mod t)}。
     *
     * <p>前 {@code k−1} 路取均匀随机、第 {@code k} 路取补数 —— 这就是
     * 论文 {@code BFF.Encode} 里"每条分享各自随机、重建时按分量相加"的落地方式，
     * 也是 ANSWER 第 11 行 {@code CtCtAdd(CtCtAdd(ct_0, ct_1), ct_2)} 能还原载荷的前提。
     *
     * <p>⚠️ <b>它消耗传入的 {@code rnd}</b>（顺序：先分享、后表随机化），
     * 所以调用顺序变了会让固定种子下的 demo 表不再可复现。
     */
    public static long[][][] splitShares(long[][] payload, int k, long t, Random rnd) {
        int kwCount = payload.length;
        int bPay = payload[0].length;
        long[][][] share = new long[kwCount][k][bPay];
        for (int i = 0; i < kwCount; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    // nextLong(bound) 而不是 nextInt((int) t)：t 可以大到 2^32，
                    // 强转 int 会溢出成 0，Random.nextInt 直接抛 "bound must be positive"。
                    share[i][a][b] = rnd.nextLong(t);
                    sum[b] = (sum[b] + share[i][a][b]) % t;
                }
            }
            for (int b = 0; b < bPay; b++) {
                share[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], t);
            }
        }
        return share;
    }
}
