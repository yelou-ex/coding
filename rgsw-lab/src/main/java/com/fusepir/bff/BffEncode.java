package com.fusepir.bff;

import com.fusepir.fusepir.*;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * <b>BFF · ENCODE</b> —— 位置函数、摆放、写表。
 *
 * <pre>
 *   Alg 1 SETUP 1:   (D, H, fp) ← BFF.Setup(n, 3)
 *   Alg 1 SETUP 8:   (D, H) ← BFF.Encode(D, H, {(K_i, y_{K_i})}_{i=1}^n)
 *   Alg 1 SETUP 9-11: for u = L_BFF to RC−1 do D[u] ← 0
 *   Alg 1 SETUP 12-16: P_{c,b}(X) ← Σ_r D[r + cR][b]·X^r
 *   Alg 1 QUERY 3:   u_a ← h_a(K) ; r_a ← u_a mod R ; c_a ← ⌊u_a/R⌋
 *   Alg 3 ENCODE 5-6:   D[u] ←$ Z_t^B        （[0, L_BFF) 全区间均匀随机）
 *   Alg 3 ENCODE 8-17:  LIFO 回填 D[p] ← y_K − Σ_{j≠p} D[h_j(K)]
 * </pre>
 *
 * <h3>本类有两套路径 —— 认准是哪一套</h3>
 * <table border="1">
 *   <tr><th></th><th>论文路径（默认）</th><th>旧几何（降级对照）</th></tr>
 *   <tr><td>位置</td><td>{@link BffHash#positions}（{@code h_a}，k 个分散位置）</td>
 *       <td>{@link BffEncodeLegacy#keywordHash}（线性探测，<b>1 个</b>位置）+ {@link BffEncodeLegacy#place}</td></tr>
 *   <tr><td>写表</td><td>{@link #encode}：剥皮 {@link BffMapping} + LIFO 回填 + 换种子重试</td>
 *       <td>{@link BffEncodeLegacy#splitShares}（随机拆 k 路）+ {@link BffEncodeLegacy#writeD}</td></tr>
 *   <tr><td>`D` 的形状</td><td>{@code [RC][B_pay]}，尾部由 {@link #zeroTail} 清零</td>
 *       <td>等价于随机化 + 覆写；尾部不被寻址</td></tr>
 * </table>
 * 两套都保留：旧的那套已搬到 {@link BffEncodeLegacy}，是为了让此前报告里的数字仍可复现（见 MAP §14.4）。
 *
 * <h3>⚠️ 旧路径为什么不满足论文（这段是历史记录，新路径已解决）</h3>
 * 旧路径是：**一个关键词一个位置** `u`（哈希 + 线性探测），
 * 再把这个位置所在 cell 的 **k 个连续行**当作 k 路。于是：
 * <ul>
 *   <li>「k 路相加 = 载荷」这条**重建性质成立**（表里存的是 k 路加性分享）；</li>
 *   <li>但 BFF 的**过滤语义没有被用到** —— 那套"BFF"实际是槽表 + 线性探测，
 *       k 路拆分只是加性分享。见 {@code docs/reports/P1-4-BFF参数化对照ChalametPIR-*.md} 的 F1–F4；</li>
 *   <li>代价：k 条路的列号相同 ⇒ {@code Acc_{a,b}} 对 a=0..k−1 是同一个值，
 *       同一份列选择被算了 k 遍（白做约 5–6.5%）。</li>
 * </ul>
 * **新路径（{@link #encode} + {@link BffHash}）已经消除了这三条**：
 * 一个关键词有 k 个分散位置、列号通常不同（实测 128 关键词里同列 0 次），
 * 写表走真正的剥皮 LIFO。
 */
public final class BffEncode {

    private BffEncode() {
    }

    /**
     * <b>Alg 1 SETUP 12-16 的落地自检</b>：把"真正会被读到的系数"钉死。
     *
     * <p>读表读的是列 {@code c_a = u/cellsPerCol ∈ [0, C)}、列内行
     * {@code (u % cellsPerCol)·maxValues + a}（{@code a ∈ [0,k)}），
     * 所以被读到的系数满足 {@code cc < C} 且 {@code rr < (cellsPerCol−1)·maxValues + k}。
     * 随机化 + 覆写只覆盖了 {@code [0, dataRadius)}，其余系数保持数组默认的 0。
     *
     * <p>⚠️ <b>这条自检是有来历的</b>：它防的是"半径算错导致整列被清空"那类事故 ——
     * 曾把尾部判据写成 {@code cc*r + rr >= L_BFF}，把「多项式列号 cc」和「槽位下标 u」
     * 当成同一个量（u 每列只摊 cellsPerCol 个，cc 却一路数到 C），
     * 于是 {@code cc ≥ 8} 时 {@code 8*16 = 128} 已逼近 130 ⇒ **第 8 列起整列被清空**，
     * 症状是 col≥8 的关键词三路 share 全 0 ⇒ 载荷 0 ⇒ 解密报
     * {@code result ciphertext is transparent}。
     *
     * @param n 多项式环维度（系数个数）
     */
    public static void checkDataRadius(long[][][] p, int c, int bPay, int n, int dataRadius) {
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
    }

    // ==================================================================
    //  ★ 论文路径（2026-10-14 深夜新增）────────────────────────────────
    //  A3 ENCODE 全文 + A1 SETUP 9-11 尾部补零 + A1 SETUP 12-16 建 P_{c,b}
    //
    //  上面那些 place / randomizeD / writeD / splitShares 是**旧几何**
    //  （"一个关键词一个位置 + 该 cell 的 k 个连续行"），保留是为了让
    //  旧路径仍可对照复现；**新默认路径不经过它们**。
    // ==================================================================

    /**
     * 位置函数工厂 —— 让 {@link #encode} 与具体的哈希实现解耦，
     * 并且**支持换种子重来**（A3 ENCODE 2-3 的 {@code return fail}）。
     */
    public interface PositionFn {
        /** 用给定种子算出 {@code [n][k]} 的位置表，每个元素必须在 {@code [0, L_BFF)}。 */
        int[][] positions(long seed);
    }

    /** {@code BFF.Encode} 的产物。 */
    public static final class Table {
        /** {@code D}：{@code [RC][B_pay]}。{@code [0, L_BFF)} 是 BFF，{@code [L_BFF, RC)} 是补的 0。 */
        public final long[][] d;
        /** 实际用掉的位置表（成功的那个种子的）。 */
        public final int[][] pos;
        /** 成功用的种子。 */
        public final long seed;
        /** 试了几个种子才成功（≥1）。 */
        public final int attempts;
        /** 剥皮栈（LIFO 回填的顺序）。 */
        public final BffMapping.Peel peel;
        /** 参数。 */
        public final BffSetup.Layout layout;

        Table(long[][] d, int[][] pos, long seed, int attempts,
              BffMapping.Peel peel, BffSetup.Layout layout) {
            this.d = d;
            this.pos = pos;
            this.seed = seed;
            this.attempts = attempts;
            this.peel = peel;
            this.layout = layout;
        }
    }

    /**
     * <b>A3 ENCODE（算法 3 的 1-18 行）</b> + <b>A1 SETUP 9-11</b>。
     *
     * <pre>
     * ENCODE(D, H, {(K_i, y_{K_i})})
     *  1: S ← MappingStep({K_i}, H, L_BFF).
     *  2: if S = fail then  return fail.          ← 换新种子重来（正文："Setup is repeated
     *  3: end if                                      with a fresh position-function seed"）
     *  5: for u = 0 to L_BFF − 1 do  D[u] ←$ Z_t^B
     *  8: while S ≠ ∅ do
     *  9:     Pop (K, p) from S.
     * 11:     D[p] ← y_K.
     * 12:     for j = 0 to k − 1 do
     * 13:         if h_j(K) ≠ p then  D[p] ← D[p] − D[h_j(K)]  (mod t)
     * 17: end while
     * 18: return D.
     * </pre>
     *
     * <p>{@code D} 按 {@code [RC][B_pay]} 分配：前 {@code L_BFF} 个是 BFF 数组，
     * 后 {@code RC − L_BFF} 个是 <b>A1 SETUP 9-11 补的 0</b>。
     * 之后 {@code P_{c,b}[r] = D[r + cR][b]} 就是一次纯 reshape —— 没有边界判断，
     * 因为尾部已经被显式清零了。
     *
     * <h3>⚠️ 第 8 行是 LIFO：必须从 {@code S} 的**末尾往前**走</h3>
     * 剥皮的单调性保证"写 {@code D[p]} 时，它那 k−1 个伙伴槽都已经是终值"。
     * <b>顺序反了就有静默假阴性</b> —— 剥离顺序的语义不是实现细节。
     *
     * <h3>⚠️ 返回 {@code null} 表示论文意义上的构造失败</h3>
     * 原文 30-31 行允许 fail：`|S| ≠ n`。真实做法是换种子重试
     * （{@code maxAttempts} 由调用方给）。**重试次数要如实报出来**
     * —— 它是 BFF 参数是否留够余量的体检指标：如果 100 次里成功不到几次，
     * 说明 `L_BFF` 相对 `n` 太小（或分段结构没实现对）。
     *
     * @param payload {@code [n][B_pay]}
     * @param maxAttempts 最多试几个种子；用满仍未成功则返回 {@code null}
     */
    public static Table encode(int n, int k, BffSetup.Layout layout, PositionFn posFn,
                               long seed0, long[][] payload, long t,
                               int maxAttempts, Random rnd) {
        final int bPay = payload[0].length;
        final int rc = (int) layout.rc();
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            final long seed = seed0 + attempt - 1;
            final int[][] pos = posFn.positions(seed);
            final BffMapping.Peel peel = BffMapping.mappingStep(pos, (int) layout.lBff, n, k);
            if (peel == null) {
                continue;                       // 2-3 行：换新种子重来
            }

            // ── 5-7: D 全网格置 0（= A1 SETUP 9-11 的尾部），再把 [0,L_BFF) 随机化 ──
            // 形状来自 BffSetup.newD（A1 SETUP 1 的 "Setup 产出 D"），这里不再自己 new。
            final long[][] d = BffSetup.newD(rc, bPay);
            for (int u = 0; u < layout.lBff; u++) {
                for (int b = 0; b < bPay; b++) {
                    d[u][b] = rnd.nextLong(t);
                }
            }

            // ── 8-17: LIFO 回填 ─────────────────────────────────────────
            for (int idx = peel.size - 1; idx >= 0; idx--) {
                final int i = peel.keyAt[idx];
                final int p = peel.slotAt[idx];
                for (int b = 0; b < bPay; b++) {
                    d[p][b] = payload[i][b];
                }
                for (int j = 0; j < k; j++) {
                    final int h = pos[i][j];
                    if (h == p) {
                        continue;               // 13 行
                    }
                    for (int b = 0; b < bPay; b++) {
                        d[p][b] = Math.floorMod(d[p][b] - d[h][b], t);
                    }
                }
            }
            return new Table(d, pos, seed, attempt, peel, layout);
        }
        return null;
    }

    /**
     * <b>A1 SETUP 12-16</b>：把 {@code D} 折成 {@code P_{c,b}}。
     *
     * <pre>
     * 12: for c = 0 to C − 1 do
     * 13:     for b = 1 to B_pay do
     * 14:         P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r.
     * 16: end for
     * </pre>
     *
     * <p>系数 {@code r} 落在 {@code X^r} 上，行下标就是 {@code u = r + c·R}；
     * 这正是 A1 QUERY 3 的 {@code r_a = u_a mod R}、{@code c_a = ⌊u_a/R⌋} 的逆映射。
     * 系数 {@code [R, N)} 保持 0（每条多项式只用到前 `R` 个系数）。
     *
     * @return {@code [C][B_pay][N]}
     */
    public static long[][][] embed(long[][] d, BffSetup.Layout layout, int bPay) {
        final long[][][] p = new long[layout.c][bPay][layout.ringDim];
        for (int c = 0; c < layout.c; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int r = 0; r < layout.r; r++) {
                    p[c][b][r] = d[r + c * layout.r][b];
                }
            }
        }
        return p;
    }

    /**
     * <b>A1 SETUP 9-11</b> —— 单独命名出来，因为它是论文里**独立的一步**。
     *
     * <pre>
     *  9: for u = L_BFF to RC − 1 do
     * 10:     D[u] ← 0 ∈ Z_t^{B_pay}.
     * 11: end for
     * </pre>
     *
     * <p>⚠️ <b>这一条此前被我误判为"空操作"</b>（当时把 `cellsPerCol·C` 当成了 `R·C`）。
     * 实际 `RC > L_BFF`，尾部是真的存在的：论文参数下是 `[155, 256)` 共 101 个槽。
     * <b>尾部必须是 0，不能是随机值</b> —— 否则明文表里会留下"不属于任何关键词"的数据。
     *
     * <p>{@link #encode} 里已经把整张网格先置 0 再随机化 {@code [0, L_BFF)}，
     * 所以尾部天然是 0；本函数是用来**显式自检**那条不变式的。
     */
    public static void zeroTail(long[][] d, BffSetup.Layout layout, int bPay) {
        for (int u = (int) layout.lBff; u < (int) layout.rc(); u++) {
            for (int b = 0; b < bPay; b++) {
                d[u][b] = 0;
            }
        }
    }

    /**
     * <b>A3 CHECK / RECONSTRUCT</b>：{@code Σ_{j=0}^{k−1} D[h_j(K)] mod t}。
     *
    /**
     * <b>A3 CHECK</b> —— 独立的那个过程，返回 {@code (d_0, …, d_{k−1})}：
     *
     * <pre>
     * CHECK(D, H, K)
     *  1: for j = 0 to k − 1 do
     *  2:     d_j ← D[h_j(K)].
     *  4: return (d_0, …, d_{k−1}).
     * </pre>
     *
     * <p>⚠️ 它是 {@link #reconstruct} 的**上游**，论文里是<b>两个过程</b>
     * （CHECK 取值、RECONSTRUCT 求和）。此前只有 {@code reconstruct}，
     * 把两步压成了一步 —— 那让"取到的 k 份份额长什么样"在调用图上看不见，
     * 也没法单独检查 {@code h_j(K)} 是否落在 {@code [0, L_BFF)}。
     *
     * <p>本函数顺便做**范围自检**：任何一个 {@code h_j(K)} 越界都直接抛异常
     * （越界会静默读到别的关键词的份额 ⇒ 假阴性）。
     *
     * @param posOf {@code [k]}，{@code posOf[j] = h_j(K)}（{@link BffHash#positions} 的产物）
     * @return {@code [k][B_pay]}，第 j 行是 {@code D[h_j(K)]}
     */
    public static long[][] check(long[][] d, int[] posOf, int k, int bPay) {
        final long[][] out = new long[k][];
        for (int j = 0; j < k; j++) {
            final int u = posOf[j];
            if (u < 0 || u >= d.length) {
                throw new IllegalStateException("h_" + j + "(K) = " + u
                    + " 越界（D 长 " + d.length + "）—— 位置函数与建表不是同一组参数");
            }
            final long[] dj = d[u];
            if (dj.length < bPay) {
                throw new IllegalStateException("D[" + u + "] 只有 " + dj.length
                    + " 项，载荷要 " + bPay + " 项");
            }
            out[j] = java.util.Arrays.copyOf(dj, bPay);
        }
        return out;
    }

    /**
     * <b>A3 RECONSTRUCT</b> —— 把 CHECK 取回的 k 份逐分量相加（A1 DECODE 5 的 {@code Recover}）：
     *
     * <pre>
     * RECONSTRUCT(D, H, K)
     *  5: (d_0, …, d_{k−1}) ← Check(D, H, K).
     *  6: y ← 0^B.
     *  7: for j = 0 to k − 1 do
     *  8:     y ← y + d_j  (mod t).
     * 10: return y.
     * </pre>
     *
     * <p>这就是 ANSWER 第 10-12 行 {@code CtCtAdd(CtCtAdd(ct_{0,b}, ct_{1,b}), ct_{2,b})}
     * 在明文侧的对应物 —— <b>本函数的返回值必须逐位等于 {@code y_K}</b>，
     * 否则就是假阴性。{@code probe/BffLayerTest} 对全部 n 个关键词逐个验这一条。
     */
    public static long[] reconstruct(long[][] d, int[] posOf, int k, int bPay, long t) {
        final long[][] dj = check(d, posOf, k, bPay);
        final long[] y = new long[bPay];
        for (int j = 0; j < k; j++) {
            for (int b = 0; b < bPay; b++) {
                y[b] = Math.floorMod(y[b] + dj[j][b], t);
            }
        }
        return y;
    }
}

