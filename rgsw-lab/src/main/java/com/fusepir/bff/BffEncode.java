package com.fusepir.bff;

import java.util.Arrays;
import java.util.List;

/**
 * <b>BFF · ENCODE</b> —— 位置函数这一半。
 *
 * <pre>
 *   Alg 1 SETUP 1: (D, H, fp) ← BFF.Setup(n, 3)
 *   Alg 1 SETUP 8: (D, H) ← BFF.Encode(D, H, {(K_i, y_{K_i})}_{i=1}^n)
 *   Alg 1 QUERY 3: u_a ← h_a(K) ; r_a ← u_a mod R ; c_a ← ⌊u_a/R⌋
 * </pre>
 *
 * <h3>本类提供什么</h3>
 * {@link #keywordHash} = 论文的 <b>位置函数 H</b>（公开参数，客户端与服务端都要算，
 * 且必须算出**同一个位置**）。它此前在 {@code CapeDemoData} 与 {@code CapeQuery}
 * 里各有一份**逐字重复**的实现，注释写着「必须逐位一致」——
 * 那种"靠人肉保持一致"的安排迟早会漂。现在只有一份。
 *
 * <h3>⚠️ 与论文的形态差：`h_i` 没有实现</h3>
 * 论文（ChalametPIR Alg.1 L8-10）是
 * {@code h_i(K) = (N/s)·(h''(K)−1) + h'(K‖i)}，i = 0..k−1 ——
 * 一个关键词有 <b>k 个分散在全表的位置</b>，且 arity 由 {@code BFF.Setup(n, 3)} 定死为 3。
 *
 * <p>我们做的是：**一个关键词一个位置** `u`（哈希 + 线性探测），
 * 再把这个位置所在的 cell 的 **k 个连续行**当作 k 路。
 * 于是：
 * <ul>
 *   <li>「3 路相加 = 载荷」这条**重建性质成立**（表里存的是 3 路加性分享）；</li>
 *   <li>但 BFF 的**过滤语义没有被用到** —— 我们的"BFF"实际是一个槽表 + 线性探测，
 *       3 路拆分只是加性分享。见 {@code docs/reports/P1-4-BFF参数化对照ChalametPIR-*.md} 的 F1–F4。</li>
 *   <li>代价：3 条路的列号相同 ⇒ {@code Acc_{a,b}} 对 a=0,1,2 是同一个值，
 *       同一份列选择被算了 3 遍（白做约 5–6.5%）。**不建议顺手优化** —— 那会离论文更远。</li>
 * </ul>
 */
public final class BffEncode {

    private BffEncode() {
    }

    /**
     * 论文的公开哈希 {@code H}：把 {@code n} 个关键词摊到 {@code span = max(n, cellsPerCol·c)}
     * 个槽位上，用**线性探测**解决碰撞，返回「关键词下标 → 槽位 u」的映射。
     *
     * <p>⚠️ 槽数组必须是 {@code span} 长，不是 {@code n} —— 按 {@code u ∈ [0, span)} 索引。
     * 这一点此前踩过：写成 {@code new int[n]} 时 {@code cc ≥ 8} 的列会被静默清空。
     *
     * @param cellsPerCol 一列里有多少个 cell（{@code ⌊R/maxValues⌋}）
     * @param c           列数 {@code C}
     */
    public static int[] keywordHash(List<String> keywords, int cellsPerCol, int c) {
        final int n = keywords.size();
        final int span = Math.max(n, cellsPerCol * c);
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
}
