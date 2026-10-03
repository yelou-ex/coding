package com.fusepir.bff;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * <b>BFF · MAPPINGSTEP</b> —— CAPE 附录 Algorithm 3 的 1-33 行。
 *
 * <pre>
 * MAPPINGSTEP({K_i}_{i=1}^n, H, L_BFF)
 *  1: Order K_1, …, K_n by h_0(K_i) and denote the resulting sequence by L.
 *  2: for u = 0 to L_BFF − 1 do  T[u] ← ∅
 *  5: for each K ∈ L do
 *  6:     for j = 0 to k − 1 do  T[h_j(K)] ← T[h_j(K)] ∪ {K}
 * 10: Initialize an empty stack Q and an empty stack S.
 * 11: for u = 0 to L_BFF − 1 do
 * 12:     if |T[u]| = 1 then  Push u into Q.
 * 16: while Q ≠ ∅ do
 * 17:     Pop a location u from Q.
 * 18:     if |T[u]| = 1 then
 * 19:         K ← the unique keyword in T[u].
 * 20:         Push (K, u) onto S.
 * 21:         for j = 0 to k − 1 do
 * 22:             v ← h_j(K).
 * 23:             T[v] ← T[v] \ {K}.
 * 24:             if |T[v]| = 1 then  Push v into Q.
 * 30: if |S| ≠ n then  return fail.
 * 33: return S.
 * </pre>
 *
 * <h3>⚠️ 这一步是"剥皮"（peeling），不是线性探测</h3>
 * 它决定的是 <b>每个关键词的"独占写槽"</b>：剥到只剩它一个占位者时，
 * 那个槽就是它的写槽。性质是：回填（{@link BffEncode#encode} 的第 8-17 行）
 * 按 LIFO 逆序进行时，<b>写某个槽的那一刻，它那 k−1 个伙伴槽都已经写过终值了</b>
 * —— 这是 `Σ_a D[h_a(K)] = y_K` 成立的机制。
 *
 * <p><b>为什么必须照抄这一步、而不能用"随机拆 k 路再加"代替</b>：
 * 后者在算术上也能让 `Σ_a share_a = y_K`，但它<b>不保证</b>
 * "每个槽只被写一次"。一个槽若被两个关键词共用，后写的会把先写的覆盖掉，
 * 结果就是<b>静默的假阴性</b> —— 而论文的前提写死是"假阴性必须为 0"。
 *
 * <h3>⚠️ 第 24 行是原文散文补上的，伪代码里漏了</h3>
 * 伪代码第 21-27 行只写了 `T[v] ← T[v] \ {K}`，
 * 但正文说 *"This may create new singleton locations, which are added to Q"*。
 * <b>没有这一步，Q 在初始单例耗尽后就空了，`|S| ≠ n` 几乎必然发生。</b>
 * 我们按散文实现（这一条与 ChalametPIR Alg 2 的写法也一致 —— 那份伪代码同样漏了）。
 */
public final class BffMapping {

    private BffMapping() {
    }

    /**
     * 剥皮栈 {@code S} —— 按<b>压栈顺序</b>存的 {@code (K, p)} 序列。
     *
     * <p>{@link BffEncode#encode} 的 LIFO 回填就是从这个数组的<b>末尾往前</b>走。
     */
    public static final class Peel {
        /** {@code [size]} 第 t 个被压栈的键的下标。 */
        public final int[] keyAt;
        /** {@code [size]} 与 {@link #keyAt} 对齐的写槽 {@code p}。 */
        public final int[] slotAt;
        /** 栈深；== {@code n} 才算成功。 */
        public final int size;

        Peel(int[] keyAt, int[] slotAt, int size) {
            this.keyAt = keyAt;
            this.slotAt = slotAt;
            this.size = size;
        }
    }

    /**
     * {@code MappingStep}：成功返回栈（{@code size == n}），失败返回 {@code null}
     * —— 对应原文第 30-31 行的 {@code return fail}（调用方要<b>换新种子重来</b>）。
     *
     * @param pos  {@code [n][k]}，{@code pos[i][j] = h_j(K_i)}，每个都必须在 {@code [0, lBff)}
     * @param lBff {@code L_BFF}
     * @param n    关键词个数
     * @param k    arity（论文 3；也支持 4）
     */
    public static Peel mappingStep(int[][] pos, int lBff, int n, int k) {
        // ── 1: 按 h_0(K) 排序，得到序列 L ───────────────────────────────
        // 原文用 Integer[] 排序只是"顺序"，结果与顺序无关（剥皮是集合运算），
        // 但照原文顺序实现，好在两个实现之间逐位可对照。
        final Integer[] order = new Integer[n];
        for (int i = 0; i < n; i++) {
            order[i] = i;
        }
        java.util.Arrays.sort(order, (a, b) -> Integer.compare(pos[a][0], pos[b][0]));

        // ── 2-4: T[u] ← ∅ ───────────────────────────────────────────────
        final List<HashSet<Integer>> t = new ArrayList<>(lBff);
        for (int u = 0; u < lBff; u++) {
            t.add(new HashSet<>());
        }

        // ── 5-9: 把每个键塞进它的 k 个位置 ──────────────────────────────
        for (int idx = 0; idx < n; idx++) {
            final int i = order[idx];
            for (int j = 0; j < k; j++) {
                final int u = pos[i][j];
                if (u < 0 || u >= lBff) {
                    throw new IllegalStateException("h_" + j + "(K_" + i + ") = " + u
                        + " 越界，L_BFF = " + lBff);
                }
                t.get(u).add(i);
            }
        }

        // ── 10: 空栈 Q（待检查的位置）与 S（剥皮结果） ──────────────────
        final ArrayDeque<Integer> q = new ArrayDeque<>();
        final int[] stackKey = new int[n];
        final int[] stackSlot = new int[n];
        int size = 0;

        // ── 11-15: 初始单例 ─────────────────────────────────────────────
        for (int u = 0; u < lBff; u++) {
            if (t.get(u).size() == 1) {
                q.push(u);
            }
        }

        // ── 16-29: 剥皮 ─────────────────────────────────────────────────
        while (!q.isEmpty()) {
            final int u = q.pop();
            final HashSet<Integer> set = t.get(u);
            if (set.size() != 1) {
                continue;                       // 18: 已经不再单例了
            }
            final int i = set.iterator().next(); // 19
            stackKey[size] = i;                  // 20: Push (K, u) onto S
            stackSlot[size] = u;
            size++;
            for (int j = 0; j < k; j++) {
                final int v = pos[i][j];         // 22
                t.get(v).remove(i);              // 23
                if (t.get(v).size() == 1) {      // 24 —— 散文补上的那一行
                    q.push(v);                   // 25
                }
            }
        }

        // ── 30-32: |S| ≠ n ⇒ fail ──────────────────────────────────────
        if (size != n) {
            return null;
        }
        final int[] keyAt = java.util.Arrays.copyOf(stackKey, size);
        final int[] slotAt = java.util.Arrays.copyOf(stackSlot, size);
        return new Peel(keyAt, slotAt, size);
    }
}
