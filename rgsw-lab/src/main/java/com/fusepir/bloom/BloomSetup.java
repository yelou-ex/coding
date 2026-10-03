package com.fusepir.bloom;

import com.fusepir.common.BfGen;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * <b>Bloom 层的 SETUP</b> —— 论文 Algorithm 2 SETUP 1-6 里与 Bloom 有关的那几行。
 *
 * <pre>
 *   A2 SETUP 1: Select public Bloom-filter parameters ℓ_BF and G = {g_1, …, g_h}.
 *   A2 SETUP 2: m ← max_{i∈[n]} |V_{K_i}|.
 *   A2 SETUP 3: for each v ∈ ∪_{i=1}^n V_{K_i} do
 *   A2 SETUP 4:     S_v ← {K_i : v ∈ V_{K_i}}.
 *   A2 SETUP 5:     b_v ← BF.Gen(0, S_v).
 *   A2 SETUP 6: end for
 * </pre>
 *
 * <h3>为什么要有这个类（2026-10-14 深夜补）</h3>
 * 审计时发现这几行**在项目里没有单一实现**：
 * <ul>
 *   <li>{@code S_v}（SETUP 3-4）<b>当时有两份独立实现</b> ——
 *       {@code bff/CapeDemoData} 的 {@code kwOfValue} 与
 *       {@code cape/CapeQueryDecode} 的 {@code kwOfValue}。
 *       危险不在"写两遍麻烦"，而在**它们可以悄悄不一致**（TreeSet vs HashSet、
 *       含不含空值），后果是 {@code b_v} 算错 ⇒ 假阴性 ⇒
 *       直接违背论文"假阴性必须为 0"这条论证前提。<br>
 *       ✅ <b>已解决</b>：{@link #valueToKeywords} 现在是**唯一实现**，
 *       {@code CapeDemoData} 与 {@code CapeQueryDecode} 都调它。
 *       （{@code probe/} 下还有几份自己写的副本 —— 那是一次性诊断件，不在生产路径上。）</li>
 *   <li>{@code m}（SETUP 2）此前直接读数据集 meta 里预先算好的值，
 *       <b>从来没有拿它跟真实 DB 对过</b>；而载荷构造用的是
 *       {@code Math.min(vals.size(), maxValues)} —— <b>meta 偏小会静默丢值</b>，
 *       而且 {@code m} 同时决定 {@code B_pay}。<br>
 *       ✅ 现在走 {@link #maxValues}（从 DB 实算）+ {@link #reconcile}（与 meta 不一致就抛异常）。</li>
 * </ul>
 *
 * <p>{@code ℓ_BF} 与 {@code G}（SETUP 1）由 {@link BfGen#choose} 从 {@code ε_BF} 反选，
 * {@code BF.Gen(0,S)} 由 {@link BfGen#bits(java.util.Collection)} 实现
 * —— 那两者在共享模块 {@code com.fusepir.common.BfGen} 里（客户端与服务端必须同一份）。
 */
public final class BloomSetup {

    private BloomSetup() {
    }

    /**
     * <b>A2 SETUP 2：{@code m ← max_{i∈[n]} |V_{K_i}|}</b> —— 从 DB 实算。
     *
     * <p>调用方应当拿它与数据集 meta 里的 {@code maxValues} **对账**，
     * 不要直接信 meta：{@link #reconcile} 就是那个对账函数。
     *
     * @param kwToValues 关键词 → 该关键词关联的值列表
     * @return 任意关键词最多的值个数（空 DB 返回 0）
     */
    public static int maxValues(Map<String, List<Integer>> kwToValues) {
        int m = 0;
        for (List<Integer> vals : kwToValues.values()) {
            if (vals != null && vals.size() > m) {
                m = vals.size();
            }
        }
        return m;
    }

    /**
     * 把"从 DB 实算的 {@code m}"与数据集 meta 里的值对账。
     *
     * <p>⚠️ <b>宁可抛异常也不要静默截断</b>：m 偏小 ⇒ 载荷构造会把多出来的值
     * 悄悄丢掉（{@code Math.min(vals.size(), m)}），而 m 偏大 ⇒ {@code B_pay} 与
     * 网格都跟着变大、性能白付。两种都不会报错，所以必须在入口处对账。
     *
     * @return {@code m}（实算值），供调用方直接使用
     */
    public static int reconcile(int mFromDb, int mFromMeta) {
        if (mFromDb != mFromMeta) {
            throw new IllegalStateException("A2 SETUP 2 对账失败：DB 实算 m = " + mFromDb
                + "，而数据集 meta 写的是 " + mFromMeta
                + "。m 同时决定 B_pay 与网格 cellsPerCol = ⌊R/m⌋，"
                + "不一致会静默丢值或白付性能 —— 请重新生成数据集。");
        }
        return mFromDb;
    }

    /**
     * <b>A2 SETUP 3-4：{@code S_v ← {K_i : v ∈ V_{K_i}}}</b>。
     *
     * <p>返回<b>确定序</b>的 {@code v → 关键词列表}（{@code TreeMap} + 保序去重），
     * 因为 {@code b_v} 虽然对集合的<b>顺序不敏感</b>（位是 OR 上去的），
     * 但"同一份输入必须产出同一份输出"是能对拍的前提。
     *
     * <p>这是 {@code S_v} 的**唯一实现** —— 此前 {@code CapeDemoData} 与
     * {@code CapeQueryDecode} 各写一遍。
     */
    public static Map<Integer, List<String>> valueToKeywords(Map<String, List<Integer>> kwToValues) {
        Map<Integer, List<String>> out = new TreeMap<>();
        for (Map.Entry<String, List<Integer>> e : kwToValues.entrySet()) {
            List<Integer> vals = e.getValue();
            if (vals == null) {
                continue;
            }
            for (Integer v : vals) {
                if (v == null) {
                    continue;
                }
                List<String> ks = out.computeIfAbsent(v, x -> new ArrayList<>());
                if (!ks.contains(e.getKey())) {     // 同一个 (v,K) 只算一次
                    ks.add(e.getKey());
                }
            }
        }
        return out;
    }

    /**
     * <b>A2 SETUP 5：{@code b_v ← BF.Gen(0, S_v)}</b> —— 逐值算 Bloom 位。
     *
     * <p>{@code BF.Gen(0,S)} 就是 {@link BfGen#bits(java.util.Collection)}
     * （把 S 里每个关键词的 h 个位置 OR 上去）。
     *
     * <p>⚠️ 论文那个首参 {@code 0} 我们**没有暴露**：{@code BfGen} 的哈希是
     * {@code SHA-256(K ‖ 0x00 ‖ i)}，其中 {@code 0x00} 是<b>位置索引的分隔字节</b>、
     * 不是 seed。论文两次调用（{@code b_v} 与 {@code b_qry}）都传 {@code 0}，
     * 所以只要两边用同一份实现就等价 —— 但"那个 0 到底是 seed 还是元素"
     * 从伪代码看不出来，这里据实记录。
     *
     * @return {@code v → ℓ_BF} 长的 0/1 位向量
     */
    public static Map<Integer, boolean[]> valueBloomBits(BfGen bf,
                                                         Map<Integer, List<String>> valueToKeywords) {
        Map<Integer, boolean[]> out = new LinkedHashMap<>();
        for (Map.Entry<Integer, List<String>> e : valueToKeywords.entrySet()) {
            out.put(e.getKey(), bf.bits(e.getValue()));
        }
        return out;
    }
}
