package com.fusepir.common;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

/**
 * <b>{@code BF.Gen} —— CAPE 的 Bloom 位函数。服务端与客户端必须共用这一份。</b>
 *
 * <h3>为什么必须共用</h3>
 * CAPE（算法 2）的合取判定是
 * <pre>
 *   服务端（SETUP）: b_v    ← BF.Gen(0, S_v)              S_v = {K_i : v ∈ V_{K_i}}（该 value 关联的关键词）
 *   客户端（QUERY）: b_qry  ← BF.Gen(0, {K_2,…,K_Q})      **只用到关键词**
 *   判定          : ⟨b_qry, b_v⟩ == τ ?   τ = ‖b_qry‖₁
 * </pre>
 * 两边<b>必须用同一个 {@code B(keyword)}</b> 才能做内积。
 * 历史上踩过的两个坑（都记在 {@code coding/docs/缺陷总表.md}）：
 * <ul>
 *   <li><b>位位置混入 value</b>（`digest(keyword + ":" + value)`）：同一位关键词在不同 value 下落到不同位置，
 *       两边永远对不上、内积恒为 0。已修。</li>
 *   <li><b>客户端把 {@code b_v} 或起来当 {@code b_qry}</b>：算出来的是"共现关键词集合"的位，
 *       {@code τ} 被撑大 ⇒ 判定变严 ⇒ <b>漏判</b>（真命中被拒）。见 {@code 缺陷总表.md} P0-2。</li>
 * </ul>
 * 所以本类放在<b>共享模块</b>里，{@code cape-fusepir-database-handoff}（服务端）与
 * {@code rgsw-lab}（客户端演示）都依赖它，<b>不允许各自再写一份</b>。
 *
 * <h3>位位置的推导：h 个【独立】哈希（counter-mode SHA-256）</h3>
 * <pre>
 *   第 i 个位置 = floorMod( SHA-256(K ‖ 0x00 ‖ i) 的前 8 字节 , ℓ )     i = 0 .. h−1
 * </pre>
 * <p>本类先后试过两种更省的写法，<b>都被实测否掉了</b>：
 * <ol>
 *   <li><b>"从 32 字节摘要里取 h 个 4 字节窗口"</b>（本类的前身）：SHA-256 只有 32 字节，
 *       `floorMod(i*4, 29)` 给出 16 个起点全落在 `[0,28]`，<b>窗口必然互相重叠</b> ⇒ h 个位置
 *       <b>不独立</b>、没有理论保证。见缺陷总表 P2-2。</li>
 *   <li><b>double hashing（Kirsch–Mitzenmacher）</b>：`pos_i = h1 + i·h2 mod ℓ`。
 *       理论上渐近等价于独立哈希，但**在小 ℓ 下会退化成"同余陪集"**。实测（ℓ=26、h=6）：
 *       `sci-fi` 得到 `{19,16,13,10,7,4}`、`action` 得到 `{4,7,10,13,16,19}`
 *       —— <b>两个不同关键词的位集合完全相同</b>，因为 `a≡4 (mod 3)` 配步长 +3 与
 *       `a≡19 (mod 3)` 配步长 −3 落在同一组 6 个位置上。
 *       而 K-M 的证明是渐近的，`h²/ℓ = 36/26 ≈ 1.4` 时根本不成立 ⇒ 假阳性率远高于公式值。</li>
 * </ol>
 * <p>现在这版是 h 次独立的 SHA-256：多花 <b>h 次哈希</b>（关键字数量级 10²~10³、h ≤ 32，
 * 代价可忽略），换来<b>真正的独立性</b>，两个问题一起消失。自检见 {@link #main}。
 */
public final class BfGen {

    /** {@code h} 的搜索上限。ε=2⁻²⁰ 时最优 {@code h = 20}，所以要能到 20 以上。 */
    public static final int MAX_HASH_COUNT = 32;

    private final int hashCount;
    private final int length;

    public BfGen(int hashCount, int length) {
        if (hashCount < 1) {
            throw new IllegalArgumentException("hashCount 必须 >= 1，当前 = " + hashCount);
        }
        if (hashCount > MAX_HASH_COUNT) {
            throw new IllegalArgumentException(
                "hashCount 超过上限 " + MAX_HASH_COUNT + "：" + hashCount);
        }
        if (length < 1) {
            throw new IllegalArgumentException("length 必须 >= 1，当前 = " + length);
        }
        this.hashCount = hashCount;
        this.length = length;
    }

    /**
     * 按目标假阳性率选最优 {@code (h, ℓ)}。
     *
     * <pre>ℓ(h) = ⌈ −h·m / ln(1 − ε^{1/h}) ⌉</pre>
     * 扫 {@code h = 1..MAX_HASH_COUNT} 取 ℓ 最小者。这个公式对<b>任意</b> h 都保证
     * 实际假阳性率 ≤ ε，所以挑出来的只是"最短的那个"，不是"唯一正确的那个"。
     *
     * @param maxSetSize 单个 value 关联的关键词数上界（Bloom 里装的元素数 m）
     * @param target     目标假阳性率 ε_BF（论文取 2⁻²⁰）
     * @param maxLength  长度上限。**本项目的硬约束是「一个 value 的 Bloom 位必须装进一个多项式槽位」**，
     *                   所以传的是环维度 N。超了直接抛，不静默截断。
     */
    public static BfGen choose(int maxSetSize, double target, int maxLength) {
        if (maxSetSize <= 0) {
            return new BfGen(1, 1);
        }
        if (!(target > 0) || target >= 1) {
            throw new IllegalArgumentException("target 必须在 (0,1) 内：" + target);
        }
        int bestHashCount = 1;
        int bestLength = Integer.MAX_VALUE;
        for (int h = 1; h <= MAX_HASH_COUNT; h++) {
            double p = Math.pow(target, 1.0 / h);
            if (p <= 0 || p >= 1) {
                continue;
            }
            double denom = Math.log(1 - p);
            if (!(denom < 0)) {
                continue;
            }
            long len = (long) Math.ceil(-h * (double) maxSetSize / denom);
            if (len < bestLength) {
                bestLength = (int) Math.min(len, Integer.MAX_VALUE);
                bestHashCount = h;
            }
        }
        if (bestLength > maxLength) {
            throw new IllegalArgumentException(String.format(
                "Bloom 长度 %d 超过上限 %d：请放宽假阳性目标，或提高环维度 N。"
                    + "（maxSetSize=%d, target=2^%.1f）",
                bestLength, maxLength, maxSetSize, Math.log(target) / Math.log(2)));
        }
        return new BfGen(bestHashCount, bestLength);
    }

    public int hashCount() {
        return hashCount;
    }

    public int length() {
        return length;
    }

    /**
     * {@code B(K)}：<b>只依赖关键词</b>。
     *
     * @return 长度 {@code ℓ} 的 0/1 向量
     */
    public boolean[] bits(String keyword) {
        boolean[] bits = new boolean[length];
        for (int position : positions(keyword)) {
            bits[position] = true;
        }
        return bits;
    }

    /** 一个 value 的 Bloom：把它关联的每个关键词的位都置上（{@code S_v} 的并）。 */
    public boolean[] bits(Collection<String> keywords) {
        boolean[] bits = new boolean[length];
        for (String keyword : keywords) {
            for (int position : positions(keyword)) {
                bits[position] = true;
            }
        }
        return bits;
    }

    /** 便于直接喂进 Slot/槽位向量：把 {@link #bits(Collection)} 转成 0/1 的 {@code long[]}。 */
    public long[] bitsAsLong(Collection<String> keywords) {
        boolean[] bits = bits(keywords);
        long[] out = new long[length];
        for (int i = 0; i < length; i++) {
            out[i] = bits[i] ? 1 : 0;
        }
        return out;
    }

    /** 置位位置（诊断/人工核对用）。 */
    public int[] positions(String keyword) {
        byte[] base = keyword.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = newSha256();
        int[] out = new int[hashCount];
        for (int i = 0; i < hashCount; i++) {
            md.reset();
            md.update(base);
            md.update((byte) 0x00);
            md.update((byte) (i >>> 8));
            md.update((byte) i);
            long value = ByteBuffer.wrap(md.digest(), 0, Long.BYTES).getLong();
            out[i] = (int) Math.floorMod(value, length);
        }
        return out;
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM 不支持 SHA-256", e);
        }
    }

    @Override
    public String toString() {
        return String.format("BfGen(h=%d, ℓ=%d)", hashCount, length);
    }


    /**
     * 自检：打印位位置，并检查「不同关键词不撞整集合」与「位置分布均匀」。
     *
     * <p>跑法（在 cape-fusepir-database-handoff 或 rgsw-lab 下）：
     * {@code .\run.ps1 -Class com.fusepir.common.BfGen}
     */
    public static void main(String[] args) {
        System.out.println("=== BfGen 位位置推导自检（h 个独立哈希）===");
        BfGen g = new BfGen(6, 26);
        System.out.printf("[params] %s%n%n", g);
        String[] words = {"sci-fi", "action", "comedy", "drama", "animation", "documentary"};
        for (String w : words) {
            int[] p = g.positions(w);
            java.util.Arrays.sort(p);
            System.out.printf("    %-14s %s%n", w, java.util.Arrays.toString(p));
        }

        // ① 不同关键词的位集合不应完全相同
        //    （double hashing 在 ℓ=26 下会撞：sci-fi 与 action 曾经完全一样，见类注释）
        int dupPairs = 0;
        for (int i = 0; i < words.length; i++) {
            for (int j = i + 1; j < words.length; j++) {
                int[] a = g.positions(words[i]);
                int[] b = g.positions(words[j]);
                java.util.Arrays.sort(a);
                java.util.Arrays.sort(b);
                if (java.util.Arrays.equals(a, b)) {
                    dupPairs++;
                    System.out.printf("    !! 位置完全相同：%s 与 %s%n", words[i], words[j]);
                }
            }
        }
        System.out.printf("%n    相同位置集合的关键词对数 = %d（应为 0）%n", dupPairs);

        // ② 单个位置应接近均匀分布在 [0,ℓ)
        int[] hist = new int[g.length()];
        int total = 0;
        for (int i = 0; i < 5000; i++) {
            for (int pos : g.positions("kw-" + i)) {
                hist[pos]++;
                total++;
            }
        }
        int min = Integer.MAX_VALUE;
        int max = 0;
        for (int c : hist) {
            min = Math.min(min, c);
            max = Math.max(max, c);
        }
        double expect = (double) total / g.length();
        System.out.printf("    5000 个关键词 × %d 位 = %d 个位置落在 %d 个桶：期望 %.0f，实测 [%d, %d]，偏差 %.1f%%%n",
            g.hashCount(), total, g.length(), expect, min, max, 100 * Math.abs(max - expect) / expect);
    }
}
