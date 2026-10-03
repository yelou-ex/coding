package com.fusepir.fusepir;

import com.fusepir.bloom.BloomScoring;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.Mpc4jRgsw;
import com.fusepir.prim.RingPack;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * <b>A1 ANSWER 13 · 变体 S（槽位域 ring packing）—— 论文那一步的适配器</b>。
 *
 * <pre>
 *   Alg 1 ANSWER 13: resp ← Pack({ct_{pay,b}}_{b=1}^{B_pay})
 *   Alg 1 ANSWER 4:  for b = 1 to B_pay do        ← B_pay 由载荷布局决定
 *   A2  ANSWER  3:   Parse {(c_{v_j}, ct^{BF}_j)} from resp_anc
 * </pre>
 *
 * <h2>与 {@link FusePirPack}（变体 R1）的分工</h2>
 * <ul>
 *   <li>{@link FusePirPack} = <b>系数域</b>变体：一条密文放一个载荷系数，
 *       {@code B_pay} 条密文。<b>不是</b>论文的 {@code Pack}（它自己的类注释写得很清楚）。</li>
 *   <li><b>本类 = 槽位域</b>：{@code B_pay} 条 LWE 样本 → <b>一个</b> RLWE 密文，
 *       第 {@code b} 个载荷字段落在第 {@code b} 个 <b>SIMD 槽</b>。这才是 A2 ANSWER 3
 *       能按候选 {@code j} "parse" 出 {@code ct^{BF}_j} 的前提。</li>
 * </ul>
 *
 * <h2>⚠️ 它能成立的前提，与 §18.2 那条"不可能"不矛盾（必须一起读）</h2>
 * MAP §18.2 证明了：<b>{@code t = 2^32} 上不存在槽位选择子</b>
 * （{@code Z_{2^k}[X]/(X^N+1)} 不是积环 ⇒ 没有幂等基）。
 * 那条墙挡的是 <b>CAPE 演示服务</b>那条 {@code t = 2^32} 的载荷通道，
 * <b>不是 FusePIR 这条</b>：
 * {@link FusePirParams#NATIVE_PLAINTEXT_MODULUS} 就是 <b>65537</b>（论文自己的 {@code t}），
 * 而 {@code 65537 − 1 = 65536 = 4 · 16384} ⇒ 在 {@code N = 8192} 与 {@code N = 16384} 上
 * <b>都可批处理</b>。
 * <b>⇒ `Pack` 在 FusePIR 通道上没有模数障碍；障碍只在 {@code t = 2^32} 那条通道上。</b>
 * 本类把这条区别做成断言（{@link #requireBatchable}），而不是留给读者去记。
 *
 * <h2>⚠️ 槽位布局不是"随便摆"，它由 {@link FusePirSetup} 决定</h2>
 * <pre>
 *   t = 65537, ℓ_BF = 18, m = 3
 *   fpSlots = fpSlots(65537)      = 3
 *   perValue = perValue(18)       = 1 + 18 = 19
 *   B_pay = payloadBpay(3,3,19)   = 3 + 1 + 3·19 = 61
 *   槽：[fp 0..2] [m_i 3] [v_0 4][bv_0 5..22] [v_1 23][bv_1 24..41] [v_2 42][bv_2 43..60]
 * </pre>
 * <b>三个 Bloom 段的起点是 5 / 24 / 43</b> —— 而论文形状的折叠只够到槽 {@code [0, 2^⌈log2 ℓ_BF⌉)}，
 * 对 {@code ℓ_BF = 18} 就是 {@code [0,32)}。⇒ <b>段 1、段 2 会被静默漏算</b>
 * （MAP §19.3 实测：算 0 而不是 3）。
 * 所以本类<b>不提供</b>"自己去调 {@code BloomScoring.bloomScore(…, lBf)}"的入口，
 * 只提供 {@link Packed#highestSlot()} 与 {@link #scoreWithLayout} ——
 * <b>把正确的折叠轮数变成唯一的走法</b>，而不是靠调用方记得。
 *
 * <h2>⚠️ 本类不做什么</h2>
 * <ul>
 *   <li><b>不接进 FusePIR/CAPE 主路径</b>（用户指示：只补缺口、不接线）。没有任何生产调用方。</li>
 *   <li><b>不解密、不持有秘密</b>：只吃公开的 LWE 分量 {@code (as, bs)} 与交换密钥。</li>
 *   <li><b>不解决 {@code q_R → Z_t} 的转换</b>：入参 {@code (as, bs)} 必须<b>已经在
 *       {@code Z_t} 里</b>。真实链路上 {@code SampleExtract_0} 的输出在 {@code q_R} 上、
 *       且是 RNS 形态，那一步（缩放或按 {@code q_LWE} 重设计 gadget）仍然是开着的
 *       （P0-3 / P1-3 第二半，见 MAP §22）。本类把这条边界做成前置检查 + 文档，
 *       而不是假装它不存在。</li>
 * </ul>
 */
public final class FusePirPackSlot {

    private FusePirPackSlot() {
    }

    /** 变体标识：给响应/日志用，防止有人把 R1 与 S 混着引。 */
    public static final String PACK_VARIANT_SLOT_DOMAIN =
        "S 槽位域 ring packing（RingPack + FusePirSetup 布局）";

    // ==================================================================
    //  前置条件
    // ==================================================================

    /**
     * <b>{@code t} 必须可批处理</b>：{@code t} 是素数且 {@code t ≡ 1 (mod 2N)}。
     *
     * <p>为什么做成会炸的断言而不是注释：{@code t = 2^32}（CAPE 演示服务那条通道的载荷模数）
     * 下槽位选择子<b>根本不存在</b>（MAP §18.2 的 mod-4 证明），
     * 而那种失败的形式是"打包出来一条看起来正常的密文、槽位全是错的"。
     * 本项目的规矩是<b>能炸就炸</b>。
     *
     * @param t 明文模数
     * @param n 环维度
     * @throws IllegalArgumentException {@code t} 不是素数，或 {@code t ≢ 1 (mod 2N)}
     */
    public static void requireBatchable(long t, int n) {
        if (t <= 2) {
            throw new IllegalArgumentException("明文模数必须 > 2，实得 " + t);
        }
        if (n <= 0 || Integer.bitCount(n) != 1) {
            throw new IllegalArgumentException("环维度必须是 2 的幂，实得 " + n);
        }
        if (!BigInteger.valueOf(t).isProbablePrime(64)) {
            throw new IllegalArgumentException("明文模数必须可批处理，但 t = " + t + " 不是素数。"
                + "⚠️ 典型踩坑：t = 2^32 —— 它连素数都不是，而且" + (1L << 32)
                + " 上【不存在】槽位选择子（MAP §18.2：Z_{2^k}[X]/(X^N+1) 不是积环）。"
                + "FusePIR 通道请用 FusePirParams.NATIVE_PLAINTEXT_MODULUS = 65537。");
        }
        long twoN = 2L * n;
        if (Math.floorMod(t - 1, twoN) != 0) {
            throw new IllegalArgumentException("明文模数必须满足 t ≡ 1 (mod 2N)：t = " + t
                + "、2N = " + twoN + "、余数 = " + Math.floorMod(t - 1, twoN)
                + " ⇒ BatchEncoder 建不出来，槽位选择子无从制造。");
        }
    }

    /** {@link #requireBatchable} 的非抛出版本（给探针做负对照用）。 */
    public static boolean isBatchable(long t, int n) {
        try {
            requireBatchable(t, n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // ==================================================================
    //  适配器的产物
    // ==================================================================

    /**
     * {@code Pack} 的产物 <b>+ 调用方必须一起带走的那几条契约</b>。
     *
     * <p>为什么不是"就返回一个 {@code Ciphertext}"：折叠轮数、槽位布局、最高参与槽
     * 这三样都是<b>打分时才需要、但只有打包时才知道</b>的东西。
     * MAP §19.3 那条静默漏算的根因，就是"打包方知道、打分方不知道"。
     * 把它绑成一个值类型，就没有"忘了传"的余地（同 {@code FusePirQuery.CellIndex} 的理由）。
     */
    public static final class Packed {
        /** 打包密文（{@code NTT} 形态；打分前由 {@link #scoreWithLayout} 负责转回系数形态）。 */
        private final Ciphertext ct;
        private final long t;
        private final int n;
        private final int bPay;
        private final int fpSlots;
        private final int mCount;
        private final int perValue;
        private final int lBf;
        private final int[] bloomSegBase;

        Packed(Ciphertext ct, long t, int n, int bPay, int fpSlots, int mCount,
               int perValue, int lBf, int[] bloomSegBase) {
            this.ct = ct;
            this.t = t;
            this.n = n;
            this.bPay = bPay;
            this.fpSlots = fpSlots;
            this.mCount = mCount;
            this.perValue = perValue;
            this.lBf = lBf;
            this.bloomSegBase = bloomSegBase;
        }

        /** 打包密文本体。⚠️ 调用方不许改它（同 {@code FusePirServerState.table()} 的口径）。 */
        public Ciphertext ct() {
            return ct;
        }

        public long t() {
            return t;
        }

        public int n() {
            return n;
        }

        public int bPay() {
            return bPay;
        }

        public int fpSlots() {
            return fpSlots;
        }

        public int mCount() {
            return mCount;
        }

        public int perValue() {
            return perValue;
        }

        public int lBf() {
            return lBf;
        }

        /** 第 {@code j} 个候选值的 Bloom 段起点槽（与 {@link FusePirSetup#bloomOffset} 同口径）。 */
        public int bloomSegBase(int j) {
            return bloomSegBase[j];
        }

        public int[] bloomSegBase() {
            return bloomSegBase.clone();
        }

        /**
         * <b>参与内积的最高槽下标</b> —— 也就是 {@link BloomScoring#bloomScoreReaching} 的入参。
         *
         * <p>载荷摆满 {@code 0..B_pay−1}，所以它就是 {@code B_pay − 1}。
         * ⚠️ <b>不能用 {@code ℓ_BF} 代替</b>：{@code B_pay = 61} 而 {@code ℓ_BF = 18}
         * ⇒ 论文形状的 5 轮折叠只够到槽 31，会漏掉槽 32..60 上的命中位（MAP §19.3）。
         */
        public int highestSlot() {
            return bPay - 1;
        }

        @Override
        public String toString() {
            return String.format("packed(S, t=%d, N=%d, B_pay=%d, lBf=%d, 段起点=%s, 最高参与槽=%d)",
                t, n, bPay, lBf, Arrays.toString(bloomSegBase), highestSlot());
        }
    }

    // ==================================================================
    //  适配器
    // ==================================================================

    /**
     * <b>把 {@code B_pay} 条 LWE 样本打包成一个槽位域 RLWE 密文</b>（A1 ANSWER 13）。
     *
     * <p>载荷布局由 {@code (t, mCount, lBf)} 按 {@link FusePirSetup} 的算式<b>自己算</b>，
     * 不接受调用方手写下标 —— 手写就会与 {@code decodePayload} 那侧对不上，
     * 而那种错的症状是"某些字段恒为 0"，很难查。
     *
     * @param m        RLWE 上下文（明文模数必须是可批处理的 {@code t}）
     * @param be       {@code BatchEncoder}（槽位选择子的唯一制造工具）
     * @param swk      交换密钥 {@code SwK[j][k]}，来自 {@link keyGen}；条数必须 ≥ {@code nLwe}
     * @param base     gadget 底 {@code B}
     * @param digits   gadget 段数（{@link RingPack} 会校验 {@code B^digits ≥ t}）
     * @param mCount   每个关键词关联的候选值个数 {@code m}
     * @param lBf      {@code ℓ_BF}
     * @param as       {@code [B_pay][nLwe]} 每条样本的 {@code a} 分量，<b>必须已在 {@code Z_t} 内</b>
     * @param bs       {@code [B_pay]} 每条样本的 {@code b} 分量，值满足
     *                 {@code b ≡ ⟨a,s⟩ + payload_b (mod t)}
     * @throws IllegalArgumentException 布局与入参不一致（形状不齐、{@code B_pay} 对不上、
     *                                  {@code t} 不可批处理、槽数不够）
     */
    public static Packed pack(Mpc4jRgsw m, BatchEncoder be, Ciphertext[][] swk,
                              int base, int digits, int mCount, int lBf,
                              long[][] as, long[] bs) {
        return pack(m, be, swk, base, digits, mCount, lBf, m.t, as, bs);
    }

    /**
     * <b>同一件事，但<b>槽位布局</b>按显式给出的 {@code tField} 算</b>（应答通道精度提升后的形态）。
     *
     * <h3>为什么需要把两个模数分开</h3>
     * 本管线现在有<b>两个明文模数</b>：
     * <ul>
     *   <li>{@code m.t = tRing} —— <b>应答通道</b>的明文模数，比字段域大 {@code K} 倍，
     *       用来装下"字段 × K"（{@link FusePirSetup#assemblePayload} 的精度倍率）；</li>
     *   <li>{@code tField = T}（论文自己的 {@code t}）—— <b>字段域</b>，决定
     *       {@code fpSlots} / {@code perValue} / {@code B_pay} / 段起点。</li>
     * </ul>
     * 布局<b>必须</b>按 {@code tField} 算：若按 {@code tRing} 算，{@code fpSlots} 会从 3 变成 2、
     * {@code B_pay} 从 61 变成 60，于是建表侧与解析侧对不上（而 {@code y} 里的 limb 宽度
     * 也确实是按 {@code T} 定的 16 bit）。<b>这两个数字混用是静默错，所以做成显式入参。</b>
     *
     * @param tField 字段域模数（论文的 {@code t}），必须 ≤ {@code m.t}
     */
    public static Packed pack(Mpc4jRgsw m, BatchEncoder be, Ciphertext[][] swk,
                              int base, int digits, int mCount, int lBf, long tField,
                              long[][] as, long[] bs) {
        if (m == null || be == null || swk == null) {
            throw new IllegalArgumentException("m / be / swk 都不能为 null");
        }
        if (tField < 2 || tField > m.t) {
            throw new IllegalArgumentException("字段域模数 tField = " + tField
                + " 必须落在 [2, 应答通道明文模数 " + m.t + "] 内");
        }
        if (as == null || bs == null) {
            throw new IllegalArgumentException("LWE 样本 (as, bs) 不能为 null");
        }
        requireBatchable(m.t, m.n);
        if (be.slotCount() != m.n) {
            throw new IllegalArgumentException("BatchEncoder 的槽数 " + be.slotCount()
                + " 与环维度 " + m.n + " 不一致 —— 两者不是同一个上下文");
        }

        final int fpSlots = FusePirSetup.fpSlots(tField);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);

        if (bs.length != bPay) {
            throw new IllegalArgumentException("b 分量有 " + bs.length + " 条，但布局要求 B_pay = "
                + bPay + "（tField=" + tField + ", m=" + mCount + ", lBf=" + lBf
                + " ⇒ fpSlots=" + fpSlots + ", perValue=" + perValue + "）");
        }
        if (as.length != bPay) {
            throw new IllegalArgumentException("a 分量有 " + as.length + " 行，但布局要求 B_pay = "
                + bPay + " 行");
        }
        final int nLwe = as[0].length;
        for (int i = 0; i < bPay; i++) {
            if (as[i] == null || as[i].length != nLwe) {
                // 不齐的一行会让 native/纯 Java 两条路径读越界内容或 0 —— 静默错答案。
                throw new IllegalArgumentException("第 " + i + " 条样本的 a 长度是 "
                    + (as[i] == null ? "null" : as[i].length) + "，与第 0 条（" + nLwe + "）不一致");
            }
        }
        if (swk.length < nLwe) {
            throw new IllegalArgumentException("交换密钥只有 " + swk.length + " 行（每条一个 LWE 维数），"
                + "但样本维数是 " + nLwe + " —— 少的那几个维数不会报错，只会静默少减几项");
        }
        if (bPay > be.slotCount()) {
            throw new IllegalArgumentException("B_pay = " + bPay + " 超过槽数 " + be.slotCount());
        }

        int[] slotOf = new int[bPay];
        for (int i = 0; i < bPay; i++) {
            slotOf[i] = i;                                  // 字段 i -> 槽 i（与 §19 的探针同口径）
        }
        int[] segBase = new int[mCount];
        for (int j = 0; j < mCount; j++) {
            segBase[j] = FusePirSetup.bloomOffset(fpSlots, j, perValue);
        }

        Ciphertext ct = RingPack.pack(m, be, swk, base, digits, as, bs, slotOf);
        return new Packed(ct, m.t, m.n, bPay, fpSlots, mCount, perValue, lBf, segBase);
    }

    /** 交换密钥（{@code SwK[j][k] = RLWE(B^k · s_j)}）。转发到 {@link RingPack#switchingKey}。 */
    public static Ciphertext[][] keyGen(Mpc4jRgsw m, int[] s, int base, int digits) {
        return RingPack.switchingKey(m, s, base, digits);
    }

    // ==================================================================
    //  RNS / q_R → Z_t 的桥（真实链路与适配器之间那一层）
    // ==================================================================

    /**
     * <b>{@code q_R} 上、RNS 形态的 LWE 样本 → {@code Z_t} 下的 {@code (β, a)}。</b>
     *
     * <h3>为什么必须有这一层</h3>
     * {@link RingPack#pack} 要求入参<b>已经在 {@code Z_t} 里</b>（BFV 明文域）。
     * 而真实链路上 {@code ct_{pay,b}} 来自
     * {@code SampleExtract_0}，它在 <b>{@code q_R}</b> 上、且是 <b>RNS 形态</b>
     * （{@link com.fusepir.prim.LweRlweBridge#sampleExtract} 返回 {@code [素数][N+1]}）。
     * 中间这一步就是"缩放"：{@code x → round(x·t/q_R)}。
     *
     * <h3>⚠️ 它会引入噪声，而这是本层最重要的事实</h3>
     * 每个 {@code a_j} 的舍入误差 {@code δ_j ∈ [−1/2, 1/2]} 乘上 {@code s_j} 后累加，
     * 残差 ≈ {@code Σ δ_j s_j}，理论 {@code std ≈ √(N·2/3)·0.289}（N=8192、三元秘密 ⇒ 约 20）。
     * <b>对 16-bit 的 limb 无害（相对误差 0.1%），对 0/1 的 Bloom 位是致命的（几十倍）。</b>
     * 实测见 {@code probe/FusePirPackSlotRnsTest}。
     *
     * <h3>⚠️ 符号约定：{@code a} 必须取反</h3>
     * RLWE（SEAL）的相位是 {@code c0 + c1·s} ⇒ {@code b + ⟨a,s⟩ = Δm + e}；
     * 而 {@link RingPack#pack} 的约定是 {@code b ≡ ⟨a,s⟩ + m (mod t)}。
     * 两边落在同一个相位上要求 {@code a} 取相反数 ——
     * <b>忘了取反的症状是"槽位全是错的"，而且不报错。</b>
     * （同 {@code LweRlweConversion:193-197} 的那条注释。）
     *
     * @param sample {@link com.fusepir.prim.LweRlweBridge#sampleExtract} 的产物：
     *               {@code [workingPrimeCount][N+1]}，{@code [pi][0] = β}、{@code [pi][1+k] = a_k}
     * @return {@code [N+1]}：{@code [0] = β}、{@code [1..N] = a}，都在 {@code [0, t)}
     */
    public static long[] rnsToT(Mpc4jRgsw m, long[][] sample) {
        if (sample == null) {
            throw new IllegalArgumentException("RNS 样本为 null");
        }
        final int L = m.workingPrimeCount;
        final int n = m.n;
        if (sample.length != L) {
            throw new IllegalArgumentException("RNS 样本有 " + sample.length + " 个素数分量，"
                + "但上下文的工作素数个数是 " + L
                + "（⚠️ 不是 declaredPrimeCount：按后者索引会读越界或读错层）");
        }
        for (int pi = 0; pi < L; pi++) {
            if (sample[pi] == null || sample[pi].length != n + 1) {
                throw new IllegalArgumentException("第 " + pi + " 个素数分量的长度是 "
                    + (sample[pi] == null ? "null" : sample[pi].length) + "，应为 N+1 = " + (n + 1));
            }
        }
        long[] residues = new long[L];
        for (int pi = 0; pi < L; pi++) {
            residues[pi] = sample[pi][0];
        }
        long[] out = new long[n + 1];
        out[0] = scaleToT(LweRlweBridge.crtCentered(m, residues), m.q, m.t);
        for (int k = 0; k < n; k++) {
            for (int pi = 0; pi < L; pi++) {
                residues[pi] = sample[pi][1 + k];
            }
            out[1 + k] = scaleToT(LweRlweBridge.crtCentered(m, residues).negate(), m.q, m.t);
        }
        return out;
    }

    /**
     * <b>按素数分量逐项相加</b> —— A1 ANSWER 12 的 {@code ct_{pay,b} ← Σ_a ct_{a,b}}（三路相加）。
     *
     * <p>三条路径的样本必须<b>在密文域相加</b>（论文那一步），而 RNS 形态下的"相加"
     * 就是<b>每个素数分量各自 mod 该素数</b>相加。不在这里做的话，调用方会各自手写一遍，
     * 而漏掉"mod 该素数"那一步不会报错、只会让 CRT 还原出别的数。
     */
    public static long[][] sumRns(Mpc4jRgsw m, long[][]... paths) {
        if (paths == null || paths.length == 0) {
            throw new IllegalArgumentException("至少要有一条路径");
        }
        final int L = m.workingPrimeCount;
        final int n = m.n;
        for (int i = 0; i < paths.length; i++) {
            if (paths[i] == null || paths[i].length != L) {
                throw new IllegalArgumentException("第 " + i + " 条路径的素数分量个数不是 " + L);
            }
            for (int pi = 0; pi < L; pi++) {
                if (paths[i][pi].length != n + 1) {
                    throw new IllegalArgumentException("第 " + i + " 条路径第 " + pi
                        + " 个分量的长度不是 N+1");
                }
            }
        }
        long[][] out = new long[L][n + 1];
        for (int pi = 0; pi < L; pi++) {
            final long mod = m.primes[pi].value();
            for (int c = 0; c <= n; c++) {
                long acc = 0;
                for (long[][] p : paths) {
                    acc = Math.floorMod(acc + p[pi][c], mod);
                }
                out[pi][c] = acc;
            }
        }
        return out;
    }

    /**
     * <b>从真实链路的输出打包</b>：{@code ct_{pay,b}} 的 RNS 形态进来，一个槽位域密文出去。
     *
     * <p>这是 {@link #pack} 的"真实输入"版本 —— 它把 {@link #rnsToT} 接在前面，
     * 所以吃的是 {@code SampleExtract_0}（经三路相加）的产物，
     * 而不是理想化的 {@code Z_t} 样本。
     *
     * @param samples {@code [B_pay][workingPrimeCount][N+1]}；{@code samples[b]} 是
     *                {@code ct_{pay,b}}。<b>三路相加请先用 {@link #sumRns} 做完</b>
     */
    public static Packed packFromRns(Mpc4jRgsw m, BatchEncoder be, Ciphertext[][] swk,
                                     int base, int digits, int mCount, int lBf,
                                     long[][][] samples) {
        if (samples == null || samples.length == 0) {
            throw new IllegalArgumentException("RNS 样本数组为空");
        }
        long[][] as = new long[samples.length][];
        long[] bs = new long[samples.length];
        for (int b = 0; b < samples.length; b++) {
            long[] zt = rnsToT(m, samples[b]);
            bs[b] = zt[0];
            as[b] = Arrays.copyOfRange(zt, 1, zt.length);
        }
        return pack(m, be, swk, base, digits, mCount, lBf, as, bs);
    }

    /**
     * {@code x ∈ Z_{q_R}} → {@code Z_t}：四舍五入 {@code x·t/q_R} 后取模（口径同 {@code LweRlweConversion.scaleDown}）。
     *
     * <p>⚠️ <b>公开是为了让"只做一次舍入"的诊断判据复用它</b>（{@code AnswerOps.phaseOfRns}）：
     * {@link #rnsToT} 对 {@code β} 与 {@code N} 个 {@code a_k} <b>各自</b>舍入一次，
     * 相位里因此多出 {@code Σ_k δ_k·s_k}（{@code |δ| ≤ ½}）—— 这是<b>桥的固有残差</b>，
     * 不是 ANSWER 的算术错。要判"算术对不对"就得把相位<b>先算完再舍入一次</b>，
     * 而那一步必须与这里口径完全一致，所以<b>不允许</b>在别处再手抄一遍这个公式。
     */
    public static long scaleToT(BigInteger x, BigInteger qR, long t) {
        BigInteger tB = BigInteger.valueOf(t);
        BigInteger num = x.multiply(tB);
        BigInteger half = qR.shiftRight(1);
        num = x.signum() >= 0 ? num.add(half) : num.subtract(half);
        return num.divide(qR).mod(tB).longValueExact();
    }

    // ==================================================================
    //  打分（把"正确的折叠轮数"变成唯一走法）
    // ==================================================================

    /**
     * <b>用打包产物做槽位域同态内积，折叠轮数由 {@link Packed#highestSlot()} 决定。</b>
     *
     * <p>为什么不直接暴露 {@code BloomScoring.bloomScore(…, lBf)}：那条路假定候选的支撑在
     * {@code [0, ℓ_BF)}，而打包产物**天然违反**它（Bloom 位散布在整个 {@code [0, B_pay)}）。
     * 实测（MAP §19.3）：{@code ℓ_BF = 18} 时 {@code ⌈log2 18⌉ = 5} 轮只够到槽 31，
     * 段 1（槽 39..41）与段 2（槽 58..60）**算出 0 而不是 3**。
     *
     * @param q 查询向量（长度必须等于槽数，二进制）—— 与论文的 {@code b_qry} 同口径
     */
    public static long scoreWithLayout(Mpc4jRgsw m, GaloisKeys gk, long[] q, Packed packed) {
        if (packed == null) {
            throw new IllegalArgumentException("打包产物不能为 null");
        }
        Ciphertext qBF = BloomScoring.encryptBloomVector(m, q);
        Ciphertext cand = new Ciphertext();
        cand.copyFrom(packed.ct());
        if (cand.isNttForm()) {
            m.evaluator.transformFromNttInplace(cand);       // ct×ct 要求非 NTT 形态
        }
        return BloomScoring.decodeScore(m,
            BloomScoring.bloomScoreReaching(m, gk, qBF, cand, packed.highestSlot()));
    }

    /** 客户端侧：从打包产物里把 {@code y ∈ Z_t^{B_pay}} 读回来（字段 {@code i} 在槽 {@code i}）。 */
    public static long[] decodePayload(Mpc4jRgsw m, BatchEncoder be, Packed packed, int bPay) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(packed.ct());
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] slots = new long[be.slotCount()];
        be.decode(pt, slots);
        return Arrays.copyOf(slots, bPay);
    }

    /** 交换密钥的体积（条数与字节），与 {@code RingPack} 的口径一致。 */
    public static String keyCost(Mpc4jRgsw m, int nLwe, int digits) {
        long perCt = 2L * m.workingPrimeCount * m.n * 8L;
        long total = perCt * nLwe * digits;
        return String.format("交换密钥 %d 条（nLwe=%d × digits=%d），每条 %d 字节，合计 %.1f MB",
            nLwe * digits, nLwe, digits, perCt, total / 1048576.0);
    }

    /** 一行自述，给日志/响应用。 */
    public static String describe() {
        return PACK_VARIANT_SLOT_DOMAIN;
    }
}
