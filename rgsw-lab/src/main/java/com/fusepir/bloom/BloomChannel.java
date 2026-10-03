package com.fusepir.bloom;

import com.fusepir.prim.Mpc4jRgsw;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.RelinKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;

/**
 * <b>Bloom 打分信道</b> —— 论文 Algorithm 2 里 Bloom 那几步所需的服务端/客户端状态与调用函数。
 *
 * <pre>
 *   A2 QUERY 4:  q^BF ← RLWE.Enc_{s_R}(b_qry)
 *   A2 ANSWER 4: ct_score,j ← CtCtMul(q^BF, ct^BF_j)
 *   A2 DECODE 8: s_j ← Dec_{s_R}(ct_score,j)
 * </pre>
 *
 * <h3>为什么单独成类（2026-10-14 深夜）</h3>
 * 这些东西此前**整体住在 {@code cape/CapeBloomScore} 里** —— 于是"Bloom 层"在文件树上
 * 是空的，CAPE 得自己带着 Bloom 的实现。现在：
 * <ul>
 *   <li>{@code bloom/} 拥有<b>信道与加密原语</b>（本类 + {@link BloomScoring} + {@link BloomSetup}
 *       + {@link ScorerWire}）；</li>
 *   <li>{@code cape/} 只做<b>按载荷分组 + 调本类</b>（见 {@code cape/CapeBloomScore.score}）。</li>
 * </ul>
 *
 * <h3>⚠️ 本信道是本实现的<b>口径差</b>，论文里没有"打分信道"这个东西</h3>
 * {@link #SCORE_T} = 65537，而 native（盲旋转）信道的 {@code t = 2^32}：
 * {@code BatchEncoder} 要求 {@code t ≡ 1 (mod 2N)}，而 {@code 2^32} 下
 * {@code new BatchEncoder(context)} 直接抛 {@code encryption parameters are not valid for batching}。
 * ⇒ <b>本实现有两条信道、各持一把独立密钥</b>，而论文只有一把 {@code sk}、一个 {@code t}。
 * 这条口径差记在缺陷总表的 D11，必须与结论一起报。
 */
public final class BloomChannel {

    /** 打分信道的明文模数。<b>不能是 2^32</b>（BatchEncoder 要求 {@code t ≡ 1 mod 2N}）。 */
    public static final long SCORE_T = 65537L;

    /** 打分信道的状态：上下文 + 重线性化密钥 + Galois 密钥。SETUP 时建一次。 */
    public static final class Scorer {
        public final Mpc4jRgsw m;
        public final RelinKeys relinKeys;
        public final GaloisKeys galoisKeys;
        public final int slots;
        public final long setupMs;

        private Scorer(int n, SecretKey sharedSk) {
            long t0 = System.nanoTime();
            // gadget 基取 2^16：它只影响 Mpc4jRgsw 自己的 RGSW 路径，本信道不用那条路径，
            // 但 Mpc4jRgsw 的构造函数要求给一个值（且 base < 2t 必须成立）。
            this.m = new Mpc4jRgsw(n, SCORE_T, 0, 1 << 16, sharedSk);
            this.relinKeys = m.relinKeys();
            this.galoisKeys = BloomScoring.galoisKeysFor(m);
            this.slots = new BatchEncoder(m.context).slotCount();
            this.setupMs = (System.nanoTime() - t0) / 1_000_000;
        }

        /**
         * 本信道的密钥。**客户端与服务端必须是同一把**，否则 {@code ct_score} 解出来是垃圾
         * （不报错，只是数值离谱 —— 实测解成 26921 而不是 {@code 0..ℓ_BF}）。
         *
         * <p>单进程回环里"同一个密钥持有者"就是这么表达的：见 {@link #setup(int, SecretKey)}。
         */
        public SecretKey secretKey() {
            return m.sk;
        }
    }

    private BloomChannel() {
    }

    /**
     * SETUP：建打分信道的密钥材料（重线性化 + Galois）——<b>新生成一把密钥</b>。
     *
     * <p><b>为什么 Galois 密钥是必需的</b>：论文 A2 ANSWER 6-7 的折叠就是
     * {@code CtCtAdd(ct_score, CtRotate(ct_score, 2^r))}，而 {@code CtRotate} 走
     * {@code Evaluator.rotateRowsInplace}，没有 Galois 密钥会直接抛。
     */
    public static Scorer setup(int n) {
        return new Scorer(n, null);
    }

    /**
     * SETUP：<b>复用一把已有的密钥</b>。
     *
     * <p>给"客户端与服务端必须是同一个密钥持有者"这个前提用（单进程回环）。
     * 真两方部署里客户端生成 {@code sk} 后，服务端只需要评估材料
     * （{@code relinKeys} / {@code galoisKeys}），<b>不该拿到 sk</b> ——
     * 本重载是给测试用的，不是协议的一部分。
     */
    public static Scorer setup(int n, SecretKey sharedSk) {
        return new Scorer(n, sharedSk);
    }

    // ------------------------------------------------------------------
    //  客户端侧：q_BF
    // ------------------------------------------------------------------

    /**
     * 把一个 Bloom 向量铺进槽位（{@code q_BF ← RLWE.Enc(b_qry)} 的编码那一步）。
     *
     * <p><b>下标约定（Bloom 打分的核心约定）</b>：第 {@code i} 位放进<b>槽位 i</b>。
     * 这一条把"下标"和"槽位"钉成同一个东西，于是
     * {@code Σ_i b_qry[i]·b_v[i]} 就是逐槽相乘再折叠的结果。
     *
     * <p>⚠️ 这是**唯一的**槽位编码实现 —— 此前 {@code CapeBloomScore}、{@code CapeQuery}
     * 与 {@code probe/CapeEndToEnd4} 各写一份。
     *
     * @param bits 长度必须不超过 {@code slots}（{@code ℓ_BF ≤ N/2} 的硬约束从这里进来）
     */
    public static long[] toSlotVector(boolean[] bits, int slots) {
        if (bits.length > slots) {
            throw new IllegalArgumentException("l_BF = " + bits.length
                + " 超过槽数 " + slots + "（l_BF <= N/2 是硬约束）");
        }
        long[] out = new long[slots];
        for (int i = 0; i < bits.length; i++) {
            out[i] = bits[i] ? 1 : 0;
        }
        return out;
    }

    /**
     * 把不超过 {@code slots} 长的小数组补零铺进槽位。
     *
     * <p>补零是<b>正确性所必需</b>的（不是省事）：它保证下标 {@code ≥ ℓ_BF} 的槽贡献为 0，
     * 于是 {@link BloomScoring#foldSlots} 只折 {@code ℓ_BF} 项就等于折满 N 项。
     * 这正是规划书 P0-1「必须先核」那一条的落地方式。
     */
    public static long[] padToSlots(long[] bits, int slots) {
        if (bits.length > slots) {
            throw new IllegalArgumentException("l_BF = " + bits.length
                + " 超过槽数 " + slots + "（l_BF <= N/2 是硬约束）");
        }
        long[] out = new long[slots];
        System.arraycopy(bits, 0, out, 0, bits.length);
        return out;
    }

    /** {@code q^BF ← RLWE.Enc_{s_R}(b_qry)}，槽位形式。 */
    public static Ciphertext encryptQuery(Scorer sc, boolean[] bQry) {
        return BloomScoring.encryptBloomVector(sc.m, toSlotVector(bQry, sc.slots));
    }

    /**
     * <b>客户端侧</b>：{@code q^BF} 加密并序列化成线上字节（D12 那条明文口的关闭方式）。
     *
     * <p>返回值直接放进 {@code /api/query} 请求体的 {@code qBFBytes} 字段。
     * 实测长度见 {@link ScorerWire}（N=8192 时 211 KB）。
     */
    public static long[] encryptQueryWire(Scorer sc, boolean[] bQry) {
        return ScorerWire.serialize(
            BloomScoring.encryptBloomVector(sc.m, toSlotVector(bQry, sc.slots)));
    }

    /**
     * <b>客户端侧 DECODE</b>：解密整条密文的全部槽（{@code s_j ← Dec(ct_score,j)}）。
     *
     * <p>只有客户端侧有 {@code sk} —— 服务端绝不该调用它。
     */
    public static long[] decryptSlots(Scorer sc, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            sc.m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(sc.m.n);
        sc.m.decryptor.decrypt(copy, pt);
        long[] slots = new long[sc.slots];
        new BatchEncoder(sc.m.context).decode(pt, slots);
        return slots;
    }
}
