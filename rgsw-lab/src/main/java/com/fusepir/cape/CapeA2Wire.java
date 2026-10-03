package com.fusepir.cape;

import com.fusepir.bloom.BloomScoring;
import com.fusepir.common.BfGen;
import com.fusepir.fusepir.FusePirClientState;
import com.fusepir.fusepir.FusePirFourStep;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirServerState;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <b>把 FusePIR（Algorithm 1）的四步接进 CAPE（Algorithm 2）—— A2 侧唯一的调用方。</b>
 *
 * <p>本类之前，{@link FusePirFourStep} 的四个入口<b>没有任何生产调用方</b>
 * （MAP §27.5 / §31.4 登记过），也就是"四步跑通了、但 CAPE 还没接线"。
 * 本类就是那根线：它把 A2 里调用 FusePIR 的四行、以及 A2 自己的打分段，
 * 接成一条能跑的链。
 *
 * <h2>它接的正是 A2 原文里那几行</h2>
 * <pre>
 *   A2 SETUP  11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE)   → {@link #setup}
 *   A2 SETUP  12: pp ← (pp_F, ℓ_BF, G, m)                            → pp_F.extendBloom(…)（已有，不重造）
 *   A2 SETUP  13: st_S ← st^F_S                                      → {@link Setup#stS()}（直传，不重造）
 *   A2 QUERY   1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1)   → {@link #query}
 *   A2 QUERY   2: b_qry ← BF.Gen(0, {K_1,…,K_Q})                     → {@link #queryVector}
 *   A2 QUERY   3: τ ← ‖b_qry‖₁                                       → {@link Query#tau()}
 *   A2 ANSWER  2: resp_anc ← FusePIR.Answer(st_S, q_anc)             → {@link #answer}
 *   A2 ANSWER  3: Parse {(ct_{v_j}, ct^BF_j)} from resp_anc          → {@link Answer#valueCt}/{@link Answer#bloomCt}
 *   A2 ANSWER  4: ct_{score,j} ← CtCtMul(q^BF, ct^BF_j)              → {@link #answer}（打分）
 *   A2 ANSWER  5-6: 折叠相加                                          → {@link #answer}（打分）
 *   A2 DECODE  2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc)   → {@link #decode}
 * </pre>
 * 四个入口的签名照 A2 原文，本类<b>不改它们</b>（MAP §27.1 / §31.2-5）。
 *
 * <h2>🔴 三个模数的账（接线第一件要记住的事，MAP §31.1）</h2>
 * <table border="1">
 *   <tr><th>模数</th><th>值</th><th>本类怎么用</th></tr>
 *   <tr><td>字段域 {@code T}（论文的 {@code t}）</td><td>{@code 65537}</td>
 *       <td><b>只用来解释槽位布局</b>：{@code B_pay = fpSlots+1+m(1+ℓ_BF)}、值槽 / 段起点、
 *           {@link #decode} 出来的"值"是字段域的数</td></tr>
 *   <tr><td>应答通道 {@code tRing}=1179649</td>
 *       <td>⚠️ <b>不是 {@code K·T}</b>：{@code tRing} 是"最小的 {@code ≡1 (mod 2N)} 且
 *           落在搜索下界之上的素数"，而 {@code K := ⌊tRing/T⌋ = 17}
 *           （实测 {@code tRing = 18T − 17 = 1179649}，而 {@code 17T = 1114129}）。
 *           本组 {@code K·T ≠ tRing}，差 65520 —— MAP §31.1 / 交接单 §3 里写的
 *           "{@code tRing = K·T}" 是简化说法，代码里 K 是整除商</td>
 *       <td><b>打分整体在这个域里</b>：{@code q^BF} 用 {@link Setup#fusepir()}{@code .ring()}
 *           加密、{@code CtCtMul} / 折叠用同一把 {@code GaloisKeys}、
 *           得分也是这个域里的数</td></tr>
 *   <tr><td>native 载荷通道 {@code 2^32}</td><td>——</td>
 *       <td><b>本类一行不碰</b>（{@code CapeDemoService} 那条路）</td></tr>
 * </table>
 *
 * <h2>⚠️ 三条硬约束，以及它们各自的"破约症状"</h2>
 * <ol>
 *   <li><b>打分不能用 {@code T}、也不能用 {@code CapeBloomScore.DEFAULT_T = 2^32}</b>。
 *       密文与 {@code GaloisKeys} 都长在 {@code tRing} 的上下文里，混用要么抛
 *       {@code NTT form mismatch} / {@code parsimId} 校验，要么<b>静默算错分</b>。</li>
 *   <li><b>槽里存的是 {@code K·field}</b>（Bloom 位是 {@code 0 / K}）
 *       ⇒ 同态内积给出的是 {@code K × 匹配位数} <b>再加上桥的残差</b>
 *       ⇒ 判定规则是"<b>把得分四舍五入到 K 的倍数，再看是不是 τ</b>"
 *       （{@link #nearestFieldScore}），<b>不是</b> {@code s_j == K·τ} 那个等号。
 *       <p>⚠️ 更狠的一条：{@code K > ones} 只够读<b>单个</b>字段；打分把残差在
 *       {@code τ = ‖b_qry‖₁} 个字段上<b>累加</b>，上界 {@code τ·ones/2}
 *       ⇒ 必须 {@code K > τ·ones}（本组 {@code τ=10、ones=11} ⇒ {@code K=128}，
 *       见 {@link #A2_MIN_SCALE_K}）。{@link #query} 里有守卫拦这件事。
 *       拿 {@code τ} 直接比（不乘 K）会把<b>每一个</b>命中候选都判成拒绝，
 *       而且不报错 —— 症状是"库明明有、却一个都不收"。</li>
 *   <li><b>{@code Resp.bloomCt(j)} 不掩码</b>（只旋转，MAP §30.2 —— 掩码乘打包件会把密文解坏）。
 *       它把第 {@code j} 个候选的 Bloom 段转到槽 {@code [0, ℓ_BF)}，
 *       但<b>段外仍是真载荷杂质</b>（相邻候选的值与 Bloom 位）。
 *       ⇒ 段外置零由 {@link Query#qBF()} 承担：客户端的 {@code b_qry} 支撑在
 *       {@code [0, ℓ_BF)}，段外全 0 ⇒ {@code CtCtMul} 的积在段外也是 0 ⇒ 折叠不带杂质。
 *       <b>反过来，{@code q^BF} 的段外一旦不是 0，得分就不等于 {@code K·⟨b_qry,b_v⟩}
 *       —— 差值正好是那些杂质位置的载荷</b>（探针 {@code CapeA2WireTest} 的 P5 把这个差值实测出来）。</li>
 * </ol>
 *
 * <h2>折叠轮数</h2>
 * 一律走 {@link BloomScoring#bloomScoreReaching}(…, {@code packed.highestSlot()})：
 * {@code B_pay = 61} ⇒ 最高参与槽 60 ⇒ 6 轮。
 * <p>⚠️ <b>但这里有一条本实现要如实说清的细节</b>：本接线下 {@code q^BF} 的支撑在
 * {@code [0, ℓ_BF)}，所以<b>论文形状的 {@code ⌈log2 ℓ_BF⌉ = 5} 轮在本接线上也够</b>
 * （积的支撑全在 {@code [0,32)} 内）。§19.3 那条"静默漏算"针对的是
 * <b>{@code q} 铺在打包件槽位上</b>（支撑到槽 60）的打法。
 * ⇒ 走 {@code bloomScoreReaching} 的理由不是"5 轮必错"，而是
 * <b>它不依赖"q 段外为 0"这条契约</b>；契约一破，两条路的得分会分开
 * （实测见探针 P5，配正/负对照）。</p>
 *
 * <p>⚠️ 本类<b>不是</b>{@code CapeDemoService} 那条路上的东西：那条路用的是
 * {@code bloom/BloomChannel} 的打分信道（两个 {@code t}、两把 sk，本实现的口径差 D11），
 * 本类<b>一行未动它</b>，也没有被它调用。</p>
 */
public final class CapeA2Wire {

    /**
     * <b>A2 这条路要求的系数模数位宽</b>（每个 RNS 素数 60 bit，共 3 个 ⇒ 工作模数 120 bit）。
     *
     * <h3>为什么 A2 必须放宽 q（2026-10-15 实测，{@code probe/ScoreMulDomainTest}）</h3>
     * A2 ANSWER 4 的 {@code CtCtMul(q^BF, ct^BF_j)} 作用在 <b>{@code Pack} 的产物</b>上。
     * 用 {@code bfvDefault(4096)}（工作模数 72 bit）时实测：
     * <table border="1">
     *   <tr><th>对象</th><th>噪声预算</th></tr>
     *   <tr><td>新加密密文</td><td>51 bit</td></tr>
     *   <tr><td>{@code RingPack} 产物</td><td><b>2 bit</b>（稠密槽位选择子吃掉 ~49 bit）</td></tr>
     *   <tr><td>一次 {@code CtCtMul} 的代价</td><td>~26 bit（实测 51 → 25）</td></tr>
     * </table>
     * ⇒ {@code 2 − 26 < 0}：得分密文<b>解出来是均匀随机值</b>（4096/4096 个槽对不上）。
     * 放宽到 {@code 3×60} 后实测 Pack 产物 <b>50 bit</b>、{@code q^BF × Pack}
     * <b>逐槽完全正确</b>（0/4096 不符）。
     *
     * <p>⚠️ <b>{@code 3×60} 不是 128-bit 安全参数</b>（SEAL 会以
     * "not compliant with HomomorphicEncryption.org security standard" 拒绝），
     * 所以只能走 {@code SecLevelType.NONE}。这是**玩具参数**，只为让 A2 那一步在预算上成立；
     * 用它复现"分数是随机值"的负对照：把这里换回 {@code null} 即可（见探针的缺陷断言）。
     */
    public static final int[] A2_COEFF_BITS = {60, 60, 60};

    /**
     * <b>A2 这条路要求的精度倍率下界</b>：{@code K > τ·ones}。
     *
     * <h3>为什么不是 {@code K > ones}</h3>
     * {@code K > ones} 只保证<b>单个字段</b>读得准（{@code |E| ≤ ones/2}）。
     * 而 A2 的判定量是<b>同态内积</b>：
     * <pre>
     *   s_j = ⟨q^BF, b_v⟩ = K·(匹配位数) + Σ_{i ∈ supp(q)} E_i,   |Σ E_i| ≤ τ·ones/2
     * </pre>
     * 判定要区分"匹配 τ 位"与"匹配 τ−1 位"（差 K）⇒ 必须 {@code K > τ·ones}。
     * 本组：{@code τ = h·|Q| = 5×2 = 10}、{@code ones = 11} ⇒ {@code K > 110} ⇒ 取 <b>128</b>。
     * 实测（K=17 时）命中候选得分 172 而 {@code K·τ = 170} —— 残差加起来就越过了 {@code K/2}。
     *
     * <p>上界 {@code τ·ones/2} 是保守的（残差是若干独立均匀量之和，实测只有个位数），
     * 但"判定必须正确"要的是<b>保证</b>，所以按上界取。
     * {@link #query} 里有一条守卫会拦住 {@code τ·ones ≥ K} 的查询（宁可抛，也不要静默误判）。
     */
    public static final long A2_MIN_SCALE_K = 128L;

    private CapeA2Wire() {
    }

    // ==================================================================
    //  A2 SETUP 11 / 12 / 13
    // ==================================================================

    /**
     * {@code A2 SETUP 11-13} 的产物：{@code (pp_F, st^F_S, sk)} + {@code pp_C} + 打分要用的常量。
     */
    public static final class Setup {
        private final FusePirFourStep fp;
        private final FusePirParams.Cape ppC;
        private final BfGen bf;
        private final int m;
        private final int slotCount;

        private Setup(FusePirFourStep fp, FusePirParams.Cape ppC, BfGen bf, int m) {
            this.fp = fp;
            this.ppC = ppC;
            this.bf = bf;
            this.m = m;
            this.slotCount = new BatchEncoder(fp.ring().context).slotCount();
        }

        /** {@code FusePIR.Setup} 的实例（{@code pp_F} / {@code st^F_S} / 环上下文都在里面）。 */
        public FusePirFourStep fusepir() {
            return fp;
        }

        /** {@code pp_F}（A2 SETUP 11 的第一个返回值）。 */
        public FusePirParams ppF() {
            return fp.pp();
        }

        /** {@code pp = (pp_F, ℓ_BF, G, m)}（A2 SETUP 12；由 {@code pp_F.extendBloom} 加宽）。 */
        public FusePirParams.Cape ppC() {
            return ppC;
        }

        /** {@code st_S = st^F_S}（A2 SETUP 13；**直传**，不重造）。 */
        public FusePirServerState stS() {
            return fp.stS();
        }

        /** {@code G} 的实现（{@code BF.Gen} 的唯一来源，客户端与服务端共用）。 */
        public BfGen bf() {
            return bf;
        }

        public int lBf() {
            return fp.lBf();
        }

        /** {@code m = max_i |V_{K_i}|}（A2 SETUP 2；与 {@code setup} 里的实算对过账）。 */
        public int m() {
            return m;
        }

        public int bPay() {
            return fp.bPay();
        }

        /** {@code N}。 */
        public int ringDim() {
            return fp.ring().n;
        }

        /** 一条密文的槽数（{@code BatchEncoder.slotCount()}，= {@code N}）。 */
        public int slotCount() {
            return slotCount;
        }

        /** 应答通道明文模数 {@code tRing}（**打分所在的域**）；{@code K = ⌊tRing/T⌋}，{@code K·T ≤ tRing}。 */
        public long tRing() {
            return fp.ringModulus();
        }

        /** 字段域模数 {@code T = 65537}（论文的 {@code t}）。 */
        public long tField() {
            return FusePirFourStep.T;
        }

        /** 精度倍率 {@code K}（槽里存的是 {@code K·field}）。 */
        public long scaleK() {
            return fp.scale();
        }

        @Override
        public String toString() {
            return String.format("A2.setup(%s；pp_C 的 ℓ_BF=%d、m=%d；tRing=%d、K=%d)",
                fp, ppC.lBf(), ppC.m(), tRing(), scaleK());
        }
    }

    /**
     * {@code A2 SETUP 11-13}：{@code FusePIR.Setup} + {@code pp_F.extendBloom} + {@code st_S ← st^F_S}。
     *
     * <p>⚠️ 传进来的 {@code db} 必须是 <b>{@code DB^CAPE}</b>（每个值已配好 {@code b_v}），
     * 不是原始 DB —— A2 SETUP 3-10 在它之前完事（MAP §27.1 第 1 条）。
     * {@code DB^CAPE} 的构造（{@code S_v → b_v = BF.Gen(0,S_v)}）走
     * {@code bloom/BloomSetup} + {@link BfGen}，本类不重写那一步。
     *
     * @param bf      A2 SETUP 1 选的 Bloom 参数（{@code ℓ_BF} 与 {@code h}）
     */
    public static Setup setup(FusePirFourStep.Db db, int ringDim, int d, int lBf,
                              long rhoH, long seed0, BfGen bf) {
        if (db == null || bf == null) {
            throw new IllegalArgumentException("DB^CAPE 与 Bloom 参数（BfGen）都不能为 null");
        }
        if (lBf < 1) {
            throw new IllegalArgumentException("A2 的接线要求 ℓ_BF ≥ 1（A2 SETUP 5 的 b_v 是 "
                + "ℓ_BF 位）：纯 A1（y 无 Bloom 段）请直接调 FusePirFourStep.setup");
        }
        if (bf.length() != lBf) {
            throw new IllegalArgumentException("BfGen 的长度 " + bf.length() + " != ℓ_BF = " + lBf
                + "：b_v 的位数与载荷里的 Bloom 段必须是同一个 ℓ_BF，"
                + "否则 ⟨b_qry,b_v⟩ 与实际摆放的段对不上（不报错，只是分算错）");
        }
        // A2 SETUP 11：注意传进去的是 DB^CAPE
        // ⚠️ 这里用 8 参重载（原 6 参签名一行未动）：两个旋钮都是 A2 这条路独有的
        //    ① coeffBits：CtCtMul 要的噪声预算（实测 2 bit vs 26 bit 的那笔账）
        //    ② minScaleK：打分要和 τ 个字段的桥残差可比（K > τ·ones）
        //    两者见 A2_COEFF_BITS / A2_MIN_SCALE_K 的注释。
        final FusePirFourStep fp = FusePirFourStep.setup(db, ringDim, d, lBf, rhoH, seed0,
            A2_COEFF_BITS, A2_MIN_SCALE_K);
        // A2 SETUP 2 的 m（实算）与 FusePIR 内部那一份对账：两处不一致 ⇒ B_pay 与网格跟着错
        int m = 1;
        for (List<FusePirFourStep.Value> vs : db.values) {
            m = Math.max(m, vs.size());
        }
        if (m != fp.mCount()) {
            throw new IllegalStateException("A2 SETUP 2 的 m 对账失败：本类实算 " + m
                + "，而 FusePIR.Setup 内部算出 " + fp.mCount()
                + " —— 两者不一致会让 pp_C 的 m 与载荷布局的 m 不是同一个数");
        }
        // A2 SETUP 12：pp ← (pp_F, ℓ_BF, G, m)。**这一条早就存在，不重造**
        final FusePirParams.Cape ppC =
            fp.pp().extendBloom(lBf, FusePirParams.BloomHashFamily.of(bf), m);
        // 形状对账：pp_C 加宽出来的 B_pay 必须与服务端表宽、与 FusePIR 的 bPay 一致
        if (ppC.bPay() != fp.bPay() || fp.stS().bPay() != fp.bPay()) {
            throw new IllegalStateException("B_pay 三方不一致：pp_C=" + ppC.bPay()
                + "、FusePIR=" + fp.bPay() + "、st^F_S 表宽=" + fp.stS().bPay());
        }
        return new Setup(fp, ppC, bf, m);
    }

    // ==================================================================
    //  A2 QUERY 1-3
    // ==================================================================

    /** {@code A2 QUERY 1-3} 的产物：{@code (q_anc, st^anc_C)} + {@code q^BF} + {@code τ}。 */
    public static final class Query {
        private final FusePirFourStep.Query qAnc;
        private final Ciphertext qBF;
        private final int tau;
        private final long tauRing;
        private final List<String> keywords;

        Query(FusePirFourStep.Query qAnc, Ciphertext qBF, int tau, long tauRing,
              List<String> keywords) {
            this.qAnc = qAnc;
            this.qBF = qBF;
            this.tau = tau;
            this.tauRing = tauRing;
            this.keywords = keywords;
        }

        /** {@code q_anc}（A2 QUERY 1 的第一个返回值）。 */
        public FusePirFourStep.Query qAnc() {
            return qAnc;
        }

        /** {@code st^anc_C}（A2 QUERY 1 的第二个返回值；A2 DECODE 2 要用）。 */
        public FusePirClientState stC() {
            return qAnc.stC();
        }

        /**
         * {@code ct^BF_qry}（客户端侧、在 {@code tRing} 域里的 {@code Enc(b_qry)}）。
         *
         * <p>⚠️ 调用方不许改它（同 {@code Packed.ct()} 的口径）。它的<b>段外全 0</b>，
         * 而这一点是 {@code Resp.bloomCt} 不掩码的代价所在（见类注释第 3 条）。
         */
        public Ciphertext qBF() {
            return qBF;
        }

        /** {@code τ = ‖b_qry‖₁}（A2 QUERY 3），**字段域**的阈值。 */
        public int tau() {
            return tau;
        }

        /** {@code K·τ} —— **应答通道**的阈值：槽里是 {@code K·field}，所以判定要用它。 */
        public long tauRing() {
            return tauRing;
        }

        /** 本次查询的关键词集合（含锚 {@code K_1}）。 */
        public List<String> keywords() {
            return new ArrayList<>(keywords);
        }

        @Override
        public String toString() {
            return String.format("A2.query(%s；b_qry 支撑 %d 位（∪%s）、τ=%d、τ_ring=%d)",
                qAnc, tau, keywords, tau, tauRing);
        }
    }

    /**
     * <b>{@code A2 QUERY 1-3}</b>：{@code q_anc ← FusePIR.Query(pp_F, sk, K_1)}，
     * {@code b_qry ← BF.Gen(0, {K_1,…,K_Q})}，{@code τ ← ‖b_qry‖₁}。
     *
     * <p>⚠️ {@code queryKeywords} 传的是<b>整个查询关键词集，含锚 {@code K_1}</b>
     * —— A2 QUERY 2 的 {@code BF.Gen(0, Q)} 是对整个 {@code Q} 取的。
     * 只传"锚以外的关键词"会把 {@code τ} 算小，症状是<b>漏判</b>（真命中被拒）。
     *
     * @param anchor 锚关键词 {@code K_1}（必须 ∈ {@code queryKeywords}）
     * @param seed   {@code q^row} 的可复现种子
     */
    public static Query query(Setup s, List<String> queryKeywords, String anchor, long seed) {
        if (s == null || queryKeywords == null || anchor == null) {
            throw new IllegalArgumentException("Setup / queryKeywords / anchor 都不能为 null");
        }
        if (queryKeywords.isEmpty() || !queryKeywords.contains(anchor)) {
            throw new IllegalArgumentException("A2 QUERY 2 的 b_qry 是对整个查询集取的："
                + "queryKeywords 必须非空且包含锚 " + anchor + "，实得 " + queryKeywords);
        }
        // A2 QUERY 1：四个入口之一（签名不动）
        final FusePirFourStep.Query qAnc = s.fusepir().query(anchor, seed);
        // A2 QUERY 2-3：b_qry 与 τ（客户端侧；服务器看不到 b_qry 本身）
        final long[] bits = queryVector(s, queryKeywords);
        final int tau = BfGen.hammingWeight(bits);
        if (tau <= 0) {
            throw new IllegalStateException("τ = ‖b_qry‖₁ = 0：b_qry 全 0 时任何候选都会得 0 分，"
                + "判定失去意义（检查查询关键词集与 ℓ_BF）");
        }
        // 🔴 守卫：判定阈值必须与"τ 个字段的桥残差之和"可比，即 K > τ·ones。
        //    不拦的话症状是**静默误判**：得分 K·τ + ΣE 与 K·(τ−1) + ΣE' 分不开。
        final int ones = weight(s.fusepir().secretBits());
        if ((long) tau * ones >= s.scaleK()) {
            throw new IllegalStateException("τ·ones = " + tau + "×" + ones + " = "
                + ((long) tau * ones) + " ≥ K = " + s.scaleK()
                + "：打分区分不开'命中 τ 位'与'命中 τ−1 位'（桥的残差在 τ 个字段上累加，"
                + "上界 τ·ones/2 已越过 K/2）。请减小查询关键词集、或按需要提高 minScaleK"
                + "（注意 tRing = K·T 必须 < gadget 覆盖 base^digits，见 ringModulusFor）。");
        }
        // ct^BF_qry 在**应答通道的域**里加密（tRing，不是 T、不是 2^32）
        final Ciphertext qBF = BloomScoring.encryptBloomVector(s.fusepir().ring(), bits);
        return new Query(qAnc, qBF, tau, s.scaleK() * tau, new ArrayList<>(queryKeywords));
    }

    /**
     * <b>客户端侧的 {@code b_qry} 槽向量</b>：长度 = 槽数，前 {@code ℓ_BF} 位 = {@code BF.Gen(0, Q)}，
     * <b>其余位为 0</b>。
     *
     * <p>这个"其余位为 0"不是格式问题，是<b>契约</b>：{@code Resp.bloomCt} 不掩码，
     * 段外是真载荷杂质，靠 {@code q^BF} 的 0 把它们乘掉（见类注释第 3 条）。
     *
     * <p>公开出来是为了让探针能构造"破约"的对照向量（段外置 1），
     * 从而把这条契约的代价测出来 —— 而不是只在注释里声明它。
     */
    public static long[] queryVector(Setup s, List<String> keywords) {
        if (keywords == null || keywords.isEmpty()) {
            throw new IllegalArgumentException("查询关键词集不能为空");
        }
        final boolean[] shortBits = s.bf().bits(keywords);
        final int slots = s.slotCount();
        if (shortBits.length > slots) {
            throw new IllegalArgumentException("ℓ_BF = " + shortBits.length + " > 槽数 " + slots
                + "：一条 Bloom 装不进一条密文（BloomScoring 的硬约束）");
        }
        final long[] bits = new long[slots];
        for (int i = 0; i < shortBits.length; i++) {
            bits[i] = shortBits[i] ? 1L : 0L;
        }
        return bits;
    }

    // ==================================================================
    //  A2 ANSWER 2 / 3（+ 4-6 的打分）
    // ==================================================================

    /** {@code A2 ANSWER 2-6} 的服务端产物。 */
    public static final class Answer {
        private final FusePirFourStep.Resp resp;
        private final Ciphertext[] ctValue;
        private final Ciphertext[] ctBloom;
        private final Ciphertext[] ctScore;
        private final int tau;
        private final long tauRing;
        private final long scoreMs;

        Answer(FusePirFourStep.Resp resp, Ciphertext[] ctValue, Ciphertext[] ctBloom,
               Ciphertext[] ctScore, int tau, long tauRing, long scoreMs) {
            this.resp = resp;
            this.ctValue = ctValue;
            this.ctBloom = ctBloom;
            this.ctScore = ctScore;
            this.tau = tau;
            this.tauRing = tauRing;
            this.scoreMs = scoreMs;
        }

        /** {@code resp_anc}（A2 ANSWER 2 的产物；A2 DECODE 2 还要用它）。 */
        public FusePirFourStep.Resp resp() {
            return resp;
        }

        /** 候选个数 = {@code m}。 */
        public int m() {
            return ctValue.length;
        }

        /** A2 ANSWER 3 的 {@code ct_{v_j}}。 */
        public Ciphertext valueCt(int j) {
            return ctValue[j];
        }

        /** A2 ANSWER 3 的 {@code ct^BF_j}（**不掩码**：段外是载荷杂质）。 */
        public Ciphertext bloomCt(int j) {
            return ctBloom[j];
        }

        /** A2 ANSWER 4-6 的 {@code ct_{score,j}}（{\@code tRing} 域里的密文分）。 */
        public Ciphertext scoreCt(int j) {
            return ctScore[j];
        }

        public int tau() {
            return tau;
        }

        public long tauRing() {
            return tauRing;
        }

        /** 打分那一段（ANSWER 4-6）的墙钟毫秒。 */
        public long scoreMs() {
            return scoreMs;
        }

        @Override
        public String toString() {
            return String.format("A2.answer(resp=%s；%d 个候选，每个一条 ct_v + 一条 ct^BF + 一条 "
                + "ct_score；打分 %.0f ms)", resp, m(), (double) scoreMs);
        }
    }

    /**
     * <b>{@code A2 ANSWER 2-6}</b>：{@code resp_anc ← FusePIR.Answer(st_S, q_anc)}
     * → parse 出每候选的 {@code (ct_{v_j}, ct^BF_j)} → 同态打分。
     *
     * <p>打分走 {@link BloomScoring#bloomScoreReaching}（轮数由
     * {@code packed.highestSlot()} 决定），{@code q^BF} 与候选密文、{@code GaloisKeys}
     * 都在 {@code tRing} 的同一个上下文里（硬约束 ①）。
     */
    public static Answer answer(Setup s, Query q) {
        if (s == null || q == null) {
            throw new IllegalArgumentException("Setup 与 Query 都不能为 null");
        }
        final FusePirFourStep fp = s.fusepir();
        final Mpc4jRgsw ring = fp.ring();
        // ---- A2 ANSWER 2 ----
        final FusePirFourStep.Resp resp = fp.answer(q.qAnc());
        // ⚠️ 用 resp 自带的那把旋转密钥：它与 valueCt/bloomCt 内部的旋转是**同一把**，
        //    另建一把会在别的上下文（或别的 sk）上，症状是解密出垃圾而不是抛异常。
        final GaloisKeys gk = resp.galoisKeys();
        final int hi = resp.packed().highestSlot();        // B_pay − 1 = 60
        final int mc = resp.mCount();
        final Ciphertext[] ctValue = new Ciphertext[mc];
        final Ciphertext[] ctBloom = new Ciphertext[mc];
        final Ciphertext[] ctScore = new Ciphertext[mc];
        final long t0 = System.nanoTime();
        for (int j = 0; j < mc; j++) {
            ctValue[j] = resp.valueCt(j);                   // A2 ANSWER 3
            ctBloom[j] = resp.bloomCt(j);                   // A2 ANSWER 3（不掩码）
            // A2 ANSWER 4-6：CtCtMul + 折叠。轮数按最高参与槽取（6 轮），不按论文形状的 5 轮。
            ctScore[j] = BloomScoring.bloomScoreReaching(ring, gk, q.qBF(), ctBloom[j], hi);
        }
        final long ms = (System.nanoTime() - t0) / 1_000_000;
        return new Answer(resp, ctValue, ctBloom, ctScore, q.tau(), q.tauRing(), ms);
    }

    // ==================================================================
    //  A2 DECODE（客户端侧：解密得分 + 判定 + FusePIR.Decode）
    // ==================================================================

    /** {@code A2 DECODE} 的客户端产物。 */
    public static final class Decoded {
        private final long[] anchorValues;
        private final long[][] scoreSlots;
        private final long[] values;
        private final boolean[] accepted;
        private final int tau;
        private final long tauRing;
        private final long scaleK;
        private final long tRing;

        Decoded(long[] anchorValues, long[][] scoreSlots, long[] values, boolean[] accepted,
                int tau, long tauRing, long scaleK, long tRing) {
            this.anchorValues = anchorValues;
            this.scoreSlots = scoreSlots;
            this.values = values;
            this.accepted = accepted;
            this.tau = tau;
            this.tauRing = tauRing;
            this.scaleK = scaleK;
            this.tRing = tRing;
        }

        /** 得分的字段域读数 {@code round(s_j/K)}（判定就是它 == τ）—— 判据要拿它比，不要拿槽值比。 */
        public long fieldScore(int j) {
            return CapeA2Wire.nearestFieldScore(scoreSlots[j][0], scaleK, tRing);
        }

        /** {@code A2 DECODE 2} 的 {@code V_{K_1}}；{@code null} 表示论文的 {@code ⊥}（指纹不符）。 */
        public long[] anchorValues() {
            return anchorValues == null ? null : anchorValues.clone();
        }

        /** {@code ⊥}？（指纹不符 —— 说明 {@code st^anc_C} 与 {@code resp_anc} 不是同一次查询） */
        public boolean isBottom() {
            return anchorValues == null;
        }

        /**
         * 第 {@code j} 个候选的<b>密文分</b>（槽值，<b>未除 K</b>）。
         *
         * <p>⚠️ 折叠后只有<b>前若干个槽</b>是完整和（窗口 {@code [0, 2^rounds)}）—— 客户端读的是
         * <b>槽 0</b>，这与 {@code BloomScoring.decodeScore} 的口径一致。
         * {@link #scoreSlots(int)} 把整条槽数组交出来，好让探针看到"别的槽不是这个数"是正常的。
         */
        public long score(int j) {
            return scoreSlots[j][0];
        }

        /** 第 {@code j} 个候选的整条得分密文的槽值（诊断用）。 */
        public long[] scoreSlots(int j) {
            return scoreSlots[j].clone();
        }

        /** 第 {@code j} 个候选的<b>值</b>（字段域，已除 K）。 */
        public long value(int j) {
            return values[j];
        }

        /** 判定：{@code s_j == K·τ}（A2 DECODE 9）。 */
        public boolean accepted(int j) {
            return accepted[j];
        }

        public int acceptedCount() {
            int n = 0;
            for (boolean b : accepted) {
                if (b) {
                    n++;
                }
            }
            return n;
        }

        /** {@code V̂_{K_1}} —— 通过 Bloom 判定的值集合（A2 DECODE 9 的收尾）。 */
        public long[] acceptedValues() {
            long[] out = new long[acceptedCount()];
            int k = 0;
            for (int j = 0; j < accepted.length; j++) {
                if (accepted[j]) {
                    out[k++] = values[j];
                }
            }
            return out;
        }

        public int tau() {
            return tau;
        }

        public long tauRing() {
            return tauRing;
        }

        @Override
        public String toString() {
            return String.format("A2.decoded(V_{K_1}=%s、槽值得分=%s、字段域得分=%s、τ_ring=%d、收下 %s)",
                anchorValues == null ? "⊥" : Arrays.toString(anchorValues),
                Arrays.toString(scoreVector()), Arrays.toString(fieldScoreVector()),
                tauRing, Arrays.toString(acceptedValues()));
        }

        /** 每个候选得分的字段域读数（{@code round(s_j/K)}）—— 判定的实际依据。 */
        public long[] fieldScoreVector() {
            final long[] s = new long[scoreSlots.length];
            for (int j = 0; j < s.length; j++) {
                s[j] = fieldScore(j);
            }
            return s;
        }

        private long[] scoreVector() {
            long[] s = new long[scoreSlots.length];
            for (int j = 0; j < s.length; j++) {
                s[j] = scoreSlots[j][0];
            }
            return s;
        }
    }

    /**
     * <b>{@code A2 DECODE}</b>：把每候选的得分与值解出来、按 {@code s_j == K·τ} 判定，
     * 再调 {@code FusePIR.Decode} 拿 {@code V_{K_1}}（A2 DECODE 2）。
     *
     * <p>⚠️ 得分读的是<b>槽值</b>（{@code Resp.decodeSlots}），值是<b>字段域</b>
     * （{@code Resp.decodeFields}）—— 两个入口混用就是"差 K 倍"的静默错（MAP §31.3）。
     */
    public static Decoded decode(Setup s, Query q, Answer a) {
        if (s == null || q == null || a == null) {
            throw new IllegalArgumentException("Setup / Query / Answer 都不能为 null");
        }
        final FusePirFourStep.Resp resp = a.resp();
        final int mc = a.m();
        final long[][] scoreSlots = new long[mc][];
        final long[] values = new long[mc];
        final boolean[] accepted = new boolean[mc];
        final long scaleK = resp.scale();
        final long tRing = s.tRing();
        for (int j = 0; j < mc; j++) {
            scoreSlots[j] = resp.decodeSlots(a.scoreCt(j));          // 槽值：**未除 K**
            values[j] = resp.decodeFields(a.valueCt(j))[0];          // 字段域：已除 K
            // 判定 = 把得分四舍五入到 K 的倍数再看是不是 τ（等价于 |s − K·τ| < K/2）。
            // 论文写的是 s_j == τ 的**等号**；本实现的打分带着桥的残差（MAP §24.4/§26.3），
            // 上界 τ·ones/2 只要 < K/2（query() 的守卫保证了这一点），取整后判定就是对的，
            // 而"等号"本身**不成立** —— 实测 K=17 时命中候选得 172 而 K·τ = 170。
            accepted[j] = nearestFieldScore(scoreSlots[j][0], scaleK, tRing) == a.tau();
        }
        // ---- A2 DECODE 2 ----
        final long[] anchor = s.fusepir().decode(q.stC(), resp);
        return new Decoded(anchor, scoreSlots, values, accepted, a.tau(), a.tauRing(), scaleK,
            tRing);
    }

    /**
     * <b>{@code score/K} 四舍五入</b> —— 得分的"字段域读数"。判定就是它 == τ。
     *
     * <p>为什么不是等号：{@code s_j = K·(匹配位数) + Σ E_i}，{@code |Σ E_i| ≤ τ·ones/2}
     * （桥的逐分量舍入残差，MAP §24.4/§26.3）。只要 {@code τ·ones/2 < K/2}，
     * 取整就把残差整个吸收掉，而 {@code s_j == K·τ} 这个等号是**不成立**的
     * （实测：{@code K=17} 时命中候选得 172、{@code K·τ = 170}）。
     * ⇒ 判定规则是"<b>把得分四舍五入到 K 的倍数</b>"，不是"得分等于 K·τ"。
     *
     * <p>⚠️ 必须先取<b>中心代表</b>：得分是小量，但内积为 0 的候选会因残差变成负数，
     * 槽里就是 {@code tRing − |E|} —— 不折叠回负数就会读出一个巨大的"得分"。
     */
    public static long nearestFieldScore(long score, long scaleK, long tRing) {
        if (scaleK < 1) {
            throw new IllegalArgumentException("精度倍率 K 必须 ≥ 1，实得 " + scaleK);
        }
        long c = Math.floorMod(score, tRing);
        if (c > tRing / 2) {
            c -= tRing;
        }
        return Math.floorDiv(c + scaleK / 2, scaleK);
    }

    // ==================================================================
    //  小工具
    // ==================================================================

    /**
     * {@code ⟨b_qry, b_v⟩} 的<b>明文参照</b>（诊断用）：把 {@code q} 的 0/1 与候选的 Bloom 位
     * 在 {@code [0, ℓ_BF)} 上做内积。
     *
     * <p>同态打分必须等于 {@code K ×} 这个数（本实现无噪声）。有它才能把
     * "打分算错了"与"载荷/参数不同源"分开。
     *
     * @param qBits 客户端查询向量（长度 = 槽数）
     * @param bloom 该候选的 {@code b_v}（长度 {@code ℓ_BF}，0/1）
     */
    public static long plainInner(long[] qBits, long[] bloom) {
        if (qBits == null || bloom == null) {
            throw new IllegalArgumentException("qBits 与 bloom 都不能为 null");
        }
        if (bloom.length > qBits.length) {
            throw new IllegalArgumentException("b_v 有 " + bloom.length + " 位，超过查询向量的槽数 "
                + qBits.length);
        }
        long s = 0;
        for (int i = 0; i < bloom.length; i++) {
            s += qBits[i] * bloom[i];
        }
        return s;
    }

    /**
     * 把 {@code K·field} 的槽值转回字段域（一次舍入）—— <b>只给诊断用</b>：
     * 正式路径请走 {@code Resp.decodeFields}（那里是同一份实现）。
     */
    public static long slotToField(Setup s, long slot) {
        return com.fusepir.fusepir.FusePirSetup.divideScale(new long[]{slot}, s.scaleK(),
            s.tRing(), s.tField())[0];
    }

    /** {@code s_L} 的汉明重量 {@code ones}（{@code K > τ·ones} 那条守卫要用）。 */
    private static int weight(int[] bits) {
        int w = 0;
        for (int b : bits) {
            w += (b != 0) ? 1 : 0;
        }
        return w;
    }
}
