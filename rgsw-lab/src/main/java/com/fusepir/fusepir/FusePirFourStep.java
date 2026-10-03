package com.fusepir.fusepir;

import com.fusepir.bff.BffEncode;
import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.bff.BffSetupBundle;
import com.fusepir.bloom.BloomScoring;
import com.fusepir.prim.BlindRotateOps;
import com.fusepir.prim.CtOps;
import com.fusepir.prim.LweRlweConversion;
import com.fusepir.prim.Mpc4jRgsw;
import com.fusepir.prim.RingPack;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;

import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * <b>FusePIR（Algorithm 1）的四步，做成 CAPE（Algorithm 2）能直接调用的四个入口。</b>
 *
 * <h2>CAPE 到底调用 FusePIR 的哪几处（逐字来自 A2 原文）</h2>
 * <pre>
 * A2 SETUP  11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE).
 * A2 QUERY   1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1).
 * A2 ANSWER  2: resp_anc ← FusePIR.Answer(st_S, q_anc).
 * A2 ANSWER  3: Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc.     ← ★决定 resp 的类型
 * A2 DECODE  2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc).
 * </pre>
 * ⇒ <b>四处</b>：{@link #setup} / {@link #query} / {@link #answer} / {@link #decode}。
 * <p>另有两条**已经存在**的接线（本类不重复造）：{@code pp_C ← pp_F.extendBloom(ℓ_BF, G, m)}
 * （A2 SETUP 12，见 {@link FusePirParams#extendBloom}）与
 * {@code st^F_S} 直接用作 {@code st_S}（A2 SETUP 13）。
 *
 * <h2>⚠️ 两处必须按原文读、否则签名会错</h2>
 * <ol>
 *   <li><b>A2 SETUP 11 传进去的是 {@code DB^CAPE}，不是原始 DB。</b>
 *       A2 SETUP 3-10 先把每个值配对成 {@code (v_{i,j}, b_{v_{i,j}})}，<b>然后</b>才调
 *       {@code FusePIR.Setup}。所以 A1 SETUP 6 的 {@code y} 在 CAPE 这条路上是
 *       {@code fp ‖ m_i ‖ v ‖ b_v ‖ …} ⇒ {@code perValue = 1 + ℓ_BF}、{@code B_pay = 61}。
 *       ⇒ {@link #setup} 因此把"每个值带不带 Bloom 段"做成参数：{@code lBf = 0} 就是纯 A1
 *       （A1 的 {@code y} 没有 Bloom，见 MAP §9.1），{@code lBf = 18} 就是 CAPE 那条路。</li>
 *   <li><b>A2 ANSWER 3 要"parse 出每个候选的 {@code (ct_{v_j}, ct^BF_j)}"。</b>
 *       槽位域 {@code Pack} 把它们全放进<b>一条</b>密文的槽里 ⇒ "parse" 落成
 *       <b>槽对齐</b>：{@link Resp#valueCt(int)} / {@link Resp#bloomCt(int)} 用
 *       {@code CtRotate} 把第 {@code j} 个候选的值 / Bloom 段转到槽 0 起
 *       （见 {@link Resp} 的类注释，那里也写清了它的**验证程度**）。</li>
 * </ol>
 *
 * <h2>本类在整条链上的位置</h2>
 * 每一步都只调用<b>已验证过的具名原语</b>，自己不含任何新算术：
 * {@code BffSetupBundle/BffEncode}（A1 SETUP）、{@code FusePirSetup}（布局与装配）、
 * {@code FusePirQuery.split}/{@code BlindRotateOps.lweEncryptIndex}（A1 QUERY）、
 * {@code CtOps.ctPtMul}/{@code BlindRotateOps.blindRotateRow}/{@code CtOps.sampleExtract0}
 * （A1 ANSWER 5-7）、{@code FusePirPackSlot.sumRns}/{@code packFromRns}（A1 ANSWER 11/13）、
 * {@code FusePirPackSlot.decodePayload}/{@code FusePirSetup.parsePayload}（A1 DECODE）。
 *
 * <h3>⚠️ 三处与论文的差异（据实登记）</h3>
 * ① {@code q^row} 无噪声（用户决定 + 规范 §2.3 一致、与论文 §2.5 不一致，MAP §25.3(2)）；
 * ② {@code q^col} 走 D3 读法（C 条标量密文）；
 * ③ 秘密是铺开后的（{@code supp(s_R) ⊆ [0,d)}）—— 这使 {@code Pack} 的密钥是 {@code d} 行，
 * 但 {@code d} <b>由安全级别定</b>（{@code d=16} 是玩具，MAP §26.4）。
 */
public final class FusePirFourStep {

    // ⚠️ 这里**不能**再有 `private FusePirFourStep() {}` 这种空构造器：
    //    本类的实例字段全是 `final`，只有那个 14 参的私有构造器给它们赋值，
    //    空构造器会让 javac 报 "variable m might not be initialized"（实测踩到）。
    //    没有公开构造器 + 类是 final ⇒ 外部本来就造不出实例。

    /** A1 的三条 BFF 路径（{@code for a = 0 to 2}）。 */
    public static final int K_PATHS = 3;

    /** 明文模数：必须**可批处理**，否则 {@code Pack} 无从谈起（MAP §18.2）。 */
    public static final long T = FusePirParams.NATIVE_PLAINTEXT_MODULUS;

    /** gadget 参数（{@code 256^3 = 2^24 > t}，且 {@code base ≤ t/2}）。 */
    public static final int GADGET_BASE = 1 << 8;
    public static final int GADGET_DIGITS = 3;

    // ==================================================================
    //  输入：DB^CAPE —— 每个关键词一组 (值, 该值的 Bloom 段)
    // ==================================================================

    /**
     * {@code DB^CAPE} 里的一条值：{@code (v, b_v)}。
     *
     * <p>纯 FusePIR（A1）时 {@code bloom} 传 {@code null}；CAPE（A2 SETUP 3-10）时
     * 传 {@code b_v ∈ {0,1}^{ℓ_BF}}。
     */
    public static final class Value {
        public final long id;
        public final long[] bloom;

        public Value(long id, long[] bloom) {
            this.id = id;
            this.bloom = bloom;
        }
    }

    /** 数据库：关键词 → 值集合（顺序即 {@code V_{K_i}} 的顺序）。 */
    public static final class Db {
        public final List<String> keywords;
        public final List<List<Value>> values;

        public Db(List<String> keywords, List<List<Value>> values) {
            if (keywords.size() != values.size()) {
                throw new IllegalArgumentException("关键词数与值集合数不一致");
            }
            this.keywords = keywords;
            this.values = values;
        }

        /** 造一个合成库（探针用）：每个关键词 1..mCount 个值，值互不相同。 */
        public static Db synthetic(int nkw, int mCount, boolean withBloom, int lBf, long seed) {
            Random rnd = new Random(seed);
            List<String> ks = new ArrayList<>(nkw);
            List<List<Value>> vs = new ArrayList<>(nkw);
            long next = 1000L;
            for (int i = 0; i < nkw; i++) {
                ks.add(String.format("kw-%04d", i));
                int cnt = 1 + rnd.nextInt(mCount);
                List<Value> list = new ArrayList<>(cnt);
                for (int j = 0; j < cnt; j++) {
                    long[] b = null;
                    if (withBloom) {
                        b = new long[lBf];
                        for (int q = 0; q < lBf; q++) {
                            b[q] = rnd.nextInt(2);
                        }
                    }
                    list.add(new Value(next++, b));
                }
                vs.add(list);
            }
            return new Db(ks, vs);
        }
    }

    // ==================================================================
    //  ① FusePIR.Setup  →  (pp_F, st^F_S, sk)
    // ==================================================================

    /**
     * {@code A2 SETUP 11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE)}。
     *
     * <p>返回三样：公开参数 {@link #pp()}、服务端状态 {@link #stS()}、
     * 密钥束 {@link #sk()}（客户端持有；{@code bk}/{@code swk} 是公开求值材料）。
     *
     * @param db      {@code DB^CAPE}
     * @param ringDim 环维度 {@code N}
     * @param d       LWE 维数（⚠️ 由安全级别定；{@code 16} 只是玩具）
     * @param lBf     {@code ℓ_BF}；<b>0 = 纯 FusePIR</b>（A1 的 {@code y} 无 Bloom 段），
     *                {@code >0 = CAPE 那条路}（每个值多 {@code ℓ_BF} 个槽）
     * @param rhoH    A3 SETUP 8 的位置函数种子 {@code ρ_H}（<b>也是 BFF.Encode 首次尝试的种子</b>）。
     *                ⚠️ 重试成功时真正生效的是 {@code ρ_H + attempt − 1}，
     *                所以 {@code pp} 用的是 {@code tab.seed} 而不是这里的 {@code rhoH}；
     *                两者靠 {@link #requirePositionsMatch} 建库时就对上。
     * @param seed0   可复现种子（只用于 {@code D} 的随机化与 {@code q^row} 的派生）
     */
    public static FusePirFourStep setup(Db db, int ringDim, int d, int lBf,
                                        long rhoH, long seed0) {
        return setup(db, ringDim, d, lBf, rhoH, seed0, null, 0L);
    }

    /**
     * <b>同 {@link #setup(Db, int, int, int, long, long)}，但可以指定应答通道的系数模数位宽。</b>
     *
     * <p>签名没有改动（原 6 参版本原样保留、行为不变）—— 这只是一个**加法式重载**，
     * 因为 A2（CAPE）那条路对噪声预算的要求与纯 A1 不同，见下。
     *
     * <h3>为什么 A2 需要更大的 {@code q}（2026-10-15 实测，{@code probe/ScoreMulDomainTest}）</h3>
     * A2 ANSWER 4 要在 {@code resp_anc} 上做一次 {@code CtCtMul(q^BF, ct^BF_j)}。
     * 本移植里 {@code CoeffModulus.bfvDefault(4096)} 的<b>工作模数只有 72 bit</b>，
     * 于是：
     * <pre>
     *   新加密密文的噪声预算         = 72 − log2(tRing) ≈ 51 bit
     *   RingPack 产物的噪声预算      = 实测 2 bit   （它被那些稠密槽位选择子吃掉约 49 bit）
     *   一次 CtCtMul 的代价          ≈ 26 bit       （实测 51 → 25）
     *   ⇒ 2 − 26 &lt; 0 ⇒ 得分解出来是均匀随机值（实测 4096/4096 个槽对不上）
     * </pre>
     * 把工作模数放宽到 {@code 3×60 = 120 bit}（{@code SecLevelType.NONE}）之后实测：
     * <b>Pack 产物 50 bit、{@code q^BF × Pack} 逐槽<b>完全正确</b>（0/4096 不符）</b>。
     *
     * <p>⚠️ <b>这不是安全参数</b>：{@code 3×60} 在 N=4096 下不满足 HomomorphicEncryption.org
     * 的 128-bit 标准（SEAL 默认会拒，所以走 {@code SecLevelType.NONE}）。
     * 它是<b>玩具参数</b>，只为让 A2 那一步在预算上成立；论文自己的参数集比这大得多。
     * 纯 A1 的调用方传 {@code null} 即可拿到原来的（合规）参数。
     *
     * @param coeffBits 每个 RNS 素数的位宽（例 {@code {60,60,60}}）；
     *                  {@code null} = {@code bfvDefault(n)}（128-bit 安全口径，原来的行为）
     * @param minScaleK 精度倍率 K 的下界 —— CAPE 的打分要它 <b>&gt; τ·ones</b>（见
     *                  {@link #ringModulusFor(int, int, int, int, long)}）；{@code ≤ 0} = 用原来的启发式
     */
    public static FusePirFourStep setup(Db db, int ringDim, int d, int lBf,
                                        long rhoH, long seed0, int[] coeffBits, long minScaleK) {
        if (db == null || db.keywords.size() < 2) {
            throw new IllegalArgumentException("DB 至少要 2 个关键词");
        }
        if (d <= 0 || d > ringDim) {
            throw new IllegalArgumentException("d 必须在 [1, N] 内（C9：d ≤ N），实得 " + d);
        }
        final int nkw = db.keywords.size();
        int mCount = 1;
        for (List<Value> vs : db.values) {
            mCount = Math.max(mCount, vs.size());
        }

        // A1 SETUP 2：L_BFF ← |D|（BffHash.allocate 里）；m ← max_i |V_{K_i}|（上面算的）
        final int fpSlots = FusePirSetup.fpSlots(T);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);
        if (bPay > ringDim) {
            throw new IllegalArgumentException("B_pay = " + bPay + " > N = " + ringDim
                + "：Pack 要求一个字段占一个槽（MAP §18.5）");
        }

        // ---------- A1 SETUP 1：BFF.Setup(n,3) ----------
        final BffSetupBundle.SetupResult su =
            BffSetupBundle.setup(nkw, K_PATHS, bPay, ringDim, 0, false, rhoH);
        final BffHash.BffParams bp = BffHash.allocate(nkw, K_PATHS);

        // ---------- A1 SETUP 3 的密钥 + 应答通道的明文模数（必须在装配 y 之前定下）----------
        // 顺序说明：`scaleK` 要参与 `assemblePayload`，而它由 s_L 的汉明重量决定，
        // 所以"生成 s_L / 定 tRing"必须挪到装配 y 之前（原先 s_L 在 Encode 之后生成）。
        final Random rnd = new Random(seed0);
        final int[] sL = new int[d];
        for (int i = 0; i < d; i++) {
            sL[i] = rnd.nextInt(2);
        }
        // 🔴 "q_R→Z_t 桥的缩放残差"的唯一解法（残差 ≤ ones/2，与明文模数无关，换大 t 没用）：
        //    字段写成 K·field 存放，K > ones 时"除以 K 一次舍入"就把残差整个吸收掉。
        //    布局仍按字段域 T 算 ⇒ B_pay / 值域 / limb 宽度全不变。
        int ones = 0;
        for (int v : sL) {
            ones += (v != 0) ? 1 : 0;
        }
        final long tRing = ringModulusFor(ringDim, ones, GADGET_BASE, GADGET_DIGITS, minScaleK);
        final long scaleK = tRing / T;

        // ---------- A1 SETUP 6：pad 到 m + 装配 y_{K_i} ----------
        final long[][] payload = new long[nkw][];
        for (int i = 0; i < nkw; i++) {
            final List<Value> vs = db.values.get(i);
            final long[] fpD = BffSetup.fpDigits(db.keywords.get(i), T, fpSlots);
            final long[] ids = new long[vs.size()];
            final long[][] blooms = (lBf > 0) ? new long[vs.size()][] : null;
            for (int j = 0; j < vs.size(); j++) {
                ids[j] = vs.get(j).id;
                if (blooms != null) {
                    blooms[j] = vs.get(j).bloom;
                    if (blooms[j] == null || blooms[j].length != lBf) {
                        throw new IllegalArgumentException("第 " + i + " 个关键词第 " + j
                            + " 个值的 Bloom 段缺失或长度不是 ℓ_BF = " + lBf);
                    }
                }
            }
            final long[] padded = FusePirSetup.padValuesToM(ids, mCount);
            final long[][] paddedBloom = (lBf > 0)
                ? Arrays.copyOf(blooms, mCount) : null;
            if (lBf > 0 && paddedBloom[mCount - 1] == null) {
                for (int j = vs.size(); j < mCount; j++) {
                    paddedBloom[j] = new long[lBf];               // 补位：值 0 + 全 0 的 Bloom
                }
            }
            payload[i] = FusePirSetup.assemblePayload(fpD, vs.size(), padded, paddedBloom,
                lBf, scaleK);
        }

        // ---------- A1 SETUP 8：BFF.Encode ----------
        // ⚠️ 喂给 Encode 的"首个尝试种子"必须是 ρ_H 本身（A3 SETUP 8：ρ_H 是位置函数的种子），
        //    **不是** seed0。这里曾经传 `seed0`，而下面 pp 用的是 `rhoH` —— 两个常量差 1，
        //    结果建表用的一套位置、查询用另一套（实测 16/16 个关键词的位置都不同）。
        final List<String> kws = db.keywords;
        final BffEncode.PositionFn posFn = seed -> BffHash.positions(kws, seed, bp, K_PATHS);
        // ⚠️ 表的算术模数必须是**载荷所在的域**：载荷已按 `scaleK` 放大，所以这里传 tRing。
        //    传 T 会让 D 的回填减法（`floorMod(d[p][b] - d[h][b], t)`）把 K·field 取模毁掉
        //    —— 症状是相位全错、但每一步单独看都对（本轮实测过）。
        final BffEncode.Table tab =
            BffEncode.encode(nkw, K_PATHS, su.layout, posFn, rhoH, payload, tRing, 64, rnd);
        if (tab == null) {
            throw new IllegalStateException("BFF.Encode 在 64 次尝试内失败 ⇒ L_BFF 相对 n 太小");
        }

        // ---------- A1 SETUP 3（续）：s_R 由 s_L 铺开，上下文用**应答通道**的明文模数 ----------
        // ⚠️ coeffBits（系数模数位宽）只影响噪声预算，不影响任何布局/算术：
        //    tRing / K / B_pay / 值槽 / 段起点全部由 (ringDim, ones, gadget, T) 决定，与 q 无关。
        final Mpc4jRgsw ref = new Mpc4jRgsw(ringDim, tRing, 0, 1 << 16, null, coeffBits);
        final SecretKey skR = LweRlweConversion.liftLweSecretToRlwe(ref, sL);
        final Mpc4jRgsw m = new Mpc4jRgsw(ringDim, tRing, 0, 1 << 16, skR, coeffBits);

        // ---------- A1 SETUP 7（公开求值材料）----------
        final Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(sL[i]);
        }
        final Ciphertext[][] swk = RingPack.switchingKey(m, sL, GADGET_BASE, GADGET_DIGITS);

        // ---------- A1 SETUP 17-18：pp 与 st_S ----------
        // 🔴 ρ_H 必须取**真正建表用的那个种子**（`tab.seed = ρ_H + attempt − 1`），
        //    不能取调用方传进来的 `rhoH`：重试成功时两者不相等。
        //
        //    为什么这一行是本轮 ANSWER 6 那个"0/61"的根因：
        //    `BffHash.positions(K, seed, hg)` 的 `seed` 与 `hg.rhoH` 是**同一个量，
        //    而该函数不校验它们一致**（`BffHash.java:490` 的原文警告）⇒
        //    建表侧一个种子、查询侧另一个种子时，**类型合法、编译通过、运行期完全静默**，
        //    症状是"查一个库里明明存在的关键词，却读到了别的格子"。
        //    实测（`probe/FusePirAnswerBisectTest`）：16/16 个关键词的位置都不同，
        //    建表那套 u_a 的明文和 = 真值 61/61，pp 那套 = 0/61。
        final BffHash.HashGen hTable = bp.hashGen(tab.seed);
        final FusePirParams pp = new FusePirParams(
            FusePirParams.bffPositions(tab.seed, hTable),
            FusePirParams.fingerprint(),
            su.layout, d, T, m.q);
        // 守卫而不是注释（同 §18.6 的 `requireGadgetCovers`：写在旁边的守卫没人用就等于没有）。
        // 它把"两边同源"变成**建库时就会抛**的不变量，而不是等 61 个字段全错再回来查。
        requirePositionsMatch(pp, db.keywords, tab.pos);
        final FusePirServerState stS = FusePirServerState.ofGrid(tab.d, pp, bPay);

        return new FusePirFourStep(m, sL, bk, swk, pp, stS, lBf, mCount, bPay,
            tab.attempts, db, payload, tab.d, tab.pos, tRing, scaleK);
    }

    /**
     * <b>选应答通道的明文模数 {@code tRing}</b>：{@code tRing ≡ 1 (mod 2N)}、素数、
     * 且 {@code tRing = K·T}（{@code K > ones} 有硬性要求，见 {@link FusePirSetup#assemblePayload}）。
     *
     * <h3>为什么 {@code K > ones} 是硬要求</h3>
     * {@code rnsToT} 逐分量缩放的残差上界是 {@code ones/2}（{@code ones} = 私钥汉明重量），
     * 与明文模数无关。字段存成 {@code K·field} 之后，客户端除以 K 一次舍入即可精确恢复
     * ⟺ {@code ones/2 < K/2} ⟺ {@code K > ones}。
     *
     * <h3>为什么还要卡上界</h3>
     * {@code RingPack.pack} 的 gadget 必须覆盖整个明文域（{@code base^digits ≥ tRing}，
     * §18.6 的 {@code requireGadgetCovers}）⇒ 这里取 {@code tRing < base^digits}
     * 作为搜索上界；找不到就<b>抛</b>并说明该改哪个旋钮（本组参数下 {@code 2^8·2^3 = 2^24}）。
     *
     * <p>⚠️ <b>这条路只因为"不要噪声"才免费</b>：BFV 的噪声随 {@code t} 增长，
     * 有噪声时换大 {@code t} 会吃掉噪声余量。本实现 Δ=1、无噪声（MAP §21 的工程决定），
     * 所以精度可以这样买。
     */
    public static long ringModulusFor(int n, int ones, int gadgetBase, int gadgetDigits) {
        return ringModulusFor(n, ones, gadgetBase, gadgetDigits, 0L);
    }

    /**
     * <b>同 {@link #ringModulusFor(int, int, int, int)}，但允许指定精度倍率的下界 {@code K ≥ minScaleK}。</b>
     *
     * <h3>为什么 CAPE（A2）需要更大的 K —— 这条是本轮实测出来的，与"读一个字段"不同</h3>
     * {@code K > ones} 只保证<b>单个字段</b>读得准（{@code |E| ≤ ones/2 < K/2} ⇒ 除以 K 一次舍入就精确）。
     * 但 CAPE 的判定是<b>同态内积</b>：{@code s_j = ⟨q, b_v⟩ = K·(匹配位数) + Σ_{i∈supp(q)} E_i}，
     * 残差要<b>在 τ = ‖b_qry‖₁ 个字段上加起来</b>：
     * {@code |Σ E_i| ≤ τ·ones/2}。而判定要区分"匹配 τ 位"与"匹配 τ−1 位"（相差 K）
     * ⇒ 必须 <b>{@code K > τ·ones}</b>。
     *
     * <p>实测（{@code probe/CapeA2WireTest}，{@code τ=10、ones=11、K=17}）：
     * 命中候选得分 {@code 172}，而 {@code K·τ = 170} —— 差 2 就已经越过 {@code K/2 = 8.5}
     * 的那条线（{@code 2 < 8.5}，但 τ=10 时残差按 {@code τ·ones/2 = 55} 计就不能保证）。
     * 本组取 {@code minScaleK = 128 > 10×11 = 110}，于是
     * {@code |Σ E_i| ≤ 55 < K/2 = 64} ⇒ 判定"四舍五入到 K 的倍数"<b>可证</b>。
     *
     * <p>⚠️ 上界 {@code τ·ones/2} 是保守的（残差是若干独立均匀量的和，实测 |ΣE| 只有个位数），
     * 但判定规则必须能<b>保证</b>正确，所以按上界取 K。
     *
     * @param minScaleK 精度倍率的下界；{@code ≤ 0} 表示用内部那条启发式（{@code ones + ones/2 + 2}）
     */
    public static long ringModulusFor(int n, int ones, int gadgetBase, int gadgetDigits,
                                      long minScaleK) {
        if (ones < 0) {
            throw new IllegalArgumentException("ones 不能为负");
        }
        final long kMin = Math.max(minScaleK,
            (long) ones + Math.max(2L, ones / 2L) + 2L);      // 余量
        final BigInteger cap = BigInteger.valueOf(gadgetBase).pow(gadgetDigits);
        final BigInteger twoN = BigInteger.valueOf(2L * n);
        final BigInteger lower = BigInteger.valueOf(T).multiply(BigInteger.valueOf(kMin));
        if (lower.compareTo(cap) >= 0) {
            throw new IllegalStateException("要装下 K = " + kMin + " 倍精度需要明文模数 ≥ " + lower
                + "，但 gadget base=" + gadgetBase + " digits=" + gadgetDigits
                + " 只覆盖到 " + cap + "。加大 gadget（例如 base=2^16, digits=2 覆盖 2^32），"
                + "或减小 d（残差上界随私钥汉明重量增长）。");
        }
        BigInteger j = lower.divide(twoN);
        for (int i = 0; i < 200000; i++) {
            final BigInteger cand = twoN.multiply(j.add(BigInteger.valueOf(i)))
                .add(BigInteger.ONE);
            if (cand.compareTo(cap) >= 0) {
                break;
            }
            if (cand.isProbablePrime(48)) {
                return cand.longValueExact();
            }
        }
        throw new IllegalStateException("在 [" + lower + ", " + cap + ") 里找不到 ≡1 (mod " + twoN
            + ") 的素数明文模数 —— 换更大的 gadget 覆盖范围再试");
    }

    /**
     * <b>守卫：建表用的位置函数必须与 {@code pp} 发布的位置函数逐位同源。</b>
     *
     * <h3>它在防什么（这是一个已经真实发生过的 bug，不是假设）</h3>
     * {@code BffHash.positions(K, seed, hg)} 的 {@code seed} 与 {@code hg.rhoH}
     * 是<b>同一个量，而该函数不校验二者一致</b>（{@code BffHash.java:490}）。
     * 于是"建表用 A 号、查询用 B 号"在<b>类型上完全合法、运行期完全静默</b>：
     * 不抛、不报错，只是每个关键词都读到<b>别的格子</b>。
     *
     * <p>本仓库实测到的那一次（2026-10-15）：{@code BffEncode.encode} 的首次尝试种子
     * 是 {@code seed0}，而 {@code pp} 用的是调用方传的 {@code rhoH}，两者差 1
     * ⇒ 16/16 个关键词的位置都不同 ⇒ ANSWER 5/6 <b>每一步都对</b>，
     * 但 P4.0 的相位判据 0/61（因为"真值"与"相位"来自两套格子）。
     *
     * <p>⚠️ <b>覆盖率不是 100%</b>：它只抓"位置函数不同源"这一种。
     * 若两套种子<b>恰好</b>给出相同位置（可能，概率极低），本守卫放行 —— 而那时
     * 协议本身也是对的，所以这不是盲区。
     *
     * @param pp       待检查的公开参数（其 {@code h()} 是查询侧会用的那一套）
     * @param keywords 关键词表（顺序必须与 {@code pos} 一致）
     * @param pos      建表侧<u>实际使用</u>的位置表 {@code [nkw][k]}
     * @throws IllegalStateException 任何一个关键词的两套位置不同
     */
    public static void requirePositionsMatch(FusePirParams pp, List<String> keywords, int[][] pos) {
        if (pp == null || keywords == null || pos == null) {
            throw new IllegalArgumentException("pp / keywords / pos 都不能为 null");
        }
        if (keywords.size() != pos.length) {
            throw new IllegalArgumentException("关键词有 " + keywords.size() + " 个，"
                + "但位置表有 " + pos.length + " 行 —— 两者不是同一张表");
        }
        for (int i = 0; i < keywords.size(); i++) {
            final int[] querySide = pp.h().positions(keywords.get(i));
            if (!java.util.Arrays.equals(querySide, pos[i])) {
                throw new IllegalStateException("建表位置与 pp 的位置函数【不同源】：关键词 #" + i
                    + "（" + keywords.get(i) + "）建表用 " + java.util.Arrays.toString(pos[i])
                    + "，而 pp.h() 给出 " + java.util.Arrays.toString(querySide)
                    + "。⚠️ 这种不一致不报错、只是每个关键词都读到别的格子 —— "
                    + "ρ_H 必须取『真正建表用的那个种子』（BffEncode.Table#seed），"
                    + "不能取调用方传进来的那个（重试成功时两者不等）。");
            }
        }
    }

    // ==================================================================
    //  状态载体（Setup 的产物）
    // ==================================================================
    private final Mpc4jRgsw m;
    private final int[] sL;
    private final Mpc4jRgsw.Rgsw[] bk;
    private final Ciphertext[][] swk;
    private final FusePirParams pp;
    private final FusePirServerState stS;
    private final int lBf;
    private final int mCount;
    private final int bPay;
    private final int encodeAttempts;
    private final Db db;
    private final long[][] payload;
    private final long[][] dArr;
    private final int[][] pos;
    /** 应答通道的明文模数（= K·T，带精度倍率；见 {@link #ringModulusFor}）。 */
    private final long tRing;
    /** 精度倍率 K = tRing / T（字段在表里存成 K·field）。 */
    private final long scaleK;

    private FusePirFourStep(Mpc4jRgsw m, int[] sL, Mpc4jRgsw.Rgsw[] bk, Ciphertext[][] swk,
                            FusePirParams pp, FusePirServerState stS, int lBf, int mCount,
                            int bPay, int encodeAttempts, Db db, long[][] payload,
                            long[][] dArr, int[][] pos, long tRing, long scaleK) {
        this.m = m;
        this.sL = sL;
        this.bk = bk;
        this.swk = swk;
        this.pp = pp;
        this.stS = stS;
        this.lBf = lBf;
        this.mCount = mCount;
        this.bPay = bPay;
        this.encodeAttempts = encodeAttempts;
        this.db = db;
        this.payload = payload;
        this.dArr = dArr;
        this.pos = pos;
        this.tRing = tRing;
        this.scaleK = scaleK;
    }

    /** 应答通道的明文模数（{@code K·T}）。**不是**字段域模数 {@link #T}。 */
    public long ringModulus() {
        return tRing;
    }

    /** 精度倍率 {@code K}：表里存的是 {@code K·field}，客户端解码时除以它。 */
    public long scale() {
        return scaleK;
    }

    /** {@code pp_F}（A2 SETUP 11 的第一个返回值）。{@code pp_C = pp_F.extendBloom(…)}。 */
    public FusePirParams pp() {
        return pp;
    }

    /** {@code st^F_S}（A2 SETUP 11 的第二个返回值；A2 SETUP 13 直接用它当 {@code st_S}）。 */
    public FusePirServerState stS() {
        return stS;
    }

    /** 环上下文（客户端与服务端共享；服务端只用它的求值器）。 */
    public Mpc4jRgsw ring() {
        return m;
    }

    /** LWE 私钥 {@code s_L}（客户端私有）。 */
    public int[] secretBits() {
        return sL.clone();
    }

    public int bPay() {
        return bPay;
    }

    public int lBf() {
        return lBf;
    }

    public int mCount() {
        return mCount;
    }

    public int encodeAttempts() {
        return encodeAttempts;
    }

    public Db db() {
        return db;
    }

    /** 真值载荷（仅探针比对）。 */
    public long[][] payloadTruth() {
        return payload;
    }

    /** BFF 数组 {@code D}（仅探针做明文侧重构核对）。 */
    public long[][] bffArray() {
        return dArr;
    }

    /** 每个关键词的 {@code k} 个位置（仅探针核对）。 */
    public int[][] positions() {
        return pos;
    }

    @Override
    public String toString() {
        return String.format("FusePIR(pp_F: n=%d, N=%d, d=%d, B_pay=%d, lBf=%d, R=%d, C=%d, "
                + "L_BFF=%d, encode 尝试 %d 次；Pack 交换密钥 %d 条)",
            db.keywords.size(), m.n, sL.length, bPay, lBf, pp.layout().r, pp.layout().c,
            pp.layout().lBff, encodeAttempts, (long) sL.length * GADGET_DIGITS);
    }

    // ==================================================================
    //  ② FusePIR.Query  →  (q_anc, st^anc_C)
    // ==================================================================

    /** {@code A2 QUERY 1} 的产物：{@code q_anc} 与 {@code st^anc_C}。 */
    public static final class Query {
        private final Ciphertext[][] qCol;
        private final long[][][] qRow;
        private final long[] colIdx;
        private final long[] rowIdx;
        private final FusePirClientState stC;

        Query(Ciphertext[][] qCol, long[][][] qRow, long[] colIdx, long[] rowIdx,
              FusePirClientState stC) {
            this.qCol = qCol;
            this.qRow = qRow;
            this.colIdx = colIdx;
            this.rowIdx = rowIdx;
            this.stC = stC;
        }

        /** {@code q_anc} 的列选择子：{@code [k][C]}，每条 {@code Enc(e_{c_a}[c])}。 */
        public Ciphertext[][] qCol() {
            return qCol;
        }

        /** {@code q_anc} 的行选择子：{@code [k][2]} 的 {@code (a, β)}。 */
        public long[][][] qRow() {
            return qRow;
        }

        public long[] colIdx() {
            return colIdx.clone();
        }

        public long[] rowIdx() {
            return rowIdx.clone();
        }

        /** {@code st^anc_C}（客户端私有；A2 DECODE 2 要用它）。 */
        public FusePirClientState stC() {
            return stC;
        }

        @Override
        public String toString() {
            return String.format("q_anc(col=%s, row=%s, q^col %d 条)",
                Arrays.toString(colIdx), Arrays.toString(rowIdx),
                (long) qCol.length * qCol[0].length);
        }
    }

    /**
     * {@code A2 QUERY 1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1)}。
     *
     * @param anchor 锚关键词 {@code K_1}
     * @param seed   可复现种子（{@code q^row} 的 {@code a} 用它生成）
     */
    public Query query(String anchor, long seed) {
        final int n = m.n;
        final int r = pp.layout().r;
        final int c = pp.layout().c;
        final int[] u = pp.h().positions(anchor);            // A1 QUERY 3: u_a ← h_a(K_1)
        if (u.length != K_PATHS) {
            throw new IllegalStateException("h_a 给了 " + u.length + " 个位置，A1 QUERY 2 要求 "
                + K_PATHS + " 路");
        }
        final Ciphertext[][] qCol = new Ciphertext[K_PATHS][c];
        final long[][][] qRow = new long[K_PATHS][][];
        final long[] colIdx = new long[K_PATHS];
        final long[] rowIdx = new long[K_PATHS];
        final Random rnd = new Random(seed);
        final long[] constant = new long[n];
        for (int a = 0; a < K_PATHS; a++) {
            final FusePirQuery.CellIndex ci = FusePirQuery.split(u[a], r, c);
            colIdx[a] = ci.c();
            rowIdx[a] = ci.r();
            // QUERY 4-5 的 q^col：D3 读法（C 条标量密文）。零分量**不跳过** ——
            // `Enc(0)` 是新鲜随机化的合法密文（相位 0），与"透明密文"不同。
            //
            for (int cc = 0; cc < c; cc++) {
                // A1 QUERY 4-5 的 q^col 单条：交给 AnswerOps 的工厂 ——
                // 它管掉两件事：零要用 `encryptZero()`（不是"加密全零消息"）、以及转 NTT 形态。
                qCol[a][cc] = AnswerOps.constantSelectorNtt(m, (cc == ci.c()) ? 1L : 0L);
            }
            // QUERY 5 的 q^row：β = ⟨a,s_L⟩ + r_a (mod 2N)，Δ=1、无噪声（用户决定，见类注释）
            qRow[a] = BlindRotateOps.lweEncryptIndex(sL, ci.r(), 2 * n, rnd);
        }
        return new Query(qCol, qRow, colIdx, rowIdx, new FusePirClientState(anchor));
    }

    // ==================================================================
    //  ③ FusePIR.Answer  →  resp_anc（含 A2 ANSWER 3 的 parse）
    // ==================================================================

    /**
     * {@code A2 ANSWER 2} 的产物 {@code resp_anc}。
     *
     * <h3>⚠️ 它必须支持 {@code A2 ANSWER 3} 的 parse，所以不是一个裸密文</h3>
     * 槽位域 {@code Pack} 把 {@code B_pay} 个字段放进<b>一条</b>密文的槽
     * （字段 {@code b} → 槽 {@code b}）。CAPE 要的是**每个候选 {@code j}** 的两样东西：
     * <pre>
     *   ct_{v_j}   ← 第 j 个候选的值
     *   ct^BF_j    ← 第 j 个候选的 Bloom 段（ℓ_BF 位）
     * </pre>
     * 于是"parse"落成<b>槽对齐</b>：
     * <ul>
     *   <li>{@link #valueCt(int)} —— 把值所在的槽转到槽 0；</li>
     *   <li>{@link #bloomCt(int)} —— 把该候选的 Bloom 段转到槽 {@code 0..ℓ_BF−1}
     *       （CAPE 的 {@code CtCtMul(q^BF, ·)} + 折叠正是按这个排布），其余槽清零。</li>
     * </ul>
     *
     * <h3>⚠️ 验证程度（不要读成"已验证"）</h3>
     * {@link #valueCt}/{@link #bloomCt} 的**槽对齐**由 {@code CtOps.ctRotateRows} +
     * 掩码明文实现；{@link #decodeSlots} 会把 {@link #bloomCt} 解出来给人看，
     * 探针据此断言"对齐后槽里的位 == 真值位"。**没有验证的是**它接入 CAPE 之后
     * 最终的 {@code ⟨B_qry,b_v⟩ = τ} 判定 —— 那属于 A2，不在本类范围。
     */
    public static final class Resp {
        private final FusePirPackSlot.Packed packed;
        private final int mCount;
        private final int perValue;
        private final int fpSlots;
        private final int lBf;
        private final int n;
        private final long t;
        private final Mpc4jRgsw ring;
        private final GaloisKeys gk;
        /** 应答通道的明文模数（{@code K·T}）与精度倍率 K。 */
        private final long tRing;
        private final long scaleK;

        Resp(FusePirPackSlot.Packed packed, Mpc4jRgsw ring, GaloisKeys gk,
             int mCount, int perValue, int fpSlots, int lBf, long tRing, long scaleK) {
            this.packed = packed;
            this.ring = ring;
            this.gk = gk;
            this.mCount = mCount;
            this.perValue = perValue;
            this.fpSlots = fpSlots;
            this.lBf = lBf;
            this.n = ring.n;
            this.t = ring.t;
            this.tRing = tRing;
            this.scaleK = scaleK;
        }

        /** 精度倍率 {@code K}（槽里存的是 {@code K·field}）。 */
        public long scale() {
            return scaleK;
        }

        /**
         * <b>槽值 → 字段域</b>：{@code field = round(slot / K)}（一次舍入）。
         *
         * <p>槽里是 {@code K·field + E}，{@code |E| ≤ ones/2 < K/2} ⇒ 除完<b>精确</b>。
         * 判"载荷对不对"的断言必须走这一条；{@link #decodeSlots} 给的是<b>未除</b>的槽值，
         * 用它与真值比会差 K 倍（这正是"两个模数混淆"的静默错形态，故做成两个方法）。
         */
        public long[] decodeFields(Ciphertext ct) {
            return FusePirSetup.divideScale(decodeSlots(ct), scaleK, tRing,
                FusePirFourStep.T);
        }

        /** 整条打包密文（A1 ANSWER 13 的 {@code resp}）。 */
        public FusePirPackSlot.Packed packed() {
            return packed;
        }

        public int mCount() {
            return mCount;
        }

        public int lBf() {
            return lBf;
        }

        /** 第 {@code j} 个候选的值在打包密文里的槽号。 */
        public int valueSlot(int j) {
            return FusePirSetup.valueOffset(fpSlots, j, perValue);
        }

        /** 第 {@code j} 个候选的 Bloom 段在打包密文里的起始槽号。 */
        public int bloomSlotBase(int j) {
            return FusePirSetup.bloomOffset(fpSlots, j, perValue);
        }

        /**
         * {@code ct_{v_j}}：把第 {@code j} 个候选的值转到槽 0。
         *
         * @throws IllegalArgumentException {@code j} 越界，或本次 {@code Pack} 没带 Bloom 段
         *                                  （纯 A1，{@code ℓ_BF = 0}）时值槽是连续的，仍可用
         */
        public Ciphertext valueCt(int j) {
            checkJ(j);
            return rotateToSlot0(valueSlot(j));
        }

        /**
         * {@code ct^BF_j}：把第 {@code j} 个候选的 Bloom 段转到槽 {@code [0, ℓ_BF)}，其余清零。
         *
         * <h3>🔴 实测状态（2026-10-15）：<b>本方法目前不成立</b> —— 最后那一步"掩码"会把密文解坏</h3>
         * 两个半边分别是对的、合起来是错的，证据是三条正/负对照（{@code FusePirFourStepTest}
         * 的 P5.0e/P5.0f/P5.0g，都是实测不是推断）：
         * <table border="1">
         *   <tr><th>半边</th><th>判据</th><th>结果</th></tr>
         *   <tr><td><b>旋转</b>（{@link FusePirFourStep#rotateRowsByComposedBits}，"2 的幂组合"）</td>
         *       <td>只旋转、不掩码，槽 {@code [0,ℓ_BF)} 与打包件槽 {@code [base, base+ℓ_BF)} 逐位比</td>
         *       <td>✅ <b>逐位相同</b>；且"转过去再转回"<b>4096/4096</b> 还原 ⇒ 组合是精确的</td></tr>
         *   <tr><td><b>掩码</b>（{@code multiplyPlain} × 槽掩码）</td>
         *       <td>同一条掩码乘在<b>新加密</b>密文上</td>
         *       <td>✅ <b>4096/4096</b> 精确（连乘两次也精确）⇒ 掩码机构本身没错</td></tr>
         *   <tr><td><b>合起来</b></td>
         *       <td>掩码乘<b>打包件</b></td>
         *       <td>❌ <b>0/4096</b>，解出的是均匀随机值 = 解密失败</td></tr>
         * </table>
         *
         * <p><b>为什么</b>（把形态/密钥/parmsId 逐条排掉之后剩下的唯一解释）：
         * 槽掩码在<b>系数域是稠密的</b>（<b>l1 ≈ N·t/2</b>），而本管线的 {@code m.encrypt}
         * 出的是<b>无噪声</b>密文（所以"新加密 × 稠密掩码"连乘两次都精确）；
         * {@code RingPack} 的产物是这条链上<b>第一条真带噪声的密文</b>
         * ⇒ 一次稠密明文乘就把它推过解密边界。
         * <b>已被实测排除的</b>：形态（系数↔NTT 往返 4096/4096）、{@code parmsId}（相同）、
         * {@code size()}（都是 2）、RNS 素数个数（都是 2）、旋转（见上）、明文本身（
         * {@code be.decode} 回 18 个 1）、复用明文。
         * <b>决定性对照</b>：同一打包件 × <b>常数</b>明文 1（系数域稀疏）⇒ <b>4096/4096 还原</b>
         * —— 唯一的变量就是"明文的系数域范数"。
         *
         * <p>⇒ <b>要给 CAPE 一条能用的 {@code ct^BF_j}</b>，至少要改一处（见 MAP §29 的选项）：
         * ① <b>不掩码</b>：只旋转、把"置零"交给 CAPE 的 {@code q^BF}（客户端侧本来就在段外是 0，
         *    于是 {@code CtCtMul} 的积在段外也是 0，折叠不会带上杂质）；
         * ② 在 <b>{@code Pack} 之前</b>按候选分别掩码（那时数据还是理想 {@code Z_t} 样本，无噪声）；
         * ③ 压低 {@code RingPack} 产物的噪声（找出它噪声的真正来处）。
         *
         * <p>⚠️ <b>不要把上面的"0/4096"读成"§4.2 没做成"</b>：§4.2 只要求把旋转换成 2 的幂组合
         * （{@code galoisKeysFor} 只有 {@code {0}∪{1,2,4,…}}，{@code 24/43} 会抛
         * {@code Galois key not present}），那一条<b>已经做成并逐位验过</b>。
         * 卡住的是它后面那一步，而那是另一个问题。
         *
         * @throws IllegalStateException {@code ℓ_BF = 0}（纯 A1 没有 Bloom 段）
         */
        public Ciphertext bloomCt(int j) {
            checkJ(j);
            if (lBf <= 0) {
                throw new IllegalStateException("ℓ_BF = 0：纯 FusePIR 的载荷没有 Bloom 段"
                    + "（A1 的 y 只有 fp‖m_i‖v…，见 MAP §9.1）");
            }
            if (lBf > n / 2) {
                throw new IllegalStateException("ℓ_BF = " + lBf + " > N/2 = " + (n / 2)
                    + "：一段 Bloom 要跨行，槽对齐不是一次行内旋转能做的");
            }
            Ciphertext rotated = rotateToSlot0(bloomSlotBase(j));
            // ⚠️ 不掩码 —— 见本方法 javadoc：掩码乘在打包件上会把密文解坏（实测 0/4096），
            //    而"段外置零"这件事由 CAPE 的 q^BF 在槽域免费完成（它在段外本来就是 0）。
            return rotated;
        }

        /**
         * <b>【诊断】整条打包密文的槽值</b>（A2 ANSWER 3 的"槽对齐"判据要拿它当基准）。
         *
         * <p>为什么对齐判据<b>不能</b>直接拿真值比：{@code Pack} 的输入是过了
         * {@code q_R→Z_t} 桥的样本，带着 ±(≤ #ones/2) 的缩放残差（MAP §24.4/§26.3）
         * ⇒ 槽里的值本身就可能差 1。那属于**桥**的问题。
         * 而"{@code valueCt(j)} 的槽 0 是不是 §{@code valueSlot(j)} 那一格"
         * 是**旋转对齐**的问题 —— 两者必须分开判，否则残差会把对齐的结论一起带偏。
         */
        public long[] packedSlots() {
            return decodeSlots(packed.ct());
        }

        /**
         * <b>【诊断】系数形态的整条打包密文</b> —— 让探针能自己驱动
         * {@link FusePirFourStep#rotateRowsByComposedBits}（P5.0c/P5.0d 的正负对照要用）。
         */
        public Ciphertext packedCoeff() {
            final Ciphertext out = new Ciphertext();
            out.copyFrom(packed.ct());
            if (out.isNttForm()) {
                ring.evaluator.transformFromNttInplace(out);
            }
            return out;
        }

        /** <b>【诊断】旋转密钥</b>（与 {@link #valueCt}/{@link #bloomCt} 用的是同一把）。 */
        public GaloisKeys galoisKeys() {
            return gk;
        }

        /** 调试/探针用：把一条密文解成槽值。 */
        public long[] decodeSlots(Ciphertext ct) {
            Ciphertext copy = new Ciphertext();
            copy.copyFrom(ct);
            if (copy.isNttForm()) {
                ring.evaluator.transformFromNttInplace(copy);
            }
            Plaintext pt = new Plaintext(n);
            ring.decryptor.decrypt(copy, pt);
            long[] out = new long[new BatchEncoder(ring.context).slotCount()];
            new BatchEncoder(ring.context).decode(pt, out);
            return out;
        }

        private Ciphertext rotateToSlot0(int slot) {
            Ciphertext src = new Ciphertext();
            src.copyFrom(packed.ct());
            if (src.isNttForm()) {
                ring.evaluator.transformFromNttInplace(src);
            }
            if (slot == 0) {
                return src;
            }
            final int half = n / 2;
            if (slot >= half) {
                throw new IllegalStateException("槽 " + slot + " ≥ N/2 = " + half
                    + "：行内旋转够不到（SEAL 的两行布局）");
            }
            return rotateRowsByComposedBits(ring, src, slot, gk);
        }

        private void checkJ(int j) {
            if (j < 0 || j >= mCount) {
                throw new IllegalArgumentException("候选下标 " + j + " 不在 [0, m = "
                    + mCount + ") 内");
            }
        }

        /**
         * 只保留槽 {@code [0, keep)}、其余清零。
         *
         * <p><b>为什么必须两步（NTT + 逐槽乘）</b>：{@code multiplyPlain} 只有在**双方都是 NTT 形态**
         * 时才是"逐槽相乘"；一方是系数形态时会退化成**多项式乘**——不报错、结果全错。
         * 这正是 {@code RingPack.slotSelector} 注释里登记过的那个坑。
         *
         * <h3>🔴 但它只对"无噪声的密文"成立（2026-10-15 实测）</h3>
         * 这条掩码明文在<b>系数域是稠密的</b>（l1 ≈ N·t/2），所以它把密文的噪声<b>放大约 2^{log2(N)+log2(t/2)}</b>。
         * 本管线的 {@code m.encrypt} 出的是<b>无噪声</b>密文 ⇒ 连乘两次都精确；
         * 而 {@code RingPack} 的产物带着这条链上唯一的噪声 ⇒ <b>一次就过界</b>，解出来是均匀随机值。
         * 实测：新加密 4096/4096（连乘两次仍 4096/4096）；打包件 0/4096，而同一打包件 × <b>常数</b>明文
         * 4096/4096 还原 —— 唯一变量就是明文的系数域范数。
         * 详见 {@link #bloomCt} 与本文件 {@code Resp.bloomCt} 的注释（MAP §29）。
         */
        private static Ciphertext maskFirstSlots(Mpc4jRgsw m, Ciphertext ct, int keep) {
            final BatchEncoder be = new BatchEncoder(m.context);
            final long[] mask = new long[be.slotCount()];
            for (int i = 0; i < keep; i++) {
                mask[i] = 1;
            }
            final Plaintext pt = new Plaintext();
            be.encode(mask, pt);
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
            final Ciphertext src = new Ciphertext();
            src.copyFrom(ct);
            if (!src.isNttForm()) {
                m.evaluator.transformToNttInplace(src);
            }
            final Ciphertext out = new Ciphertext();
            m.evaluator.multiplyPlain(src, pt, out);
            if (out.isNttForm()) {
                m.evaluator.transformFromNttInplace(out);
            }
            return out;
        }

        @Override
        public String toString() {
            return String.format("resp_anc(%s；m=%d, ℓ_BF=%d, 值槽=%d.., Bloom 槽=%d..)",
                packed, mCount, lBf, valueSlot(0), lBf > 0 ? bloomSlotBase(0) : -1);
        }
    }

    /**
     * <b>{@code CtRotateRows(ct, slot)} —— 用「2 的幂组合」实现任意行内步长</b>（§4.2；A2 ANSWER 3 的 parse）。
     *
     * <h3>为什么不能把 {@code slot} 直接传给 {@code rotateRowsInplace}</h3>
     * 旋转密钥是 {@code BloomScoring.galoisKeysFor(m)} 建的，它<b>只包含</b>
     * {@code {0} ∪ {1, 2, 4, …, N/4}}（{@code galoisKeysFor:286}）。
     * 而槽号根本不是 2 的幂 —— 本组参数下值槽 {@code 4}、Bloom 段起点 {@code 5 / 24 / 43}。
     * 直接 {@code rotateRowsInplace(ct, 24, gk)} 会抛
     * {@code IllegalArgumentException: Galois key not present}
     * （<b>实测：P5 就崩在这里，整个探针在 A2 ANSWER 3 那一步中断</b>）。
     *
     * <h3>为什么"组合"是对的（不是近似）</h3>
     * 行内旋转对步长<b>可加</b>：复合 {@code 2^{i_1}, 2^{i_2}, …} 之后，槽 {@code i} 的载荷
     * 来自槽 {@code i + Σ2^{i_j}}。所以把 {@code slot} 按二进制拆开逐位旋转，
     * 结果与"一次旋转 {@code slot}"<b>逐槽相同</b>。本实现无噪声 ⇒ 这一步是<b>精确</b>的。
     * 代价只是 {@code popcount(slot)} 次旋转而不是 1 次：本组参数下最多 4 次（{@code 43 = 32+8+2+1}）。
     *
     * <p>⚠️ <b>另一条路是"多造密钥"</b>：把 {@code galoisKeysFor} 扩成含全部步长
     * （{@code N/2} 条密钥 ⇒ 密钥体积 ×{@code N/2}）。本实现选<b>组合</b>这条 ——
     * 它不增加任何密钥材料，也不改 {@code BloomScoring} 那套已经稳定的步长集合。
     *
     * <p>⚠️ <b>调用方注意形态</b>：{@code ctRotateRows} 走的是 {@code rotateRowsInplace}，
     * 输入输出都保持 {@code ct} 原来的形态（系数形态进、系数形态出）。
     *
     * @param slot 目标步长，必须 {@code 0 ≤ slot < N/2}（SEAL 两行布局下 {@code rotateRows} 的上限）
     * @throws IllegalArgumentException 越界，或需要的某个 {@code 2^i} 超出了密钥集合的 {@code N/4}
     */
    public static Ciphertext rotateRowsByComposedBits(Mpc4jRgsw m, Ciphertext src,
                                                      int slot, GaloisKeys gk) {
        if (slot < 0 || slot >= m.n / 2) {
            throw new IllegalArgumentException("行内步长 " + slot + " 不在 [0, N/2 = "
                + (m.n / 2) + ") 内");
        }
        // 守卫：用到的每一个 2 的幂都必须真的在密钥集合里。
        // 不守卫的话，越界要到 SEAL 内部才炸，而那时的报错离"我这里少建了一条密钥"很远
        //（§18.6 的 `requireGadgetCovers` 是同一条纪律）。
        for (int i = 0; i < 31; i++) {
            final int bit = 1 << i;
            if (bit > slot) {
                break;
            }
            if ((slot & bit) != 0 && bit > m.n / 4) {
                throw new IllegalArgumentException("步长 " + slot + " 需要 2^" + i + " = " + bit
                    + " 的旋转密钥，但 galoisKeysFor 只建到 N/4 = " + (m.n / 4)
                    + "（行内旋转的上限是 N/4，再大要走列旋转）");
            }
        }
        Ciphertext out = src;
        for (int i = 0; i < 31; i++) {
            final int bit = 1 << i;
            if (bit > slot) {
                break;
            }
            if ((slot & bit) != 0) {
                out = CtOps.ctRotateRows(m, out, bit, gk);
            }
        }
        return out;
    }

    /**
     * <b>{@code A1 ANSWER 5-11}</b>：三路列选择 + 盲旋转 + SampleExtract_0 + 相加，
     * 交出 {@code ct_{pay,b}} —— 每条是<b>截到前 {@code d} 项</b>的 LWE 样本
     * {@code [β, a_0 … a_{d−1}]}（第 0 项是 {@code β}）。
     *
     * <p>为什么把它与 ANSWER 13 分开：这样 {@code Pack} 的输入可以**单独验**——
     * 用 {@code β − Σ_{k<d} a_k·s_L[k] mod t} 直接读出每个字段的相位，
     * 判据与 Pack 完全无关（MAP §27 的 P4.0 就是这么做的）。
     */
    public long[][][] answerSamples(Query q) {
        final long[][][] rns = answerRnsSamples(q);
        final long[][][] out = new long[bPay][][];
        for (int b = 0; b < bPay; b++) {
            final long[] ztD = AnswerOps.toTruncatedZLwe(m, rns[b], sL.length);
            out[b] = new long[][]{Arrays.copyOfRange(ztD, 1, ztD.length), new long[]{ztD[0]}};
        }
        return out;
    }

    /**
     * <b>【诊断】ANSWER 5-11 在 {@code Z_{q_R}} 上的样本（三路相加后，</b><u>未</u>过 {@code q_R→Z_t} 桥<b>）</b>。
     *
     * <p>形状 {@code [B_pay][workingPrimeCount][N+1]}，{@code [b][pi][0] = β}、
     * {@code [b][pi][1+k] = a_k}。
     *
     * <h3>为什么要有它</h3>
     * {@code rnsToT} 把 {@code β} 与 {@code N} 个 {@code a_k} <b>各自</b>舍入到 {@code Z_t}，
     * 相位里因此多出 {@code Σ_k δ_k·s_k}（上界 {@code #ones/2}）—— 那是<b>桥的固有残差</b>
     * （MAP §24.4 / §26.3），不是 ANSWER 的算术错。
     * 拿它 + {@link AnswerOps#phaseOfRns} 就能把相位<b>先在 {@code Z_{q_R}} 里算完再舍入一次</b>，
     * 于是"相位 == 真值"在这一层是<b>精确</b>判据；而交付层带着残差，要用带容差的那条。
     * <b>两条分开报，才不会把桥的残差误报成盲旋转错。</b>
     * ⚠️ 与 {@link #answerSamples} 是<b>同一次计算</b>的两半：{@code answerSamples} 就是在它的结果上
     * 逐字段过一遍 {@code toTruncatedZLwe}，所以两者<b>不可能漂移</b>。
     */
    public long[][][] answerRnsSamples(Query q) {
        if (q == null) {
            throw new IllegalArgumentException("q_anc 不能为 null（A2 ANSWER 2）");
        }
        final long[][][] out = new long[bPay][][];
        for (int b = 0; b < bPay; b++) {
            final long[][][] perPath = new long[K_PATHS][][];
            for (int a = 0; a < K_PATHS; a++) {
                // ---- A1 ANSWER 5 / 6 / 7 ----
                // 三步都走 AnswerOps 的接口：形态转换、零密文、RNS 形状这些事都收在那里，
                // 本方法不再自己转形态（§27.4 那三处错就是自己转出来的）。
                final Ciphertext acc = AnswerOps.columnSelect(m, q.qCol()[a], stS, b);
                final Ciphertext accPrime = AnswerOps.blindRotateStep(
                    m, bk, acc, q.qRow()[a][0], q.qRow()[a][1][0]);
                perPath[a] = AnswerOps.sampleExtract0Rns(m, accPrime);
            }
            // ---- A1 ANSWER 11：三路相加（在 RNS 分量上逐素数求和，缩放之前）----
            out[b] = AnswerOps.sumPaths(m, perPath);
        }
        return out;
    }

    /**
     * {@code A2 ANSWER 2: resp_anc ← FusePIR.Answer(st_S, q_anc)}。
     *
     * <p>⚠️ <b>签名里只有 {@code st_S} 与 {@code q_anc}，没有秘密</b> —— 与论文一致：
     * 服务端拿不到 {@code r_a}/{@code c_a}/{@code K_1}。本实现把 {@code bk}/{@code swk}
     * 当作**公开求值材料**从 {@code this} 取（它们由客户端在 SETUP 时发布）。
     */
    public Resp answer(Query q) {
        final long[][][] samples = answerSamples(q);
        final long[][] as = new long[bPay][];
        final long[] bs = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            as[b] = samples[b][0];
            bs[b] = samples[b][1][0];
        }
        // ---- A1 ANSWER 13：resp ← Pack({ct_{pay,b}}) ----
        // ⚠️ 槽位布局按**字段域** T 算（不是按 m.t = tRing）：见 FusePirPackSlot.pack 的重载注释。
        final BatchEncoder be = new BatchEncoder(m.context);
        final FusePirPackSlot.Packed packed = FusePirPackSlot.pack(
            m, be, swk, GADGET_BASE, GADGET_DIGITS, mCount, lBf, T, as, bs);
        return new Resp(packed, m, BloomScoring.galoisKeysFor(m),
            mCount, FusePirSetup.perValue(lBf), FusePirSetup.fpSlots(T), lBf, tRing, scaleK);
    }

    // ==================================================================
    //  ④ FusePIR.Decode  →  V_{K_1} 或 ⊥
    // ==================================================================

    /**
     * {@code A2 DECODE 2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc)}。
     *
     * @return 值集合；{@code null} 表示论文的 {@code ⊥}（指纹不符）
     */
    public long[] decode(FusePirClientState anchorStC, Resp resp) {
        if (anchorStC == null || resp == null) {
            throw new IllegalArgumentException("st^anc_C 与 resp_anc 都不能为 null");
        }
        final BatchEncoder be = new BatchEncoder(m.context);
        // DECODE 2-4：y[β] ← Dec_{s_R}(ct_{pay,β})
        final long[] yScaled = FusePirPackSlot.decodePayload(m, be, resp.packed(), bPay);
        // DECODE 4.5：**槽值 → 字段域** —— 除以精度倍率 K（一次舍入）。
        //   🔴 这一步就是"q_R→Z_t 桥的缩放残差"的消除点：槽里是 K·field + E、|E| ≤ ones/2，
        //   而 K > ones ⇒ 舍入后 E 被完全吸收、field 精确。**不先做这一步就解析会误判**：
        //   m_i 的校验（0 ≤ m_i ≤ m）拿到 K·m_i 会直接判越界。
        final long[] y = FusePirSetup.divideScale(yScaled, scaleK, tRing, T);
        // DECODE 5：Recover (f, m_K, v_1…v_m) ← y
        final FusePirSetup.Payload p = FusePirSetup.parsePayload(y, mCount, T, lBf);
        // DECODE 6-7：f ≠ fp(K) ⇒ ⊥
        final long want = BffSetup.fpFromDigits(p.fpDigits, 0, p.fpDigits.length, T);
        final long got = BffSetup.fp(anchorStC.keyword());
        if (want != got) {
            return null;
        }
        // DECODE 9：return {v_1, …, v_{m_K}}
        final long[] out = new long[p.count];
        System.arraycopy(p.values, 0, out, 0, p.count);
        return out;
    }
}
