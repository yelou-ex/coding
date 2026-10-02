package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.RelinKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>CAPE Algorithm 2 的 ANSWER 8 那一段</b>：把「锚检索结果」变成
 * <b>每候选一组的 {@code ({ct_v_j}, ct_score,j)}</b>，并且分数是<b>同态算出来的密文</b>。
 *
 * <h3>为什么需要这个类（规划书里的 G1 / G2）</h3>
 * 补的是规划书 §1.2 的两个定义性缺口：
 * <ul>
 *   <li><b>G1 加密 Bloom 打分</b>：{@link BloomScoring} 早就写好并自检 5/5，但
 *       <b>主路径一次都没调用</b>（实测搜不到调用点）；</li>
 *   <li><b>G2 每候选项的密文分数</b>：论文 A2 ANSWER 8 是
 *       {@code resp ← ({ct_{v_j}, ct_score,j})}，而旧实现返回的是<b>扁平 long[]</b>，
 *       根本没有"按候选分组"的中间表示。</li>
 * </ul>
 *
 * <h3>论文依据（逐行）</h3>
 * <pre>
 *   A2 ANSWER 4: ct_score,j ← CtCtMul(q_BF, ct_{B^F_j})
 *   A2 ANSWER 6: for r = 0 .. log2(l_BF)-1 do
 *   A2 ANSWER 7:     ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
 *   A2 ANSWER 8: resp ← ({ct_{v_j}, ct_score,j})_j
 *   A2 DECODE 8: s_j ← Dec(ct_score,j)
 *   A2 DECODE 9: if s_j = tau then R ← R ∪ {v_j}
 * </pre>
 *
 * <h3>明文模数的选型（实测，见 {@link CapeScoreChannelProbe}）</h3>
 * 本类<b>必须</b>跑在 {@code t = 65537} 上，这不是随意挑的：
 * <table border="1">
 *   <tr><th>t</th><th>{@code new BatchEncoder(context)}</th><th>能否做槽位域打分</th></tr>
 *   <tr><td>{@code 2^32}（库里的 {@code plainModulus}，native 路径在用）</td>
 *       <td>抛 {@code IllegalArgumentException: encryption parameters are not valid for batching}</td>
 *       <td>否</td></tr>
 *   <tr><td>{@code 65537}（{@code 1 + 2^16}，素数）</td><td>OK，{@code slotCount() = N}</td>
 *       <td>可以</td></tr>
 * </table>
 * 根因：{@code BatchEncoder} 需要 {@code t ≡ 1 (mod 2N)} 才能取 2N 次单位根，而
 * {@code 2^32} 连素数都不是。所以 <b>「打分信道的 t」与「native 盲旋转信道的 t」在本实现里
 * 是两个值</b> —— 这是一处必须在报告里显式声明的形态差，不是实现疏忽。
 *
 * <h3>本类不做的那一步（论文的 {@code Pack}）</h3>
 * 论文里 {@code ct_{B^F_j}} 是<b>从检索结果里取出来的密文</b>，由服务端同态
 * {@code Pack} 成槽位密文。本实现里它走的是：
 * <pre>
 *   nativeCapeAnswer 解出 payload（单进程回环：JVM 同时持 sk 与跑查询）
 *     → 按候选 j 取出它的 l_BF 位 Bloom 段
 *     → 编成槽位密文（服务端侧密封）
 * </pre>
 * 也就是 <b>D2 那条已知偏差仍在</b>（候选 Bloom 密文不是"检索出来的那条密文"），
 * 真障碍是 {@code SampleExtract} 输出在 {@code q_R} 上、喂 {@code RingPack} 要缩放到
 * {@code Z_t}，而该缩放引入约 sqrt(N) 的舍入噪声（{@code SampleToPackLink} 实测 |残差| 最大约 30，
 * 是 Bloom 位值 1 的十几到几十倍）⇒ 「{@code s_j == tau} 精确判定」在那条路上不成立。
 * 本类<b>不掩盖</b>这一点。
 *
 * <p>本类取代不了 {@link BloomScoring}（打分算子在那里），也不改它 —— 它只负责
 * 「分组 + 打包 + 调用打分 + 组装响应」这一段编排。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeBloomScore 8192 18}
 */
public final class CapeBloomScore {

    /** 打分信道的明文模数。<b>不能是 2^32</b>（BatchEncoder 要求 {@code t ≡ 1 mod 2N}）。 */
    public static final long SCORE_T = 65537L;

    /** 一个候选的完整应答：{@code (ct_v_j, ct_score,j)}（论文 A2 ANSWER 8）。 */
    public static final class Candidate {
        /** 候选值 id，取自载荷第 {@code 2+j(1+l_BF)} 项。 */
        public final int valueId;
        /** 该候选的 Bloom 段（{@code b_{v_j}}），自载荷取出。**不是**密文，见类注释。 */
        public final long[] bloomBits;
        /**
         * 候选 Bloom 段的<b>槽位密文</b> {@code ct_{B^F_j}}。
         *
         * <p>它是服务端侧资产，不进响应；进响应的是 {@link #ctScore}。
         */
        public final Ciphertext ctBloom;
        /** <b>密文分数</b> {@code ct_score,j}：每个槽都等于 {@code s_j = <b_qry, b_{v_j}>}。 */
        public final Ciphertext ctScore;

        Candidate(int valueId, long[] bloomBits, Ciphertext ctBloom, Ciphertext ctScore) {
            this.valueId = valueId;
            this.bloomBits = bloomBits;
            this.ctBloom = ctBloom;
            this.ctScore = ctScore;
        }
    }

    /** 一次打分的全部产物（服务端侧资产 + 发回客户端的那部分）。 */
    public static final class Result {
        /** 逐候选的 {@code ({ct_v_j}, ct_score,j)}（论文 A2 ANSWER 8 的那个 {@code resp}）。 */
        public final List<Candidate> candidates;
        /**
         * 服务端自检用：每条 {@code ct_score,j} 解密出来的槽值。
         *
         * <p><b>绝不进响应。</b>单进程回环里服务器顺手能看到它（用来证明"密文分数 ==
         * 明文参考值"），但真两方部署里这个值只有客户端解得出。
         */
        public final long[] plainScoreSlots;
        /** 打分总耗时（ms），用于把"接进主路径后多花多少"变成可报的数。 */
        public final long scoreMs;

        Result(List<Candidate> candidates, long[] plainScoreSlots, long scoreMs) {
            this.candidates = candidates;
            this.plainScoreSlots = plainScoreSlots;
            this.scoreMs = scoreMs;
        }
    }

    /** 打分信道的服务端状态：上下文 + 重线性化密钥 + Galois 密钥。SETUP 时建一次。 */
    public static final class Scorer {
        public final Mpc4jRgsw m;
        public final RelinKeys relinKeys;
        public final GaloisKeys galoisKeys;
        public final int slots;
        public final long setupMs;

        private Scorer(int n, SecretKey sharedSk) {
            long t0 = System.nanoTime();
            // gadget 基取 2^16：它只影响 Mpc4jRgsw 自己的 RGSW 路径，本类不用那条路径，
            // 但 Mpc4jRgsw 的构造函数要求给一个值（且 base < 2t 必须成立）。
            this.m = new Mpc4jRgsw(n, SCORE_T, 0, 1 << 16, sharedSk);
            this.relinKeys = m.relinKeys();
            this.galoisKeys = BloomScoring.galoisKeysFor(m);
            this.slots = new BatchEncoder(m.context).slotCount();
            this.setupMs = (System.nanoTime() - t0) / 1_000_000;
        }

        /**
         * 本信道的密钥。**客户端与服务端必须是同一把**，否则 {@code ct_score} 解出来是垃圾
         * （不报错，只是数值离谱 —— 实测解成 26921 而不是 0..ℓ_BF）。
         *
         * <p>单进程回环里"同一个密钥持有者"就是这么表达的：见 {@link #setup(int, SecretKey)}。
         */
        public SecretKey secretKey() {
            return m.sk;
        }
    }

    private CapeBloomScore() {
    }

    /**
     * SETUP：建打分信道的密钥材料（重线性化 + Galois）——<b>新生成一把密钥</b>。
     *
     * <p><b>为什么 Galois 密钥是必需的</b>：论文 A2 ANSWER 6-7 的折叠就是
     * {@code CtCtAdd(ct_score, CtRotate(ct_score, 2^r))}，而 {@code CtRotate} 走
     * {@code Evaluator.rotateRowsInplace}，没有 Galois 密钥会直接抛。
     * 实测 N=8192 的一次性成本见 {@link CapeScoreChannelProbe}。
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
     * 把一个 Bloom 向量铺进槽位（客户端侧，{@code q_BF ← RLWE.Enc(b_qry)}）。
     *
     * <p><b>下标约定（本类的核心约定，实证见自检第 1 节）</b>：
     * 第 {@code i} 位放进<b>槽位 i</b>。这一条把"下标"和"槽位"钉成同一个东西，
     * 于是 {@code Sum_i b_qry[i]*b_v[i]} 就是逐槽相乘再折叠的结果。
     *
     * @param bits 长度必须不超过 {@code slots}（{@code l_BF <= N/2} 的硬约束从这里进来）
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

    /** {@code q_BF ← RLWE.Enc_{s_R}(b_qry)}，槽位形式。 */
    public static Ciphertext encryptQuery(Scorer sc, boolean[] bQry) {
        return BloomScoring.encryptBloomVector(sc.m, toSlotVector(bQry, sc.slots));
    }

    /**
     * <b>客户端侧</b>：{@code q_BF} 加密并序列化成线上字节（D12 那条明文口的关闭方式）。
     *
     * <p>返回值直接放进 {@code /api/query} 请求体的 {@code qBFBytes} 字段。
     * 实测长度见 {@link CapeScorerWire}（N=8192 时 211 KB）。
     */
    public static long[] encryptQueryWire(Scorer sc, boolean[] bQry) {
        return CapeScorerWire.serialize(
            BloomScoring.encryptBloomVector(sc.m, toSlotVector(bQry, sc.slots)));
    }

    /**
     * 把不超过 {@code slots} 长的小数组补零铺进槽位。
     *
     * <p>补零是<b>正确性所必需</b>的（不是省事）：它保证下标 {@code >= l_BF} 的槽贡献为 0，
     * 于是 {@code foldAllSlots} 折全部 N 个槽 == 论文只折 {@code l_BF} 项。
     * 这正是规划书 P0-1「必须先核」那一条的落地方式。
     */
    static long[] padToSlots(long[] bits, int slots) {
        if (bits.length > slots) {
            throw new IllegalArgumentException("l_BF = " + bits.length
                + " 超过槽数 " + slots + "（l_BF <= N/2 是硬约束）");
        }
        long[] out = new long[slots];
        System.arraycopy(bits, 0, out, 0, bits.length);
        return out;
    }

    // ------------------------------------------------------------------
    //  服务端侧：分组 + 打包 + 打分
    // ------------------------------------------------------------------

    /**
     * <b>论文 A2 ANSWER 4-8</b>：对每个候选算密文分数，按候选分组返回。
     *
     * @param sc            打分信道（SETUP 建的）
     * @param qBF           客户端给的 {@code q_BF} 密文
     * @param payload       锚检索解出来的载荷（{@code B_pay} 个系数），布局同
     *                      {@code CapeDemoData.buildTables}：{@code [0]=指纹}、
     *                      {@code [1]=候选数}，之后每个候选占 {@code 1 + l_BF} 项
     *                      （值 id + Bloom 位）
     * @param maxCandidates 最多看几个候选（演示库里是 {@code maxValues}=3）
     * @param lBf           {@code l_BF}。<b>必须与建表时用的一致</b>，否则载荷被切错位。
     */
    public static Result score(Scorer sc, Ciphertext qBF, long[] payload,
                               int maxCandidates, int lBf) {
        long t0 = System.nanoTime();
        if (payload.length < 2) {
            throw new IllegalArgumentException("payload 太短: " + payload.length);
        }
        int count = (int) payload[1];
        int lookups = Math.min(maxCandidates, Math.max(0, count));

        List<Candidate> cands = new ArrayList<>();
        long[] plain = new long[Math.max(1, lookups)];
        int bPay = payload.length;

        for (int j = 0; j < lookups; j++) {
            int base = 2 + j * (1 + lBf);
            if (base + 1 + lBf > bPay) {
                break;                       // 载荷不够长（B_pay 与 maxValues 不一致）
            }
            int valueId = (int) payload[base];
            if (valueId <= 0) {
                continue;                    // 空槽：论文里 D[u] = 空
            }
            long[] bits = new long[lBf];
            for (int bi = 0; bi < lBf; bi++) {
                bits[bi] = payload[base + 1 + bi] != 0 ? 1 : 0;
            }
            // (2) 服务端按候选 j 取出其 Bloom 段，打包成一个槽位 RLWE（每位一槽）
            Ciphertext ctBF = BloomScoring.encryptBloomVector(sc.m,
                padToSlots(bits, sc.slots));
            // (3) ct_score,j ← CtCtMul(q_BF, ct_BF,j)，再折叠（A2 ANSWER 6-7）
            Ciphertext ctScore = BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBF, ctBF);
            cands.add(new Candidate(valueId, bits, ctBF, ctScore));
            plain[cands.size() - 1] = BloomScoring.decodeScore(sc.m, ctScore);
        }
        return new Result(cands, plain, (System.nanoTime() - t0) / 1_000_000);
    }

    /**
     * 明文参考值 {@code s_j = <b_qry, b_{v_j}>}（AND 的汉明重量）。
     *
     * <p><b>它是"负对照"的对照物</b>：密文分数必须逐候选等于它，否则"打分做了"
     * 这句话就没有证据。注意它<b>不能</b>替代密文分数 —— 判定必须走
     * {@code Dec(ct_score)}，这一点由下面的负对照 N2 钉住。
     */
    public static long plainScore(boolean[] bQry, long[] bloomBits) {
        long s = 0;
        for (int i = 0; i < bQry.length && i < bloomBits.length; i++) {
            if (bQry[i] && bloomBits[i] != 0) {
                s++;
            }
        }
        return s;
    }

    /** 载荷里的指纹（{@code payload[0]}）。用于 P0-4 的 {@code f != fp(K) => 空}。 */
    public static long fingerprintOf(long[] payload) {
        return payload.length > 0 ? payload[0] : 0;
    }

    // ------------------------------------------------------------------
    //  自检
    // ------------------------------------------------------------------

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    /**
     * 自检：<b>含规划书 P0-1 点名要的那条 {@code l_BF < N/2} 用例</b>，以及
     * 三条负对照（空查询 / 破坏 ct_score / 换一个 q_BF）。
     *
     * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeBloomScore [N] [lBf]}
     */
    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int lBf = args.length > 1 ? Integer.parseInt(args[1]) : 18;

        System.out.println("=== CAPE A2 ANSWER 4-8：每候选密文分数 自检 ===");
        System.out.printf("[参数] N=%d  l_BF=%d  t=%d（打分信道）%n%n", n, lBf, SCORE_T);

        Scorer sc = setup(n);
        System.out.printf("[setup] 打分信道 %.0f ms，槽数 = %d%n", (double) sc.setupMs, sc.slots);
        System.out.printf("        %s%n%n", sc.m.describe());

        // ---------- 0. 硬约束 ----------
        System.out.println("---------------- 0. 硬约束 ----------------");
        check("l_BF <= N/2（规划书 第四节）", lBf <= n / 2,
            "l_BF=" + lBf + "  N/2=" + (n / 2));
        check("l_BF < N/2（本轮新增覆盖点：旧自检只测了 l_BF = N/2）",
            lBf < n / 2, "l_BF=" + lBf);

        // ---------- 1. 槽位布局实证（不靠推理） ----------
        System.out.println();
        System.out.println("---------------- 1. 槽位布局实证（toSlotVector 的约定）----------------");
        {
            boolean[] one = new boolean[lBf];
            one[7] = true;
            long[] sv = toSlotVector(one, sc.slots);
            long[] back = decryptSlots(sc, BloomScoring.encryptBloomVector(sc.m, sv));
            int mism = 0;
            for (int i = 0; i < sc.slots; i++) {
                if (back[i] != sv[i]) {
                    mism++;
                }
            }
            check("第 i 位 -> 槽位 i 的往返（0/1 全对）", mism == 0, "失配槽 = " + mism);
            check("置位落在槽 7", back[7] == 1, "槽7=" + back[7]);
        }

        // ---------- 2. 打分正确性 ----------
        System.out.println();
        System.out.println("---------------- 2. 打分正确性（明文参考 vs 密文分数）----------------");
        boolean[] bQry = new boolean[lBf];
        for (int i = 0; i < lBf; i += 3) {
            bQry[i] = true;
        }
        long tau = 0;
        for (boolean b : bQry) {
            if (b) {
                tau++;
            }
        }
        System.out.printf("       b_qry 置位 = %d 个，tau = %d%n", tau, tau);

        Ciphertext qBF = encryptQuery(sc, bQry);

        long[] hit = bitsOf(bQry);                 // 完全命中
        long[] extra = bitsOf(bQry);
        extra[1] = 1;
        extra[4] = 1;                              // 命中且多余位（该值还关联别的关键词）
        long[] miss1 = bitsOf(bQry);
        // ⚠️ 必须清掉一个**确实被 b_qry 置位**的下标，否则这条用例什么都没测：
        //    第一版写的是 miss1[lBf-1] = 0，而 b_qry 的步长是 3（0,3,6,9,12,15），
        //    下标 17 本来就没置位 ⇒ 分数仍是 tau，用例静默失效（自检把它抓出来了）。
        int missAt = -1;
        for (int i = lBf - 1; i >= 0; i--) {
            if (bQry[i]) {
                missAt = i;
                break;
            }
        }
        miss1[missAt] = 0;                         // 漏掉最高那个已置位（贴着 l_BF 上界）

        scoreCase(sc, qBF, tau, "C1 候选含 b_qry 全部位 -> s = tau", hit, tau);
        scoreCase(sc, qBF, tau, "C2 候选 = b_qry 本身 -> s = tau", bitsOf(bQry), tau);
        scoreCase(sc, qBF, tau, "C3 候选多几个位（仍含全部查询位）-> s = tau", extra, tau);
        scoreCase(sc, qBF, tau, "C4 漏掉下标 " + missAt + "（贴着 l_BF 上界）-> s = tau-1，应拒",
            miss1, tau - 1);
        scoreCase(sc, qBF, tau, "C5 全 0 候选 -> s = 0", new long[lBf], 0);

        // ---------- 3. 论文 A2 ANSWER 6-7 的折叠当量：l_BF 项 vs 全部槽 ----------
        //
        // 规划书 P0-1 的「必须先核」：foldAllSlots 折全部 N 个系数，而论文折 l_BF 项。
        // 两者相等 等价于 下标 >= l_BF 的项贡献为 0。
        System.out.println();
        System.out.println("---------------- 3. 折叠当量（P0-1 点名的先决条件）----------------");
        {
            long[] t1 = new long[lBf];
            for (int i = 0; i < lBf; i++) {
                t1[i] = 1;                          // 全部 l_BF 位都置 1
            }
            Ciphertext ct = BloomScoring.encryptBloomVector(sc.m, padToSlots(t1, sc.slots));
            Ciphertext sc1 = BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBF, ct);
            long got = BloomScoring.decodeScore(sc.m, sc1);
            check("T1 候选 = 前 l_BF 位全 1 -> s = tau（下标 >= l_BF 的槽对结果无贡献）",
                got == tau, "s=" + got + " 期望 tau=" + tau);
            check("T2 折叠后所有槽都相同（逐槽扫描）", allSlotsEqual(sc, sc1),
                "不一致槽 = " + countDistinctSlots(sc, sc1));
        }

        // ---------- 4. 负对照 ----------
        System.out.println();
        System.out.println("---------------- 4. 负对照（没有这些，判定做了没有证据）----------------");
        {
            Ciphertext ctHit = BloomScoring.encryptBloomVector(sc.m, padToSlots(hit, sc.slots));
            long honest = BloomScoring.decodeScore(sc.m,
                BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBF, ctHit));
            System.out.printf("      [基线] 诚实算出来的 s = %d（tau = %d）%n", honest, tau);
            check("基线：诚实分数 == tau", honest == tau, "s=" + honest);

            // N1：空查询（tau=0）—— 若判定真在比 tau，则任何候选都不该以 s=tau 通过
            boolean[] empty = new boolean[lBf];
            Ciphertext qEmpty = encryptQuery(sc, empty);
            long sEmpty = BloomScoring.decodeScore(sc.m,
                BloomScoring.bloomScore(sc.m, sc.galoisKeys, qEmpty, ctHit));
            check("N1 空查询 b_qry 全 0 -> s = 0（而不是碰巧等于 tau）", sEmpty == 0,
                "s=" + sEmpty + " tau=" + tau);

            // N2：破坏 ct_score（整条置零）-> 判定必须失败。
            //     这条是规划书 P0-3 的验收关键：没有它，不能排除"判定根本没做"。
            Ciphertext broken = new Ciphertext();
            broken.copyFrom(BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBF, ctHit));
            zeroOut(broken);
            long sBroken = BloomScoring.decodeScore(sc.m, broken);
            check("N2 把 ct_score 置零 -> 解密得 0 != tau（判定必须失败）",
                sBroken != tau, "s=" + sBroken + " tau=" + tau
                    + " -> " + (sBroken == tau ? "竟然通过 X" : "被拒 OK"));

            // N3：用另一个查询的 q_BF 打分 -> 分数必须与 tau 不同
            //     （证明分数真的依赖 q_BF，不是常数）
            boolean[] other = new boolean[lBf];
            other[0] = true;
            other[1] = true;
            Ciphertext qOther = encryptQuery(sc, other);
            long sOther = BloomScoring.decodeScore(sc.m,
                BloomScoring.bloomScore(sc.m, sc.galoisKeys, qOther, ctHit));
            check("N3 换成另一个 q_BF -> 分数改变（分数确实依赖查询）", sOther != tau,
                "s=" + sOther + " tau=" + tau);
        }

        System.out.println();
        System.out.println(failed == 0
            ? "=== 全部通过：Bloom 打分已按 A2 ANSWER 4-8 分组产出密文分数 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static void zeroOut(Ciphertext ct) {
        long[] d = ct.data();
        for (int i = 0; i < d.length; i++) {
            d[i] = 0;
        }
    }

    private static long[] bitsOf(boolean[] b) {
        long[] out = new long[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = b[i] ? 1 : 0;
        }
        return out;
    }

    private static void scoreCase(Scorer sc, Ciphertext qBF, long tau, String what,
                                  long[] candidateBits, long expected) {
        Ciphertext ctBF = BloomScoring.encryptBloomVector(sc.m,
            padToSlots(candidateBits, sc.slots));
        Ciphertext score = BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBF, ctBF);
        long got = BloomScoring.decodeScore(sc.m, score);
        boolean ok = got == expected;
        check(what, ok, "s=" + got + " 期望=" + expected
            + (ok && expected == tau ? " -> 接受" : ok ? "" : " X"));
    }

    /** 解密整条密文的全部槽（自检用；只有客户端侧有 sk）。 */
    static long[] decryptSlots(Scorer sc, Ciphertext ct) {
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

    private static boolean allSlotsEqual(Scorer sc, Ciphertext ct) {
        long[] s = decryptSlots(sc, ct);
        for (int i = 1; i < s.length; i++) {
            if (s[i] != s[0]) {
                return false;
            }
        }
        return true;
    }

    private static int countDistinctSlots(Scorer sc, Ciphertext ct) {
        long[] s = decryptSlots(sc, ct);
        int bad = 0;
        for (int i = 1; i < s.length; i++) {
            if (s[i] != s[0]) {
                bad++;
            }
        }
        return bad;
    }

    /**
     * 供服务端组装响应：把候选列表变成可 JSON 化的结构。
     *
     * <p><b>刻意不含任何分数</b> —— 分数只能以密文形式（{@code ctScore}）出去，
     * 明文 s_j 一旦出现在响应里，"判定走密文"就变成了一句空话。
     */
    static List<Object> toWire(List<Candidate> cands) {
        List<Object> out = new ArrayList<>();
        for (Candidate cand : cands) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("valueId", cand.valueId);
            one.put("bloomBits", cand.bloomBits);
            out.add(one);
        }
        return out;
    }
}
