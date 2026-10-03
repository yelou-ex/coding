package com.fusepir.fusepir;

import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.serialization.SealSerializable;

import java.util.Arrays;

/**
 * <b>A1 ANSWER 13 · 变体 R1：系数域打包（coefficient-domain packing）</b>。
 *
 * <pre>
 *   Alg 1 ANSWER 13: resp ← Pack({ct_{pay,b}}_{b=1}^{B_pay})
 *   Alg 1 DECODE 1-4: for each packed ciphertext ct_{pay,β} ∈ resp do
 *                         y[β] ← Dec_{s_R}(ct_{pay,β})
 * </pre>
 *
 * <h2>⚠️⚠️ 先说结论：这<b>不是</b>论文的 {@code Pack}，D2 <b>没有</b>被关闭</h2>
 *
 * <p>本类实现的是 <b>变体 R1（系数域打包）</b>，<b>不是</b>论文 A1 ANSWER 13 语义上的
 * {@code Pack}。三条必须一起读的边界：
 *
 * <ol>
 *   <li><b>(a) 输出不是"槽位可寻址"的。</b>
 *       论文的 {@code Pack} 产出的是 <b>槽位打包</b>密文：{@code ct_{pay,β}} 落在第 β 个
 *       <b>SIMD 槽</b>（{@code N/2} 个槽），所以 A2 ANSWER 3 才能按候选 {@code j} 把
 *       {@code ct^{BF}_j} 从 {@code resp_anc} 里 <b>parse</b> 出来，并把它当成
 *       ℓ_BF 槽位的打分密文喂给 {@code CtCtMul(q^{BF}, ·)}。
 *       本类的输出把 {@code y[β]} 放在<b>环系数</b>上（{@code Z_q[X]/(X^N+1)} 的系数位置），
 *       而<b>环系数做不了 SIMD 槽的事</b>：{@code CtCtMul} / {@code CtRotate} 是槽域运算，
 *       对"每个系数一个独立 LWE 样本"的密文没有意义。
 *       ⇒ <b>系数域能装下 B_pay 个系数，装不出 m 个 ℓ_BF 槽位密文。</b></li>
 *
 *   <li><b>(b) 因此 A2 ANSWER 3 仍然无法满足。</b>
 *       {@code Parse {(ct_{v_j}, ct^{BF}_j)}_{j=1}^m from resp_anc} —— 我们<b>没有</b>
 *       per-candidate 的 {@code ct^{BF}_j}，也没有 per-candidate 的 {@code ct_{v_j}}。</li>
 *
 *   <li><b>(c) 所以 D2 仍然开放。</b>
 *       D2 = "我们<b>重新加密</b>候选的 Bloom 向量
 *       （{@code cape/CapeBloomScore.encryptCandidateBloom}），而不是从响应里 parse
 *       出 {@code ct^{BF}_j}"。R1 <b>不改变</b>这条替代路径的存在。
 *       <b>"Pack 做完了"这句话是错的</b>；正确的说法是
 *       "Pack 的一个<b>系数域变体</b>落地了，论文那一步仍然没有"。</li>
 * </ol>
 *
 * <h2>⚠️⚠️ 第二条边界（本轮探针实测，必须一起读）：<b>密集打包在本库做不到</b></h2>
 *
 * <p>R1 的原始设想是"一个系数位置放一个载荷系数 ⇒ {@code ⌈B_pay/N⌉ = 1} 条密文"。
 * <b>实测这条路在本库（MPC4J 的 SEAL 移植）上不成立</b>，证据链完整地记在
 * {@code probe/CoeffPackTest} 里（都是断言，不是打印）：
 *
 * <ol>
 *   <li><b>单位置是精确的。</b> {@link LweRlweBridge#packFromSample} 与
 *       {@link LweRlweBridge#sampleExtract} 在<b>同一个位置 j</b> 上逐位互逆：
 *       摆回去之后用库解密器读第 j 个系数，等于直接解密原密文第 j 个系数
 *       （5 个位置全部相符，探针第 3 项）。</li>
 *   <li><b>多位置不行。</b> 把 {@code packFromSample} 在一个密文上叠 K 次，
 *       或者按它自己的约定一次摆 K 个位置，得到的密文<b>只有目标位置的伴生信息</b>：
 *       直接解密时<b>只有第 0 个位置</b>能读出正确值，其余位置全是均匀随机数
 *       （探针「负对照·静默错误」项：K=6 时 6/6 错，且<b>不抛任何异常</b>）。
 *       更关键的是：两个<b>各自正确</b>的单位置密文相加之后，
 *       <b>第二个位置会坏掉</b>（探针「累积」项：{@code P0+P1} 之后
 *       {@code [0]} 与 {@code [1]} 都不是原值，而 {@code P0}、{@code P1} 单独都正确）。
 *       ⇒ <b>"把 B_pay 个样本塞进一条密文再整体解密"这条路在本库不成立。</b></li>
 *   <li><b>失败的形态是"静默"的。</b> 坏位置解出来的是 32-bit 均匀随机数，
 *       没有异常、没有告警。这正是本类<b>不</b>提供密集打包 API 的原因 ——
 *       提供一个会静默给出垃圾的 {@code packDense} 比不提供危险得多。</li>
 * </ol>
 *
 * <p>⇒ 因此 R1 落地成 <b>"每个载荷系数一条系数域密文"</b>：{@code B_pay} 条密文，
 * 每条只承担<b>一个</b>系数（单位置，已实测精确）。
 * <b>条数因此与"未打包"完全一样</b>（{@code B_pay} 条 vs {@code B_pay} 条）——
 * 但注意<b>不是"字节一样"</b>：实测打包件的单条密文序列化后<b>约为</b>
 * {@code encrypt()} 出来同类密文的一半（两者裸数据长度相同、序列化差 2 倍，
 * 探针已把这条做成了断言；具体字节数每次运行会浮动，所以<b>不在这里写死数字</b>，
 * 以 {@code probe/CoeffPackTest} 第 7 节的实测输出为准）。
 * 这个差额<b>不是 R1 省下来的</b> —— 它是"密文处在哪一层 / 哪个 {@code parmsId}"的差别，
 * 所以在报告里按<b>条数</b>说"没有改善"，按<b>字节</b>把两个数都摆出来。
 * R1 真正买到的是把 A1 DECODE 1-3 的"<b>响应里是密文、客户端自己解</b>"这件事
 * 实现了出来（现状是服务端用 {@code c->decryptor} 解完发明文，见 MAP §4 · DECODE L2-4）。
 *
 * <h2>结构性前提（不是我们加的，是"没有密钥切换"这件事本身的代价）</h2>
 * <ol>
 *   <li><b>LWE 密钥必须就是 RLWE 密钥</b>（LWE-in-RLWE）。本仓库由 {@code CapeQuery} 强制
 *       {@code s_L == s_R}（{@code CapeQuery:221-245,270-274}）。</li>
 *   <li><b>样本必须真的来自同一条 RLWE 密文</b>（同 N、同 q、同素数基）。要打包
 *       "各自独立加密的 LWE 密文"，那一步就是<b>密钥切换 / ring packing</b>，
 *       需要 ≈12 GB 的切换密钥（MAP §6:294 登记的那条架构决定）。
 *       ⇒ 本类的样本由"加密一条 {@code e_j·value} 的 RLWE 密文再
 *       {@code sampleExtract} 第 j 个系数"产出 —— 这是本仓库里<b>唯一</b>
 *       能让 {@code b + ⟨a, s_R⟩ = value} 真的成立的做法
 *       （自造 {@code (b,a)} 需要私钥的<b>系数形式</b>，而 MPC4J 的
 *       {@code SecretKey.data()} 是 NTT 域，见 {@link LweRlweBridge} 的类注释）。</li>
 * </ol>
 *
 * <h2>为什么不是"槽位域 Pack"（用户已决定，不再重新论证）</h2>
 * <p>槽位域 Pack 把 1 个载荷比特经 {@code q_R} 量级的 LWE 样本塞进 {@code Z_t} 槽，
 * 会带舍入残差（{@code N=8192} 时约 66 个单位，而比特值是 1）。要精确需
 * {@code t² ≳ 2q_R}，而 {@code t² = 2^64 ≪ q_R ≈ 2^174} —— <b>没有写法能精确</b>。
 * 硬塞进 A2 的精确判据 {@code s_j = τ} 就是<b>静默的正确性失败</b>，比现在这条
 * <b>有记录</b>的偏离（D2）更糟。⇒ <b>槽位域 Pack 已推迟，本类不碰它。</b>
 *
 * @see LweRlweBridge#sampleExtract
 * @see LweRlweBridge#packFromSample
 * @see com.fusepir.probe.CoeffPackTest
 */
public final class FusePirPack {

    private FusePirPack() {
    }

    /**
     * 变体标识。凡引用本类的地方都要带上它 —— 项目里已经有三次
     * "加了函数"与"论文那一步真的做了"被混起来的事故，
     * 这个字符串的作用是<b>让 R1 和论文的 Pack 在日志里就长得不一样</b>。
     */
    public static final String PACK_VARIANT_COEFFICIENT_DOMAIN =
        "Pack/R1-coefficient-domain（**不是**论文 A1 ANSWER 13 的槽位域 Pack；"
            + "输出不可槽位寻址 ⇒ A2 ANSWER 3 仍无法 satisfy ⇒ D2 仍开放；"
            + "且**密集打包在本库实测不成立** ⇒ 一个系数一条密文）";

    // ==================================================================
    //  A1 ANSWER 13 —— 打包
    // ==================================================================

    /**
     * <b>A1 ANSWER 13（变体 R1）</b>：{@code B_pay} 个载荷系数 → {@code B_pay} 条系数域密文，
     * 每个系数用自己的<b>位置</b>（第 0 个用位置 0，第 β 个用位置 β）。
     *
     * <h3>为什么"一个系数一条密文"而不是"一条装 B_pay 个"</h3>
     * 见类注释第 2 条边界：多位置密集打包在本库<b>实测不成立</b>，
     * 且失败形态是静默的（解出 32-bit 随机数、不抛异常）。所以这里只走<b>单位置</b>那条
     * 已实测精确的路（{@link LweRlweBridge#packFromSample}）。
     *
     * <h3>精确性（单位置）</h3>
     * <pre>
     *   sampleExtract(ct, j) 返回 (b, a)： b + ⟨a, s⟩ ≡ phase[j]
     *   packFromSample(·, j) 把它摆回第 j 个系数：  phase'[j] ≡ b + ⟨a, s⟩，其余系数为 0
     *   ⇒ phase'[j] ≡ phase[j]，两个方向都是同一组模加/模减，
     *     没有取整、没有缩放、不碰私钥 ⇒ 逐素数残数相等
     * </pre>
     * 所以客户端 {@code SampleExtract_β} 再解密，得到的就是 {@code y[β]}，<b>逐位相同</b>。
     *
     * @param m       环上下文（{@code N}、{@code t}、密钥）
     * @param payload {@code y} 的系数（{@code Z_t} 上）；长度即 {@code B_pay}
     * @return 长度 {@code B_pay} 的数组，第 β 条密文承载 {@code y[β]}
     * @throws IllegalArgumentException {@code payload} 为空，或某个系数不在 {@code Z_t} 内
     */
    public static Ciphertext[] packCoefficientDomain(Mpc4jRgsw m, long[] payload) {
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("payload 不能为空（B_pay = 0 无法打包）");
        }
        final Ciphertext[] out = new Ciphertext[payload.length];
        for (int beta = 0; beta < payload.length; beta++) {
            out[beta] = packSingleCoefficient(m, payload[beta], beta);
        }
        return out;
    }

    /**
     * 把一个系数打成<b>一条</b>系数域密文（位置 = {@code beta}）。
     *
     * <p>这是 {@link LweRlweBridge#packFromSample} 的<b>唯一</b>被本类使用的调用形态 ——
     * 即"一个密文装一个样本"。本类<b>不</b>提供多位置变体，理由见类注释。
     *
     * <p>⚠️ {@code beta} 是<b>公开的布局参数</b>（不是随机的）：客户端必须用同一个
     * {@code β} 去 {@code SampleExtract}。读错位置会<b>静默给出别的系数</b>，
     * 探针里的「负对照 1（位置）」就是抓这个的。
     */
    public static Ciphertext packSingleCoefficient(Mpc4jRgsw m, long value, int beta) {
        if (value < 0 || value >= m.t) {
            throw new IllegalArgumentException("载荷系数 " + value + " 不在 Z_t 内（t = " + m.t + "）");
        }
        if (beta < 0 || beta >= m.n) {
            throw new IllegalArgumentException("beta = " + beta + " 越界（N = " + m.n + "）");
        }
        // 用本库的密钥造一条"密文 = 明文"的 RLWE 密文，再抽出第 beta 个系数 ——
        // 这样 b + ⟨a, s_R⟩ = value 是【真的】，不是构造出来的自洽。
        final long[] one = new long[m.n];
        one[beta] = value;
        final Ciphertext slot = m.encrypt(one);
        final long[][] sample = LweRlweBridge.sampleExtract(m, slot, beta);
        return LweRlweBridge.packFromSample(m, sample, beta);
    }

    // ==================================================================
    //  A1 DECODE 1-4 —— 解包
    // ==================================================================

    /**
     * <b>A1 DECODE 2-3（变体 R1）</b>：读回一个载荷系数。
     *
     * <pre>
     *   Alg 1 DECODE 2: for each packed ciphertext ct_{pay,β} ∈ resp do
     *   Alg 1 DECODE 3:     y[β] ← Dec_{s_R}(ct_{pay,β})
     * </pre>
     * 系数域里"第 β 条打包密文"就是"第 β 条密文"，读它 = {@code SampleExtract_β} 再库解密。
     *
     * <p>⚠️ 用 {@link LweRlweBridge#decryptSampleViaPack} 而不是直接
     * {@code m.decrypt(packed)[beta]}：前者是<b>实测的</b>读数路径
     * （单位置下两者一致，见探针第 3 项），而且它忠实地表达了协议里客户端要做的事
     * —— 客户端<b>只有密文</b>，它的解密器就是"抽系数 + 用秘密读"。
     */
    public static long unpackCoefficient(Mpc4jRgsw m, Ciphertext packed, int beta) {
        if (beta < 0 || beta >= m.n) {
            throw new IllegalArgumentException("beta = " + beta + " 越界（N = " + m.n + "）");
        }
        final long[][] sample = LweRlweBridge.sampleExtract(m, packed, beta);
        return LweRlweBridge.decryptSampleViaPack(m, sample, beta);
    }

    /**
     * <b>A1 DECODE 1-4（变体 R1）</b>：按公开布局读回整个 {@code y}。
     *
     * @param packed {@link #packCoefficientDomain} 的产物
     * @param bPay   期望的系数个数 {@code B_pay}
     * @throws IllegalArgumentException {@code bPay ≤ 0}，或
     *         {@code packed.length < bPay}（响应被截断）。截断<b>不能</b>静默补零 ——
     *         那会让客户端把缺失的系数读成 0，看起来像"候选的值是 0"
     */
    public static long[] unpackCoefficientDomain(Mpc4jRgsw m, Ciphertext[] packed, int bPay) {
        if (packed == null || packed.length == 0) {
            throw new IllegalArgumentException("packed 不能为空");
        }
        if (bPay <= 0) {
            throw new IllegalArgumentException("B_pay 必须 > 0，实得 " + bPay);
        }
        if (packed.length < bPay) {
            throw new IllegalArgumentException("响应只有 " + packed.length + " 条密文，少于声明的 B_pay = "
                + bPay + "（截断不能静默补零）");
        }
        final long[] y = new long[bPay];
        for (int beta = 0; beta < bPay; beta++) {
            y[beta] = unpackCoefficient(m, packed[beta], beta);
        }
        return y;
    }

    // ==================================================================
    //  负对照专用（探针用；都是"只让一边错"的能力）
    // ==================================================================

    /**
     * <b>负对照专用</b>：在第 {@code from} 个位置打包、在第 {@code readAt} 个位置解密。
     *
     * <p>存在理由：{@code pack} 与 {@code unpack} 用的是<b>同一个位置约定</b>，
     * 所以"往返一致"有一个<b>平凡的解释</b>——"两边一起错"。
     * 本函数提供"只让一边错"的能力，证明<b>位置约定是真的在起作用</b>。
     */
    public static long[] roundTripAtWrongPosition(Mpc4jRgsw m, long[] payload,
                                                  int from, int readAt) {
        final long[] y = new long[payload.length];
        for (int beta = 0; beta < payload.length; beta++) {
            final Ciphertext packed = packSingleCoefficient(m, payload[beta], from);
            y[beta] = unpackCoefficient(m, packed, readAt);
        }
        return y;
    }

    /**
     * <b>负对照专用</b>：写 {@code readAt} 个位置、读 {@code declaredBPay} 个位置
     * —— 也就是"声明的 {@code B_pay} 与实际装了几个系数不符"。
     *
     * <p>证明"<b>个数</b>也是协议的一部分"：
     * <ul>
     *   <li>{@code declaredBPay > readAt}（声明的比实际多）⇒ 必须<b>抛</b>，
     *       不能静默把缺的几条解成 0 —— 静默补零会让客户端以为"那些候选的值是 0"，
     *       看起来像"没命中"，是最坏的一种失败；</li>
     *   <li>{@code declaredBPay < readAt}（声明的比实际少）⇒ 尾部系数<b>丢失</b>，
     *       与完整载荷比较必须失配。</li>
     * </ul>
     *
     * @return 长度 2 的数组：{@code [0] = 读到的 y（抛了就是 null)}，
     *         {@code [1] = 抛出的异常的消息 hashCode（没抛就是 null）}
     */
    public static Object[] packAndUnpackWithWrongCount(Mpc4jRgsw m, long[] payload,
                                                       int readAt, int declaredBPay) {
        final Ciphertext[] packed = packCoefficientDomain(m,
            Arrays.copyOf(payload, Math.min(payload.length, Math.max(0, readAt))));
        try {
            return new Object[]{unpackCoefficientDomain(m, packed, declaredBPay), null};
        } catch (RuntimeException e) {
            return new Object[]{null, e.getMessage()};
        }
    }

    // ==================================================================
    //  线成本
    // ==================================================================

    /**
     * 一条 RLWE 密文序列化后的字节数（{@code SealSerializable.save()}）。
     *
     * <p>为什么<b>实测</b>而不是套公式：套"2 分量 × 工作素数 × N × 8"会漏掉 SEAL 的
     * 序列化头；更危险的是会漏掉<b>不同 {@code parmsId} 下工作素数个数不同</b>这件事
     * （本探针第一版就踩到了：{@code firstParmsId()} 下的密文与 {@code encrypt()} 出来的
     * 密文序列化长度差一个素数分量）。所以实测，并把公式值一起打印。
     *
     * <p>{@code SealSerializable.save()} 声明了 {@code IOException}（内部是字节数组流，
     * 实际不会失败）；这里包成 {@link IllegalStateException}，不让调用方为了"量个长度"
     * 写 try/catch。
     */
    public static int wireBytes(Ciphertext ct) {
        try {
            return new SealSerializable<>(ct).save().length;
        } catch (java.io.IOException e) {
            throw new IllegalStateException("密文序列化失败（不该发生：底层是字节数组流）", e);
        }
    }

    /** 公式侧（不含序列化头）：{@code 2 × 工作素数 × N × 8}。为 {@code private} ——
     *  它<b>不是</b>一个能替实测值的公式（见 {@link #wireBytes}），
     *  所以不对外暴露一个会误导调用方的公开入口。 */
    private static long wireBytesFormula(Mpc4jRgsw m) {
        return 2L * m.workingPrimeCount * m.n * 8L;
    }

    /**
     * 打包前后的线成本对照（只算"响应体里的载荷"这一项，不含 CAPE 的打分密文）。
     *
     * <p>⚠️ <b>R1 在这里没有任何改善</b>：{@code B_pay} 条 → {@code B_pay} 条。
     * 原因见类注释（密集打包实测不成立）。<b>这条数字必须如实报出来</b>，
     * 否则"打包了"听起来像是省了 60 倍。
     *
     * @param perCt     一条系数域密文的字节数（实测）
     * @param denseGoal 理想中的密集条数 {@code ⌈B_pay/N⌉}（本库<b>做不到</b>，只作对照）
     */
    public static String wireCostReport(Mpc4jRgsw m, int bPay, int perCt, int denseGoal) {
        final long total = (long) perCt * bPay;
        return String.format(
            "N=%d，公式侧 2 × 工作素数 %d × N × 8 = %d 字节/条；实测 %d 字节/条%n"
                + "       R1 实际：B_pay=%d 条 × %d 字节 = %.2f MB（**与未打包一样，无改善**）%n"
                + "       密集设想：%d 条 = %.2f MB（比例 1/%d）—— **本库实测做不到**，见类注释%n"
                + "       ⚠️ 与 524401 那条旧数字的关系：那是【另一组系数模数】下的上下文"
                + "（工作素数 4 ⇒ 524288 + 头），本次上下文工作素数 = %d",
            m.n, m.workingPrimeCount, wireBytesFormula(m), perCt,
            bPay, perCt, total / 1048576.0,
            denseGoal, perCt * (double) denseGoal / 1048576.0, bPay,
            m.workingPrimeCount);
    }

    // ==================================================================
    //  A1 DECODE 5 的入口 —— 载荷切分本身不在这里
    // ==================================================================

    /**
     * <b>变体 R1 的客户端侧入口</b>：{@code 解包 → A1 DECODE 5 的 Recover}。
     *
     * <p>⚠️ <b>切分逻辑不重写</b>：{@code Recover (f, m_K, v_1 … v_m) ← y} 已经在
     * {@link FusePirDecode#decodePayloadCoefficients}（按 {@link FusePirSetup#valueOffset}
     * 这些布局函数切）。本方法只做 {@code resp_anc}（{@code B_pay} 条密文）→ {@code y}
     * 的转换，然后<b>转发</b>给它 —— 这样"布局只有一份"这条不变量不会被本类破坏。
     *
     * @param m       客户端环上下文（必须有与服务端<b>同一把</b> {@code s_R}：单进程回环里
     *                就要求 {@code new Mpc4jRgsw(n, t, 0, base, sharedSk)}）
     * @param packed  A1 ANSWER 13 的产物
     * @param bPay    {@code B_pay}（公开参数）
     * @param t       载荷域 {@code t}（切槽要用；必须与构造侧同一个）
     */
    public static java.util.List<Integer> decodePackedPayload(Mpc4jRgsw m, Ciphertext[] packed,
                                                             int bPay, long t) {
        final long[] y = unpackCoefficientDomain(m, packed, bPay);
        return FusePirDecode.decodePayloadCoefficients(y, t);
    }

    /** 便于日志/探针打印的一段自述（把"这不是 Pack"写在输出里，而不是只写在注释里）。 */
    public static String describe() {
        return PACK_VARIANT_COEFFICIENT_DOMAIN + System.lineSeparator()
            + "       R1：一个载荷系数 = 一条系数域密文（单位置 packFromSample），"
            + "客户端 SampleExtract_β + 解密 ⇒ y[β] 逐位精确。";
    }

    /** 便于探针比较：返回第一个不同的下标，全等返回 −1（长度不同时返回 {@code min}）。 */
    public static int firstMismatch(long[] payload, long[] y) {
        final int n = Math.min(payload.length, y.length);
        for (int i = 0; i < n; i++) {
            if (payload[i] != y[i]) {
                return i;
            }
        }
        return payload.length == y.length ? -1 : n;
    }

    /** 便于探针报错信息：两数组前若干个元素。 */
    public static String head(long[] a, long[] b, int k) {
        return "payload" + Arrays.toString(Arrays.copyOf(a, Math.min(k, a.length)))
            + " vs y" + Arrays.toString(Arrays.copyOf(b, Math.min(k, b.length)));
    }
}
