package com.fusepir.prim;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * 盲旋转（BlindRotate）——按 CAPE 论文定义实现，并按 Pirouette 的结构修正轮数口径。
 *
 * <h3>论文定义</h3>
 * {@code BlindRotate(ct_L, ct_R) → ct'_R}：给定 LWE 加密 {@code ct_L ← LWE.Enc_s(r)} 与累加器
 * {@code P(X) = Σ p_i X^i} 的 RLWE 加密，按加密下标 r 同态旋转累加器，
 * 使 <b>p_r 落到 ct'_R 的常数系数</b>上。要算的就是 {@code X^{−r}·P(X)}。
 *
 * <h3>两种等价口径（本文件都实现，用于互相验证）</h3>
 * <ol>
 *   <li><b>按索引位（压缩变体 CAPE-C / FusePIR-C 的结构）</b>：{@link #blindRotateByBits}。
 *       r = Σ z_i·2^i，于是
 *       <pre>X^{−r} = Π_i X^{−z_i·2^i}   →   每轮 ACC ← CMUX(RGSW(z_i), ACC, ACC·X^{−2^i})</pre>
 *       共 <b>⌈log₂N⌉</b> 轮（N=16384 → 14），自举密钥 = 14 个 RGSW。
 *       Pirouette §4.1 原文：{@code ct_k ← LWEtoRGSW(c̃t_k), ∀k ∈ [0, log(N)−1]}，
 *       {@code {RGSW(idx_i)}_{i∈[0,⌈log2 N⌉−1]}} 用作 CMUX 控制位。</li>
 *   <li><b>按秘密位（教科书 CGGI，= CAPE / FusePIR 的结构）</b>：{@link #blindRotate}。
 *       {@code X^{−r} = X^{−b}·Π_i X^{a_i·s_i}}，每轮 {@code CMUX(RGSW(s_i), ACC, ACC·X^{a_i})}
 *       后再补一次公开旋转 {@code X^{−b}}。共 <b>d</b> 轮（d = LWE 维数 = 512），
 *       自举密钥 = d 个 RGSW。</li>
 * </ol>
 * 两者数学等价（{@code Σ a_i s_i − b ≡ −r}），但代价差 d/⌈log₂N⌉ ≈ 37 倍。
 * <b>论文（CAPE/FusePIR）的结构是口径 2</b>——因为它的 {@code ct_L} 就是一条 LWE 密文；
 * 口径 1 属于 CAPE-C/FusePIR-C（控制位需由 {@code LWEtoRGSW} 产出），本文件保留它作交叉校验。
 *
 * <p><b>三个函数都不接收明文索引</b>：口径 2 收 LWE 密文 {@code (a, b)}；
 * 口径 1 收逐位 {@code RGSW} 控制位 + 公开的 2^i 步长；
 * A1 ANSWER 6 的具名入口 {@link #blindRotate(Mpc4jRgsw, Mpc4jRgsw.Rgsw[], Ciphertext, long[], long)}
 * 收的同样是 {@code q^row} 的 {@code (a, β)} 两个分量。
 * 验收代码需要的期望值要自己另外带。
 *
 * <p>剩余缺口：口径 1 需要"把一条 LWE 密文同态地分解成逐位 LWE 密文"（Pirouette 的
 * Alg.3 {@code BitDecomp}，参数见其 Table 3：n_in=1300、n_out=600、B=2¹⁴、B_ksk=2³）。
 * 本文件的测试用**已知索引**直接给出控制位（RGSW 仍是真密文，只是"选哪一支"由已知位决定），
 * 因此旋转机构本身被完整验证；BitDecomp 是后续要补的那一步。
 */
public final class BlindRotateOps {

    private BlindRotateOps() {
    }

    /**
     * 口径 1（论文结构）：按<b>索引位</b>轮，每轮旋转步长为 −2^i。
     *
     * <p><b>注意这个函数不收索引</b>：索引不以任何形式（明文或密文）作为参数进来。
     * 每轮的旋转步长 {@code −2^i} 是<b>公开常数</b>，"这一轮要不要转到 X^{−2^i}"完全由
     * {@code bkBits[i] = RGSW(z_i)} 这条密文在 {@link Mpc4jRgsw#cmux} 里决定。
     * 因此调用方（例如验收代码）如果想知道期望结果 {@code p_r}，需要自己另外带着 {@code r}——
     * <b>绝不要把明文 {@code r} 传进协议路径</b>。
     *
     * @param bkBits 长度须为 ⌈log₂N⌉，第 i 个是 {@code RGSW(z_i)}，z_i 为索引第 i 位
     *               （真实的控制位来自 BitDecomp + LWEtoRGSW）
     */
    public static Ciphertext blindRotateByBits(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bkBits, Ciphertext acc) {
        Ciphertext cur = acc;
        for (int i = 0; i < bkBits.length; i++) {
            // z_i = 1 时把 ACC 乘 X^{−2^i}：z_i=0 保持，z_i=1 旋转 → 合起来得到 X^{−Σ z_i 2^i}
            Ciphertext rotated = m.multiplyPowerOfX(cur, -(1L << i));
            cur = m.cmux(bkBits[i], cur, rotated);
        }
        return cur;
    }

    /**
     * 口径 2（教科书 CGGI）：按<b>秘密位</b>轮，最后补一次公开旋转 X^{−b}。
     * 保留用于与口径 1 交叉验证。
     */
    public static Ciphertext blindRotate(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bkSecrets, Ciphertext acc,
                                         long[] a, long b) {
        Ciphertext cur = acc;
        long twoN = 2L * m.n;
        for (int i = 0; i < a.length; i++) {
            // a_i ≡ 0 (mod 2N) ⇒ X^{a_i} = 1 ⇒ CMUX 的两支是同一条密文 ⇒ 这一轮是恒等变换，跳过。
            //
            // ⚠️ 不能真的走一遍 CMUX：那时 rotated 与 cur 内容相同，diff = 0，
            // externalProduct 会拿到全零明文，SEAL 抛 "result ciphertext is transparent"。
            // 而 a 由 PRG 派生、取值在 [0,2N)，所以 a_i = 0 **必然会出现**：
            //   N=2048、d=512 时单次查询至少命中一个 0 的概率 ≈ 1 − (1 − 1/4096)^512 ≈ 12%
            //   N=16384（q_L=2^15）、d=512 时 ≈ 1.5%
            // d 越小越不容易撞上——这正是"小参数巧合能跑、真实参数才炸"的又一例。
            if (Math.floorMod(a[i], twoN) == 0) {
                continue;
            }
            Ciphertext rotated = m.multiplyPowerOfX(cur, a[i]);
            cur = m.cmux(bkSecrets[i], cur, rotated);
        }
        return m.multiplyPowerOfX(cur, -b);
    }

    /**
     * <b>{@code Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b})} —— A1 ANSWER 6 的具名入口</b>。
     *
     * <pre>
     *   out_cape.txt:879-889   A1 ANSWER 5: Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X)).
     *   out_cape.txt:885-889   A1 ANSWER 6: Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b}).
     *   out_cape.txt:890-894   A1 ANSWER 7: ct_{a,b} ← SampleExtract_0(Acc'_{a,b}).
     *   out_cape.txt:662-676   定义: BlindRotate(ct_L, ct_R) → ct'_R，
     *                                 把 p_r 搬到 ct'_R 的常数系数上 —— 即算 X^{−r}·P(X)。
     * </pre>
     *
     * <p>伪代码把这一步写成<b>一个二元调用</b>：入参是 {@code q^row}（QUERY 5 的
     * {@code LWE.Enc_{s_L}(r_a)}）与 {@code Acc}（ANSWER 5 的产物），出参是旋转后的累加器。
     * 本函数就是那个签名。它<b>不</b>重新实现任何东西 ——
     * 内部逐字委托给 {@link #blindRotate(Mpc4jRgsw, Mpc4jRgsw.Rgsw[], Ciphertext, long[], long)}
     * （教科书 CGGI 口径 2，也是 CAPE/FusePIR 的结构，见本文件类注释）。
     * 所以"新入口"与"老实现"不可能漂移：只有一份算术。
     *
     * <h3>⚠️ 签名对不上伪代码的地方（必须说，不能说成"就是那一行"）</h3>
     * <ol>
     *   <li><b>多了 {@code m} 与 {@code bk}。</b>盲旋转要 {@code d} 个
     *       {@code RGSW(s_i)} 自举密钥（{@code d} = LWE 维数，论文 §5.1 那组参数是 512），
     *       还要一个 SEAL 上下文/求值器。论文把它们当"公开求值材料"省略了
     *       （{@code out_cape.txt:659-661}: "The corresponding public evaluation keys
     *       <b>are omitted from the notation</b> when they are clear from context"）——
     *       所以这里<b>照抄论文的省略是不行的</b>，Java 里没有上下文就没法算。
     *       也就是说：<b>本函数不是"零额外入参"</b>，它只是把伪代码那两个入参
     *       放在了参数表的前面、并让它们保持原来的顺序与含义。</li>
     *   <li><b>{@code q^row} 被拆成 {@code (a, b)} 两个 long 数组/标量。</b>
     *       论文的 {@code q^row} 是<b>一条 LWE 密文对象</b>；本仓库的 Java 侧
     *       LWE 密文就是 {@code (a, β)} 两个裸值（{@link #lweEncryptIndex} 与
     *       {@code LweRlweBridge.sampleExtract} 都返回这个形状，没有密文类）。
     *       所以"把 LWE 密文传进来"在 Java 里落成"传它的两个分量"。</li>
     *   <li><b>参数顺序是 {@code (a, b)}，容易写反。</b>两个都是 long 数组/标量，
     *       编译器一个都不会拦 —— 写反的症状是"旋转错一个量、不报错"。
     *       本函数<b>不做</b>任何自检能抓住它（{@code a} 与 {@code b} 的值域相同），
     *       调用方要自己保证；这也是本函数<b>没有</b>做成
     *       {@code blindRotate(m, bk, acc, long[] qRow)} 单参形态的原因 ——
     *       那种形态会把 {@code q^row} 的"两个分量"藏起来，更看不出顺序。</li>
     * </ol>
     *
     * <h3>⚠️⚠️ 调用方状况：<b>生产路径上没有 Java 调用方</b> —— 本函数目前只被探针调用</h3>
     * <b>这不是遗漏，是如实登记。</b>我们这条 ANSWER 路径的步骤 4-8
     * <b>整个跑在 native/C++ 里</b>：
     * <pre>
     *   native-jni/src/main/cpp/rgsw_blindrotate.cpp
     *     :494-512  void blind_rotate(ctx, bk, acc, a, beta, out)   ← 逐字对应本函数
     *     :680      blind_rotate(c, bk, accCol, av[a], betav[a], rot); ← cape_answer_core 里那次调用
     * </pre>
     * 也就是说：<b>ANSWER 6 在生产里是真实执行、且被端到端验收过的</b>
     * （{@code nativeCapeAnswerSealedC} 那条路），但执行它的是 C++ 的
     * {@code blind_rotate}，<b>不是</b>这个 Java 函数。本函数存在的理由只有一条：
     * <b>让伪代码那一行在 Java 侧可调用</b>（同一个理由与 {@code CtOps.ctPtMul} /
     * {@code CtOps.sampleExtract0} 一致 —— 那两个是 A1 ANSWER 5 / 7，同样 0 个生产调用方）。
     *
     * <p>⚠️ 我们也<b>没有</b>把 Java 侧某个 {@code blindRotate} 的调用点改接到这里，
     * 因为<b>没有一个现成调用点真的在做 A1 ANSWER 6</b>，硬接会改变语义：
     * <ul>
     *   <li>{@code cape/CapeQueryDecode.java:259} —— 用的是 {@code bk = RGSW(r_a 的各个位)}，
     *       即<b>口径 1</b>（按索引位）＋"已知索引"的双密钥口径；</li>
     *   <li>{@code prim/LweToRgswOps.java:68} —— 用盲旋转做<b>舍入测试</b>（判 LWE 的低位），
     *       是 {@code LWEtoRGSW} 的内部步骤，不是 ANSWER 6；</li>
     *   <li>{@code prim/BlindRotateOps.java:172} 等 —— 纯探针（自检旋转机构本身）。</li>
     * </ul>
     * 把其中任何一个换成"按 {@code (a, b)} 对 {@code Acc} 旋转"都会<b>改变它算的东西</b>
     * （前者要求 {@code a} 是"位分解后的控制位"，后者要求 {@code a} 是 {@code ⟨a,s⟩} 的原始分量）。
     * 所以本轮<b>不动</b>它们 —— 记在这里，别把"没接上"说成"接上了"。
     *
     * <p><b>被谁调用（grep 过）：</b>只有 {@code probe/HashGenRhoTest.java}
     * （本轮新建的探针，用真密文跑一次 ANSWER 5-6-7 并验常数项 = {@code P_{c_a,b}[r_a]}）。
     * 它<b>不是</b>生产路径，也<b>不在</b>任何验收命令清单里。
     *
     * <h3>⚠️ 名字为什么是 {@code blindRotateRow} 而不是 {@code blindRotate}</h3>
     * Java 不允许同一个类里两个方法只有<b>名字与参数个数</b>相同而类型擦除后撞车 ——
     * 更直接的原因是：口径 2 的 {@link #blindRotate(Mpc4jRgsw, Mpc4jRgsw.Rgsw[], Ciphertext, long[], long)}
     * <b>已经是 {@code (m, bk, acc, a, b)} 这个签名</b>，本函数与它<b>入参类型完全相同</b>，
     * 只是把后两个参数的含义从"LWE 密文的 {@code (a, β)}"改称"{@code q^row} 的两个分量"。
     * 也就是说：<b>在本仓库的 Java 表示下，伪代码那一行与口径 2 的签名本来就重合</b>
     * （这正是"LWE 密文没有对象类型、只有两个裸分量"的直接后果）。
     * 所以这里只加了一层<b>入口校验</b>（见 N-5：{@code bk} 短了必须抛）并给了一个
     * "这一步就是 A1 ANSWER 6"的名字，<b>不</b>假装它是一个新的算术实现。
     *
     * @param qRowA {@code q^row} 的公开 {@code a} 分量（长度 = LWE 维数 {@code d}）
     * @param qRowB {@code q^row} 的公开 {@code β} 分量（标量）
     * @return {@code Acc'_{a,b}} —— 常数系数上放着 {@code P_{c_a,b}[r_a]} 的那条密文
     */
    public static Ciphertext blindRotateRow(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, Ciphertext acc,
                                            long[] qRowA, long qRowB) {
        if (qRowA == null) {
            throw new IllegalArgumentException("q^row 的 a 分量为 null");
        }
        if (bk == null) {
            throw new IllegalArgumentException("自举密钥 bk 为 null");
        }
        if (bk.length < qRowA.length) {
            // ⚠️ bk 比 d 短不会报错，只会**少转几圈** ⇒ 相位差 a_i·s_i 的累积缺失 ⇒ 静默错值。
            throw new IllegalArgumentException("自举密钥只有 " + bk.length + " 个 RGSW，"
                + "但 q^row 的 a 有 " + qRowA.length + " 项 —— 少转的圈数不会报错，只会算错");
        }
        requireIndexConvention(qRowA, qRowB, m.n);
        return blindRotate(m, bk, acc, qRowA, qRowB);
    }

    // ------------------------------------------------------------------
    //  入口校验：q^row 的编码约定（P0-1 修法②）
    // ------------------------------------------------------------------

    /**
     * <b>绊线：{@code q^row = (a, β)} 必须落在本项目的「无噪声索引」约定里
     * —— {@code Δ = 1}、{@code q_L = 2N}，即所有分量都在 {@code [0, 2N)}。</b>
     *
     * <h3>它在防什么</h3>
     * {@code 缺陷总表.md` 的 P0-1：通用 {@code LWE.encrypt} 按
     * {@code b = ⟨a,s⟩ + Δ·m + e (mod q)}、{@code Δ = q/t} 编码。
     * 把那样一条密文<b>直接</b>喂进这里，旋转量会变成 {@code Δr = 256r} 而不是 {@code r}
     * —— 而且**不报错**，只是转到别的行去。本方法就是为这条静默失败准备的。
     *
     * <h3>⚠️⚠️ 它只是绊线，<b>不是</b>证明 —— 三种情形的覆盖率已算清并实测</h3>
     * <table border="1">
     *   <tr><th>情形</th><th>判据命中吗</th></tr>
     *   <tr><td><b>把通用 LWE 密文直接喂进来</b>（P0-1 的真实形态）</td>
     *       <td>✅ <b>几乎必然命中</b>。通用 LWE 的 {@code a} 均匀于 {@code [0, q)}，
     *           而 {@code q}（SEAL 上下文模数，约 2^218）≫ {@code 2N = 16384}
     *           ⇒ {@code a[0]} 就越界、直接抛</td></tr>
     *   <tr><td>只有 {@code β} 是 Δ 缩放的（{@code a} 已归约）</td>
     *       <td>⚠️ <b>只命中 3/4</b>：{@code β = Δ·r} 里 {@code Δ·r &lt; 2N} 的那部分混得进来
     *           （{@code N = 8192}、{@code Δ = 256} ⇒ {@code r &lt; 64} 时漏掉，实测 192/256 命中）</td></tr>
     *   <tr><td><b>{@code a} 与 {@code β} 都已预先 {@code mod 2N} 归约</b></td>
     *       <td>❌ <b>完全不命中，而且原理上不可能命中</b> —— 归约后的值域与合法输入<b>完全一样</b>。
     *           这是本绊线的真实盲区，不是"覆盖率不够"</td></tr>
     * </table>
     * <b>⇒ 值域绊线只能挡住"直接把大模数密文喂进来"这一种（而那正是 P0-1 的实际形态），
     * 对"已经归约过"的输入无能为力。</b>
     * {@code probe/BlindRotateIndexGuardTest} 把三种情形都做成断言
     * —— 包括第三种<b>刻意期望它放行</b>，免得读者以为本方法是完备的。
     *
     * <p><b>想要完备就用 {@link #requireIndexModulus}</b>：让调用方<b>声明</b>
     * 自己的 {@code (a,b)} 落在哪个模数里，只有 {@code 2N} 被接受 ——
     * 那条看的是<b>声明</b>而不是值域，所以盲区消失（代价是要求调用方诚实声明）。
     * 本方法签名里没有模数可声明，所以它只能做值域绊线 —— <b>这是刻意的取舍，不是疏漏</b>。
     *
     * @throws IllegalArgumentException 有任何分量不在 {@code [0, 2N)} 内
     */
    public static void requireIndexConvention(long[] a, long b, int n) {
        final long qL = 2L * n;
        if (a == null) {
            throw new IllegalArgumentException("q^row 的 a 分量为 null");
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] < 0 || a[i] >= qL) {
                throw new IllegalArgumentException(indexConventionMessage(
                    String.format("a[%d] = %d", i, a[i]), qL));
            }
        }
        if (b < 0 || b >= qL) {
            throw new IllegalArgumentException(indexConventionMessage("beta = " + b, qL));
        }
    }

    /**
     * <b>完备版校验</b>：调用方<b>声明</b>它的 LWE 密文所在的模数 {@code qL}，
     * 而本实现只支持 {@code qL = 2N}（{@code Δ = 1}）。
     *
     * <p>与 {@link #requireIndexConvention} 的分工：那一条只能看值域（能挡"直接喂大模数密文"，
     * 挡不住已归约过的输入），这一条看的是<b>声明</b>，盲区消失。
     * <b>新代码请用这一条</b>；老调用点先加值域绊线。
     *
     * @throws IllegalArgumentException {@code qL != 2N}
     */
    public static void requireIndexModulus(long qL, int n) {
        final long want = 2L * n;
        if (qL != want) {
            throw new IllegalArgumentException("本实现的盲旋转只支持 q_L = 2N = " + want
                + "（Δ = 1、「无噪声索引」约定，见 lweEncryptIndex 的注释），"
                + "但调用方声明的 q_L = " + qL + "。"
                + "⚠️ 通用 LWE.encrypt 用 Δ = q/t 编码：直接喂进来会让旋转量变成 Δr 而不是 r"
                + "（P0-1，症状是转到别的行且不报错）。"
                + "要接通用 LWE 密文，必须先把它反缩放到 Z_{2N}，或在本函数内部实现 Δ 反缩放。");
        }
    }

    private static String indexConventionMessage(String what, long qL) {
        return "q^row 违反了本项目的「无噪声索引」约定：" + what + " 不在 [0, " + qL + ") 内。"
            + "本约定是 b ≡ ⟨a,s⟩ + r (mod 2N)、Δ = 1（见 lweEncryptIndex 的注释），"
            + "而通用 LWE.encrypt 用 b = ⟨a,s⟩ + Δ·m + e (mod q) 编码 —— 那种密文直接喂进来，"
            + "旋转量会变成 Δr 而不是 r，且【不报错】（缺陷总表 P0-1）。"
            + "⚠️ 本绊线按值域判断：能挡住『直接喂大模数密文』（a 均匀于 [0,q) ≫ 2N ⇒ 必中），"
            + "但【挡不住】已经预先 mod 2N 归约过的输入 —— 那种输入的值域与合法输入完全一样。"
            + "要完备请改用 requireIndexModulus(qL, n) 显式声明模数。";
    }

    /**
     * q_L = 2N 下的 LWE 加密：{@code b = ⟨a,s⟩ + r mod 2N}。
     *
     * <p>⚠️ <b>这是"无噪声索引"约定，是本项目的工程决定，不是论文原文。</b>
     * 见 {@code coding/README.md} 3.7 —— 小规模跑通阶段采用候选 (b)：Δ=1、不引入误差项 {@code e}。
     * 真实 LWE 是 {@code b = ⟨a,s⟩ + r + e}，而本实现的盲旋转对 {@code e} <b>零容忍</b>
     * （实测 {@code e=±1} 就整体推移一格、取到相邻记录，见 README 3.4）。
     *
     * <p><b>后果</b>：用这个函数造出来的"LWE 密文"<b>不满足 LWE 的噪声模型</b>，
     * 因此<b>不能引用 LWE 的安全性论证</b>。仅用于正确性验证与流程跑通。
     * 补真实噪声后，所有基于它的测试结论都必须重跑。
     */
    public static long[][] lweEncryptIndex(int[] s, long r, int qL, Random rnd) {
        long[] a = new long[s.length];
        long sum = 0;
        for (int i = 0; i < s.length; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + a[i] * s[i]) % qL;
        }
        return new long[][]{a, {Math.floorMod(sum + r, qL)}};
    }

    // ------------------------------------------------------------------

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== 盲旋转：口径 1（按索引位，论文结构） vs 口径 2（按秘密位，交叉校验）===");

        // ---------- A) 正确性 + 两口径互相验证（小参数，能完整建出自举密钥）----------
        int n = 2048;
        int L = Integer.numberOfTrailingZeros(n);   // ⌈log2 N⌉，N 是 2 的幂
        int qL = 2 * n;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("[A] " + m.describe());
        System.out.printf("    口径 1 轮数 = ⌈log2 N⌉ = %d；口径 2 轮数 = d%n", L);

        Random rnd = new Random(20260919L);
        long[] p = new long[n];
        for (int i = 0; i < n; i++) {
            p[i] = (i % 1000) + 1;
        }
        Ciphertext acc = m.encrypt(p);
        long index = 1234;

        // --- 口径 1：索引的每一位一个 RGSW ---
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bkBits = new Mpc4jRgsw.Rgsw[L];
        for (int i = 0; i < L; i++) {
            bkBits[i] = m.encryptRgswConstant((index >>> i) & 1L);
        }
        long bkBitsMs = ms(t0);
        System.out.printf("    口径 1：自举密钥 %d 个 RGSW（每个 %d 密文），%.0f ms%n",
            L, bkBits[0].size(), (double) bkBitsMs);

        t0 = System.nanoTime();
        Ciphertext out1 = blindRotateByBits(m, bkBits, acc);
        long t1 = ms(t0);
        long[] got1 = m.decrypt(out1);
        long want = p[(int) (index % n)];
        int match1 = countMatch(got1, p, index, m.t, n);
        failed += report("A1 口径 1：p_r 落到常数系数", got1[0] == want,
            String.format("index=%d, %d 轮, %.0f ms；常数系数 got=%d want=p_%d=%d；整条一致的系数 %d/%d",
                index, L, (double) t1, got1[0], index, want, match1, n));

        // --- 口径 2：LWE 秘密的每一位一个 RGSW，末尾补 X^{-b} ---
        int d = 64;
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bkSec = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bkSec[i] = m.encryptRgswConstant(s[i]);
        }
        long bkSecMs = ms(t0);
        long[][] lwe = lweEncryptIndex(s, index, qL, rnd);
        t0 = System.nanoTime();
        Ciphertext out2 = blindRotate(m, bkSec, acc, lwe[0], lwe[1][0]);
        long t2 = ms(t0);
        long[] got2 = m.decrypt(out2);
        int match2 = countMatch(got2, p, index, m.t, n);
        System.out.printf("    口径 2：自举密钥 %d 个 RGSW，%.0f ms%n", d, (double) bkSecMs);
        failed += report("A2 口径 2（d=64）：p_r 落到常数系数", got2[0] == want,
            String.format("index=%d, %d 轮, %.0f ms；常数系数 got=%d；整条一致的系数 %d/%d",
                index, d, (double) t2, got2[0], match2, n));
        failed += report("A3 两种口径结果一致", got1[0] == got2[0],
            String.format("口径 1 常数系数 %d vs 口径 2 常数系数 %d", got1[0], got2[0]));

        // ---------- B) 论文规模：真实自举密钥体积与耗时 ----------
        int N = 16384;
        int Lbig = Integer.numberOfTrailingZeros(N);   // 14
        Mpc4jRgsw big = new Mpc4jRgsw(N, 65537L, 0, 1 << 16);
        System.out.println();
        System.out.println("[B] " + big.describe());
        long ctBytes = (long) big.workingPrimeCount * N * 8;
        System.out.printf("    单个密文 %.2f MB；口径 1 需要 %d 个 RGSW%n", ctBytes / 1048576.0, Lbig);

        long[] msg = new long[N];
        for (int i = 0; i < N; i++) {
            msg[i] = (i % 1000) + 1;
        }
        Ciphertext accBig = big.encrypt(msg);
        long idxBig = 12345;

        Mpc4jRgsw.Rgsw[] bkBig = new Mpc4jRgsw.Rgsw[Lbig];
        t0 = System.nanoTime();
        for (int i = 0; i < Lbig; i++) {
            bkBig[i] = big.encryptRgswConstant((idxBig >>> i) & 1L);
        }
        long bkBigMs = ms(t0);
        double bkMB = (double) Lbig * bkBig[0].size() * ctBytes / 1048576.0;
        System.out.printf("[B1] 自举密钥：%d 个 RGSW × %d 密文 × %.2f MB = %.0f MB，构造 %.0f ms%n",
            Lbig, bkBig[0].size(), ctBytes / 1048576.0, bkMB, (double) bkBigMs);

        t0 = System.nanoTime();
        Ciphertext outBig = blindRotateByBits(big, bkBig, accBig);
        long brBigMs = ms(t0);
        long[] gotBig = big.decrypt(outBig);
        long wantBig = msg[(int) (idxBig % N)];
        failed += report("B2 论文规模盲旋转（口径 1）", gotBig[0] == wantBig,
            String.format("N=%d, index=%d, %d 轮 CMUX, %.0f ms；常数系数 got=%d want=%d",
                N, idxBig, Lbig, (double) brBigMs, gotBig[0], wantBig));

        System.out.println();
        System.out.printf("    → 盲旋转 %.1f s/次（%.1f s 构造密钥），自举密钥 %.0f MB%n",
            brBigMs / 1000.0, bkBigMs / 1000.0, bkMB);

        System.out.println();
        System.out.println(failed == 0 ? "=== 盲旋转正确性全部通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 与理想结果 X^{−index}·P 对照：系数 i 取 p_{(i+index) mod n}，跨过 X^N 的项带负号。 */
    private static int countMatch(long[] got, long[] p, long index, long t, int n) {
        int match = 0;
        for (int i = 0; i < n; i++) {
            int src = (int) ((i + index) % n);
            long expect = (i + index) < n ? p[src] : (p[src] == 0 ? 0 : t - p[src]);
            if (got[i] == expect) {
                match++;
            }
        }
        return match;
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
