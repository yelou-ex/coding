package com.fusepir.fusepir;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.common.BfGen;

import java.math.BigInteger;

/**
 * <b>{@code pp} —— Algorithm 1 SETUP 17 的公开参数，以及 Algorithm 2 SETUP 12 对它的加宽。</b>
 *
 * <pre>
 *   A1 SETUP  3: Select public parameters (N, d, t, q), and generate HE keys sk = (s_L, s_R).
 *   A1 SETUP 17: pp ← (H, fp, R, C, N, d, t, q).
 *   A1 SETUP 18: st_S ← ({P_{c,b}}_{c,b}, pp).
 *   A1 SETUP 19: return (pp, st_S, sk).
 *   A2 SETUP 12: pp ← (pp_F, ℓ_BF, G, m).
 *   A2 SETUP 13: st_S ← st^F_S.
 *   A2 SETUP 14: return (pp, st_S, sk).
 * </pre>
 *
 * <h3>本类型之前不存在（审计 A1 SETUP 17 / A2 SETUP 12 两条的缺口）</h3>
 * 伪代码把 {@code pp} 当三元返回值的第一个分量一路传下去
 * （A1 ANSWER 1 的 {@code Parse st_S = ({P_{c,b}}, pp)}、A2 ANSWER 1 的
 * {@code Parse (q_anc, q^BF)} 之后服务端要能拿到 {@code ℓ_BF}），
 * 而代码里此前**没有任何类型承载它** —— 参数散在
 * {@code BffSetup.Layout}、{@code CapeDemoData.Tables} 与系统属性
 * （{@code -Dcape.t}、{@code -Dcape.lbf}、{@code -Dcape.maxValues}）里各一份。
 * 症状不是"跑不动"，而是**没有任何一个对象能回答"这一组参数是什么"**。
 *
 * <h3>⚠️ {@code H} 与 {@code fp} 是<b>函数</b>，不是数据（按论文原样表示）</h3>
 * 论文的 {@code H = {h_j : K → [L_BFF]}_{j=0}^{k−1}}（A3 SETUP 9）与
 * {@code fp_{ρ_fp} : K → {0,1}^μ}（A3 SETUP 10）都是函数，所以本类
 * <b>只存可调用的函数</b>：
 * <ul>
 *   <li>{@link BffHashFamily}（{@code H}）：一次调用给出同一个关键词的 <b>k 个</b>位置，
 *       实现是 {@code kw -> BffHash.positions(kw, ρ_H, hg)} —— 位置函数的**唯一实现**在
 *       {@link BffHash#positions(String, long, BffHash.HashGen)}；</li>
 *   <li>{@link Fingerprint}（{@code fp}）：实现是方法引用 {@code BffSetup::fp}；</li>
 *   <li>{@code G}（A2 的 {@code {g_1,…,g_h}}）：{@link BloomHashFamily}，
 *       实现是 {@code bf::positions}（{@link BfGen}）。</li>
 * </ul>
 * <b>不预先展开成表</b>（例如 {@code int[n][k]} 的位置表）：展开既随 n 膨胀（pp 是公开参数，
 * 该是常数量级），又会把"客户端与服务端各自算一遍 {@code h_a}"这条性质藏起来 ——
 * 而这条性质正是"同一份实现两边逐位一致"能被检查的前提。
 * {@code probe/FusePirStateTest} 用**反射**断言本类里没有 {@code int[]}/{@code int[][]} 字段
 * （配一个"故意带位置表的类"作负对照，证明该判据有分辨力）。
 *
 * <h3>⚠️ {@code H} 与 Bloom 的 {@code G} 是两个<b>不同类型</b>的接口（有意为之）</h3>
 * {@link BffHashFamily} 的值域是 {@code [0, L_BFF)}、长度为 {@code k=3}；
 * {@link BloomHashFamily} 的值域是 {@code [0, ℓ_BF)}、长度为 {@code h}。
 * 两者长得像（MAP §9.1：BFF = Binary Fuse Filter 与 BF = Bloom Filter 缩写像、语义无关），
 * 把 Bloom 的位置函数喂给 BFF 是本项目已经踩过的那类坑 ⇒ 这里**不做成同一个接口**，
 * 让混用变成编译错误而不是静默算错。
 *
 * <h3>⚠️ A2 的加宽用<b>子类</b>（{@link Cape}），不用可选字段 —— 三条理由</h3>
 * <ol>
 *   <li><b>A2 SETUP 12 是"加宽同一个 pp"，不是另一件东西</b>：算法 2 全程把 {@code pp_F}
 *       当 {@code pp} 用（A2 SETUP 11 把 {@code DB^CAPE} 交给 {@code FusePIR.Setup}、
 *       A2 QUERY 1 用 {@code pp_F} 调 {@code FusePIR.Query}）。子类让 {@code Cape} 实例
 *       **可以直接用在任何需要 {@code pp_F} 的地方**；可选字段做不到这一点。</li>
 *   <li><b>可选字段会让"半个 pp"合法</b>：{@code lBf = 0} / {@code G = null} / {@code m = 0}
 *       都是能构造出来的状态，于是每个读 {@code ℓ_BF} 的地方都要自己判空
 *       —— 而漏判的后果是 {@code B_pay} 静默变小、载荷被切错位（本项目的老毛病）。
 *       子类让"从 A1 的 pp 上读 ℓ_BF"变成**编译错误**。</li>
 *   <li><b>A2 SETUP 13 明确写 {@code st_S ← st^F_S}</b>：服务端状态**只**引用 {@code pp_F}，
 *       加宽后的 pp 作为协议公开参数单独传。子类把"两个 pp"这件事摆到类型层面，
 *       {@code probe/FusePirStateTest} 对这条接线（{@code st_S.params() == pp_F} 且
 *       {@code != 加宽后的 pp}）有断言 + 负对照。</li>
 * </ol>
 * <p>⚠️ 因此 {@link #extendBloom} 对**已经是 CAPE 的 pp** 直接抛异常：{@code pp} 上加宽两次
 * 在论文里没有对应的一行（A2 SETUP 12 只加宽一次）。
 *
 * <h3>{@code R}、{@code C}、{@code N} 由 {@link BffSetup.Layout} 承载（不复制成三个 int）</h3>
 * A1 SETUP 17 列的是 {@code (H, fp, R, C, N, d, t, q)}，本类的字段是
 * {@code (h, fp, layout, d, t, q)}：{@code R = layout.r}、{@code C = layout.c}、
 * {@code N = layout.ringDim}。{@link BffSetup.Layout} 是**同一个对象**、不是副本 ——
 * 复制成三个 int 就是新的漂移源（A1 SETUP 4 的 {@code (R,C)} 已经在
 * {@code BffSetup.layout} 里定死一份，见 MAP §12.7 与 §14.1）。
 * {@code layout} 顺带给出 {@code L_BFF} 与 {@code s}（A1 SETUP 17 没列它们，
 * 但 {@code H} 的值域就是 {@code [0, L_BFF)}，且 A1 SETUP 9-11 的尾部要 {@code RC}）。
 *
 * <h3>⚠️ {@code q} 是 {@link BigInteger}，不是 {@code long}</h3>
 * 我们的 {@code q} 是 SEAL 系数模数链里工作素数的积（{@code Mpc4jRgsw.q}；
 * SEAL 的 {@code bfvDefault} 用的是 ~60 bit 的素数，见 MAP §13.1 证据②），
 * <b>装不进 {@code long}</b>；用 {@code long} 会静默截断。
 * 论文只写 "select public parameters (N, d, t, q)"，没给数值（MAP §13.1 已登记
 * "log q / 系数模数链 未给出"）。
 *
 * <h3>⚠️ 本轮<b>没有</b>实现的、与本类型紧邻的东西（不许说成做了）</h3>
 * <ul>
 *   <li>A1 SETUP 3 的后半句 {@code generate HE keys sk = (s_L, s_R)}：<b>没有</b>
 *       （MAP §15.7 第 6 条）。本类型只承载公开参数，{@code sk} 按 A1 SETUP 19 是
 *       <b>单独</b>返回的第三个分量，不在 {@code pp} 里。</li>
 *   <li>没有任何真实调用方：{@code cape/} 与 {@code bff/} **一个都没接**
 *       （本轮不许动 {@code cape/}）。当前的调用方只有
 *       {@code probe/FusePirStateTest}，这一点在下面的取值函数注释里逐条写明。</li>
 * </ul>
 *
 * <h3>⚠️ 未验证（探针验不了、也不假装验了）</h3>
 * <ul>
 *   <li>{@code q} 与真实 SEAL 上下文的一致性：探针只是把 {@code q} <b>存进去再读出来</b>，
 *       <b>没有</b>与 {@code Mpc4jRgsw.q} 或 {@code CoeffModulus.bfvDefault(N)} 对过账；</li>
 *   <li>{@code d} 与 native 盲旋转上下文的 {@code d} 一致：同样只是存读，
 *       <b>没有</b>与 {@code NativeBlindRotate.nativeCreateContext(N,t,d)} 对过账；</li>
 *   <li>{@code t} 与 native 载荷域一致：本类型只记录数值，跨信道的两个 {@code t}（D11）
 *       由调用方负责一致，本类不做强制。</li>
 * </ul>
 */
public class FusePirParams {

    /**
     * {@code H} —— BFF 的位置函数族 {@code {h_j : K → [L_BFF]}_{j=0}^{k−1}}
     * （A3 SETUP 9 {@code H ← BFF.HashGen(ρ_H, L_BFF, s, k)}；A1 QUERY 3 {@code u_a ← h_a(K)}）。
     *
     * <p>一次调用返回同一关键词的**全部 k 个**位置（{@code out[a] = h_a(K)}），
     * 因为伪代码里它们总是一起用（A1 QUERY 3 的循环 a=0..2）。
     *
     * <p>实现只有一份：{@link BffHash#positions(String, long, BffHash.HashGen)}。
     * 本接口的工厂 {@link FusePirParams#bffPositions} 只是把它绑上 {@code (ρ_H, hg)}。
     */
    @FunctionalInterface
    public interface BffHashFamily {
        /** @return 长度 {@code k} 的位置数组，每项必须落在 {@code [0, L_BFF)} */
        int[] positions(String keyword);
    }

    /**
     * {@code fp} —— 指纹函数 {@code fp : K → {0,1}^μ}（A3 SETUP 10；A1 SETUP 6 拼进载荷、
     * A1 DECODE 6 {@code if f ≠ fp(K) then return ⊥}）。
     *
     * <p>返回的是**未拆槽**的 40-bit 值（{@code μ = 40}，论文 §5.1）。
     * 装进载荷时按 base-{@code t} 拆成 {@code FusePirSetup.fpSlots(t)} 个槽
     * （{@link BffSetup#fpDigits}），<b>拆与拼必须成对使用</b>。
     *
     * <p>实现只有一份：{@link BffSetup#fp(String)}（方法引用 {@code BffSetup::fp}）。
     */
    @FunctionalInterface
    public interface Fingerprint {
        /** @return 40-bit 指纹（{@code [1, 2^40)}；{@code 0} 被 {@code BffSetup.fp} 排除掉） */
        long of(String keyword);
    }

    /**
     * {@code G = {g_1, …, g_h}} —— Bloom 的哈希函数族（A2 SETUP 1；A2 SETUP 5 / QUERY 2
     * 的 {@code BF.Gen(0, S)} 与 A2 QUERY 3 的 {@code τ ← ‖b_qry‖₁} 都走它）。
     *
     * <p>一次调用返回关键词的 <b>h 个</b>位位置，每项落在 {@code [0, ℓ_BF)}。
     * <b>与 {@link BffHashFamily} 不是同一个接口</b>（见类注释）。
     *
     * <p>实现只有一份：{@code com.fusepir.common.BfGen.positions}（客户端与服务端必须共用），
     * 工厂 {@link #of(BfGen)} 只是方法引用 {@code bf::positions}。
     *
     * <p>⚠️ {@code h} 没有单独存成本类的字段：A2 SETUP 1 选的是
     * {@code ℓ_BF} <b>与</b> {@code G}，而 {@code |G| = h} 就是本函数返回值数组的长度
     * （{@code g.positions(K).length}）。
     *
     * <p>⚠️ <b>返回值是 h 次独立哈希的原始结果，可能重复</b>（{@code probe/FusePirStateTest}
     * 实测某个关键词给出 {@code [1, 0, 9, 5, 9]}）—— 去重发生在 {@code BF.Gen} 里
     * （{@code BfGen.bits} 对位置做 OR）。所以 {@code |G| = h} 数的是<b>函数个数</b>，
     * 不是"不同位置数"；{@code τ = ‖b_qry‖₁ ≤ h·|S|} 这条上界也因此成立。
     */
    @FunctionalInterface
    public interface BloomHashFamily {
        /** @return 长度 {@code h} 的位置数组，每项落在 {@code [0, ℓ_BF)} */
        int[] positions(String keyword);

        /**
         * 把一个 {@link BfGen}（= {@code ℓ_BF} + {@code h} + h 个哈希）的
         * <b>位置函数</b>交出来 —— 方法引用 {@code bf::positions}，不是数据拷贝。
         *
         * <p>调用方：{@code probe/FusePirStateTest}（A2 SETUP 1/12）；
         * 生产侧（{@code cape/CapeQuery}）目前仍直接用 {@code BfGen} 对象，
         * <b>本轮没有接线</b>（不许动 {@code cape/}）。
         */
        static BloomHashFamily of(BfGen bf) {
            return bf::positions;
        }
    }

    /** {@code H}（A1 SETUP 17 的第一项）。 */
    private final BffHashFamily h;
    /** {@code fp}（A1 SETUP 17 的第二项）。 */
    private final Fingerprint fp;
    /** {@code R, C, N}（A1 SETUP 17 的第三~五项）+ {@code L_BFF, s}（见类注释）。 */
    private final BffSetup.Layout layout;
    /** {@code d} —— LWE 维数（A1 SETUP 3；论文未给数值，MAP §13.1）。 */
    private final int d;
    /** {@code t} —— 明文模数（A1 SETUP 3）。⚠️ 本实现有两个 {@code t}（D11），这是 native 载荷域那个。 */
    private final long t;
    /** {@code q} —— 密文模数（A1 SETUP 3）。用 {@link BigInteger}，理由见类注释。 */
    private final BigInteger q;

    /**
     * <b>A1 SETUP 17</b>：{@code pp ← (H, fp, R, C, N, d, t, q)}。
     *
     * <p>把 {@code (R, C, N)} 交成一个 {@link BffSetup.Layout}（见类注释：
     * 不复制成三个 int）。构造时只做**形状自检**（非空、{@code d>0}、{@code t>1}、
     * {@code q>1}、{@code R ≤ N}），不做密码学校验。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一），以及内部
     * {@link #extendBloom}（A2 SETUP 12 需要先有 {@code pp_F}）。
     * ⚠️ 生产路径**没有**调用方 —— 本轮不许动 {@code cape/}。
     *
     * @param h      {@code H}，通常是 {@link #bffPositions}
     * @param fp     {@code fp}，通常是 {@code BffSetup::fp}
     * @param layout A1 SETUP 4 选出的 {@code (R, C)} + 环维度 {@code N}
     * @param d      LWE 维数
     * @param t      明文模数（native 载荷域）
     * @param q      密文模数
     */
    public FusePirParams(BffHashFamily h, Fingerprint fp, BffSetup.Layout layout,
                         int d, long t, BigInteger q) {
        if (h == null) {
            throw new IllegalArgumentException("H 不能为 null（A1 SETUP 17 的第一项就是函数 H）");
        }
        if (fp == null) {
            throw new IllegalArgumentException("fp 不能为 null（A1 SETUP 17 的第二项是函数 fp）");
        }
        if (layout == null) {
            throw new IllegalArgumentException("layout 不能为 null（R/C/N 在里面，A1 SETUP 17）");
        }
        if (d <= 0) {
            throw new IllegalArgumentException("d 必须 > 0（LWE 维数），实得 " + d);
        }
        if (t <= 1) {
            throw new IllegalArgumentException("t 必须 > 1（明文模数），实得 " + t);
        }
        if (q == null || q.compareTo(BigInteger.ONE) <= 0) {
            throw new IllegalArgumentException("q 必须 > 1（密文模数），实得 " + q);
        }
        if (layout.r > layout.ringDim) {
            throw new IllegalArgumentException("R=" + layout.r + " > N=" + layout.ringDim
                + "：A1 SETUP 4 要求 R ≤ N");
        }
        this.h = h;
        this.fp = fp;
        this.layout = layout;
        this.d = d;
        this.t = t;
        this.q = q;
    }

    // ==================================================================
    //  native 应答信道的明文模数（一个**已经硬编码**在代码里的常量，本轮只是给它名字）
    // ==================================================================

    /**
     * <b>{@code nativeCapeAnswer} 所在信道的明文模数 {@code t = 65537}</b>
     * —— 它<b>不是</b> {@link #t()}，而是 {@code fusepir/FusePirAnswer#run} 里
     * {@code nativeCreateContext(n, 65537L, 16)} 那一行的那个数。
     *
     * <pre>
     *   A1 SETUP  3: Select public parameters (N, d, t, q) —— 论文没给数值（MAP §13.1）。
     *   A1 ANSWER 1: Parse st_S = ({P_{c,b}}_{c,b}, pp).
     *   A1 ANSWER 5-11: CtPtMul / BlindRotate / SampleExtract_0 / CtCtAdd —— **全在 native**。
     * </pre>
     *
     * <h3>⚠️ 为什么值得单独立一个常量（而不是继续写在 {@code run} 里）</h3>
     * 本实现有<b>两个 {@code t}</b>（缺陷总表 D11 / MAP §13.1）：
     * <ul>
     *   <li>{@link #t()}（A1 SETUP 3 的 {@code t}）—— <b>载荷</b>所在的域，
     *       也是 {@code D}/{@code P_{c,b}} 的取值域。我们的 demo 是 {@code 2^32}。</li>
     *   <li>本常量 —— <b>native 应答上下文</b>的明文模数，{@code 65537}（论文 §5.1 的那个值）。
     *       {@code {P_{c,b}}} 是在这个上下文里当明文乘上去的。</li>
     * </ul>
     * 两者<b>可以不同，而且我们的 demo 里确实不同</b>。这个差别此前只以一个字面量
     * {@code 65537L} 的形式存在，于是"表按 {@code pp.t()} 建、却被送进一个
     * {@code t=65537} 的上下文"这件事在代码里看不出来。给它名字之后：
     * <ul>
     *   <li>{@code fusepir/FusePirAnswer#runServerSide} 会拿 {@link #t()} 与它**对账**，
     *       不一致时抛异常（<b>不是</b>悄悄把表取模 —— 那正是本项目最怕的静默错）；</li>
     *   <li>{@code probe/FusePirAnswerParseTest} 把这条对账做成了负对照
     *       （建一张 {@code t = 2^32} 的表去调 native 路径必须被拦住）。</li>
     * </ul>
     *
     * <p>⚠️ <b>本常量不改任何行为</b>：{@code FusePirAnswer#run} 的
     * {@code nativeCreateContext(n, 65537L, 16)} 逐字不变，只是改成引用这个常量。
     * 想真正统一两个 {@code t} 是独立一轮的事（会动载荷与全部密文）。
     */
    public static final long NATIVE_PLAINTEXT_MODULUS = 65537L;

    // ==================================================================
    //  A3 SETUP 9 / 10 的两个函数工厂（把函数绑上它的公开种子/段结构）
    // ==================================================================

    /**
     * {@code H ← BFF.HashGen(ρ_H, L_BFF, s, k)}（A3 SETUP 9）的函数形态。
     *
     * <p>返回 {@code kw -> BffHash.positions(kw, ρ_H, hg)} —— 一次调用给出 k 个位置。
     * <b>位置函数的算式一行都没有复制到本类里</b>：本类只做绑定
     * （{@code ρ_H}、{@code (L_BFF, s, k)}），算式仍在 {@link BffHash}。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
     */
    public static BffHashFamily bffPositions(long rhoH, BffHash.HashGen hg) {
        if (hg == null) {
            throw new IllegalArgumentException("HashGen 不能为 null（A3 SETUP 9 的 (L_BFF, s, k)）");
        }
        return keyword -> BffHash.positions(keyword, rhoH, hg);
    }

    /**
     * {@code fp_{ρ_fp}}（A3 SETUP 10）的函数形态 —— 方法引用 {@code BffSetup::fp}。
     *
     * <p>⚠️ 只提供这个工厂是为了让调用点看不出"指纹用哪个种子"：
     * 论文要求 {@code ρ_H} 与 {@code ρ_fp} **独立采样**（A3 SETUP 8），
     * 而 {@code ρ_fp} 在我们的实现里是常量 {@link BffSetup#FP_SEED}
     * （demo 为了可复现性把它钉死了，见 {@code BffSetupBundle.sampleSeeds} 的说明）。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
     */
    public static Fingerprint fingerprint() {
        return BffSetup::fp;
    }

    // ==================================================================
    //  A1 SETUP 17 的各项取值
    //  ⚠️ 下面每个取值函数的调用方**目前只有探针**（逐个断言"确实存进去了"），
    //     cape/ 一个都没接 —— 本轮不许动 cape/。
    // ==================================================================

    /** {@code H}（函数）。调用方：{@code probe/FusePirStateTest}。 */
    public BffHashFamily h() {
        return h;
    }

    /** {@code fp}（函数）。调用方：{@code probe/FusePirStateTest}。 */
    public Fingerprint fp() {
        return fp;
    }

    /** {@code R, C, N}（+ {@code L_BFF, s}）的载体。调用方：{@code probe/FusePirStateTest}。 */
    public BffSetup.Layout layout() {
        return layout;
    }

    /** {@code R}（= {@code layout.r}，A1 SETUP 4）。调用方：{@code probe/FusePirStateTest}。 */
    public int r() {
        return layout.r;
    }

    /** {@code C}（= {@code layout.c}，A1 SETUP 4；A1 ANSWER 5 的求和上界）。调用方：探针。 */
    public int c() {
        return layout.c;
    }

    /** {@code N}（= {@code layout.ringDim}，环维度）。调用方：{@code probe/FusePirStateTest}。 */
    public int n() {
        return layout.ringDim;
    }

    /** {@code d}（LWE 维数）。调用方：{@code probe/FusePirStateTest}。 */
    public int d() {
        return d;
    }

    /** {@code t}（明文模数，native 载荷域）。调用方：{@code probe/FusePirStateTest}。 */
    public long t() {
        return t;
    }

    /** {@code q}（密文模数）。调用方：{@code probe/FusePirStateTest}。 */
    public BigInteger q() {
        return q;
    }

    // ==================================================================
    //  A2 SETUP 12: pp ← (pp_F, ℓ_BF, G, m)
    // ==================================================================

    /**
     * <b>A2 SETUP 12</b>：{@code pp ← (pp_F, ℓ_BF, G, m)} —— 把 A1 的 {@code pp} 加宽。
     *
     * <pre>
     *   A2 SETUP  1: Select public Bloom-filter parameters ℓ_BF and G = {g_1, …, g_h}.
     *   A2 SETUP  2: m ← max_{i∈[n]} |V_{K_i}|.
     *   A2 SETUP 12: pp ← (pp_F, ℓ_BF, G, m).
     * </pre>
     *
     * <p>为什么不复制成"另一份 pp"而是子类：见类注释的三条理由。
     * {@code pp_F} 的每一项**原样搬到子类实例**（同一个 {@code H}/{@code fp}/{@code Layout} 引用），
     * 所以 {@link Cape} 实例在需要 {@code pp_F} 的地方可以直接用。
     *
     * <p>⚠️ <b>本函数做两条形状自检</b>（都不是论文写的，是本实现的硬约束，如实登记）：
     * <ol>
     *   <li>{@code ℓ_BF ≤ N/2}：Bloom 位要铺进 SEAL 的槽位，而槽数 = {@code N/2}。
     *       超了 {@code bloom/BloomChannel.toSlotVector} 会抛 —— 在这里提前拦。</li>
     *   <li>{@code m ≥ 1}：{@code m} 是 A2 SETUP 2 的 {@code max_i |V_{K_i}|}，
     *       空库时无意义；{@code m = 0} 会让 {@code B_pay} 少掉全部值域
     *       （症状是载荷被切错，不报错）。</li>
     * </ol>
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
     *
     * @param lBf {@code ℓ_BF}（A2 SETUP 1）
     * @param g   {@code G}（A2 SETUP 1 的函数族，通常 {@code BloomHashFamily.of(bf)}）
     * @param m   {@code m}（A2 SETUP 2）
     * @throws IllegalArgumentException 若已经是一个 CAPE 的 pp（加宽两次在论文里没有对应行）、
     *         或 {@code ℓ_BF}/{@code m} 越界
     */
    public Cape extendBloom(int lBf, BloomHashFamily g, int m) {
        if (this instanceof Cape) {
            throw new IllegalArgumentException(
                "本对象已经是 CAPE 的 pp（A2 SETUP 12）；再调一次 extendBloom 在论文里没有对应的一行");
        }
        if (g == null) {
            throw new IllegalArgumentException("G 不能为 null（A2 SETUP 1 的 {g_1,…,g_h}）");
        }
        if (lBf < 1) {
            throw new IllegalArgumentException("ℓ_BF 必须 ≥ 1，实得 " + lBf);
        }
        if (lBf > n() / 2) {
            throw new IllegalArgumentException("ℓ_BF=" + lBf + " > N/2=" + (n() / 2)
                + "：Bloom 位要铺进 SEAL 槽位（槽数 = N/2），"
                + "越界会在 bloom/BloomChannel.toSlotVector 抛。这是本实现的硬约束，不是论文的。");
        }
        if (m < 1) {
            throw new IllegalArgumentException("m 必须 ≥ 1（A2 SETUP 2 的 max_i |V_{K_i}|），实得 " + m);
        }
        return new Cape(h, fp, layout, d, t, q, lBf, g, m);
    }

    /**
     * <b>A2 SETUP 12 的产物</b>：{@code pp ← (pp_F, ℓ_BF, G, m)} —— CAPE 的公开参数。
     *
     * <p>{@code pp_F} 的 8 项由父类承载（{@link FusePirParams}），本类只加 A2 的三项：
     * {@code ℓ_BF}、{@code G}、{@code m}。字段与 A2 SETUP 12 的元组**一一对应**，
     * 没有第四项（打分信道那个 {@code t} 是本实现的口径差 D11，不是论文的 {@code pp} 的一部分
     * —— 它由 {@code bloom/BloomChannel} 自己持有，见 {@link FusePirClientState.Cape} 里
     * {@code τ} 的域）。
     *
     * <p>⚠️ <b>取值函数的调用方目前只有 {@code probe/FusePirStateTest}</b>，
     * 除了 {@link #bPay()}（它把 {@code (ℓ_BF, m, t)} 转成 A1 ANSWER 4 的循环上界，
     * 由探针用来与表宽对账）。
     */
    public static final class Cape extends FusePirParams {
        /** {@code ℓ_BF}（A2 SETUP 1；A2 ANSWER 5 的折叠轮数 {@code log2 ℓ_BF}）。 */
        private final int lBf;
        /** {@code G = {g_1,…,g_h}}（A2 SETUP 1，函数族）。 */
        private final BloomHashFamily G;
        /** {@code m}（A2 SETUP 2）。 */
        private final int m;

        private Cape(BffHashFamily h, Fingerprint fp, BffSetup.Layout layout, int d, long t,
                     BigInteger q, int lBf, BloomHashFamily g, int m) {
            super(h, fp, layout, d, t, q);
            this.lBf = lBf;
            this.G = g;
            this.m = m;
        }

        /** {@code ℓ_BF}。调用方：{@code probe/FusePirStateTest}（+ {@link #bPay()}）。 */
        public int lBf() {
            return lBf;
        }

        /** {@code G}（函数族）。调用方：{@code probe/FusePirStateTest}。 */
        public BloomHashFamily g() {
            return G;
        }

        /** {@code m}。调用方：{@code probe/FusePirStateTest}（+ {@link #bPay()}）。 */
        public int m() {
            return m;
        }

        /**
         * {@code B_pay} —— A1 ANSWER 4 的循环上界，也就是 {@code D} 每个条目的宽度。
         *
         * <pre>
         *   A1 SETUP 6: y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ ··· ‖ v_{i,m} ∈ Z_t^{B_pay}
         *   A2 SETUP 7-10: V^CAPE ← {(v_{i,j}, b_{v_{i,j}})} —— 每个值占 1 + ℓ_BF 项
         * </pre>
         *
         * <p>算式**一行都没有在这里重写**：转发到
         * {@link FusePirSetup#payloadBpay}（配合 {@link FusePirSetup#fpSlots} 与
         * {@link FusePirSetup#perValue}），也就是全项目唯一那一份载荷布局算式
         * （{@code cape/CapeSetup.bPay} 同样转发到它）。
         *
         * <p>⚠️ <b>{@code B_pay} 的算式本身是推断，不是原文</b>：论文从未写过它
         * （MAP §13.1 已登记"未给出"），且 Alg 2 从头到尾没再提 {@code B_pay}。
         * 这里的价值在于"参数与服务端表宽必须是同一个数"能被**对账**
         * —— 探针拿它与 {@link FusePirServerState#bPay()} 比（负对照：把 {@code m} 改 1
         * 必须让这一项对不上）。
         *
         * <p><b>唯一的调用方是 {@code probe/FusePirStateTest}</b>；
         * 生产侧（{@code cape/CapeSetup.bPay} / {@code CapeDemoService}）仍各自走原路。
         */
        public int bPay() {
            return FusePirSetup.payloadBpay(FusePirSetup.fpSlots(t()), m(),
                FusePirSetup.perValue(lBf()));
        }

        /** 父类的 {@code toString} + A2 的三项（{@code ℓ_BF}、{@code G}、{@code m}）。调用方：探针。 */
        @Override
        public String toString() {
            return "pp_cape(pp_F=[" + super.toString() + "], ℓ_BF=" + lBf
                + ", G=<Bloom 位置函数族>, m=" + m + ", B_pay=" + bPay() + ")";
        }
    }

    /**
     * {@code pp} 的可读形式。
     *
     * <p>只打印**数值项**，函数项打印其类别（{@code H=<BFF 位置函数>}）——
     * 函数没有可打印的值；而把 {@code H} 在某个关键词上的位置打出来就等于
     * 把"这是哪个关键词"写进日志（A1 QUERY 3 的 {@code u_a = h_a(K)} 是客户端私有的中间量）。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（负对照：打印串里**不许**出现关键词，
     * 用一个含关键词的串作对照证明该判据有分辨力）。
     */
    @Override
    public String toString() {
        return "pp(H=<BFF 位置函数>, fp=<40-bit 指纹函数>, layout=[" + layout + "], d=" + d
            + ", t=" + t + ", q=" + q.bitLength() + " bit)";
    }
}
