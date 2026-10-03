package com.fusepir.fusepir;

import com.fusepir.bff.*;

/**
 * <b>Algorithm 1 · SETUP</b> —— 网格参数这一半（{@code R, C, cellsPerCol, L_BFF}）。
 *
 * <pre>
 *   Alg 1 SETUP 4:  Select R, C such that RC ≥ L_BFF, R ≤ N.
 *   Alg 1 SETUP 14: P_{c,b}(X) ← Σ_{r=0}^{R-1} D[r + cR][b]·X^r
 * </pre>
 *
 * <h3>本类消掉的重复</h3>
 * {@code cellsPerCol} 与 {@code C}（列数）这两条算式此前在
 * <b>三个地方各写了一遍</b>（{@code CapeDemoData}、{@code CapeQuery.build}、
 * {@code CapeQuery.buildIndicesOnly}），靠注释写着"必须与 … 逐位一致"。
 * 客户端与服务端**必须**算出同一组网格，否则会静默查错列 —— 那种安排迟早会漂。
 * 现在只有一份。
 *
 * <h3>⚠️ 与论文的形态差（P1-4 已记）</h3>
 * <ol>
 *   <li><b>推导顺序是反的</b>。论文是
 *       {@code BFF.Setup(n,3) → L_BFF ← |D| → 才选 (R,C)}；
 *       我们是**先按 n 定列数** {@code C = ⌈n/cellsPerCol⌉}，
 *       再把 {@code L_BFF = cellsPerCol · C} 当成副产品。
 *       ⇒ {@link BffSetup#paperLBff} 那两条闭式**我们不使用**。</li>
 *   <li><b>一个位置占 {@code maxValues} 行，不是一行</b>。
 *       论文的 {@code r_a = u_a mod R} 直接是列内行号；
 *       我们是 {@code (u mod cellsPerCol) · maxValues + a}，
 *       把 k 路分享塞进同一个 cell 的连续 k 行。</li>
 *   <li>因此论文的 {@code RC ≥ L_BFF} 在我们这里退化成
 *       {@code cellsPerCol · C ≥ n}（本组参数：{@code 5·26 = 130 ≥ 128}）。</li>
 * </ol>
 */
public final class FusePirSetup {

    private FusePirSetup() {
    }

    /**
     * 一列里有多少个 cell：{@code ⌊R / maxValues⌋}。
     *
     * <p>每个关键词要占 {@code maxValues} 行（cell），所以一列能放
     * {@code ⌊R/maxValues⌋} 个关键词 —— 这也是"为什么 {@code R} 不能太小"的原因。
     */
    public static int cellsPerCol(int r, int maxValues) {
        return Math.max(1, r / maxValues);
    }

    /**
     * 需要多少列：{@code ⌈n / cellsPerCol⌉}。
     *
     * <p>⚠️ 论文给了 {@code RC ≥ L_BFF} 这个**约束**，但没给怎么把 {@code C} 定下来。
     * 我们取"刚好装下 n 个关键词"的最小列数 —— 于是 {@code L_BFF} 变成几何副产品。
     */
    public static int columns(int kwCount, int cellsPerCol) {
        return Math.max(1, (kwCount + cellsPerCol - 1) / cellsPerCol);
    }

    /**
     * 我们的 {@code L_BFF} = {@code cellsPerCol · C}（{@code Span}）。
     *
     * <p>它不是按 {@code BFF.Setup(n,3)} 算出来的，见类注释第 1 条。
     */
    public static int span(int cellsPerCol, int c) {
        return cellsPerCol * c;
    }

    // ==================================================================
    //  y 的布局（Alg 1 SETUP 6）—— 全项目只有这一份
    // ==================================================================
    //
    //   Alg 1 SETUP 6: y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ ··· ‖ v_{i,m} ∈ Z_t^{B_pay}
    //
    //   ⚠️ 2026-10-14 深夜：这一段算式此前在**全项目 24 处**各写了一遍
    //   （构造侧写 `2 + j*(1+lBf)`、解析侧再写一遍、探针里又写一遍）。
    //   布局是论文里**定义一次**的东西，两边各自手抄就是标准的漂移源 ——
    //   改一处忘一处，症状是"载荷被切错位"，而且不会报错。
    //   现在只有这里的四个函数，构造侧与解析侧共用。

    /**
     * 一个值占几项。
     *
     * <p>论文 FusePIR 里 {@code v_{i,j} ∈ Z_t} 占 **1** 项；CAPE 把值换成
     * {@code (v, b_v)}，一个值就占 {@code 1 + ℓ_BF} 项（{@code b_v} 是 ℓ_BF 位的 Bloom 段）。
     * <b>CAPE 这一层加宽是我们的推断</b>（Alg 2 从未重述 {@code B_pay}）。
     */
    public static int perValue(int lBf) {
        return 1 + lBf;
    }

    // ==================================================================
    //  fp 占几个槽（2026-10-14 深夜新增）
    // ==================================================================
    //
    //  论文 §5.1（out_cape.txt:1157）："the fingerprint length is 40 bits"。
    //  A1 SETUP 6:  y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ … ‖ v_{i,m} ∈ Z_t^{B_pay}
    //
    //  ⚠️ 关键观察：**论文自己的 t = 65537（16 bit）也装不下 40 bit 的 fp。**
    //  所以 `y` 里那个 `fp(K_i)` 必然是 **⌈40 / log2 t⌉ 个 Z_t 槽**，
    //  而不是一个。我们此前默认 `fp` 占 1 个槽（B_pay = 2 + m·perValue），
    //  那个 "2" 是**我们的推断**，论文从未写 B_pay 的算式 —— 现在按位数算。
    //
    //  t = 2^32（我们的 native 载荷域） ⇒ 每槽 32 bit ⇒ fpSlots = 2
    //  t = 65537（论文的 t）          ⇒ 每槽 16 bit ⇒ fpSlots = 3

    /** 论文的指纹长度 {@code μ = 40} bit（`out_cape.txt:1157`）。 */
    public static final int FP_BITS = 40;

    /** 一个 {@code Z_t} 槽能装多少 bit：{@code ⌊log2 t⌋}。 */
    public static int slotBits(long t) {
        if (t <= 1) {
            throw new IllegalArgumentException("t 必须 > 1，实得 " + t);
        }
        return 63 - Long.numberOfLeadingZeros(t);
    }

    /**
     * {@code fp} 占几个 {@code Z_t} 槽：{@code ⌈μ / ⌊log2 t⌋⌉}。
     *
     * <p>为什么是"按位拆"而不是"塞进一个槽"：{@code t = 2^32} 时一个槽只有 32 bit，
     * 40 bit 的指纹**物理上放不进**。按位拆之后两边（构造侧与解析侧）
     * 都用 {@code BffSetup.fpDigits}/{@code fpFromDigits} 换算，不会各自手写。
     */
    public static int fpSlots(long t) {
        final int bits = slotBits(t);
        return Math.max(1, (FP_BITS + bits - 1) / bits);
    }

    /** {@code m_i}（值的个数）所在的下标 —— 紧跟 {@code fp} 的 {@code fpSlots} 个槽。 */
    public static int countOffset(int fpSlots) {
        return fpSlots;
    }

    /**
     * {@code B_pay = fpSlots + 1 + m · perValue}。
     *
     * <p>⚠️ <b>论文从未写过 {@code B_pay} 的算式</b>（A1 SETUP 6 只说
     * {@code y ∈ Z_t^{B_pay}}，MAP §13.1 已登记"未给出"）。
     * 此前我们推的是 {@code 2 + m·perValue}，那个 `2` 把 40-bit 的 `fp` 当成了 1 个槽。
     * 现在按 A1 SETUP 6 的拼接顺序重算：{@code fp}（fpSlots 个）+ {@code m_i}（1 个）
     * + 每个值 {@code perValue} 个。
     */
    public static int payloadBpay(int fpSlots, int m, int perValue) {
        return fpSlots + 1 + m * perValue;
    }

    /** {@code y} 里第 {@code j} 个值（0-based）的**值**所在下标。 */
    public static int valueOffset(int fpSlots, int j, int perValue) {
        return fpSlots + 1 + j * perValue;
    }

    /** {@code y} 里第 {@code j} 个值的 Bloom 段起始下标（紧跟在值后面）。 */
    public static int bloomOffset(int fpSlots, int j, int perValue) {
        return valueOffset(fpSlots, j, perValue) + 1;
    }

    // ==================================================================
    //  A1 SETUP 6：pad 到 m 个值  +  y_{K_i} 的装配 / 解析
    //  （2026-10-15 补齐；此前**没有**这两个方向的具名函数 —— 装配只在
    //    demo 资产 `CapeDemoData.buildPayload`（private）里，而
    //    `probe/CoeffPackTest:481` 只能"同分布重写"一遍。）
    //
    //  依据：`coding/docs/CAPE-数学规范-SETUP到ANSWER.md`
    //    §1.3（`payload_i` 的字段顺序与索引约定、`m = max_i m_i`（不足处补 0））
    //    §四（DECODE 的字段解析：指纹 / 个数 / 第 j 个值与其 Bloom）
    //  ⚠️ 该规范把"个数"写成 **2 个 limb**（`B_pay = β_fp + 2 + m·(1+ℓ_BF)`），
    //     而本仓库一直按 **1 个 limb** 算（`payloadBpay = fpSlots + 1 + …`）。
    //     两者不可能同时对；**这是一个待决的口径**，见 MAP §25.2。
    //     本处**按本仓库现有口径**实现（`countOffset`/`valueOffset`/`bloomOffset`），
    //     所以不改变任何既有数据与探针；口径本身没有被偷偷改掉。
    // ==================================================================

    /**
     * <b>A1 SETUP 6 前半：把 {@code V_{K_i}} 补齐到 {@code m} 个值。</b>
     *
     * <p>规范 §1.3 原文：{@code m = max_i m_i（不足处补 0）}。
     * 补的是 <b>{@code 0}</b>，不是"复制最后一个值"也不是"跳过" ——
     * 后者会让载荷长度随关键词变化，而 {@code B_pay} 必须对所有关键词是同一个数。
     *
     * @param values 该关键词的真实值集合（长度可 &lt; {@code m}，也可 = {@code m}）
     * @param m      {@code max_i |V_{K_i}|}
     * @return 长度恰为 {@code m} 的新数组
     * @throws IllegalArgumentException {@code values} 长于 {@code m}（那就是 {@code m} 算错了，
     *         静默截断会丢值 ⇒ 与 {@code BloomSetup.reconcile} 同一个立场）
     */
    public static long[] padValuesToM(long[] values, int m) {
        if (values == null) {
            throw new IllegalArgumentException("values 为 null");
        }
        if (m < 1) {
            throw new IllegalArgumentException("m 必须 ≥ 1（它是 max_i |V_{K_i}|），实得 " + m);
        }
        if (values.length > m) {
            throw new IllegalArgumentException("该关键词有 " + values.length + " 个值 > m = " + m
                + "：说明 m 不是最大值（A1 SETUP 2 的 m ← max_i |V_{K_i}| 算错了），"
                + "静默截断会丢值");
        }
        long[] out = new long[m];
        System.arraycopy(values, 0, out, 0, values.length);   // 其余位天然是 0
        return out;
    }

    /**
     * <b>A1 SETUP 6 后半：{@code y_{K_i} ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ b_{v_{i,1}} ‖ … ‖ v_{i,m} ‖ b_{v_{i,m}}}。</b>
     *
     * <p>字段下标全部走 {@link #countOffset}/{@link #valueOffset}/{@link #bloomOffset} ——
     * <b>不许调用方手写</b>。手写会让"构造侧拆、解析侧拼"对不上，
     * 症状是"某些字段恒为 0"，而 {@code fingerprintOk} 那边只会表现为"查不中"。
     *
     * @param fpDigits 指纹的 {@code fpSlots} 段（由 {@code BffSetup.fpDigits} 拆）
     * @param count    {@code m_i}（该关键词真实的值个数，≤ {@code m}）
     * @param values   已 {@link #padValuesToM} 到 {@code m} 个
     * @param bloom    {@code [m][ℓ_BF]} 每个值的 Bloom 位；{@code null} 表示全 0
     * @param lBf      {@code ℓ_BF}
     * @throws IllegalArgumentException 形状不符（长度、二进制性、值域）
     */
    public static long[] assemblePayload(long[] fpDigits, int count, long[] values,
                                         long[][] bloom, int lBf) {
        return assemblePayload(fpDigits, count, values, bloom, lBf, 1L);
    }

    /**
     * <b>带上"精度倍率"的装配</b>：每个字段写成 {@code scale · field}（{@code scale = K}）。
     *
     * <h3>为什么需要 K —— 这是"q_R → Z_t 桥的缩放残差"的唯一解法</h3>
     * ANSWER 12 要把 {@code SampleExtract_0} 的样本从 {@code Z_{q_R}} 缩放到应答通道的明文域，
     * 而 {@code FusePirPackSlot.rnsToT} 是<b>逐分量</b>舍入的：{@code a_k} 的舍入误差
     * {@code δ_k ∈ (−½,½]} 乘上 {@code s_k} 后累加，相位里因此多出 {@code E = Σ_k δ_k s_k}，
     * <b>{@code |E| ≤ ones/2}（{@code ones} = 私钥的汉明重量）—— 这个绝对误差与明文模数<u>无关</u></b>，
     * 所以"把 t 换大"救不了它；能救的只有<b>让字段本身带上 K 倍余量</b>：
     * {@code K > ones} 时，收到 {@code K·field + E} 之后除以 K 一次舍入就<b>精确</b>恢复 {@code field}。
     *
     * <p>⇒ 调用方（{@code FusePirFourStep.setup}）必须用<b>应答通道的明文模数</b>
     * {@code tRing > K·T}（{@code T} 是字段域 = 论文的 {@code t}），
     * 而<b>槽位布局仍然按 {@code T} 算</b>（所以 {@code B_pay}、值域、limb 宽度全都不变）。
     *
     * @param scale {@code K ≥ 1}；{@code 1} 就是论文原样的 {@code y}
     */
    public static long[] assemblePayload(long[] fpDigits, int count, long[] values,
                                         long[][] bloom, int lBf, long scale) {
        if (scale < 1) {
            throw new IllegalArgumentException("精度倍率 K 必须 ≥ 1，实得 " + scale);
        }
        if (fpDigits == null || values == null) {
            throw new IllegalArgumentException("fpDigits / values 不能为 null");
        }
        final int fpSlots = fpDigits.length;
        final int perValue = perValue(lBf);
        final int m = values.length;
        final int bPay = payloadBpay(fpSlots, m, perValue);
        if (count < 0 || count > m) {
            throw new IllegalArgumentException("count = " + count + " 不在 [0, m] = [0, " + m + "] 内");
        }
        if (bloom != null && bloom.length != m) {
            throw new IllegalArgumentException("bloom 有 " + bloom.length + " 行，应为 m = " + m);
        }
        long[] y = new long[bPay];
        for (int i = 0; i < fpSlots; i++) {
            y[i] = fpDigits[i] * scale;
        }
        y[countOffset(fpSlots)] = count * scale;
        for (int j = 0; j < m; j++) {
            y[valueOffset(fpSlots, j, perValue)] = values[j] * scale;
            final int bo = bloomOffset(fpSlots, j, perValue);
            if (bloom == null) {
                continue;
            }
            if (bloom[j] == null || bloom[j].length != lBf) {
                throw new IllegalArgumentException("第 " + j + " 个值的 Bloom 段长度是 "
                    + (bloom[j] == null ? "null" : bloom[j].length) + "，应为 ℓ_BF = " + lBf);
            }
            for (int i = 0; i < lBf; i++) {
                final long bit = bloom[j][i];
                if (bit != 0 && bit != 1) {
                    throw new IllegalArgumentException("Bloom 位必须是 0/1，第 " + j + " 个值第 "
                        + i + " 位是 " + bit + " —— 非二进制位会让 ⟨B_qry,b_v⟩ 的判据失去意义");
                }
                y[bo + i] = bit * scale;
            }
        }
        return y;
    }

    /** {@link #assemblePayload} 的逆：DECODE 侧的字段解析（规范 §四）。 */
    public static final class Payload {
        /** 指纹的 {@code fpSlots} 段。 */
        public final long[] fpDigits;
        /** {@code m_i}（该关键词真实的值个数）。 */
        public final int count;
        /** 已补齐到 {@code m} 个的值（下标 {@code ≥ count} 的位是补的 0）。 */
        public final long[] values;
        /** {@code [m][ℓ_BF]} 每个值的 Bloom 位。 */
        public final long[][] bloom;

        Payload(long[] fpDigits, int count, long[] values, long[][] bloom) {
            this.fpDigits = fpDigits;
            this.count = count;
            this.values = values;
            this.bloom = bloom;
        }
    }

    /**
     * <b>{@link #assemblePayload}(…, scale) 的逆，并且顺手把"桥的缩放残差"一次消掉。</b>
     *
     * <pre>
     *   收到：slot = K·field + E   （E 是 q_R→Z_t 的逐分量舍入残差，|E| ≤ ones/2）
     *   返回：field                （四舍五入除以 K；K > ones 时 E 被完全吸收 ⇒ 精确）
     * </pre>
     *
     * <p>⚠️ <b>必须"先除再解析"</b>：{@code parsePayload} 里的 {@code m_i} 校验
     * （{@code 0 ≤ m_i ≤ m}）拿到 {@code K·m_i} 会直接判越界。
     *
     * <p>⚠️ <b>只把"贴近 {@code tRing} 的那一点点"当负残差</b>：{@code K·field} 本身可以<b>超过
     * {@code tRing/2}</b>（只要 {@code field > tRing/(2K)} 就会），所以<b>不能</b>按"中心代表"整体
     * 折叠 —— 那会把大的正字段误判成负数。本方法实测踩过这个坑：只有大的指纹 limb 出错、
     * 小字段全对（症状是解码值偏一个常数）。
     *
     * @param y      {@link FusePirPackSlot#decodePayload} 的产物（值域 {@code Z_{tRing}}）
     * @param scale  K
     * @param tRing  应答通道的明文模数
     * @param t      字段域模数（论文的 {@code t}），结果落在 {@code [0, t)}
     */
    public static long[] divideScale(long[] y, long scale, long tRing, long t) {
        if (y == null) {
            throw new IllegalArgumentException("y 为 null");
        }
        if (scale < 1) {
            throw new IllegalArgumentException("精度倍率 K 必须 ≥ 1，实得 " + scale);
        }
        final long half = scale / 2;
        final long[] out = new long[y.length];
        for (int i = 0; i < y.length; i++) {
            long c = Math.floorMod(y[i], tRing);
            if (c > tRing - scale) {
                c -= tRing;                        // 只有"离 tRing 不到 K"的那一点才是负残差
            }
            final long q = (c >= 0) ? (c + half) / scale : -((-c + half) / scale);
            out[i] = Math.floorMod(q, t);
        }
        return out;
    }

    /**
     * <b>把 {@code y ∈ Z_t^{B_pay}} 拆回字段</b>（A1 DECODE 5 的
     * {@code Recover (f, m_K, v_1, …, v_m) ← y}）。
     *
     * <p>与 {@link #assemblePayload} 是严格互逆的一对，两者<b>共用同一组偏移函数</b>。
     *
     * @param m 值个数（= 建表时的 {@code m}）；由调用方给，因为 {@code y} 的长度只能定出
     *          {@code B_pay} 而 {@code B_pay = fpSlots + 1 + m·perValue} 在
     *          {@code fpSlots} 未知时解不出唯一的 {@code m}
     */
    public static Payload parsePayload(long[] y, int m, long t, int lBf) {
        if (y == null) {
            throw new IllegalArgumentException("y 为 null");
        }
        final int fpSlots = fpSlots(t);
        final int perValue = perValue(lBf);
        final int bPay = payloadBpay(fpSlots, m, perValue);
        if (y.length < bPay) {
            throw new IllegalArgumentException("y 只有 " + y.length + " 项，布局要求至少 B_pay = "
                + bPay + "（t=" + t + ", m=" + m + ", lBf=" + lBf + "）");
        }
        long[] fp = new long[fpSlots];
        System.arraycopy(y, 0, fp, 0, fpSlots);
        final int count = (int) y[countOffset(fpSlots)];
        if (count < 0 || count > m) {
            throw new IllegalArgumentException("y 里的个数 m_i = " + count + " 不在 [0, m=" + m
                + "] 内 —— 载荷与布局不同源");
        }
        long[] values = new long[m];
        long[][] bloom = new long[m][lBf];
        for (int j = 0; j < m; j++) {
            values[j] = y[valueOffset(fpSlots, j, perValue)];
            final int bo = bloomOffset(fpSlots, j, perValue);
            System.arraycopy(y, bo, bloom[j], 0, lBf);
        }
        return new Payload(fp, count, values, bloom);
    }
}
