package com.fusepir.bff;

/**
 * <b>BFF · SETUP</b> —— 参数这一半。
 *
 * <pre>
 *   Alg 1 SETUP 1: (D, H, fp) ← BFF.Setup(n, 3).
 *   Alg 1 SETUP 2: L_BFF ← |D|
 *   Alg 3 SETUP 1-3: if k=3 then s ← 2^floor(log_3.33(n) + 2.25)
 *                    L_BFF ← max(⌈(0.875 + 0.25·max(1, log10(n/6)))·n⌉, ⌈1.125n⌉)
 *   Alg 3 SETUP 5-7: k=4 的同形闭式（2^floor(log_2.91(n) − 0.5)、1.075n）
 * </pre>
 *
 * <h3>⚠️ 我们的实现与这两条闭式的关系（必须一起说）</h3>
 * <ol>
 *   <li>这两个函数是**论文的闭式**，本类把它们从
 *       {@code probe.CapeBffParamDiag} 搬进来 —— 它们是**协议层的定义**，
 *       不是验收代码，所以应该在 {@code bff/} 里。</li>
 *   <li><b>我们的默认路径不用这两条闭式。</b>{@link #fromBff} 按
 *       CAPE 正文的指示（*"follow the parameterization of BFF used in ChalametPIR"*）
 *       取 {@link BffHash#allocate} 的 {@code arrayLength} 作为 `L_BFF`。
 *       原因不是"我们偷懒"，而是**闭式与 `HashGen` 互不自洽**：
 *       `n=128` 时闭式给 155，而 `h_a` 的值域是 `[0, 256)`，
 *       且 155 写不成 `(segmentCount+k−1)·s`。见 MAP §12.6。</li>
 *   <li>✅ <b>{@code h_a}（位置函数）已实现</b> —— 在 {@link BffHash#positions}。
 *       ⚠️ 本行此前写的是"没有实现，用的是 {@code BffEncode#keywordHash} 的线性探测"，
 *       那是**旧几何**的描述；新路径已改走 BFF 参考实现的位置函数。
 *       （`keywordHash` 仍在，但只服务旧几何的对照路径。）</li>
 * </ol>
 *
 * <p>闭式的值仍保留作对照：`n=128, k=3` 时闭式给 {@code L_BFF = 155}
 * （ChalametPIR 的 `⌊⌋` 版是 154），BFF 参数化给 **256**。
 */
public final class BffSetup {

    private BffSetup() {
    }

    /**
     * {@code BFF.Setup(n, k)} 的产物 —— 论文 Alg 1 SETUP 1-2 与 Alg 3 SETUP 1-3 那几行。
     *
     * <p>{@code (D, H, fp)} 这三样里：{@code H} 由 {@link BffEncodeLegacy#keywordHash} 提供，
     * {@code fp} 由 {@link #fp} 提供，本类给出的是数组长度 {@code L_BFF = |D|} 与段大小 {@code s}。
     */
    public static final class Params {
        /** arity（论文 Alg 1 SETUP 1 定死为 3）。 */
        public final int k;
        /** 关键词个数 {@code n}。 */
        public final long n;
        /** 段大小 {@code s}（恒为 2 的幂）。 */
        public final long s;
        /** 数组长度 {@code L_BFF = |D|}。 */
        public final long lBff;

        Params(int k, long n, long s, long lBff) {
            this.k = k;
            this.n = n;
            this.s = s;
            this.lBff = lBff;
        }

        @Override
        public String toString() {
            return "BFF.Setup(n=" + n + ", k=" + k + ") -> s=" + s + ", L_BFF=" + lBff
                + "（L_BFF/n = " + String.format("%.4f", lBff / (double) n) + "）";
        }
    }

    /**
     * <b>{@code (D, H, fp) ← BFF.Setup(n, 3)}</b>（Alg 1 SETUP 1-2；闭式在 Alg 3 SETUP 1-3）。
     *
     * <p>⚠️ {@code k} 论文定死为 3（附录 A 原话 *"Our concrete FusePIR instantiation uses k=3"*）；
     * 这里允许传 4，只为对 ChalametPIR 的 k=4 闭式做对照（{@code CapeBffParamDiag}）。
     *
     * <p>⚠️ <b>默认路径不用这两条闭式算出的 {@code L_BFF}</b>：默认走 {@link #fromBff}
     * （即 {@link BffHash#allocate} 的 {@code arrayLength}）。原因见类注释第 2 条。
     * <br>⚠️ 本段此前写的是"我们实际用的是 {@code L_BFF = cellsPerCol·C} —— 网格副产品"，
     * 那是**旧几何**的口径；`cellsPerCol` 那套已随旧几何挪进 {@link BffEncodeLegacy}。
     * <br>⚠️ 本类此前还有一个 2 参的 {@code setup(n,k)} 重载，**没有任何调用方**，已删除
     * （`selectRC` 走的是带 {@code useCeil} 的那个）。
     *
     * @param useCeil {@code true} → CAPE 附录 Alg 3 L3（{@code ⌈·⌉}，n=128 给 155）；
     * {@code false} → ChalametPIR 附录 B Alg 1 L3（{@code ⌊·⌋}，给 154）。
     * 两者差 1，见 MAP §12.3。
     */
    public static Params setup(long n, int k, boolean useCeil) {
        return new Params(k, n, paperS(k, n), paperLBff(k, n, useCeil));
    }

    /**
     * 指纹函数 {@code fp}（Alg 1 SETUP 1 的 {@code (D, H, fp)} 里的第三个）。
     *
     * <h3>⚠️ 2026-10-14 深夜：从 32-bit 改成论文的 <b>40-bit</b>（μ = 40）</h3>
     * 论文 §5.1 明写 *"the fingerprint length is <b>40 bits</b>"*（`out_cape.txt:1157`），
     * 而我们此前用的是 {@code String.hashCode}（32-bit）映射进 {@code Z_t} —— 这是 D7
     * 登记的一条保真度偏差。现在 {@link #fp(String)} 返回真正的 40-bit 值。
     *
     * <p>⚠️ <b>40 bit 装不进一个 {@code Z_t} 槽</b>（论文自己的 `t = 65537` 只有 16 bit，
     * 我们的 `t = 2^32` 只有 32 bit）⇒ 载荷里 {@code fp} 占
     * {@code FusePirSetup.fpSlots(t)} 个槽，由 {@link #fpDigits}/{@link #fpFromDigits}
     * 做位拆分与拼回。<b>这两件事必须成对使用</b> —— 构造侧拆、解析侧拼，
     * 任何一边手写都会让"指纹校验"变成永远通过或永远失败。
     *
     * <p>⚠️ 与论文的另一处对齐：正文说 *"The seeds ρ_H and ρ_fp are sampled
     * <b>independently</b>"* ⇒ {@code fp} 用自己的种子 {@link #FP_SEED}，
     * 与位置函数的 {@code ρ_H} 无关。
     *
     * <p>⚠️ 早期的「一槽」入口 {@link #fp(String, long)} 保留：它把 40-bit 值映进
     * {@code Z_t}，只服务旧几何的对照路径（那边的载荷仍是 1 槽指纹）。
     * <b>新代码请用 {@link #fpDigits}</b>。
     */
    public static long fp(String keyword) {
        return oracle40(keyword, FP_SEED);
    }

    /** 指纹种子 {@code ρ_fp}（A3 SETUP 8：与 {@code ρ_H} 独立采样）。 */
    public static final long FP_SEED = 20261015L;

    /**
     * 把 40-bit 指纹按 <b>base-t</b> 拆进 {@code fpSlots} 个 {@code Z_t} 槽（低位在前）。
     *
     * <p>用 base-t 而不是"按 2 的幂切位"：{@code t} 不一定是 2 的幂
     * （论文的 65537 就不是），base-t 对任意 {@code t} 都对，
     * 而且 {@code t = 2^32} 时它退化成"每 32 bit 一段"。
     *
     * <p>可拼回的前提是 {@code t^fpSlots > 2^40}，由
     * {@code FusePirSetup.fpSlots} 的定义保证。
     */
    public static long[] fpDigits(String keyword, long t, int fpSlots) {
        long v = fp(keyword);
        final long[] d = new long[fpSlots];
        for (int i = 0; i < fpSlots; i++) {
            d[i] = v % t;
            v /= t;
        }
        return d;
    }

    /** 从载荷的 {@code [offset, offset + fpSlots)} 把 40-bit 指纹拼回来。 */
    public static long fpFromDigits(long[] y, int offset, int fpSlots, long t) {
        long v = 0;
        long mul = 1;
        for (int i = 0; i < fpSlots; i++) {
            v += Math.floorMod(y[offset + i], t) * mul;
            mul *= t;
        }
        return v;
    }

    /**
     * 40-bit 随机预言机（{@code fp} 用）。
     *
     * <p>⚠️ <b>每个载荷系数都必须落在 {@code [0, t)}</b>：答案在同态里按 `mod t` 算，
     * 超了会**静默回绕**，症状只是某个值差一个 `t` 的倍数
     * （早期版本用 `hash % 1_000_000 + 1`，指纹 661965 回来变成
     * 6595 = 661965 − 10·65537）。所以 {@code fpDigits} 拆出的每一段都保证 `< t`，
     * 而 {@code CapeDemoData.buildPayload} 结尾还有一次逐项自检。
     *
     * <p>⚠️ <b>此前这里还有一个「一槽」重载 {@code fp(keyword, t)}</b>
     * （把 40-bit 值映进 `Z_t`，丢掉高位）—— 40-bit 上线后**它没有任何调用方**了，
     * 已删除。需要"塞进一个槽"的地方本来就不该用指纹（那是 32-bit 时代的口径）。
     */
    private static long oracle40(String keyword, long seed) {
        final long h = BffHash.oracleHash(keyword, seed);
        long v = h >>> 24;                       // 取高 40 bit
        if (v == 0) {
            v = 1;                               // 0 会让「f=0 ⇒ 未命中」与真值混淆
        }
        return v;
    }

    /**
     * <b>{@code D} 的形状</b> —— Alg 1 SETUP 1 的 {@code (D, H, fp)} 里那个 {@code D}。
     *
     * <pre>
     *   Alg 1 SETUP  2: L_BFF ← |D|
     *   Alg 1 SETUP  9-11: for u = L_BFF to RC−1 do D[u] ← 0 ∈ Z_t^{B_pay}
     *   Alg 3 ENCODE 6: D[u] ←$ Z_t^B
     * </pre>
     *
     * <p>⚠️ <b>形状是 {@code [RC][B_pay]}，不是 {@code [L_BFF][B_pay]}</b>。
     * 这一点此前我写错过（当时写的是 `[L_BFF][B_pay]`）：Alg 1 SETUP 9-11 要写
     * {@code D[u], u ∈ [L_BFF, RC)}，**说明 {@code D} 在论文里就是按 {@code RC} 长的**，
     * 前 {@code L_BFF} 个是 BFF 数组、后 {@code RC − L_BFF} 个是补的 0。
     * 按 {@code [L_BFF]} 分配的话，那一步会直接越界。
     *
     * <p>本函数只负责**按形状分配**（Alg 1 SETUP 1 的"Setup 产出 D"）。
     * 往里填什么由 {@link BffEncode#encode} 决定：
     * 它先把整张网格置 0（= SETUP 9-11 的尾部），再把 {@code [0, L_BFF)} 均匀随机化
     * （Alg 3 ENCODE 5-6），最后 LIFO 回填。
     *
     * @param rc {@code R · C}（见 {@link Layout#rc()}），**不是** {@code L_BFF}
     */
    public static long[][] newD(int rc, int bPay) {
        return new long[rc][bPay];
    }

    /**
     * 段大小 {@code s}（CAPE Alg.3 第 2/5 行 = ChalametPIR Alg.1 第 2 行）。
     *
     * <pre>
     *   k = 3:  s = 2^floor( log_3.33(n) + 2.25 )
     *   k = 4:  s = 2^floor( log_2.91(n) - 0.5  )
     * </pre>
     * 注意它恒是 <b>2 的幂</b>（两个出处都这么写）。
     */
    public static long paperS(int k, long n) {
        double lg = Math.log(n) / Math.log(k == 3 ? 3.33 : 2.91);
        double e = (k == 3) ? (lg + 2.25) : (lg - 0.5);
        return 1L << (long) Math.floor(e);
    }

    /**
     * {@code L_BFF} 的闭式。
     *
     * <p>CAPE Alg.3 第 3/6 行：
     * <pre>
     *   k = 3:  L = max( ceil( (0.875 + 0.25·max(1, log10(n/6))) · n ), ceil(1.125·n) )
     *   k = 4:  L = max( ceil( (0.77  + 0.305·max(1, log10(n/(6·1e5)))) · n ), ceil(1.075·n) )
     * </pre>
     * ChalametPIR Alg.1 第 3 行写的是同一件事，但用 {@code floor} 而不是 {@code ceil}
     * （{@code N = ⌊c·m⌋}，且第二项是 {@code ⌊1.125m⌋}）。<b>两篇这一处确实不一致</b>，
     * 不假装它们一模一样。
     *
     * <p>⚠️ 还有一条更要紧的观察：<b>CAPE 自己的闭式并不收敛到它自己声明的 1.125n</b>
     * —— 它随 n 单调升到 ~2.18n ⇒ 「照抄论文的闭式」不足以复现论文的量。
     *
     * @param useCeil true = CAPE 的形状（ceil）；false = ChalametPIR 的形状（floor）
     */
    public static long paperLBff(int k, long n, boolean useCeil) {
        double scale;
        double cap;
        if (k == 3) {
            double lg = Math.log10(n / 6.0);
            scale = 0.875 + 0.25 * Math.max(1.0, lg);
            cap = 1.125;
        } else {
            double lg = Math.log10(n / (6.0 * 1e5));
            scale = 0.77 + 0.305 * Math.max(1.0, lg);
            cap = 1.075;
        }
        long a = useCeil ? (long) Math.ceil(scale * n) : (long) Math.floor(scale * n);
        long b = useCeil ? (long) Math.ceil(cap * n) : (long) Math.floor(cap * n);
        return Math.max(a, b);
    }

    // ==================================================================
    //  A1 SETUP 4: Select R, C such that RC ≥ L_BFF, R ≤ N.
    //  —— 论文只给约束、不给策略。这个策略是我们的，理由全部写在下面。
    // ==================================================================

    /**
     * 网格 {@code (R, C)} 与 {@code L_BFF} 的一次性产物。
     *
     * <pre>
     *   A1 SETUP  2: L_BFF ← |D|                       （由 A3 SETUP 3/6 的闭式给出）
     *   A1 SETUP  4: Select R, C such that RC ≥ L_BFF, R ≤ N.
     *   A1 SETUP  9-11: for u = L_BFF to RC − 1: D[u] ← 0
     *   A1 SETUP 14: P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r
     *   A1 QUERY  3: u_a ← h_a(K); r_a ← u_a mod R; c_a ← ⌊u_a/R⌋
     * </pre>
     *
     * <p>{@code r} 是"一条多项式里用多少个系数"（= 行数），
     * {@code c} 是"一个载荷块要几条多项式"（= 列数）。<b>不要</b>把 {@code N}
     * 与 {@code L_BFF} 搞混：前者是环维度（论文 16384），后者是 BFF 数组长度（论文 n=128 时 155）。
     *
     * <h3>⚠️ `R` 的策略是本实现定的，论文没有给</h3>
     * A1 SETUP 4 只写了约束 `RC ≥ L_BFF`、`R ≤ N`。我们取 **`R = C = √L_BFF`**：
     * <pre>
     *   R = 2^⌊log2 √L_BFF⌋        （不超过 √L_BFF 的最大 2 的幂）
     *   C = ⌈ L_BFF / R ⌉
     * </pre>
     * 三条依据：
     * <ol>
     *   <li><b>`R` 取 2 的幂</b>：FusePIR-C 的附录 B 写 *"the row bits drive the
     *       bitwise evaluation of BlindRotate"*，且 `ℓ_r = ⌈log2 R⌉` 是**位长**
     *       —— 只有 `R` 是 2 的幂时"按位分解行号"才是无损的。</li>
     *   <li><b>根号开在 `L_BFF` 上，不是 `N` 上</b>：FusePIR 属于 SealPIR/OnionPIR 一系，
     *       那一系把数据库切成 `√D × √D` 方格、查询发 `√D` 条密文；
     *       FusePIR 的 `R×C` + `C` 条列选择子就是这个结构，作用在 **BFF 数组**上。
     *       论文里**没有任何**式子把 `R` 与 `N` 挂钩（`N` 只出现在上界 `R ≤ N`）。</li>
     *   <li><b>`R` 与 `C` 是同一个代价的两头</b>：`C` ⇒ `C` 次 CtPtMul + `C` 条上传密文；
     *       `R` ⇒ `ℓ_r = ⌈log2 R⌉` 轮盲旋转。方格布局把两者平衡掉。</li>
     * </ol>
     *
     * <p><b>这条策略与论文自己那组实验对得上</b>（证据见 {@code MAP.md} §13.3）：
     * 论文报告"每查询 3 条 RLWE 密文"（安全性证明里的 `3ℓ`，`ℓ` = 查询次数）
     * 且查询大小 2304.97 KiB = 3 × 768 KiB（N=16384 + 3 个 60-bit 素数的一条密文）
     * ⇒ 论文在 `n ∈ {128,256,512}` 上 **`C = 1`**。
     * ⚠️ 我们的方格策略**不**给他们那个 `C = 1`（他们 `R ≥ L_BFF`），
     * 但两者都满足论文给出的**唯一约束**；我们取方格是因为它让
     * "同态选列"那一半真的在做事（`C = 1` 时列选择子是 `RLWE.Enc([1])`，不携带信息）。
     *
     * <p>⚠️ 反过来也要说清楚：**`C = 1` 时列选择子是 `RLWE.Enc([1])`，不携带查询信息**
     * —— 论文那套 `R×C` 的"密文列选择"在他们自己评估过的所有规模上都是**空转的**，
     * 要到 `L_BFF > N`（`n > N/1.21`，论文参数下 n > 13500）才会真正启用多列。
     * 所以 {@link #selectRC} 保留 {@code forceR} 参数：想看多列路径时显式指定小的 `R`。
     */
    public static final class Layout {
        /** {@code A1 SETUP 2}：`L_BFF ← |D|`。 */
        public final long lBff;
        /** {@code A3 SETUP 2/5}：段数 `s`（恒为 2 的幂）。 */
        public final long s;
        /** {@code A1 SETUP 4}：行数 `R` = 一条多项式里用到的系数个数。 */
        public final int r;
        /** {@code A1 SETUP 4}：列数 `C` = 一个载荷块的多项式条数。 */
        public final int c;
        /** 环维度 `N`（论文 16384）。 */
        public final int ringDim;
        /** 是否照论文策略自动选的 `R`（false 表示调用方强制指定）。 */
        public final boolean rIsAuto;

        Layout(long lBff, long s, int r, int c, int ringDim, boolean rIsAuto) {
            this.lBff = lBff;
            this.s = s;
            this.r = r;
            this.c = c;
            this.ringDim = ringDim;
            this.rIsAuto = rIsAuto;
        }

        /** `RC` —— A1 SETUP 9-11 那条尾部补零的上界。 */
        public long rc() {
            return (long) r * c;
        }

        /** 网格里非 `D` 的槽数：`RC − L_BFF`。为 0 时第 9-11 行是空循环。 */
        public long tailLen() {
            return rc() - lBff;
        }

        @Override
        public String toString() {
            return "L_BFF=" + lBff + ", s=" + s + ", R=" + r + (rIsAuto ? "(auto)" : "(forced)")
                + ", C=" + c + ", RC=" + rc() + ", tail=" + tailLen() + ", N=" + ringDim;
        }
    }

    /**
     * {@code BFF.Setup(n, 3)} + {@code A1 SETUP 4} 一次做完，返回 {@link Params} 与 {@link Layout}。
     *
     * @param n       关键词个数
     * @param k       arity（论文定死 3）
     * @param ringDim 环维度 `N`
     * @param forceR  强制指定的 `R`（{@code 0} = 用论文策略自动选）
     * @param useCeil {@code L_BFF} 闭式用 `⌈·⌉`（CAPE 附录 Alg 3）还是 `⌊·⌋`（ChalametPIR Alg 1），见 MAP §12.3
     */
    public static Layout selectRC(long n, int k, int ringDim, int forceR, boolean useCeil) {
        final Params p = setup(n, k, useCeil);
        return layout(p.lBff, p.s, ringDim, forceR);
    }

    /**
     * <b>按 BFF 参考实现的参数化定布局</b> —— 走 {@link BffHash#allocate} 的
     * {@code arrayLength} 与 {@code segmentLength}。
     *
     * <p>⚠️ <b>与 {@link #selectRC} 的区别不是风格，是数不一样</b>：
     * `n = 128` 时 CAPE Alg 3 L3 的闭式给 `L_BFF = 155`，
     * 而 BFF 参数化给 `arrayLength = 256`、`segmentLength = 64`。
     * 后者才是 {@code HashGen} 能落地的那个（前者连 `(segmentCount+k−1)·s` 都写不出来）。
     * 见 {@link BffHash} 的类注释与 MAP §12。
     */
    public static Layout fromBff(int n, int k, int ringDim, int forceR) {
        final BffHash.BffParams bp = BffHash.allocate(n, k);
        return layout(bp.arrayLength, bp.segmentLength, ringDim, forceR);
    }

    /**
     * 由<b>已经定好的</b> {@code (L_BFF, s)} 与 {@code R}、`N` 组装出 {@link Layout}。
     *
     * <h3>⚠️ `R` 的自动策略：`R = C = √L_BFF`（用户 2026-10-14 定）</h3>
     * <pre>
     *   R = 2^⌊log2 √L_BFF⌋        （不超过 √L_BFF 的最大 2 的幂）
     *   C = ⌈ L_BFF / R ⌉
     * </pre>
     * <b>为什么是"开在 L_BFF 上的根号"而不是"开在 N 上的"</b>：
     * FusePIR 属于 SealPIR/OnionPIR 一系，那一系的经典做法是把数据库切成
     * **`√D × √D` 的方格**、查询发 `√D` 条密文。FusePIR 的 `R×C` + `C` 条列选择子
     * 密文**就是这个结构**，只不过作用在 **BFF 数组（长度 `L_BFF`）**上。
     * ⇒ 同一条思路给出的根号是 `√L_BFF`，与环维度 `N` 无关。
     *
     * <p>⚠️ <b>论文里没有任何式子把 `R` 与 `N` 联系起来</b> —— 唯一提到 `N` 的地方
     * 就是那条上界 `R ≤ N`。所以 `R = √N` 是可以跑、但**没有依据**的取值
     * （而且 `n=128` 时 `√N ≈ 90 < L_BFF = 256`，落进 `C > 1` 那侧却并不是最平衡的点）。
     *
     * <h3>代价的两头（这才是 `R`、`C` 存在的理由）</h3>
     * <ul>
     *   <li>`C` ⇒ 列选择的开销与查询大小：`Acc_{a,b} = Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b})`
     *       是 `C` 次密文乘明文，`q_a^col` 是 `C` 条要上传的密文。</li>
     *   <li>`R` ⇒ 盲旋转的轮数：FusePIR-C 附录 B 明说 *"the row bits drive the bitwise
     *       evaluation of BlindRotate"*，位数正是 `ℓ_r = ⌈log2 R⌉`。
     *       ⇒ **`R` 取 2 的幂时按位分解无损**，所以这里恒取 2 的幂。</li>
     * </ul>
     * 方格布局把两者平衡在 `√L_BFF` 上。
     *
     * <h3>⚠️ 这条策略的副作用（必须一起说）</h3>
     * <b>当 `L_BFF` 是 2 的幂时，`R = C = √L_BFF` 给出 `RC = L_BFF` 恰好相等
     * ⇒ `A1 SETUP 9-11` 的尾部是空的（`tail = 0`）。</b>
     * 这是合法的（论文只要求 `RC ≥ L_BFF`），但意味着**那一步在我们的默认参数下不做任何事**。
     * 要让那一步真的清槽，只能取 `R > L_BFF`，而那时 `C = 1`
     * —— 二者在 `L_BFF` 为 2 的幂时**互斥**（`tail = 0 ⟺ R | L_BFF`，`C > 1 ⟺ R < L_BFF`）。
     * 需要非空尾部时用 {@code forceR} 显式指定（例如 `R = 8192`，尾部 7936 个槽）。
     *
     * @param forceR 强制指定的 `R`（{@code 0} = 用上面的方格策略）
     */
    public static Layout layout(long lBff, long s, int ringDim, int forceR) {
        if (lBff <= 0) {
            throw new IllegalArgumentException("L_BFF 必须 > 0");
        }
        final int r;
        final boolean auto;
        if (forceR > 0) {
            r = forceR;
            auto = false;
        } else {
            // 不超过 √L_BFF 的最大 2 的幂（方格布局的一边）
            final long root = (long) Math.floor(Math.sqrt((double) lBff));
            long p = 1;
            while (p * 2 <= root) {
                p <<= 1;
            }
            r = (int) Math.min(ringDim, Math.max(1L, p));
            auto = true;
        }
        if (r <= 0) {
            throw new IllegalArgumentException("R 必须 > 0");
        }
        if (r > ringDim) {
            throw new IllegalArgumentException("R=" + r + " > N=" + ringDim
                + "：A1 SETUP 4 要求 R ≤ N");
        }
        final int c = (int) Math.max(1, (lBff + r - 1) / r);
        return new Layout(lBff, s, r, c, ringDim, auto);
    }
}
