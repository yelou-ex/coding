package com.fusepir.prim;

import java.math.BigInteger;
import java.util.Random;

/**
 * <b>LWE 密钥切换（维度 N → d）</b>：把"维度 N、秘密为 {@code s}"的 LWE 样本，
 * 搬到"维度 d、秘密为<b>另一把无关密钥</b> {@code s'}"的 LWE 样本上。
 *
 * <h3>为什么需要它（论文位置）</h3>
 * 论文 §2.5 讲 {@code SampleExtract} 时写明：SampleExtract <b>可以包含一次密钥切换</b>，
 * 切到"后续计算所用的那把 LWE 密钥"上（原文：{@code SampleExtract may include a key switch
 * to the LWE key used in subsequent computation}）。
 * 本项目此前把这一步省掉了——代码把 {@code d} 硬钉成 {@code N}
 * （LWE-in-RLWE：LWE 秘密就是 RLWE 环秘密本身，见 {@link LweRlweConversion}），
 * 于是 {@code SampleExtract} 天然不需要切换。代价是：只要想拿这把 LWE 密钥再做别的事，
 * 密钥维度就只能按 {@code N = 8192} 算，而它按 {@code d = 16} 算就够了——
 * 同一套密钥结构下体积差 {@code (N+1)/(d+1) ≈ 512} 倍（对 N=8192、d=16）。本类补上这一步。
 *
 * <h3>相位约定（先看这条，否则符号会错）</h3>
 * 本类<b>统一</b>采用 {@code 相位 = b − ⟨a,s⟩}：加密写 {@code b = ⟨a,s⟩ + m}，
 * 解密 {@link #decrypt} 就是返回 {@code b − ⟨a,s⟩}。
 * 任务书给的正确性判据也是这个符号：{@code b' − ⟨a',s'⟩ ≡ b − ⟨a,s⟩ (mod t)}。
 *
 * <h3>构造（标准 gadget 分解型密钥切换，本类自己实现）</h3>
 * <ol>
 *   <li><b>切换密钥</b>：{@code ksk[j][k] = LWE_{s'}( B^k · s[j] mod t )}，
 *       即 {@code ksk[j][k].b = ⟨ksk[j][k].a, s'⟩ + B^k·s[j] mod t}，
 *       其中 {@code j ∈ [0,N)}、{@code k ∈ [0,digits)}、{@code B} 是 gadget 基。
 *       覆盖性要求 <b>{@code B^digits ≥ t}</b>（见 {@link #checkCoverage}：不满足直接抛异常，
 *       绝不静默截断）。</li>
 *   <li><b>分解</b>：把每个 {@code a[j] ∈ [0,t)} 拆成 {@code digits} 个基 {@code B} 的"小数字"
 *       {@code a[j][k]}，即 {@code a[j] = Σ_k a[j][k]·B^k}，{@code 0 ≤ a[j][k] < B}。</li>
 *   <li><b>切换</b>：
 *       <pre>
 *   b' = b − Σ_j Σ_k a[j][k]·ksk[j][k].b   (mod t)
 *   a' = − Σ_j Σ_k a[j][k]·ksk[j][k].a     (d 维向量, mod t)
 *       </pre>
 *       即"从 {@code b' = b}、{@code a' = 0} 起，把每一项<b>减</b>进去"。
 *       </li>
 * </ol>
 *
 * <h3>⚠️ 与任务书文字的一处符号偏离（必须知道）</h3>
 * 任务书同时给了三句话：(a) ksk 载荷是 {@code +B^k·s[j]}；(b) 切换时 {@code b' = b + Σ…}、
 * {@code a' = Σ…}（"加法累加"）；(c) 结果必须满足 {@code b' − ⟨a',s'⟩ ≡ b − ⟨a,s⟩}。
 * <b>这三句在 {@code 相位 = b − ⟨a,s⟩} 约定下不能同时成立</b>：按 (a)+(b) 推出的实际关系是
 * {@code b' − ⟨a',s'⟩ ≡ b + ⟨a,s⟩}（推导：{@code b' − ⟨a',s'⟩ = b + Σ a[j][k](b_{jk} − ⟨a_{jk},s'⟩)
 * = b + Σ a[j][k]B^k s[j] = b + ⟨a,s⟩}）。于是用任务书自检里那条
 * {@code b = ⟨a,s⟩ + m} 的样本，解出来的相位是 {@code m + 2⟨a,s⟩} 而<b>不是</b> {@code m}——
 * 往返直接失败（本项目已实测：见 {@code LweKeySwitchTest} 的 {@code [sign-probe]} 一行，
 * 它把两种符号都算出来打印，加法版给出非 m）。
 *
 * <p>本类的取舍：<b>保留 (a) 的 ksk 载荷定义，把 (b) 改成减法累加</b>，因为 (c) 是可验证的
 * 判据（也是"用 s' 解密必须等于 m"的直接来源），而 (b) 只是实现描述。
 * 这个形式就是 BV 密钥切换里 {@code c' = (0,b) − Σ a_{j,τ}·c̃_{j,τ}} 的写法。
 * 若改用"加法累加"，等价的做法是把 ksk 载荷取负（{@code LWE_{s'}(−B^k·s[j])}）——两条路等价，
 * 但都<b>必须</b>有一处负号，不能两处都是正的。
 *
 * <h3>为什么正确（一句话证明）</h3>
 * 由 {@code b_{jk} − ⟨a_{jk}, s'⟩ ≡ B^k·s[j]}，乘以 {@code a[j][k]} 对 {@code (j,k)} 求和：
 * <pre>
 *   b' − ⟨a',s'⟩ = b − Σ_{j,k} a[j][k]·(b_{jk} − ⟨a_{jk},s'⟩)
 *                = b − Σ_{j,k} a[j][k]·B^k·s[j]
 *                = b − Σ_j a[j]·s[j] = b − ⟨a,s⟩        (mod t)  ✅
 * </pre>
 *
 * <h3>与 {@code SampleExtract} 的符号对接（集成提示，本类不接线）</h3>
 * {@link LweRlweBridge#sampleExtract} 抽出的样本用的是另一种约定
 * （那边写 {@code b + ⟨a,s⟩ = 相位}，负循环的索引把符号吃进了 a 里）。
 * 要把那种样本喂进本类，只需先把 a <b>取负</b>（{@code a ← −a mod t}）：
 * {@code b + ⟨a,s⟩ = b − ⟨−a,s⟩}。本类不做自动适配——宁可让调用方显式写这一步，
 * 也不想在符号上猜。
 *
 * <h3>本类<b>不</b>做、也<b>没</b>验证的事（诚实清单）</h3>
 * <ul>
 *   <li><b>不含噪声</b>：本项目这一层的模数是精确的 {@code t = 65537}（没有舍入、没有
 *       {@code Δ = q/t} 的缩放），所以 ksk 用<b>无噪声</b>的精确加密
 *       {@code b = ⟨a,s'⟩ + 载荷 mod t}。密钥切换因此是<b>精确同态</b>的，
 *       往返逐位可复现。真实 LWE 还要加高斯噪声并依赖噪声增长上界，
 *       <b>本类不模拟噪声增长</b>——"噪声预算"这一维度未验证。</li>
 *   <li><b>不检查 s 与 s' 是否独立</b>：本地无法验证两把密钥的独立性，这是调用方的责任。
 *       （探针里专门用"故意相关的 s'"做负对照，说明本类确实不会替你发现这件事。）</li>
 *   <li><b>不做模数切换</b>：输入输出都在同一个 {@code t} 下。若样本来自 RLWE 层的大模数
 *       {@code q_R}，那一步缩放属 {@link LweRlweConversion} 的范围，不在本类。</li>
 *   <li><b>数值范围有上限</b>：要求 {@code t ≤ 2^31} 且 {@code base ≤ t}，
 *       以保证热循环里的 {@code long} 乘法不溢出（见 {@link #generate} 的守卫）。
 *       本项目的 {@code t = 65537}、{@code base = 256} 远在范围内。</li>
 *   <li><b>没有做安全性评估</b>：{@code s'} 维度只有 {@code d = 16}、且 ksk 无噪声，
 *       这是一份"功能正确性"实现，不是安全参数选择建议。</li>
 * </ul>
 *
 * <h3>调用说明</h3>
 * 生成密钥：{@link #generate}；切换样本：{@link #switchSample}；解密验证：{@link #decrypt}。
 * 自检见 {@code com.fusepir.probe.LweKeySwitchTest}。
 */
public final class LweKeySwitch {

    private LweKeySwitch() {
    }

    // ==================================================================
    //  切换密钥
    // ==================================================================

    /**
     * 切换密钥 {@code ksk[j][k] = LWE_{s'}(B^k·s[j] mod t)} 的容器。
     *
     * <p>存储用<b>扁平数组</b>而不是 {@code long[][]}：
     * 第 {@code e = j·digits + k} 条占据 {@code b[e]} 与 {@code a[e·d .. e·d+d)}。
     * 这样 {@code long[][]} 的每行对象头开销（约 16 B/行，N=8192/digits=3 时约 0.4 MB）
     * 就不进来了，{@link #bytes()} 的口径也因此干净：{@code 条数 × (d+1) × 8}。
     * <b>不计</b>的部分：对象头、数组头（合计几十字节，可忽略）。
     */
    public static final class SwitchKey {

        private final int n;
        private final int d;
        private final int base;
        private final int digits;
        private final long t;
        /** 长度 = N·digits，第 e 条的 b。 */
        private final long[] b;
        /** 长度 = N·digits·d，第 e 条的 d 维 a。 */
        private final long[] a;

        private SwitchKey(int n, int d, int base, int digits, long t, long[] b, long[] a) {
            this.n = n;
            this.d = d;
            this.base = base;
            this.digits = digits;
            this.t = t;
            this.b = b;
            this.a = a;
        }

        /** 原样本维度 N（RLWE 环秘密的系数个数）。 */
        public int dimensionN() {
            return n;
        }

        /** 目标维度 d（后续计算所用的独立 LWE 密钥维度）。 */
        public int dimensionD() {
            return d;
        }

        /** gadget 基 B。 */
        public int base() {
            return base;
        }

        /** gadget 位数（分解出的数字个数）。 */
        public int digits() {
            return digits;
        }

        /** 模数 t。 */
        public long modulus() {
            return t;
        }

        /** 密钥条数 = N·digits（每条本身是一个 d 维 LWE 样本）。 */
        public int entries() {
            return n * digits;
        }

        /**
         * 密钥字节数 = {@code 条数 × (d+1) × 8}。
         *
         * <p>口径说明：每条 LWE 样本 = 1 个 b + d 个 a，各占 8 字节（{@code long}）。
         * <b>不含</b> JVM 对象头/数组头（几十字节），也<b>不含</b>网络序列化的长度前缀——
         * 后者取决于具体线格式，本类不做假设（本项目 t=65537 时其实 17 bit/系数就够，
         * 若按位打包还能再小，但那是编码层的事，不在这里虚报）。
         */
        public long bytes() {
            return (long) entries() * (d + 1) * 8L;
        }

        /** 第 (j,k) 条密钥的 b（带下标守卫，越界直接抛，不做静默钳位）。 */
        public long kskB(int j, int k) {
            return b[entryIndex(j, k)];
        }

        /** 第 (j,k) 条密钥 a 的第 i 个分量（带下标守卫）。 */
        public long kskA(int j, int k, int i) {
            int e = entryIndex(j, k);
            if (i < 0 || i >= d) {
                throw new IllegalArgumentException("目标维度下标 i=" + i + " 越界（d=" + d + "）");
            }
            return a[e * d + i];
        }

        private int entryIndex(int j, int k) {
            if (j < 0 || j >= n) {
                throw new IllegalArgumentException("源维度下标 j=" + j + " 越界（N=" + n + "）");
            }
            if (k < 0 || k >= digits) {
                throw new IllegalArgumentException("数字下标 k=" + k + " 越界（digits=" + digits + "）");
            }
            return j * digits + k;
        }

        /** 一行描述，便于探针打印口径。 */
        public String describe() {
            String exp = (base > 0 && (base & (base - 1)) == 0)
                ? "2^" + Integer.numberOfTrailingZeros(base) : "非 2 的幂";
            return String.format(
                "ksk[N=%d, d=%d, base=%d=%s, digits=%d, t=%d] = %d 条 × %d 个 long = %,d B",
                n, d, base, exp, digits, t, entries(), d + 1, bytes());
        }
    }

    // ==================================================================
    //  守卫
    // ==================================================================

    /**
     * <b>覆盖性守卫：{@code B^digits ≥ t} 必须成立，否则抛异常。</b>
     *
     * <p>为什么用断言而不是注释：不满足时 {@code a[j]} 的高位<b>会被静默丢掉</b>
     * （分解只剩余数），切换结果看起来"正常"但相位是错的——本项目被这类静默错值
     * 坑过多次，所以这里宁可炸。
     *
     * <p>边界是<b>精确</b>的：取值域是 {@code [0,t)}，所以需要 {@code B^digits ≥ t}；
     * 例如 {@code t = 65537} 时 {@code 256^2 = 65536 = t−1} <b>不够</b>（差 1），
     * 而 {@code 256^3 = 16777216} 够。
     *
     * <p>用 {@link BigInteger} 算幂：{@code B^digits} 很容易超出 {@code long}
     * （例如 {@code 256^9 = 2^72}），用 {@code long} 会溢出成一个假的"通过"。
     *
     * @throws IllegalArgumentException 当 {@code t < 2}、{@code base < 2}、{@code digits < 1}，
     *         或 {@code base^digits < t} 时
     */
    public static void checkCoverage(long t, int base, int digits) {
        if (t < 2) {
            throw new IllegalArgumentException("模数 t=" + t + " 非法：必须 ≥ 2");
        }
        if (base < 2) {
            throw new IllegalArgumentException("gadget 基 base=" + base + " 非法：必须 ≥ 2");
        }
        if (digits < 1) {
            throw new IllegalArgumentException("gadget 位数 digits=" + digits + " 非法：必须 ≥ 1");
        }
        BigInteger cover = BigInteger.valueOf(base).pow(digits);
        BigInteger modulus = BigInteger.valueOf(t);
        if (cover.compareTo(modulus) < 0) {
            throw new IllegalArgumentException(
                "gadget 覆盖不足：base^digits = " + base + "^" + digits + " = " + cover
                    + " < t = " + t + "，缺 " + modulus.subtract(cover)
                    + "；这样分解会静默丢掉高位，切换后的相位是错的。请增大 digits 或 base。");
        }
    }

    // ==================================================================
    //  密钥生成
    // ==================================================================

    /**
     * 生成切换密钥：{@code ksk[j][k] = LWE_{s'}( B^k · s[j] mod t )}。
     *
     * <p>每条都是一个 d 维、秘密为 {@code s'} 的 LWE 样本，载荷（相位）是
     * {@code B^k · s[j] mod t}，也就是 {@code b = ⟨a,s'⟩ + 载荷 mod t}。
     * 每条独立均匀采样 {@code a}（由 {@code rnd} 决定）——<b>无噪声</b>，理由见类注释的诚实清单。
     *
     * <p><b>关于 s 与 s' 的独立性</b>：本方法<b>不检查、也无法检查</b>。
     * 传进相关的两把密钥（例如 {@code s' = s[0..d)}）会得到一个"看起来正常、
     * 但切换后仍能用 s 的前 d 位解开"的密钥——探针 {@code LweKeySwitchTest}
     * 专门把这种情况当作负对照，用来证明它的"错密钥解出垃圾"检查确实有效。
     *
     * @param s      源秘密，长度 N（即 d 以外的维度），每个分量须在 {@code [0,t)}
     * @param sPrime 目标秘密，长度 d，每个分量须在 {@code [0,t)}；必须<b>独立</b>于 {@code s}
     * @param t      模数（本项目 {@code 65537}）
     * @param base   gadget 基 B（本项目 {@code 256}）
     * @param digits gadget 位数（本项目 {@code 3}，覆盖 {@code 256^3 = 2^24 > t}）
     * @param rnd    随机源；固定种子 ⇒ 结果可复现
     * @throws IllegalArgumentException 参数非法、覆盖不足、或秘密分量越界
     */
    public static SwitchKey generate(long[] s, long[] sPrime, long t, int base, int digits, Random rnd) {
        if (s == null || s.length < 1) {
            throw new IllegalArgumentException("源秘密 s 为空");
        }
        if (sPrime == null || sPrime.length < 1) {
            throw new IllegalArgumentException("目标秘密 s' 为空（维度 d 必须 ≥ 1）");
        }
        if (rnd == null) {
            throw new IllegalArgumentException("随机源 rnd 为 null");
        }
        checkCoverage(t, base, digits);
        // 溢出守卫：base ≤ t ≤ 2^31 ⇒ 数字(<base) × ksk 系数(<t) < 2^62，
        // 热循环里的 long 累加不会溢出。超出就得换 BigInteger，本类不假装支持。
        if (t > (1L << 31)) {
            throw new IllegalArgumentException(
                "模数 t=" + t + " 超过本类上限 2^31：热循环的 long 乘法会溢出，请改用 BigInteger 版本");
        }
        if (base > t) {
            throw new IllegalArgumentException("gadget 基 base=" + base + " > t=" + t + "：基不应大于模数");
        }

        int n = s.length;
        int d = sPrime.length;
        long[] sn = new long[n];
        for (int j = 0; j < n; j++) {
            if (s[j] < 0 || s[j] >= t) {
                throw new IllegalArgumentException("s[" + j + "]=" + s[j] + " 不在 [0," + t + ") 内");
            }
            sn[j] = s[j];
        }
        for (int i = 0; i < d; i++) {
            if (sPrime[i] < 0 || sPrime[i] >= t) {
                throw new IllegalArgumentException("s'[" + i + "]=" + sPrime[i] + " 不在 [0," + t + ") 内");
            }
        }

        long[] b = new long[n * digits];
        long[] a = new long[n * digits * d];
        for (int j = 0; j < n; j++) {
            long power = 1;                       // B^k mod t
            for (int k = 0; k < digits; k++) {
                int e = j * digits + k;
                long mu = power * sn[j] % t;      // 载荷 = B^k · s[j] mod t
                long acc = 0;
                int off = e * d;
                for (int i = 0; i < d; i++) {
                    long ai = Math.floorMod(rnd.nextLong(), t);
                    a[off + i] = ai;
                    acc = (acc + ai * sPrime[i]) % t;
                }
                b[e] = (acc + mu) % t;
                power = power * base % t;
            }
        }
        return new SwitchKey(n, d, base, digits, t, b, a);
    }

    // ==================================================================
    //  切换 / 解密 / 工具
    // ==================================================================

    /**
     * 把维度 N 的样本 {@code (a, b)} 切换到维度 d：返回 {@code long[d+1]}，
     * 约定与 {@link LweRlweBridge#sampleExtract} 一致：{@code [0] = b'}，
     * {@code [1..d] = a'}。
     *
     * <p>实现就是"从 {@code b' = b}、{@code a' = 0} 起，逐条把
     * {@code a[j][k]·ksk[j][k]} <b>减</b>进去"（负号的理由见类注释的"符号偏离"一节）。
     * 数学上等价于先算正和 {@code S_b = Σ a[j][k]·ksk[j][k].b}、
     * {@code S_a = Σ a[j][k]·ksk[j][k].a}，再取
     * {@code b' = b − S_b}、{@code a' = −S_a}——本实现就是这么算的（先累正和再取负），
     * 因为 {@code floorMod} 在热循环里更贵。
     *
     * <p><b>每一步都 mod t</b>，不攒大和：{@code a[j][k] < base ≤ t}、
     * {@code ksk 系数 < t}，单项 < 2^62，加上 {@code acc < t} 仍在 {@code long} 内
     * （见类注释的上限约定）。
     *
     * @param key 切换密钥
     * @param a   源样本的 a，长度必须<b>恰好</b>等于 {@code key.dimensionN()}，分量在 {@code [0,t)} 内
     * @param b   源样本的 b（会先 mod t 归一）
     * @throws IllegalArgumentException 维度不符或分量越界
     */
    public static long[] switchSample(SwitchKey key, long[] a, long b) {
        if (key == null) {
            throw new IllegalArgumentException("切换密钥为 null");
        }
        if (a == null || a.length != key.n) {
            throw new IllegalArgumentException(
                "样本 a 的维度 " + (a == null ? "null" : String.valueOf(a.length))
                    + " 与切换密钥的 N=" + key.n + " 不一致：密钥切换不会自动适配维度，"
                    + "维度搞错会静默产出垃圾。");
        }
        long t = key.t;
        long[] sumA = new long[key.d];
        long sumB = 0;
        for (int j = 0; j < key.n; j++) {
            long aj = a[j];
            if (aj < 0 || aj >= t) {
                throw new IllegalArgumentException("a[" + j + "]=" + aj + " 不在 [0," + t + ") 内");
            }
            if (aj == 0) {
                continue;                     // 整个 j 的数字全 0，跳过（纯优化，不改变结果）
            }
            long[] dig = decompose(aj, key.base, key.digits);
            for (int k = 0; k < key.digits; k++) {
                long c = dig[k];
                if (c == 0) {
                    continue;
                }
                int e = j * key.digits + k;
                sumB = (sumB + c * key.b[e]) % t;
                int off = e * key.d;
                for (int i = 0; i < key.d; i++) {
                    sumA[i] = (sumA[i] + c * key.a[off + i]) % t;
                }
            }
        }
        long[] out = new long[key.d + 1];
        out[0] = Math.floorMod(Math.floorMod(b, t) - sumB, t);
        for (int i = 0; i < key.d; i++) {
            out[1 + i] = sumA[i] == 0 ? 0 : t - sumA[i];   // 取负：a' = −S_a mod t
        }
        return out;
    }

    /**
     * 解密：{@code 相位 = b − ⟨a,s⟩ mod t}。
     *
     * <p>样本约定：{@code sample[0] = b}，{@code sample[1..len]} 是 a（与
     * {@link LweRlweBridge} 一致）。本类按"相位 = 消息 m"构造样本
     * （即 {@code b = ⟨a,s⟩ + m}），所以解密返回的就是 m。
     *
     * <p><b>维度必须严丝合缝</b>：{@code sample.length == secret.length + 1}，
     * 否则抛异常。这条守卫是刻意加的——"用错密钥/错维度去解"是本仓库反复出现的
     * 静默错值来源，这里让它要么正确、要么响。
     * （想用截断的密钥做负对照，请显式截断后再调，见探针的做法。）
     *
     * @param secret 维度恰为 {@code sample.length − 1} 的秘密向量
     * @throws IllegalArgumentException 长度不匹配或 {@code t < 2}
     */
    public static long decrypt(long[] sample, long[] secret, long t) {
        if (sample == null || secret == null) {
            throw new IllegalArgumentException("sample 或 secret 为 null");
        }
        if (t < 2) {
            throw new IllegalArgumentException("模数 t=" + t + " 非法：必须 ≥ 2");
        }
        if (sample.length != secret.length + 1) {
            throw new IllegalArgumentException(
                "维度不匹配：样本长度 " + sample.length + "（= d+1 ⇒ d=" + (sample.length - 1)
                    + "），秘密长度 " + secret.length
                    + "。用错维度解密不会报错到别处，只会给出垃圾值，因此这里直接抛。");
        }
        return Math.floorMod(sample[0] - innerProduct(sample, 1, secret, t), t);
    }

    /** ⟨a, s⟩ mod t，{@code a} 从下标 {@code a0} 开始读。长度不符直接抛。 */
    public static long innerProduct(long[] a, int a0, long[] s, long t) {
        if (a == null || s == null) {
            throw new IllegalArgumentException("innerProduct 的入参为 null");
        }
        if (a0 < 0 || a.length - a0 < s.length) {
            throw new IllegalArgumentException(
                "内积长度不匹配：a 从 " + a0 + " 起只剩 " + (a.length - a0) + " 个，秘密有 " + s.length + " 个");
        }
        long acc = 0;
        for (int i = 0; i < s.length; i++) {
            acc = (acc + Math.floorMod(a[a0 + i], t) * Math.floorMod(s[i], t)) % t;
        }
        return acc;
    }

    /** ⟨a, s⟩ mod t（两向量必须等长）。 */
    public static long innerProduct(long[] a, long[] s, long t) {
        if (a == null || s == null) {
            throw new IllegalArgumentException("innerProduct 的入参为 null");
        }
        if (a.length != s.length) {
            throw new IllegalArgumentException(
                "内积维度不匹配：a 长 " + a.length + "，s 长 " + s.length);
        }
        return innerProduct(a, 0, s, t);
    }

    /**
     * 把 {@code value ∈ [0, base^digits)} 拆成 {@code digits} 个基 {@code base} 的小数字（低位在前）。
     *
     * <p><b>越界就抛，不截断</b>：拆完 {@code digits} 位后若余数非零，说明
     * {@code value ≥ base^digits}，高位装不下。判据 {@code 余数 == 0} 与
     * {@code value < base^digits} 完全等价，而且<b>不需要算幂</b>（也就没有溢出问题）。
     * 例如 {@code t = 65537}、{@code base = 256}、{@code digits = 2} 时
     * {@code value = 65536} 会拆出 {@code [0,0]} 并留下余数 1——正是会被静默截断的那个值。
     *
     * @throws IllegalArgumentException {@code base < 2}、{@code digits < 1}、{@code value < 0}，
     *         或 {@code value ≥ base^digits}
     */
    public static long[] decompose(long value, int base, int digits) {
        if (base < 2) {
            throw new IllegalArgumentException("gadget 基 base=" + base + " 非法：必须 ≥ 2");
        }
        if (digits < 1) {
            throw new IllegalArgumentException("gadget 位数 digits=" + digits + " 非法：必须 ≥ 1");
        }
        if (value < 0) {
            throw new IllegalArgumentException("待分解值 value=" + value + " 为负：请先归一化到 [0,t)");
        }
        long[] out = new long[digits];
        long v = value;
        for (int k = 0; k < digits; k++) {
            out[k] = v % base;
            v /= base;
        }
        if (v != 0) {
            throw new IllegalArgumentException(
                "值 " + value + " 超出 base^digits = " + base + "^" + digits
                    + " 的可分解范围（拆完 " + digits + " 位仍余 " + v
                    + "）：高位会被静默丢掉，故直接抛。");
        }
        return out;
    }
}
