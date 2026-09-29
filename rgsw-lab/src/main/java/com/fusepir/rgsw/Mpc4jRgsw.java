package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Decryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Encryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Evaluator;
import edu.alibaba.mpc4j.crypto.fhe.seal.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.RelinKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.Modulus;

import java.math.BigInteger;
import java.util.Random;

/**
 * 建立在 <b>MPC4J 的 BFV</b> 之上的 RGSW 层。
 *
 * <h3>⚠️ 路线提示（详见 coding/RLWE路线审计.md）</h3>
 * 本文件走的是 <b>路线 B：纯 Java 移植版</b>（`edu.alibaba.mpc4j.crypto.fhe.seal.*`，
 * 即 `coding/lib/mpc4j-crypto-fhe-seal.jar`），<b>不是</b>目标路线
 * <b>路线 A：native</b>（`coding/native-jni/lib/mpc4j-native-fhe.dll` + 真 SEAL 4.0.0）。
 *
 * <p>为什么还没搬：native 侧现在只有<b>协议级</b>接口（keyGen/generateQuery/generateReply/…），
 * <b>没有原语级接口，也没有任何 RGSW 实现</b>。要让 RGSW 也走 native，必须先给那个 DLL
 * 增加一层原语级 JNI（含 RGSW/外部乘积/CMUX）。在那之前，本文件的价值是：
 * <b>RGSW 逻辑的正确实现 + 测试基准</b>（自检 5/5 全绿），迁到 native 时按同样的算法照搬。
 *
 * <p>与 `com.fusepir.rlwe`（自研 RLWE，路线 C）的关系：自研那套已弃用，只作为交叉校验保留。
 * 理由：协议级运算（CtCtMul / 重线性化含缩放回落 / 槽位打包 / 旋转 / 序列化）MPC4J 都是现成且成熟的，
 * 自研那套要补齐这些需要几百行高难度代码（实测已经卡在"缩放回落"上）。
 *
 * <h3>RGSW 与外部乘积怎么架在 MPC4J 上</h3>
 * <ul>
 *   <li><b>原始加密</b>：MPC4J 没有"不缩放加密"，用
 *       "加密零 + 把消息加进系数"来实现。注意 SEAL 的密文默认在 <b>NTT 域</b>，
 *       而 NTT 是线性的，所以可以直接在 NTT 域加消息：
 *       <br>· 常数消息 g → 每个 NTT 系数都加 g（因为 NTT(常数 c) = 全 c）
 *       <br>· 消息 g·s → 加 g·(密钥的 NTT 系数)，而 SEAL 的私钥本来就是 NTT 存储的</li>
 *   <li><b>切段</b>：把源密文拷一份、转回系数域，逐系数跨素数还原成大整数，再按 B 进制切段；</li>
 *   <li><b>外部乘积</b>：每层用 {@code Evaluator.multiplyPlain}（乘的是公开的数字多项式）
 *       与 RGSW 分量相乘并累加。数字小于 B，而 B = 2^16 = 65536 &lt; t = 65537，正好落在 Z_t 里。</li>
 * </ul>
 */
public final class Mpc4jRgsw {

    /** 多项式次数 */
    public final int n;
    /** 明文模数 t */
    public final long t;
    /** gadget 基数 B */
    public final int base;
    /** gadget 层数 */
    public final int levels;

    public final EncryptionParameters parms;
    public final SealContext context;
    public final KeyGenerator keyGen;
    public final SecretKey sk;
    public final Encryptor encryptor;
    public final Decryptor decryptor;
    public final Evaluator evaluator;

    /** 系数模数的各素数 */
    public final Modulus[] primes;
    /** 系数模数 q = 各素数之积 */
    public final BigInteger q;
    /** q 的位宽 */
    public final int qBits;
    /** 增量式 CRT 每一步的逆元 */
    private final BigInteger[] crtStepInv;

    /**
     * 密文实际使用的模数分量个数。
     *
     * <p><b>它比 {@code parms.coeffModulus().length} 少一个</b>：BFV 会把最后一个素数留作
     * 缩放用的特殊素数 {@code q_last}（密文×密文之后要用它做 divide_and_round）。
     * 所以 N=16384 时"声明 9 个素数 / 438 位"，而密文里只有 8 个分量 / 389 位工作模数。
     *
     * <p>踩坑记录：之前按 {@code primes.length}（9）去索引密文数据，在 N=2048
     * （只有 1 个素数、没有特殊素数）时一直是巧合正确，到论文规模才崩：
     * {@code ArrayIndexOutOfBoundsException: Index 262144 out of bounds for length 262144}
     * （262144 = 2 分量 × 8 素数 × 16384）。
     */
    public final int workingPrimeCount;
    /** 声明模数的位宽（含特殊素数），仅用于展示 */
    public final int declaredQBits;

    /** 重线性化密钥的缓存（懒生成）。做 {@code CtCtMul} 必需。 */
    private RelinKeys relinKeys;

    /**
     * 重线性化密钥（懒生成并缓存）。
     *
     * <p><b>⚠️ 只有 ≥2 个工作素数时才可用</b>：重线性化需要密钥切换，而 N=2048 时
     * {@code bfvDefault} 只给 1 个素数，会抛
     * {@code keyswitching is not supported by the context}。
     * 实测：<b>N ≥ 4096 才能做密文×密文</b>（N=4096 声明 3 素数/工作 2 素数）。
     */
    public RelinKeys relinKeys() {
        if (relinKeys == null) {
            RelinKeys keys = new RelinKeys();
            keyGen.createRelinKeys(keys);
            relinKeys = keys;
        }
        return relinKeys;
    }

    /** @param unused 保留参数（素数个数由 bfvDefault 自动决定） */
    public Mpc4jRgsw(int n, long t, int unused, int base) {
        this.n = n;
        this.t = t;
        this.base = base;

        this.parms = new EncryptionParameters(SchemeType.BFV);
        parms.setPolyModulusDegree(n);
        parms.setCoeffModulus(CoeffModulus.bfvDefault(n)); // 自带符合 128-bit 安全标准的参数
        parms.setPlainModulus(new Modulus(t));
        this.context = new SealContext(parms);
        if (!context.isParametersSet()) {
            throw new IllegalStateException("SEAL 参数无效: " + context.parametersErrorMessage());
        }
        this.primes = parms.coeffModulus();
        int declaredBits = 0;
        BigInteger declaredProd = BigInteger.ONE;
        for (Modulus m : primes) {
            declaredBits += m.bitCount();
            declaredProd = declaredProd.multiply(BigInteger.valueOf(m.value()));
        }
        this.declaredQBits = declaredBits;

        this.keyGen = new KeyGenerator(context);
        this.sk = keyGen.secretKey();
        this.encryptor = new Encryptor(context, sk);
        this.decryptor = new Decryptor(context, sk);
        this.evaluator = new Evaluator(context);

        // 用一条真实密文的数组长度反推"工作层"的素数个数，比猜 API 可靠：
        // 布局是 [size][coeffModulusSize][n]，所以 coeffModulusSize = length / (size * n)。
        Ciphertext probeCt = new Ciphertext();
        encryptor.encryptZeroSymmetric(probeCt);
        this.workingPrimeCount = probeCt.data().length / (probeCt.size() * n);

        // q 与层数都按"工作模数"算（不含 q_last），否则层数会偏多、白做几层
        BigInteger prod = BigInteger.ONE;
        for (int j = 0; j < workingPrimeCount; j++) {
            prod = prod.multiply(BigInteger.valueOf(primes[j].value()));
        }
        this.q = prod;
        this.qBits = q.bitLength();

        BigInteger running = BigInteger.ONE;
        this.crtStepInv = new BigInteger[workingPrimeCount];
        for (int k = 0; k < workingPrimeCount; k++) {
            if (k == 0) {
                running = BigInteger.valueOf(primes[0].value());
                continue;
            }
            BigInteger mk = BigInteger.valueOf(primes[k].value());
            crtStepInv[k] = running.mod(mk).modInverse(mk);
            running = running.multiply(mk);
        }

        this.levels = levelsFor(base, q);
    }

    private static int levelsFor(int base, BigInteger q) {
        int l = 1;
        BigInteger cap = BigInteger.valueOf(base);
        while (cap.compareTo(q) <= 0) {
            cap = cap.multiply(BigInteger.valueOf(base));
            l++;
        }
        return l;
    }

    // ---------------- 基本 RLWE 运算（全部走 MPC4J） ----------------

    /** 普通 BFV 加密：消息 ∈ Z_t */
    public Ciphertext encrypt(long[] m) {
        Plaintext pt = new Plaintext(m);
        Ciphertext ct = new Ciphertext();
        encryptor.encryptSymmetric(pt, ct);
        return ct;
    }

    /**
     * 解密：MPC4J 内部已完成缩放与取整，直接得到 Z_t 上的消息。
     *
     * <p>注意 BFV 解密要求密文处于<b>系数域</b>，所以 NTT 域的密文要先转回来
     * （拷一份转，不改调用方的密文）。
     */
    public long[] decrypt(Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(n);
        decryptor.decrypt(copy, pt);
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            out[i] = pt.get(i);
        }
        return out;
    }

    public void addInplace(Ciphertext acc, Ciphertext x) {
        evaluator.addInplace(acc, x);
    }

    public void subInplace(Ciphertext acc, Ciphertext x) {
        evaluator.subInplace(acc, x);
    }

    public Ciphertext add(Ciphertext x, Ciphertext y) {
        Ciphertext out = new Ciphertext();
        evaluator.add(x, y, out);
        return out;
    }

    /** 加密零 */
    public Ciphertext encryptZero() {
        Ciphertext ct = new Ciphertext();
        encryptor.encryptZeroSymmetric(ct);
        return ct;
    }

    /** 确保密文处于 NTT 域（MPC4J 的密文形式跟着明文走，所以要显式统一） */
    private Ciphertext toNtt(Ciphertext ct) {
        if (!ct.isNttForm()) {
            evaluator.transformToNttInplace(ct);
        }
        return ct;
    }

    // ---------------- 原始加密（不缩放）+ RGSW ----------------

    /**
     * 在 NTT 域把一个"常数消息 g"加到密文的分量 polyIndex 上。
     * NTT(常数 c) = 全 c，所以每个 NTT 系数都加 g。
     */
    private void addConstantNtt(Ciphertext ct, int polyIndex, BigInteger g) {
        long[] data = ct.data();
        // 必须用工作层的素数个数（比声明少一个，见 workingPrimeCount 的说明）
        int L = workingPrimeCount;
        for (int j = 0; j < L; j++) {
            long p = primes[j].value();
            long v = g.mod(BigInteger.valueOf(p)).longValue();
            int off = (polyIndex * L + j) * n;
            for (int i = 0; i < n; i++) {
                long s = data[off + i] + v;
                data[off + i] = s >= p ? s - p : s;
            }
        }
    }

    /*
     * 【曾经踩过的坑，留档以免以后又走回头路】
     *
     * 早期这里有一个 addScaledSecretNtt()：把私钥 s 当作 NTT 域数组，逐系数乘 g 再加到密文上，
     * 用来构造 group1 的相位 g·s。它在 MPC4J 上必错，原因有两个：
     *
     *   1. MPC4J 的私钥是"系数域的 ternary 多项式"（KeyGenerator 里
     *      RingLwe.samplePolyTernary(..., secretKeyRns.coeff()) 直接写进 coeff()），
     *      不是 NTT 域。对系数域数组做"逐系数相乘"得到的东西没有数学含义。
     *   2. 即使私钥恰好在 NTT 域，"逐 NTT 系数相乘"也不等于多项式乘 g（那是逐点乘，
     *      对应的是多项式环里的循环卷积，不是缩放）。
     *
     * 正确且更省事的做法见 encryptRgswConstant()：根本不碰私钥，把 g 加到第二个分量上。
     */

    /** 一个 RGSW 密文：两组、每组 levels 个密文 */
    public static final class Rgsw {
        public final Ciphertext[] group0;
        public final Ciphertext[] group1;

        Rgsw(Ciphertext[] g0, Ciphertext[] g1) {
            this.group0 = g0;
            this.group1 = g1;
        }

        public int size() {
            return group0.length + group1.length;
        }
    }

    /**
     * RGSW 加密一个<b>常数</b>选择器 μ ∈ {0,1}。
     *
     * <p>group0[i] 的相位 = g_i·μ；group1[i] 的相位 = g_i·(μ·s)。
     */
    public Rgsw encryptRgswConstant(long mu) {
        if (mu != 0 && mu != 1) {
            throw new IllegalArgumentException("本实现目前只支持常数选择器 0/1");
        }
        Ciphertext[] g0 = new Ciphertext[levels];
        Ciphertext[] g1 = new Ciphertext[levels];
        BigInteger power = BigInteger.ONE;
        BigInteger b = BigInteger.valueOf(base);
        for (int i = 0; i < levels; i++) {
            Ciphertext c0 = toNtt(encryptZero());
            if (mu == 1) {
                addConstantNtt(c0, 0, power);          // g_i · μ
            }
            g0[i] = c0;

            Ciphertext c1 = toNtt(encryptZero());
            if (mu == 1) {
                // 关键一步：不要显式去算 g_i·s（见上方留档的坑）。NTT 是线性的，
                // 把常数 g_i 加到第二个分量上，相位就自动多出 g_i·s：
                //     phase(c0, c1 + g) = c0 + (c1 + g)·s = phase + g·s
                // 于是 group1[i] 的相位 = g_i·(μ·s)，和定义完全一致，且全程不接触私钥。
                addConstantNtt(c1, 1, power);          // 相位 += g_i · (μ·s)
            }
            g1[i] = c1;

            power = power.multiply(b);
        }
        return new Rgsw(g0, g1);
    }

    // ---------------- 切段与外部乘积 ----------------

    /** 把源密文某个分量（系数域）的第 i 个系数还原成 Z_q 上的大整数 */
    private BigInteger crtAt(long[] data, int polyIndex, int coeffIndex) {
        // 同样只能用工作层的素数个数：跨素数还原出来的就是密文的实际模数 q（不含 q_last）
        int L = workingPrimeCount;
        BigInteger x = null;
        BigInteger mv = null;
        for (int j = 0; j < L; j++) {
            long pj = primes[j].value();
            long rj = data[(polyIndex * L + j) * n + coeffIndex];
            if (j == 0) {
                x = BigInteger.valueOf(rj);
                mv = BigInteger.valueOf(pj);
                continue;
            }
            BigInteger mj = BigInteger.valueOf(pj);
            BigInteger diff = BigInteger.valueOf(rj).subtract(x).mod(mj);
            BigInteger tv = diff.multiply(crtStepInv[j]).mod(mj);
            x = x.add(mv.multiply(tv));
            mv = mv.multiply(mj);
        }
        return x;
    }

    /**
     * 把一个分量切成 levels 段（输入会先转回系数域，用副本，不动原密文）。
     *
     * <p><b>这里必须用"平衡位"（balanced digits），不能用无符号位。</b>
     * MPC4J 的 {@code transformToNttInplace(Plaintext, parmsId)} 做的是 fast plain lift：
     * 先把明文系数按"有符号代表元"嵌进 RNS —— {@code 值 >= (t+1)/2} 的会被当成 {@code 值 - t}，
     * 再在 Z_q 上做 NTT。所以明文能无损表达的数字范围只有 {@code (-t/2, t/2)}，
     * 而 t = 65537 时窗口是 (-32768.5, 32768.5)。
     *
     * <p>如果用无符号位 {@code [0, B) = [0, 65536)}，凡是 > 32768 的数字都会被静默地
     * 解释成负数，外部乘积就整体错位（表现为"RGSW(0) 通过、RGSW(1) 全错"）。
     * 平衡位把每一段限制在 {@code (-B/2, B/2]} = [-32767, 32768]，正好落在窗口内。
     *
     * <p>平衡位不会引入近似误差：只要 {@code B^levels / 2 > q}，逐段平衡展开就是精确的
     * （本例 q ≈ 2^54，B = 2^16，levels = 4，B^4/2 = 2^63 ≫ 2^54，余项必为 0）。
     * 顺带还把噪声减半。
     */
    public long[][] decompose(Ciphertext ct, int polyIndex) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        // MPC4J 的密文形式跟着明文走：先统一到"系数域"再读系数
        if (copy.isNttForm()) {
            evaluator.transformFromNttInplace(copy);
        }
        long[] data = copy.data();
        long[][] digits = new long[levels][n];
        BigInteger b = BigInteger.valueOf(base);
        BigInteger half = b.shiftRight(1);                 // B/2
        BigInteger plainMod = BigInteger.valueOf(t);
        BigInteger window = BigInteger.valueOf((t - 1) / 2); // 明文窗口上界
        for (int i = 0; i < n; i++) {
            BigInteger x = crtAt(data, polyIndex, i);      // 无符号代表元，x ∈ [0, q)
            for (int k = 0; k < levels; k++) {
                BigInteger r = x.mod(b);                   // [0, B)
                if (r.compareTo(half) > 0) {
                    r = r.subtract(b);                     // 居中到 (-B/2, B/2]
                }
                if (r.abs().compareTo(window) > 0) {
                    throw new IllegalStateException(String.format(
                        "平衡位 %s 超出明文窗口 ±%s：底 B=%d 相对明文模数 t=%d 太大，"
                            + "请加大 t 或减小底。", r, window, base, t));
                }
                // 负数字存成 t + r：MPC4J 的 fast plain lift 会把它还原回负数
                digits[k][i] = r.signum() < 0 ? r.add(plainMod).longValueExact() : r.longValueExact();
                x = x.subtract(r).divide(b);               // 继续切下一段
            }
        }
        return digits;
    }

    /**
     * 外部乘积：RGSW ⊗ RLWE → RLWE。
     *
     * <p>切段数字走 {@link #decompose}：平衡位、绝对值 ≤ B/2 = 32768，
     * 落在明文的 (-t/2, t/2) 窗口内，所以能安全地当 Z_t 明文喂给
     * {@code multiplyPlain}（MPC4J 会按有符号代表元把它嵌进 Z_q 再做 NTT）。
     */
    public Ciphertext externalProduct(Rgsw rgsw, Ciphertext src) {
        long[][] d0 = decompose(src, 0);
        long[][] d1 = decompose(src, 1);

        // 累加器必须与 RGSW 分量同形式（NTT 域）
        Ciphertext acc = toNtt(encryptZero());
        Ciphertext tmp = new Ciphertext();
        for (int i = 0; i < levels; i++) {
            multiplyPlainNtt(rgsw.group0[i], d0[i], tmp);
            evaluator.addInplace(acc, tmp);
            multiplyPlainNtt(rgsw.group1[i], d1[i], tmp);
            evaluator.addInplace(acc, tmp);
        }
        return acc;
    }

    /**
     * 密文乘"公开数字多项式"。
     *
     * <p>MPC4J 要求明文与密文<b>同形式</b>，所以先把数字明文转到 NTT 域
     * （用该密文的 parmsId），再调 multiplyPlain。
     */
    private void multiplyPlainNtt(Ciphertext ct, long[] digits, Ciphertext dst) {
        Plaintext pt = new Plaintext(digits);
        evaluator.transformToNttInplace(pt, ct.parmsId());
        evaluator.multiplyPlain(ct, pt, dst);
    }

    /**
     * CMUX：c=0 得 a，c=1 得 b。
     *
     * <p>形式统一在这里收尾：外部乘积的累加器在 NTT 域，而调用方传进来的 a/b
     * 一般是系数域（{@code encrypt} 出来的就是系数域），直接相加会抛
     * {@code NTT form mismatch}。所以在<b>副本</b>上转 NTT，不动调用方的密文。
     */
    public Ciphertext cmux(Rgsw rgsw, Ciphertext a, Ciphertext b) {
        Ciphertext an = toNtt(copyOf(a));
        Ciphertext bn = toNtt(copyOf(b));
        Ciphertext diff = new Ciphertext();
        evaluator.sub(bn, an, diff);
        Ciphertext prod = externalProduct(rgsw, diff);
        return add(an, prod);
    }

    /**
     * 把密文乘上<b>公开</b>单项式 X^k（负循环环 Z_q[X]/(X^N+1)）。
     *
     * <p>盲旋转两处都要它：每轮 CMUX 前后按 LWE 系数 a_i 旋转累加器，最后再按公开量旋一次。
     * 这是纯系数搬移，不需要任何密钥。
     *
     * <p>符号约定（环里 X^N = −1）：先把 k 按 mod 2N 约化；k ≥ N 等价于整体取负再平移 k−N；
     * 平移过程中跨过 X^N 的项也要变号——两个条件异或决定最终符号。
     * 与 native 侧 {@code index_pir.cpp} 里的 {@code negacyclic_shift_poly_coeffmod} 同一约定，
     * 也与路线 C 上已通过测试的 {@code MonomialOps} 一致。
     *
     * <p>注意逐<b>工作层</b>素数做（BFV 的 q_last 不在密文里，见 workingPrimeCount）。
     */
    public Ciphertext multiplyPowerOfX(Ciphertext ct, long k) {
        boolean wasNtt = ct.isNttForm();
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (wasNtt) {
            evaluator.transformFromNttInplace(copy);
        }
        long twoN = 2L * n;
        long kk = ((k % twoN) + twoN) % twoN;
        boolean negate = kk >= n;
        int shift = (int) (kk % n);
        int size = copy.size();
        long[] data = copy.data();
        long[] src = new long[n];
        for (int c = 0; c < size; c++) {
            for (int j = 0; j < workingPrimeCount; j++) {
                long p = primes[j].value();
                int off = (c * workingPrimeCount + j) * n;
                System.arraycopy(data, off, src, 0, n);
                for (int i = 0; i < n; i++) {
                    int t = i + shift;
                    boolean wrap = t >= n;
                    if (wrap) {
                        t -= n;
                    }
                    long v = src[i];
                    if (negate ^ wrap) {
                        v = (v == 0) ? 0 : p - v;
                    }
                    data[off + t] = v;
                }
            }
        }
        if (wasNtt) {
            evaluator.transformToNttInplace(copy);
        }
        return copy;
    }

    /**
     * RGSW 加密一个<b>任意明文多项式</b> m(X)。
     *
     * <p>这是"完成盲旋转"所需的关键原语：有了 RGSW(s(X))（s 是密钥多项式），
     * 服务器就能在<b>不知道 s</b> 的前提下把一条密文乘上 s——
     * {@code externalProduct(RGSW(s), Q)} 的相位 = phase(Q)·s(X) ✓。
     * 这正是 Pirouette/OnionPIR 用来从查询里导出控制位的手法
     * （MPC4J 的 OnionPIR 里那行 {@code tfhe_cipher.encrypt(secret_key.data(), enc_sk)} 就是这个）。
     *
     * <p>约定（与常数版一致，只是把常数换成多项式）：
     * <pre>
     *   group0[i] 相位 = g_i·m(X)           ← 把 g_i·m(X) 加到分量 0
     *   group1[i] 相位 = g_i·m(X)·s(X)      ← 把 g_i·m(X) 加到分量 1（"c1 技巧"自动带上 ·s）
     * </pre>
     * <b>注意 group1 不需要乘 s</b>：把同一个量加到"第二个分量"上，相位里就自动多出一个 ·s
     * （这一点与常数版完全相同，也是常数版根本不碰私钥的原因）。
     * 一开始我在这里多乘了一次 s，结果 RGSW(1) 都对不上——测试立刻抓出来了。
     *
     * <p>实现上 group0/group1 用的都是同一个 NTT 域数组 {@code NTT(m)}，
     * 借道 {@code transformToNttInplace} 做 fast plain lift 得到（它把系数按有符号代表元
     * 嵌入 Z_q 再 NTT）。
     *
     * <p>⚠️ m 的系数须落在 {@code ±t/2} 内：超出窗口的值会被 fast plain lift 静默当成负数
     * （这个坑前面已经踩过一次）。
     */
    public Rgsw encryptRgswPoly(long[] m) {
        if (m.length != n) {
            throw new IllegalArgumentException("明文多项式长度须为 N=" + n);
        }
        Plaintext pt = new Plaintext(m);
        evaluator.transformToNttInplace(pt, context.firstParmsId());
        long[] mNtt = pt.data();

        Ciphertext[] g0 = new Ciphertext[levels];
        Ciphertext[] g1 = new Ciphertext[levels];
        BigInteger power = BigInteger.ONE;
        BigInteger b = BigInteger.valueOf(base);
        for (int i = 0; i < levels; i++) {
            Ciphertext c0 = toNtt(encryptZero());
            Ciphertext c1 = toNtt(encryptZero());
            long[] d0 = c0.data();
            long[] d1 = c1.data();
            for (int pi = 0; pi < workingPrimeCount; pi++) {
                long p = primes[pi].value();
                BigInteger pBig = BigInteger.valueOf(p);
                long gi = power.mod(pBig).longValue();
                int off0 = (0 * workingPrimeCount + pi) * n;
                int off1 = (1 * workingPrimeCount + pi) * n;
                for (int j = 0; j < n; j++) {
                    // 同一个量 NTT(g_i · m) = g_i · NTT(m)（逐点）
                    long scaled = BigInteger.valueOf(gi)
                        .multiply(BigInteger.valueOf(mNtt[pi * n + j]))
                        .mod(pBig).longValue();
                    long s0 = d0[off0 + j] + scaled;
                    d0[off0 + j] = s0 >= p ? s0 - p : s0;
                    long s1 = d1[off1 + j] + scaled;   // 加到第二个分量 → 相位自动带 ·s
                    d1[off1 + j] = s1 >= p ? s1 - p : s1;
                }
            }
            g0[i] = c0;
            g1[i] = c1;
            power = power.multiply(b);
        }
        return new Rgsw(g0, g1);
    }

    /**
     * 密文标量乘：所有分量、所有工作素数的系数都乘上公开常数 k（mod 各素数）。
     *
     * <p>NTT 是线性的，所以"先 NTT 再逐点乘 k"与"先乘 k 再 NTT"等价——
     * 因此在 NTT 域直接逐点乘即可，不需要来回转换形式。
     * 用途：{@link LweToRgswOps} 里把 {@code RLWE(μ)} 缩放成 {@code (g_i·Δ⁻¹)·RLWE(μ)}。
     */
    public Ciphertext scalarMultiply(Ciphertext ct, BigInteger k) {
        Ciphertext out = new Ciphertext();
        out.copyFrom(ct);
        long[] data = out.data();
        int size = out.size();
        for (int c = 0; c < size; c++) {
            for (int pi = 0; pi < workingPrimeCount; pi++) {
                long p = primes[pi].value();
                BigInteger pBig = BigInteger.valueOf(p);
                long km = k.mod(pBig).longValue();
                int off = (c * workingPrimeCount + pi) * n;
                for (int j = 0; j < n; j++) {
                    data[off + j] = BigInteger.valueOf(data[off + j])
                        .multiply(BigInteger.valueOf(km)).mod(pBig).longValue();
                }
            }
        }
        return out;
    }

    /** 深拷贝一份密文（copyFrom 是 MPC4J 自带的数据拷贝） */
    private static Ciphertext copyOf(Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        return copy;
    }

    public String describe() {
        return String.format(
            "N=%d, t=%d, 声明素数=%d(%d bit) 工作层=%d(%d bit), base=%d, levels=%d",
            n, t, primes.length, declaredQBits, workingPrimeCount, qBits, base, levels);
    }

    // ---------------- 自检 ----------------

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        System.out.println("=== RGSW on top of MPC4J (BFV) ===");
        // N 默认 2048（跑得快）；传参可跑论文规模，例如 16384。
        // 注意：以前 N 大到 16384 会 OOM——原因是 Galois 置换表被预分配成 N 行
        // （AbstractGaloisTool:64 的 new int[N][N]），补丁改成惰性行分配后已无此限制
        // （N=16384、8 层：8.6 GB → 约 14 MB）。
        long tCtx = System.nanoTime();
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.printf("[ctx] N=%d，上下文 + 密钥生成 %.0f ms%n",
            n, (System.nanoTime() - tCtx) / 1e6);
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20260916L);
        int failed = 0;

        // 1. RLWE 往返
        long[] msg = new long[m.n];
        for (int i = 0; i < m.n; i++) {
            msg[i] = rnd.nextInt(64);
        }
        Ciphertext ct = m.encrypt(msg);
        long[] back = m.decrypt(ct);
        long diff = countDiff(msg, back);
        failed += report("Test 1  MPC4J RLWE round-trip", diff == 0,
            "wrong coefficients = " + diff);

        // 2. RGSW(1) ⊗ ct 应当等于 ct
        Mpc4jRgsw.Rgsw one = m.encryptRgswConstant(1);
        Ciphertext prod1 = m.externalProduct(one, ct);
        long[] out1 = m.decrypt(prod1);
        long diff1 = countDiff(msg, out1);
        failed += report("Test 2  RGSW(1) x ct  = ct", diff1 == 0,
            "wrong coefficients = " + diff1);

        // 3. RGSW(0) ⊗ ct 应当是 0
        Mpc4jRgsw.Rgsw zero = m.encryptRgswConstant(0);
        Ciphertext prod0 = m.externalProduct(zero, ct);
        long[] out0 = m.decrypt(prod0);
        long bad0 = 0;
        for (long v : out0) {
            if (v != 0) {
                bad0++;
            }
        }
        failed += report("Test 3  RGSW(0) x ct  = 0", bad0 == 0,
            "non-zero coefficients = " + bad0);

        // 4. CMUX：A + RGSW(mu)(B-A)
        long[] mA = new long[m.n];
        long[] mB = new long[m.n];
        for (int i = 0; i < m.n; i++) {
            mA[i] = 11;
            mB[i] = 22;
        }
        Ciphertext a = m.encrypt(mA);
        Ciphertext b = m.encrypt(mB);
        for (int mu = 0; mu <= 1; mu++) {
            Ciphertext res = m.cmux(m.encryptRgswConstant(mu), a, b);
            long[] got = m.decrypt(res);
            long[] want = mu == 0 ? mA : mB;
            long d = countDiff(want, got);
            failed += report("Test 4." + mu + "  CMUX(mu=" + mu + ") -> "
                + (mu == 0 ? "A" : "B"), d == 0, "wrong coefficients = " + d);
        }

        System.out.println();
        System.out.println(failed == 0 ? "=== ALL TESTS PASSED ===" : "=== " + failed + " FAILED ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long countDiff(long[] a, long[] b) {
        long c = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                c++;
            }
        }
        return c;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
