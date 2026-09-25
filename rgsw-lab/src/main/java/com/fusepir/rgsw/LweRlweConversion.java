package com.fusepir.rgsw;

import cape.he.LWE;
import cape.he.LWECiphertext;
import cape.he.LWEParams;
import cape.he.LWESecretKey;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;

import java.math.BigInteger;
import java.util.Random;

/**
 * <b>LWE ↔ RLWE 桥</b>：把 <b>RLWE 层</b>（`rgsw-lab`，多素数大模数）与 <b>LWE 层</b>
 * （`lwe-java` 包 {@code cape.he}，单个 {@code long} 模数）真正接起来。
 *
 * <h3>为什么需要它（此前的问题）</h3>
 * 原来只有 {@link LweRlweBridge}：它在 RLWE 密文的系数域里做 coefficient ↔ sample 映射，
 * 全程用 {@code long[][]}（每个素数下的 CRT 残数），<b>从不经过 {@code cape.he} 的类型</b>。
 * 也就是说 {@code rgsw-lab} 与 {@code lwe-java} 从未在同一段代码里出现——两岸只有
 * "q_L = 2N"、"t = 2^ν" 这样的<b>纸面约定</b>。本类补上真正的转换。
 *
 * <h3>三个关键约定（务必先读）</h3>
 * <ol>
 *   <li><b>LWE-in-RLWE</b>：LWE 的秘密就是 RLWE 的秘密多项式，维度 = N。
 *       因此<b>不需要密钥切换</b>——这正是 CAPE 能让"查询 = 1 个密文"的原因
 *       （论文 §2.5 说 SampleExtract "必要时"才含密钥切换，我们这种情形不需要）。</li>
 *   <li><b>模数必须切换</b>：RLWE 的模数 {@code q_R} 是 8 个素数之积（约 389 bit），
 *       而 {@code cape.he} 的模数是<b>单个 {@code long}</b>。所以 RLWE → LWE 必须把
 *       {@code q_R} 缩放到一个 64 位以内的 {@code q_L}（且 {@code cape.he} 要求
 *       <b>q_L 是 2 的幂</b>）。这一步是<b>有损的</b>（噪声与消息一起被缩放）。</li>
 *   <li>⚠️ <b>{@code q_L = 2N} 装不下 t = 65537 的载荷</b>：BFV 的相位是 {@code Δ_R·m}，
 *       {@code Δ_R = q_R/t}；缩放后 {@code Δ_L = q_L/t}。当 {@code q_L = 2N = 4096 < t = 65537} 时
 *       {@code Δ_L = 0}，消息<b>根本无法表示</b>。
 *       所以：<b>q_L = 2N 只用于盲旋转的"索引"（Δ=1 的原始下标），载荷必须用更大的 q_L</b>
 *       （例如 2³²，此时 {@code Δ_L = 65534}）。</li>
 * </ol>
 *
 * <h3>两个方向的语义</h3>
 * <ul>
 *   <li>{@link #extractLwe}（RLWE → LWE，论文的 {@code SampleExtract_j}）：
 *       取出 RLWE 密文第 j 个系数，做 {@code q_R → q_L} 缩放，产出 {@code cape.he.LWECiphertext}。</li>
 *   <li>{@link #packLwe}（LWE → RLWE，论文的 {@code Pack}）：把（同模数 q_R 下的）LWE 样本
 *       摆回 RLWE 的系数位置。这是 {@code SampleExtract} 的逆，也是三条检索路径结果的合流点。</li>
 * </ul>
 * <b>注意</b>：{@code packLwe} 要求样本本身处于 {@code q_R} 下（即由 {@code extractResidues} 抽出的形态）。
 * 把一条<b>小模数</b>的 LWE 密文"提升"成 RLWE 密文（真·lifting）需要噪声填充等额外构造，
 * <b>不在本类范围内</b>——见调用说明文档。
 *
 * <p>调用说明见 {@code coding/rgsw-lab/LWE_RLWE桥_调用说明.md}。
 */
public final class LweRlweConversion {

    private LweRlweConversion() {
    }

    // ==================================================================
    //  RLWE 密钥 → cape.he 的 LWE 密钥（LWE-in-RLWE）
    // ==================================================================

    /**
     * 把 RLWE 的秘密多项式取成<b>系数形式</b>，并转成 {@code cape.he} 的 {@link LWESecretKey}。
     *
     * <p>要点：SEAL 的 {@code SecretKey.data()} 给的是 <b>NTT 域</b>（实测系数是 ≈q 的大数，
     * 不是 ±1/0 的三元值），所以必须先做一次逆 NTT。Java 移植版<b>没有</b>
     * {@code transformFromNttInplace(Plaintext)}，只有一个密文版本，于是这里把秘密
     * 塞进一个 size=1 的密文里借道做变换。
     *
     * <p>得到的秘密系数是<b>三元</b> {−1,0,1}（SEAL 默认的密钥分布），
     * 而不是 {@code cape.he} 默认假设的二进制 {0,1}——本方法据实返回，不做强转。
     *
     * @param m  RLWE 上下文
     * @param qL LWE 层的模数（须是 2 的幂），秘密系数按它取模
     */
    public static LWESecretKey rlweSecretAsLweKey(Mpc4jRgsw m, long qL) {
        int n = m.n;
        int L = m.workingPrimeCount;
        SecretKey sk = m.keyGen.secretKey();
        Plaintext data = sk.data();

        long[] coeffs;
        if (data.isNttForm()) {
            coeffs = inverseNttSecret(m, data, L, n);
        } else {
            coeffs = data.data();
        }

        BigInteger qLB = BigInteger.valueOf(qL);
        long[] s = new long[n];
        long[] residues = new long[L];
        for (int k = 0; k < n; k++) {
            for (int pi = 0; pi < L; pi++) {
                residues[pi] = coeffs[pi * n + k];      // 布局：[(0)*L + pi]*n + k
            }
            BigInteger centered = LweRlweBridge.crtCentered(m, residues);
            s[k] = centered.mod(qLB).longValueExact();
        }
        return new LWESecretKey(s, qL);
    }

    /** 把 RLWE 秘密读成居中小整数（便于观察分布，例如确认是不是三元）。 */
    public static long[] rlweSecretCoefficientsCentered(Mpc4jRgsw m) {
        int n = m.n;
        int L = m.workingPrimeCount;
        Plaintext data = m.keyGen.secretKey().data();
        long[] coeffs = data.isNttForm() ? inverseNttSecret(m, data, L, n) : data.data();
        long[] out = new long[n];
        long[] residues = new long[L];
        for (int k = 0; k < n; k++) {
            for (int pi = 0; pi < L; pi++) {
                residues[pi] = coeffs[pi * n + k];
            }
            out[k] = LweRlweBridge.crtCentered(m, residues).longValueExact();
        }
        return out;
    }

    /**
     * 把 NTT 域的秘密多项式转成系数域。
     *
     * <p>Java 移植版<b>没有</b> {@code transformFromNttInplace(Plaintext)}，只有密文版本；
     * 且有两处硬约束逼着写法：
     * <ul>
     *   <li>{@code Ciphertext.resize} 要求 {@code size ≥ SEAL_CIPHERTEXT_SIZE_MIN = 2}（size=1 直接抛 "invalid size"）；</li>
     *   <li>某个分量全零会被判成"透明密文"，{@code transformFromNttInplace} 抛
     *       {@code result ciphertext is transparent}。</li>
     * </ul>
     * 所以这里借一个 <b>size=2</b> 的密文，把秘密<b>同时放进两个分量</b>（避免出现全零分量），
     * 逆变换后只读第 0 个分量——两个分量各自独立做变换，互不影响。
     */
    private static long[] inverseNttSecret(Mpc4jRgsw m, Plaintext secretNtt, int L, int n) {
        Ciphertext carrier = new Ciphertext();
        carrier.resize(m.context, m.context.firstParmsId(), 2);
        long[] dst = carrier.data();
        long[] src = secretNtt.data();
        int len = Math.min(src.length, L * n);
        System.arraycopy(src, 0, dst, 0, len);          // 第 0 个分量
        System.arraycopy(src, 0, dst, L * n, len);      // 第 1 个分量（防止被判透明）
        carrier.setNttForm(true);
        m.evaluator.transformFromNttInplace(carrier);
        return carrier.data();      // 第 0 个分量的布局是 [pi * n + i]
    }

    // ==================================================================
    //  RLWE → LWE（论文 SampleExtract_j）
    // ==================================================================

    /**
     * 抽 RLWE 密文第 j 个系数，做 {@code q_R → q_L} 模数切换，产出 {@code cape.he} 的 LWE 密文。
     *
     * <p>缩放：对每个分量 {@code x ∈ Z_qR}（居中）算 {@code round(x·q_L/q_R)} 再 mod q_L。
     * 于是相位 {@code Δ_R·m} → {@code Δ_L·m}，{@code Δ_L = q_L/t}，消息保持不变。
     *
     * @param lweParams 目标 LWE 参数。⚠️ <b>必须满足</b> {@code dimension == N}（LWE-in-RLWE 的硬约束）、
     *                  {@code plaintextModulus == t}、且 {@code modulus} 是 2 的幂——不满足会**抛异常**，
     *                  不会静默产出一个"元数据与实际维度不一致"的密文
     */
    public static LWECiphertext extractLwe(Mpc4jRgsw m, Ciphertext ctR, int j, LWEParams lweParams) {
        // ⚠️ 这两个校验很关键：维度与明文模数都由 RLWE 这边决定，LWE 层不能自说自话。
        //    漏掉校验时不会报错，只会产出一个 a.length=N 但 params.dimension 说成别的值的密文，
        //    后续 LWE.decrypt 用的是密文自己的 a，所以"能跑"，但元数据已经错了。
        if (lweParams.dimension != m.n) {
            throw new IllegalArgumentException(String.format(
                "LWE-in-RLWE 要求 dimension == N：dimension=%d 而 N=%d。"
                    + "（SampleExtract 抽出的样本维度恒为环维度 N，不是 Pirouette 的 d=512；"
                    + "后者要靠密钥切换才能对上，本项目未实现）",
                lweParams.dimension, m.n));
        }
        if (lweParams.plaintextModulus != m.t) {
            throw new IllegalArgumentException(String.format(
                "LWE 的明文模数必须与 RLWE 一致：LWE t=%d 而 RLWE t=%d（抽出的系数带着 RLWE 的 Δ_R=q_R/t）",
                lweParams.plaintextModulus, m.t));
        }

        long[][] sample = LweRlweBridge.sampleExtract(m, ctR, j);   // [L][N+1]，每素数残数
        int L = m.workingPrimeCount;
        int n = m.n;
        long qL = lweParams.modulus;
        BigInteger qLB = BigInteger.valueOf(qL);

        long[] residues = new long[L];
        for (int pi = 0; pi < L; pi++) {
            residues[pi] = sample[pi][0];
        }
        long b = scaleDown(LweRlweBridge.crtCentered(m, residues), m.q, qLB);

        long[] a = new long[n];
        for (int k = 0; k < n; k++) {
            for (int pi = 0; pi < L; pi++) {
                residues[pi] = sample[pi][1 + k];
            }
            // ⚠️ 符号约定不同，必须取反：
            //   RLWE（SEAL）的相位是  c0 + c1·s  ⇒  b + ⟨a,s⟩ = Δm + e
            //   cape.he 的相位是        b − ⟨a,s⟩  ⇒  b = ⟨a,s⟩ + Δm + e
            // 两边要落在同一个相位上，cape.he 用的 a 必须是 RLWE 那套的相反数。
            a[k] = scaleDown(LweRlweBridge.crtCentered(m, residues).negate(), m.q, qLB);
        }
        return new LWECiphertext(a, b, qL, lweParams.plaintextModulus);
    }

    /** 把 RLWE 密文第 j 个系数抽成"每素数残数"形态（q_R 下），供 {@link #packLwe} 用。 */
    public static long[][] extractResidues(Mpc4jRgsw m, Ciphertext ctR, int j) {
        return LweRlweBridge.sampleExtract(m, ctR, j);
    }

    private static long scaleDown(BigInteger x, BigInteger qR, BigInteger qL) {
        BigInteger num = x.multiply(qL);
        BigInteger half = qR.shiftRight(1);          // q_R/2，四舍五入
        num = x.signum() >= 0 ? num.add(half) : num.subtract(half);
        BigInteger scaled = num.divide(qR);          // 截断；上面已加/减半个 q_R，等价于就近取整
        return scaled.mod(qL).longValueExact();
    }

    // ==================================================================
    //  LWE → RLWE（论文 Pack；LWE-in-RLWE，同模数 q_R）
    // ==================================================================

    /**
     * 把（q_R 下的）LWE 样本摆回 RLWE 密文的第 j 个系数位置——{@code SampleExtract} 的逆。
     *
     * <p><b>为什么不需要密钥切换</b>：LWE 的秘密就是 RLWE 的秘密多项式。
     * 密文 {@code (c0, c1)} 在系数 j 处给出 {@code b = c0[j]}、{@code a_k = ±c1[(j−k) mod N]}；
     * 反过来把 {@code a_k} 摆回去即可，相位自动一致。
     *
     * @param sample {@link #extractResidues}（或 {@link LweRlweBridge#sampleExtract}）的产物
     */
    public static Ciphertext packLwe(Mpc4jRgsw m, long[][] sample, int j) {
        return LweRlweBridge.packFromSample(m, sample, j);
    }

    // ==================================================================
    //  自检
    // ==================================================================

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int qLBits = args.length > 1 ? Integer.parseInt(args[1]) : 32;
        long qL = 1L << qLBits;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== LWE ↔ RLWE 桥自检 ===");
        System.out.println("[RLWE] " + m.describe());
        System.out.printf("[LWE ] 维度 = N = %d, q_L = 2^%d = %d, t = %d, Δ_L = q_L/t = %d%n%n",
            n, qLBits, qL, m.t, qL / m.t);

        // ---------- T0 密钥：取 RLWE 秘密的系数形式 ----------
        long t0 = System.nanoTime();
        LWESecretKey skLwe = rlweSecretAsLweKey(m, qL);
        long keyMs = (System.nanoTime() - t0) / 1_000_000;
        long[] centered = rlweSecretCoefficientsCentered(m);
        int minusOne = 0, zero = 0, plusOne = 0, other = 0;
        for (long v : centered) {
            if (v == -1) minusOne++;
            else if (v == 0) zero++;
            else if (v == 1) plusOne++;
            else other++;
        }
        report("T0 取 RLWE 密钥的系数形式（LWE-in-RLWE）", other == 0,
            String.format("%d ms；系数分布：−1 有 %d、0 有 %d、+1 有 %d、其它 %d（SEAL 默认是三元密钥）",
                keyMs, minusOne, zero, plusOne, other));

        // ---------- 准备：明文多项式与 RLWE 密文 ----------
        long[] poly = new long[n];
        for (int i = 0; i < n; i++) {
            poly[i] = (i % 1000) + 1;
        }
        Ciphertext ctR = m.encrypt(poly);
        LWEParams lweParams = new LWEParams(n, qL, (int) m.t, 0.0);
        LWE lwe = new LWE(lweParams, new Random(20260923L));

        // ---------- T1 RLWE → LWE：抽系数后用 cape.he 解密 ----------
        int wrong = 0;
        StringBuilder detail = new StringBuilder();
        for (int j : new int[]{0, 1, 7, 1234, n - 1}) {
            LWECiphertext ctL = extractLwe(m, ctR, j, lweParams);
            long got = lwe.decrypt(skLwe, ctL);
            if (got != poly[j]) {
                wrong++;
                detail.append(String.format(" [j=%d got=%d want=%d]", j, got, poly[j]));
            }
        }
        report("T1 RLWE → LWE：抽出的样本用 cape.he 解密 = 原多项式对应系数", wrong == 0,
            String.format("抽查 0、1、7、1234、N−1，错 %d 个%s", wrong, detail));

        // ---------- T2 三条检索路径：在 LWE 域里相加 ----------
        long[] poly2 = new long[n];
        long[] poly3 = new long[n];
        for (int i = 0; i < n; i++) {
            poly2[i] = (i % 500) + 1;
            poly3[i] = (i % 250) + 1;
        }
        Ciphertext ct2 = m.encrypt(poly2);
        Ciphertext ct3 = m.encrypt(poly3);
        int j = 321;
        LWECiphertext a1 = extractLwe(m, ctR, j, lweParams);
        LWECiphertext a2 = extractLwe(m, ct2, j, lweParams);
        LWECiphertext a3 = extractLwe(m, ct3, j, lweParams);
        long[] sumA = new long[n];
        for (int k = 0; k < n; k++) {
            sumA[k] = Math.floorMod(a1.getA()[k] + a2.getA()[k] + a3.getA()[k], qL);
        }
        long sumB = Math.floorMod(a1.getB() + a2.getB() + a3.getB(), qL);
        LWECiphertext sumCt = new LWECiphertext(sumA, sumB, qL, (int) m.t);
        long gotSum = lwe.decrypt(skLwe, sumCt);
        long wantSum = Math.floorMod(poly[j] + poly2[j] + poly3[j], m.t);
        report("T2 三路在 LWE 域相加（CAPE 的三条检索路径合流）", gotSum == wantSum,
            String.format("j=%d：三路读回和 = %d，期望 = %d", j, gotSum, wantSum));

        // ---------- T3 LWE → RLWE：Pack 回 RLWE 再解密 ----------
        int wrong3 = 0;
        StringBuilder detail3 = new StringBuilder();
        for (int jj : new int[]{0, 1, 7, 1234, n - 1}) {
            long[][] sample = extractResidues(m, ctR, jj);
            Ciphertext packed = packLwe(m, sample, jj);
            long got = m.decrypt(packed)[jj];
            if (got != poly[jj]) {
                wrong3++;
                detail3.append(String.format(" [j=%d got=%d want=%d]", jj, got, poly[jj]));
            }
        }
        report("T3 LWE → RLWE：Pack 回第 j 个系数后 RLWE 解密 = 原值", wrong3 == 0,
            String.format("抽查 5 个系数，错 %d 个%s", wrong3, detail3));

        // ---------- T4 q_L = 2N 的边界：Δ = 0，装不下 t=65537 ----------
        long qSmall = 2L * n;
        boolean rejected;
        String note;
        try {
            new LWEParams(n, qSmall, (int) m.t, 0.0);
            rejected = false;
            note = "竟然接受了（与预期不符）";
        } catch (IllegalArgumentException e) {
            rejected = true;
            note = "LWEParams 直接拒绝：" + e.getMessage();
        }
        report("T4 q_L = 2N 装不下 t=65537（Δ = q/t = 0）——文档必须写明", rejected,
            String.format("q_L = 2N = %d, t = %d, Δ = %d；%s", qSmall, m.t, qSmall / m.t, note));

        System.out.println();
        System.out.println(failed == 0
            ? "=== LWE ↔ RLWE 桥自检全部通过 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
