package com.fusepir.prim;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.math.BigInteger;

/**
 * LWE ↔ RLWE 桥：SampleExtract 与 Pack（LWE-in-RLWE 嵌入）。
 *
 * <h3>这两个是干什么的</h3>
 * <ul>
 *   <li><b>SampleExtract_j</b>（论文原文）：给定 {@code ct_R ← RLWE.Enc_s(Σ m_i X^i)}，
 *       取出第 j 个系数，输出 {@code ct_L ← LWE.Enc_s(m_j)}——把 RLWE 的一个系数
 *       "降维"成同一密钥下的 LWE 样本。</li>
 *   <li><b>Pack</b>（论文原文）：把一批 LWE 密文的消息打包进一个 RLWE 密文。
 *       当 <b>LWE 密钥就是 RLWE 密钥</b>（LWE-in-RLWE）时，打包只是系数摆放，
 *       <b>不需要任何密钥切换</b>——这正是 CAPE 能让"查询 = 1 个密文"的原因。</li>
 * </ul>
 *
 * <h3>系数约定（负循环环 Z_q[X]/(X^N+1)）</h3>
 * RLWE 密文 (c0, c1) 的相位多项式是 {@code c0 + c1·s}；第 j 个系数处的 LWE 样本为
 * {@code b = c0[j]}，a 向量满足 {@code b + ⟨a,s⟩ = (c0 + c1·s)[j]}。
 * 负循环卷积里跨过 X^N 的项要变号，于是正确的索引是 <b>reverse</b> 约定：
 * <pre>
 *   a_k = c1[(j−k) mod N]，当 (j−k) &lt; 0 时取负（因为跨过了 X^N）
 * </pre>
 * Pack 则是它的逆映射：把 a_k 摆回 c1[(j−k) mod N]（同样带符号）。
 *
 * <h3>怎么验证（重要）</h3>
 * <b>不要</b>用"b + ⟨a,s⟩ = c0[j] + (c1⊛s)[j]"来验证——那是<b>同义反复</b>：
 * 换元后左右两边是同一个和式，只能证明自己索引自洽，证明不了正确性（本项目实测被它骗过一次）。
 * 正确的验证是：<b>把抽出的 LWE 样本用 Pack 放回 RLWE，交给库自己的解密器读</b>，
 * 结果必须等于原密文在该系数上的解密值。这样既验证了 SampleExtract，也验证了 Pack，
 * 而且不需要私钥的系数形式。
 *
 * <p>为什么不需要私钥：MPC4J 的 {@code SecretKey.data()} 给的是 <b>NTT 域</b>
 * （实测系数是 ≈q 的大数，不是 ±1/0 的三元小值），所以想自己算 ⟨a,s⟩ 是错的；
 * 而 Pack + 库解密绕开了这一点，也正是协议里客户端的真实做法。
 */
public final class LweRlweBridge {

    private LweRlweBridge() {
    }

    /** 取 RLWE 密文第 j 个系数，得到 LWE 样本：返回 [prime][0]=b, [prime][1..N]=a（reverse 约定）。 */
    public static long[][] sampleExtract(Mpc4jRgsw m, Ciphertext ct, int j) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        long[] data = copy.data();
        int n = m.n;
        int L = m.workingPrimeCount;
        long[][] out = new long[L][n + 1];
        for (int pi = 0; pi < L; pi++) {
            long mod = m.primes[pi].value();
            out[pi][0] = data[(0 * L + pi) * n + j];                 // b = c0[j]
            for (int k = 0; k < n; k++) {
                int d = j - k;
                boolean flip = d < 0;                                 // 跨过 X^N → 变号
                int idx = flip ? d + n : d;
                long v = data[(1 * L + pi) * n + idx];                // c1[(j−k) mod N]
                out[pi][1 + k] = flip && v != 0 ? mod - v : v;
            }
        }
        return out;
    }

    /** Pack：把 LWE 样本 (b, a) 嵌回 RLWE 密文的第 j 个系数位置（sampleExtract 的逆映射）。 */
    public static Ciphertext packFromSample(Mpc4jRgsw m, long[][] sample, int j) {
        int n = m.n;
        int L = m.workingPrimeCount;
        Ciphertext ct = new Ciphertext();
        ct.resize(m.context, m.context.firstParmsId(), 2);
        long[] data = ct.data();
        for (int pi = 0; pi < L; pi++) {
            long mod = m.primes[pi].value();
            data[(0 * L + pi) * n + j] = sample[pi][0];
            for (int k = 0; k < n; k++) {
                int d = j - k;
                boolean flip = d < 0;
                int idx = flip ? d + n : d;
                long v = sample[pi][1 + k];
                data[(1 * L + pi) * n + idx] = flip && v != 0 ? mod - v : v;
            }
        }
        ct.setNttForm(false);
        return ct;
    }

    /** 客户端侧读回一个 LWE 样本：Pack 回 RLWE 后用库解密器取该系数。 */
    public static long decryptSampleViaPack(Mpc4jRgsw m, long[][] sample, int j) {
        Ciphertext packed = packFromSample(m, sample, j);
        return m.decrypt(packed)[j];
    }

    /** 把每个素数下的残数用 CRT 还原成 Z_q 上的大整数并中心化（留给后续 q_R → q_L 模数切换桥用）。 */
    public static BigInteger crtCentered(Mpc4jRgsw m, long[] residues) {
        BigInteger x = BigInteger.ZERO;
        BigInteger base = BigInteger.ONE;
        for (int pi = 0; pi < m.workingPrimeCount; pi++) {
            BigInteger mj = BigInteger.valueOf(m.primes[pi].value());
            BigInteger diff = BigInteger.valueOf(residues[pi]).subtract(x).mod(mj);
            BigInteger inv = (pi == 0) ? BigInteger.ONE : base.mod(mj).modInverse(mj);
            x = x.add(base.multiply(diff.multiply(inv).mod(mj)));
            base = base.multiply(mj);
        }
        return x.compareTo(base.shiftRight(1)) > 0 ? x.subtract(base) : x;
    }

    // ------------------------------------------------------------------

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== LWE ↔ RLWE 桥（SampleExtract / Pack）===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 1000) + 1;
        }
        Ciphertext ct = m.encrypt(msg);

        // ---- 1) SampleExtract + Pack 往返：放回后用库解密器读，必须等于原值 ----
        int wrong = 0;
        int checked = 0;
        for (int j : new int[]{0, 1, 7, 1234, n - 1}) {
            long[][] sample = sampleExtract(m, ct, j);
            long back = decryptSampleViaPack(m, sample, j);
            long want = m.decrypt(ct)[j];
            checked++;
            if (back != want) {
                wrong++;
                System.out.printf("       j=%d: 往返得到 %d，期望 %d%n", j, back, want);
            }
        }
        failed += report("1  SampleExtract → Pack → 库解密 往返一致", wrong == 0,
            String.format("抽查 %d 个系数（含 0、1、7、%d、N−1），错 %d 个", checked, 1234, wrong));

        // ---- 2) 整条链：盲旋转 → SampleExtract_0 → Pack → 解密 ----
        int L = Integer.numberOfTrailingZeros(n);
        long index = 1234;
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[L];
        for (int i = 0; i < L; i++) {
            bk[i] = m.encryptRgswConstant((index >>> i) & 1L);
        }
        Ciphertext acc = m.encrypt(msg);
        Ciphertext out = BlindRotateOps.blindRotateByBits(m, bk, acc);
        long[][] extracted = sampleExtract(m, out, 0);
        long got = decryptSampleViaPack(m, extracted, 0);
        failed += report("2  整条链：逐位 RGSW → 盲旋转 → SampleExtract_0 → Pack → 解密",
            got == msg[(int) (index % n)],
            String.format("index=%d：读回 %d，期望 p_index=%d", index, got, msg[(int) (index % n)]));

        System.out.println();
        System.out.println(failed == 0 ? "=== LWE ↔ RLWE 桥全部通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
