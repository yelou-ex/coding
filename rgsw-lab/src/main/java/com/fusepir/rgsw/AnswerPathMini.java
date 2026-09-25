package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>最小 ANSWER 路径</b>：列选择（`CtPtMul`）→ `BlindRotate` → `SampleExtract_0` → 三路相加 → 解密。
 *
 * <h3>想验证什么</h3>
 * 此前所有自检里，盲旋转的累加器都是 {@code m.encrypt(载荷)}——<b>全新密文、噪声最小</b>。
 * 但协议里 {@code Acc} 来自<b>列选择</b>：{@code Acc_{a,b} ← Σ_c CtPtMul(q_col,a[c], P_{c,b}(X))}，
 * 它的噪声要大得多（BFV 密文×明文会把噪声乘上明文系数的大小）。
 * <b>"列选择 → 盲旋转"这条链一次都没跑过</b>——本文件就是补这一环。
 *
 * <h3>构造（论文算法 1 SETUP 第 14 行 + ANSWER 第 5 行）</h3>
 * <pre>
 *   一维 BFF 数组   D[0 .. RC-1]，D[r + cR] = 第 c 列第 r 行
 *   列多项式        P_c(X) = Σ_r D[r+cR]·X^r            （每列一个明文多项式）
 *   打包成整表      A(X)   = Σ_{c,r} D[r+cR]·X^{cR+r} = Σ_u D[u]·X^u   （就是 D 本身）
 *   客户端的列选择子 E(X)   = Σ_c e[c]·X^{-cR}            （one-hot，e[c_a]=1）
 *   服务端列选择    Acc    = CtPtMul(ct_col, A(X)) = A(X)·E(X)
 *
 *   A(X)·E(X) 的 X^r 系数 = e[0]·D[r] + Σ_{c≥1} e[c]·D[r+cR] = Σ_c e[c]·D[r+cR]
 *                          = D[r + c_a·R]        ← 正好是"被选中那一列的第 r 行"
 * </pre>
 * 然后 {@code BlindRotate(LWE(r_a), Acc)} 把第 {@code r_a} 行挪到常数位，
 * {@code SampleExtract_0} 取出，三个 BFF 位置相加即得载荷。
 *
 * <h3>⚠️ 本测试的前提（也是它的局限）</h3>
 * 索引 {@code LWE(r_a)} 是<b>无噪声</b>的（{@code b = ⟨a,s⟩ + r}）。真实索引带噪声时，
 * 实测会整体推偏行号（见 3.4 / `BlindRotateStress`）。本测试只回答一个问题：
 * <b>"列选择的累加器"喂给盲旋转，能不能正确工作。</b>
 */
public class AnswerPathMini {

    private static final int R = 64;   // 行数
    private static final int C = 4;    // 列数（RC = 256 ≤ N）
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int qL = 2 * n;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 最小 ANSWER 路径：列选择 → 盲旋转 → SampleExtract → 三路相加 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    布局: R=%d 行, C=%d 列, RC=%d ≤ N=%d；LWE: d=%d, q_L=2N=%d%n%n",
            R, C, R * C, n, d, qL);

        Random rnd = new Random(20260919L);
        int nKw = 8;                      // 关键词数（小规模）
        // ---- 值域两档：小值 / 全值域，用来分辨噪声是否被明文系数放大搞垮 ----
        long[][] dbs = new long[2][];
        String[] names = {"小值载荷（1..1000）", "全值域载荷（随机 mod t）"};
        dbs[0] = smallDb(nKw, rnd);
        dbs[1] = fullRangeDb(nKw, rnd);

        // setup 材料：自举密钥 BK（只跟 LWE 密钥有关，两个场景共用）
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        System.out.printf("[setup] 自举密钥 %d 个 RGSW 构造 %.0f ms%n%n",
            d, (System.nanoTime() - t0) / 1e6);

        for (int sc = 0; sc < 2; sc++) {
            System.out.println("──────────────── " + names[sc] + " ────────────────");
            runScenario(m, n, d, qL, s, bk, dbs[sc], nKw, rnd);
            System.out.println();
        }

        // ---- 专项：LWE 的 a 分量里出现 0（真实协议里必然出现，见下）----
        System.out.println("──────────────── 专项：a 分量含 0（a_0 ≡ 0）────────────────");
        zeroComponentCase(m, n, d, qL, s, bk, dbs[0], rnd);
        System.out.println();

        System.out.println(failed == 0
            ? "=== 最小 ANSWER 路径通过：列选择 + 盲旋转 + 样本提取 + 三路相加 全部正确 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /**
     * 专项：LWE 的某个 a 分量为 0 时，盲旋转必须仍然正确。
     *
     * <p>真实协议里 {@code a} 由 PRG 派生、取值在 {@code [0,2N)}，所以某个 {@code a_i = 0}
     * 是<b>必然会出现</b>的（d=512、N=2048 时单次查询命中概率约 1−(1−1/4096)^512 ≈ 12%）。
     * 而 {@code a_i ≡ 0 (mod 2N)} 时 {@code X^{a_i} = 1}，CMUX 的两支变成同一条密文：
     * {@code diff = 0} → {@code externalProduct} 拿到全零明文 → SEAL 抛
     * {@code "result ciphertext is transparent"}。这一轮本来是<b>恒等变换</b>，直接跳过即可。
     */
    private static void zeroComponentCase(Mpc4jRgsw m, int n, int d, int qL, int[] s,
                                          Mpc4jRgsw.Rgsw[] bk, long[] D, Random rnd) {
        long[] A = new long[n];
        System.arraycopy(D, 0, A, 0, R * C);
        int[] ua = bffPositions(3);

        long[][][] samples = new long[3][][];
        for (int a = 0; a < 3; a++) {
            int u = ua[a];
            int r = u % R;
            int c = u / R;
            long[] sel = new long[n];
            if (c == 0) {
                sel[0] = 1;
            } else {
                sel[n - c * R] = m.t - 1;
            }
            Ciphertext cNtt = m.encrypt(sel);
            if (!cNtt.isNttForm()) {
                m.evaluator.transformToNttInplace(cNtt);
            }
            Plaintext pt = new Plaintext(A);
            m.evaluator.transformToNttInplace(pt, cNtt.parmsId());
            Ciphertext acc = new Ciphertext();
            m.evaluator.multiplyPlain(cNtt, pt, acc);

            // 造一条 a_0 = 0 的索引密文
            long[][] lwe = BlindRotateOps.lweEncryptIndex(s, r, qL, rnd);
            long a0 = lwe[0][0];
            lwe[1][0] = Math.floorMod(lwe[1][0] - a0 * s[0], qL);   // ⟨a,s⟩ 少掉 a_0·s_0
            lwe[0][0] = 0;

            Ciphertext out = BlindRotateOps.blindRotate(m, bk, acc, lwe[0], lwe[1][0]);
            samples[a] = LweRlweBridge.sampleExtract(m, out, 0);
        }
        long[][] sum = addSamples(m, samples);
        long got = LweRlweBridge.decryptSampleViaPack(m, sum, 0);
        long expect = 0;
        for (int a = 0; a < 3; a++) {
            expect = (expect + D[ua[a]]) % m.t;
        }
        failed += report("A3 a 分量含 0（a_0 = 0）时仍然正确", got == expect,
            String.format("读回 %d，期望 %d", got, expect));
    }

    private static void runScenario(Mpc4jRgsw m, int n, int d, int qL, int[] s,
                                    Mpc4jRgsw.Rgsw[] bk, long[] D, int nKw, Random rnd) {
        // ---------- 服务端 SETUP：把 D 打包成明文多项式 A(X) ----------
        long[] A = new long[n];
        System.arraycopy(D, 0, A, 0, R * C);
        Plaintext ptA = new Plaintext(A);

        // ---------- 客户端 QUERY：对关键词 K 的三个 BFF 位置 ----------
        int kw = 3;
        int[] ua = bffPositions(kw);
        long yK = payloadOf(kw, D);          // = Σ_a D[u_a] mod t

        long[][][] samples = new long[3][][];
        for (int a = 0; a < 3; a++) {
            int u = ua[a];
            int r = u % R;
            int c = u / R;

            // 列选择子 E(X) = X^{−cR}（one-hot：只有第 c 项为 1）
            // 负循环环里 X^{−cR} = −X^{N−cR}（c=0 时就是 X^0 = 1）
            long[] sel = new long[n];
            if (c == 0) {
                sel[0] = 1;
            } else {
                sel[n - c * R] = m.t - 1;     // −1 (mod t)
            }

            // 客户端加密选择子
            Ciphertext ctCol = m.encrypt(sel);

            // ---------- 服务端：CtPtMul = 密文 × 明文 ----------
            Ciphertext cNtt = new Ciphertext();
            cNtt.copyFrom(ctCol);
            if (!cNtt.isNttForm()) {
                m.evaluator.transformToNttInplace(cNtt);
            }
            Plaintext pt = new Plaintext(A);
            m.evaluator.transformToNttInplace(pt, cNtt.parmsId());
            Ciphertext acc = new Ciphertext();
            m.evaluator.multiplyPlain(cNtt, pt, acc);

            // ---- 中间验收：列选择本身就对不对（还没盲旋转）----
            if (a == 0) {
                long[] got = m.decrypt(acc);
                int wrong = 0;
                StringBuilder first = new StringBuilder();
                for (int rr = 0; rr < R; rr++) {
                    long want = D[rr + c * R];
                    if (got[rr] != want) {
                        wrong++;
                        if (wrong <= 3) {
                            first.append(String.format(" [r=%d got=%d want=%d]", rr, got[rr], want));
                        }
                    }
                }
                int budget = noiseBudget(m, acc);
                failed += report("A0 列选择本身（c=" + c + "）：Acc 的系数 r 应 = 选中列第 r 行",
                    wrong == 0, String.format("错 %d/%d%s；累加器噪声余量 %s bit",
                        wrong, R, first, budget < 0 ? "n/a" : String.valueOf(budget)));
            }

            // ---------- 服务端：盲旋转（索引无噪声）----------
            long[][] lwe = BlindRotateOps.lweEncryptIndex(s, r, qL, rnd);
            Ciphertext out = BlindRotateOps.blindRotate(m, bk, acc, lwe[0], lwe[1][0]);

            // ---------- 服务端：SampleExtract_0 ----------
            samples[a] = LweRlweBridge.sampleExtract(m, out, 0);
        }

        // ---------- 三路相加（同密钥，直接加）----------
        long[][] sum = new long[samples[0].length][];
        for (int pi = 0; pi < sum.length; pi++) {
            sum[pi] = new long[samples[0][pi].length];
            long mod = m.primes[pi].value();
            for (int k = 0; k < sum[pi].length; k++) {
                long v = 0;
                for (int a = 0; a < 3; a++) {
                    v = (v + samples[a][pi][k]) % mod;
                }
                sum[pi][k] = v;
            }
        }

        // ---------- 客户端 DECODE ----------
        long got = LweRlweBridge.decryptSampleViaPack(m, sum, 0);
        // recompute expected via plaintext sum, for a readable message
        long expect = 0;
        for (int a = 0; a < 3; a++) {
            expect = (expect + D[ua[a]]) % m.t;
        }
        failed += report("A1 三路相加 → 解密 = 载荷指纹/值",
            got == expect,
            String.format("关键词 %d：三个位置 %d/%d/%d，读回 %d，期望 %d（Σ D[u_a] = %d）",
                kw, ua[0], ua[1], ua[2], got, expect, yK));

        // ---------- 换一个关键词：应当得到不同的值 ----------
        int kw2 = 6;
        int[] ub = bffPositions(kw2);
        long[][][] s2 = new long[3][][];
        for (int a = 0; a < 3; a++) {
            s2[a] = onePath(m, n, d, qL, s, bk, A, ub[a], rnd);
        }
        long[][] sum2 = addSamples(m, s2);
        long got2 = LweRlweBridge.decryptSampleViaPack(m, sum2, 0);
        long expect2 = 0;
        for (int a = 0; a < 3; a++) {
            expect2 = (expect2 + D[ub[a]]) % m.t;
        }
        failed += report("A2 换关键词同样正确", got2 == expect2,
            String.format("关键词 %d：读回 %d，期望 %d", kw2, got2, expect2));
    }

    /** 完整走一遍"列选择 → 盲旋转 → SampleExtract"，返回一条 LWE 样本。 */
    private static long[][] onePath(Mpc4jRgsw m, int n, int d, int qL, int[] s, Mpc4jRgsw.Rgsw[] bk,
                                    long[] A, int u, Random rnd) {
        int r = u % R;
        int c = u / R;
        long[] sel = new long[n];
        if (c == 0) {
            sel[0] = 1;
        } else {
            sel[n - c * R] = m.t - 1;
        }
        Ciphertext cNtt = m.encrypt(sel);
        if (!cNtt.isNttForm()) {
            m.evaluator.transformToNttInplace(cNtt);
        }
        Plaintext pt = new Plaintext(A);
        m.evaluator.transformToNttInplace(pt, cNtt.parmsId());
        Ciphertext acc = new Ciphertext();
        m.evaluator.multiplyPlain(cNtt, pt, acc);

        long[][] lwe = BlindRotateOps.lweEncryptIndex(s, r, qL, rnd);
        Ciphertext out = BlindRotateOps.blindRotate(m, bk, acc, lwe[0], lwe[1][0]);
        return LweRlweBridge.sampleExtract(m, out, 0);
    }

    private static long[][] addSamples(Mpc4jRgsw m, long[][][] ss) {
        long[][] sum = new long[ss[0].length][];
        for (int pi = 0; pi < sum.length; pi++) {
            sum[pi] = new long[ss[0][pi].length];
            long mod = m.primes[pi].value();
            for (int k = 0; k < sum[pi].length; k++) {
                long v = 0;
                for (long[][] x : ss) {
                    v = (v + x[pi][k]) % mod;
                }
                sum[pi][k] = v;
            }
        }
        return sum;
    }

    private static int noiseBudget(Mpc4jRgsw m, Ciphertext ct) {
        try {
            return m.decryptor.invariantNoiseBudget(ct);
        } catch (Throwable e) {
            return -1;
        }
    }

    // ---------------- 最小 BFF（k=3）：把载荷拆成三份放到三个位置 ----------------

    private static int[] bffPositions(int kw) {
        // 位置互不重复：R*C = 256 个可用位，关键词 i 用 3i, 3i+1, 3i+2
        return new int[]{3 * kw, 3 * kw + 1, 3 * kw + 2};
    }

    /** Σ_a D[h_a(K)] mod t —— 由构造保证 = 该关键词的载荷。 */
    private static long payloadOf(int kw, long[] D) {
        int[] u = bffPositions(kw);
        return (D[u[0]] + D[u[1]] + D[u[2]]) % 65537L;
    }

    private static long[] smallDb(int nKw, Random rnd) {
        long[] D = new long[R * C];
        for (int i = 0; i < nKw; i++) {
            int[] u = bffPositions(i);
            // 把载荷拆成三份，保证 Σ = 载荷
            long y = 1000 + i;
            long p1 = y / 3;
            long p2 = y / 3;
            long p3 = y - p1 - p2;
            D[u[0]] = p1;
            D[u[1]] = p2;
            D[u[2]] = p3;
        }
        return D;
    }

    private static long[] fullRangeDb(int nKw, Random rnd) {
        long t = 65537L;
        long[] D = new long[R * C];
        for (int i = 0; i < nKw; i++) {
            int[] u = bffPositions(i);
            long p1 = Math.floorMod(rnd.nextLong(), t);
            long p2 = Math.floorMod(rnd.nextLong(), t);
            long p3 = Math.floorMod(rnd.nextLong(), t);
            D[u[0]] = p1;
            D[u[1]] = p2;
            D[u[2]] = p3;
        }
        return D;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
