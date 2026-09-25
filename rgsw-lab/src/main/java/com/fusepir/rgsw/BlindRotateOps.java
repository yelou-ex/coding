package com.fusepir.rgsw;

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
 * <p><b>两个函数都不接收明文索引</b>：口径 2 收 LWE 密文 {@code (a, b)}；
 * 口径 1 收逐位 {@code RGSW} 控制位 + 公开的 2^i 步长。验收代码需要的期望值要自己另外带。
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
