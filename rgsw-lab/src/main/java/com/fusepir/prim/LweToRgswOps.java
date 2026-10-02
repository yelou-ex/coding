package com.fusepir.prim;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.math.BigInteger;
import java.util.Random;

/**
 * 论文子程序 <b>LWEtoRGSW(ct_L) → C_μ</b>：把 {@code LWE.Enc_s(μ)}（μ ∈ {0,1}）转成 {@code RGSW.Enc_s(μ)}。
 *
 * <h3>论文怎么说的</h3>
 * <ul>
 *   <li>CAPE §2.5：LWEtoRGSW "converting the encrypted bit into the RGSW representation
 *       used for selector expansion"；</li>
 *   <li>附录 C：LWE 密文"are converted to RGSW form by LWEtoRGSW; the column bits are then
 *       expanded into the encrypted one-hot selector, while <b>the row bits drive the
 *       bit-wise evaluation of BlindRotate</b>"；</li>
 *   <li>算法 4 第 2 步（SETUP）："Generate the <b>public evaluation material</b> required by
 *       LWEtoRGSW"——即所需材料是 setup 阶段发布的密钥，不是新协议消息。</li>
 * </ul>
 * Pirouette 说明其本质："This operation is also known as <b>circuit bootstrapping</b> ...
 * includes basic operations such as <b>blind rotations</b> and homomorphic automorphisms."
 *
 * <h3>本文件的构造</h3>
 * 只用已发表的构件，不自创新构造：
 * <ol>
 *   <li><b>盲旋转取出 μ</b>：用自举密钥 {@code BK = {RGSW(s_i)}} 对 {@code LWE(μ)} 做一次盲旋转，
 *       测试多项式取<b>舍入函数</b>（高半区为 1、低半区为 0）。因为 {@code β = ⟨a,s⟩ + Δ·μ}，
 *       高半区恰好对应 μ=1，于是旋转后<b>常数系数就是 μ</b>，得到 {@code RLWE(μ)}。</li>
 *   <li><b>装配 RGSW</b>：{@code group0[i] = (g_i·Δ⁻¹)·RLWE(μ)}（公开常数标量乘），
 *       {@code group1[i] = group0[i] ⊗ enc_sk}，其中 {@code enc_sk = RGSW(s(X))}。
 *       外部乘积把相位乘上 {@code s(X)}，于是 group1 的相位正好是 {@code g_i·μ·s}。</li>
 * </ol>
 * 第 2 步的 {@code Δ⁻¹} 把 {@code RLWE(μ)} 的 {@code Δ·μ} 相位还原成<b>未缩放的原始 g_i·μ</b>
 * ——我们的外部乘积依赖这个约定（group 相位不带 Δ，因为切段数字已经带了 Δ）。
 *
 * <h3>论文要求的 BlindRotate 由此闭合</h3>
 * <pre>
 *   客户端 query: 逐位 LWE {LWE(z_j)}（a 由种子 PRG 派生，线上只传 ρ 与 β）✓ 与 CAPE-C 一致
 *   服务器:       RGSW(z_j) ← LWEtoRGSW(LWE(z_j))          ← 本文件
 *                 ACC ← CMUX(RGSW(z_j), ACC, ACC·X^{−2^j})  ← BlindRotateOps.blindRotateByBits
 *                 response ← SampleExtract_0(ACC)            ← LweRlweBridge
 * </pre>
 */
public final class LweToRgswOps {

    private LweToRgswOps() {
    }

    /**
     * 论文子程序 LWEtoRGSW。
     *
     * @param bk     自举密钥 {RGSW(s_i)}（setup 发布）；s = LWE 密钥比特
     * @param a      LWE 密文的公开 a 分量
     * @param beta   LWE 密文的公开 β 分量
     * @param encSk  setup 发布的 RGSW(s(X))，用来在 external product 里"乘上 s"
     * @return RGSW(μ)，μ 为 ct_L 所加密的比特
     */
    public static Mpc4jRgsw.Rgsw convert(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, long[] a, long beta,
                                         Mpc4jRgsw.Rgsw encSk) {
        int n = m.n;
        // (1) 舍入测试多项式：高半区为 1、低半区为 0
        long[] round = new long[n];
        for (int j = n / 2; j < n; j++) {
            round[j] = 1;
        }
        Ciphertext acc = m.encrypt(round);
        Ciphertext rlweMu = BlindRotateOps.blindRotate(m, bk, acc, a, beta);

        // (2) 装配 RGSW(μ)：group0 = g_i·Δ⁻¹·RLWE(μ)，group1 = group0 ⊗ enc_sk
        BigInteger delta = m.q.divide(BigInteger.valueOf(m.t));
        BigInteger deltaInv = delta.modInverse(m.q);
        BigInteger power = BigInteger.ONE;
        BigInteger base = BigInteger.valueOf(m.base);
        Ciphertext[] g0 = new Ciphertext[m.levels];
        Ciphertext[] g1 = new Ciphertext[m.levels];
        for (int i = 0; i < m.levels; i++) {
            Ciphertext s0 = m.scalarMultiply(rlweMu, power.multiply(deltaInv));
            g0[i] = s0;
            g1[i] = m.externalProduct(encSk, s0);
            power = power.multiply(base);
        }
        return new Mpc4jRgsw.Rgsw(g0, g1);
    }

    // ------------------------------------------------------------------

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int qL = 2 * n;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== LWEtoRGSW（论文子程序）+ 论文要求的位驱动盲旋转 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d%n%n", d, qL);

        Random rnd = new Random(20260919L);
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        // setup 材料：BK = {RGSW(s_i)}，以及 enc_sk = RGSW(s(X))
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        long[] skPoly = new long[n];
        for (int i = 0; i < d; i++) {
            skPoly[i] = s[i];       // 把 LWE 密钥作为多项式放进 RLWE 密钥（LWE-in-RLWE）
        }
        Mpc4jRgsw.Rgsw encSk = m.encryptRgswPoly(skPoly);
        System.out.printf("[setup] BK(%d 个 RGSW) + enc_sk(RGSW(s)) 构造 %.0f ms%n%n",
            d, (System.nanoTime() - t0) / 1e6);

        // ---- 验收 0：中间量——盲旋转后常数位是否就是 μ ----
        long[] roundPoly = new long[n];
        for (int j = n / 2; j < n; j++) {
            roundPoly[j] = 1;
        }
        for (int mu = 0; mu <= 1; mu++) {
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + a[i] * s[i]) % qL;
            }
            long beta = Math.floorMod(sum + (mu == 1 ? qL / 2 : 0), qL);
            Ciphertext acc0 = m.encrypt(roundPoly);
            Ciphertext rlwe = BlindRotateOps.blindRotate(m, bk, acc0, a, beta);
            long[] dec = m.decrypt(rlwe);
            StringBuilder pre = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                pre.append(dec[i]).append(" ");
            }
            failed += report("0  盲旋转后常数位 = μ（μ=" + mu + "）", dec[0] == mu,
                String.format("常数位 got=%d want=%d；前 4 个系数: %s", dec[0], mu, pre));
        }

        // ---- 验收 1：LWEtoRGSW(LWE(1)) ⊗ ct = ct ----
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 1000) + 1;
        }
        Ciphertext ct = m.encrypt(msg);
        for (int mu = 0; mu <= 1; mu++) {
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + a[i] * s[i]) % qL;
            }
            // β = ⟨a,s⟩ + Δ·μ，Δ = q_L/t；这里 t=2（比特），故 Δ = qL/2
            long beta = Math.floorMod(sum + (mu == 1 ? qL / 2 : 0), qL);
            Mpc4jRgsw.Rgsw c = convert(m, bk, a, beta, encSk);
            long[] got = m.decrypt(m.externalProduct(c, ct));
            long[] want = mu == 1 ? msg : new long[n];
            int wrong = 0;
            for (int i = 0; i < n; i++) {
                if (got[i] != want[i]) {
                    wrong++;
                }
            }
            failed += report("1  LWEtoRGSW(LWE(" + mu + ")) ⊗ ct = " + (mu == 1 ? "ct" : "0"),
                wrong == 0, String.format("错位 %d/%d（首个系数 got=%d want=%d）",
                    wrong, n, got[0], want[0]));
        }

        // ---- 验收 2：论文要求的"位驱动"盲旋转，用 LWEtoRGSW 产出的控制位 ----
        long[] payload = new long[n];
        for (int i = 0; i < n; i++) {
            payload[i] = (i * 7 + 3) % 1000 + 1;
        }
        Ciphertext acc = m.encrypt(payload);
        int bits = Integer.numberOfTrailingZeros(n);   // ⌈log2 N⌉
        long index = 777 % n;
        Mpc4jRgsw.Rgsw[] controls = new Mpc4jRgsw.Rgsw[bits];
        for (int j = 0; j < bits; j++) {
            long zj = (index >>> j) & 1L;
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + a[i] * s[i]) % qL;
            }
            long beta = Math.floorMod(sum + (zj == 1 ? qL / 2 : 0), qL);
            controls[j] = convert(m, bk, a, beta, encSk);   // ← 服务器只看到 (a, β)
        }
        Ciphertext out = BlindRotateOps.blindRotateByBits(m, controls, acc);
        long[] got = m.decrypt(out);
        failed += report("2  论文要求的位驱动盲旋转（控制位全部来自 LWEtoRGSW）",
            got[0] == payload[(int) index],
            String.format("index=%d（bits=%d）: 常数位 got=%d want=%d",
                index, bits, got[0], payload[(int) index]));

        System.out.println();
        System.out.println(failed == 0
            ? "=== LWEtoRGSW 打通：论文口径的 BlindRotate（row bits + 位驱动）完整闭合 ==="
            : "=== 有 " + failed + " 项失败 ===");
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
