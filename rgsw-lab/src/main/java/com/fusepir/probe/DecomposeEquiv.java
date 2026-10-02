package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * <b>差分测试：切段快路径（纯 long）与慢路径（BigInteger）必须逐位完全一致。</b>
 *
 * <p>背景：{@code Mpc4jRgsw.decompose} 原本每个系数做一次 BigInteger CRT 重构，
 * 实测占一轮 CMUX 的 <b>45%</b>（6.25 ms / 15.55 ms，见 {@code CmuxProfile}）。
 * 现在加了一条纯 long 快路径（128 位 Garner + Montgomery），
 * <b>语义必须不变</b> —— 本类就是那个保证：
 * <ol>
 *   <li>对同一批随机密文，逐系数逐段比较 {@code decomposeFast} 与 {@code decomposeBig}；</li>
 *   <li>顺带验证快路径确实被启用（{@code fastDecompose}），否则本测试等于没测；</li>
 *   <li>验证切段重构回去等于原值（{@code Σ digits[k]·B^k ≡ x (mod q)}）—— 这条独立于慢路径，
 *       防止"两条路一起错"。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.DecomposeEquiv 4096}
 */
public final class DecomposeEquiv {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int rounds = args.length > 1 ? Integer.parseInt(args[1]) : 6;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 切段：纯 long 快路径 vs BigInteger 慢路径 差分测试 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[test]   N=%d, 随机密文 %d 条，逐系数逐段对拍%n", n, rounds);

        report("0. 快路径已启用（否则本测试无意义）", m.fastDecompose,
            "fastDecompose=" + m.fastDecompose + "，工作素数=" + m.workingPrimeCount
                + "，base=" + m.base + "（2^" + Integer.numberOfTrailingZeros(m.base) + "）");
        if (!m.fastDecompose) {
            System.out.println("\n=== 1 PASS / 1 FAIL（快路径未启用，无法对拍）===");
            System.exit(1);
        }

        Random rnd = new Random(20260930L);
        boolean allEqual = true;
        boolean allReconstruct = true;
        long firstDiffAt = -1;
        int coeffsChecked = 0;

        for (int r = 0; r < rounds; r++) {
            long[] msg = new long[n];
            for (int i = 0; i < n; i++) {
                msg[i] = Math.floorMod(rnd.nextLong(), m.t);
            }
            Ciphertext ct = m.encrypt(msg);
            Ciphertext coeff = new Ciphertext();
            coeff.copyFrom(ct);
            if (coeff.isNttForm()) {
                m.evaluator.transformFromNttInplace(coeff);
            }
            long[] data = coeff.data();
            for (int poly = 0; poly < 2; poly++) {
                long[][] fast = m.decomposeFast(data, poly);
                long[][] slow = m.decomposeBig(data, poly);
                for (int k = 0; k < fast.length; k++) {
                    for (int i = 0; i < n; i++) {
                        coeffsChecked++;
                        if (fast[k][i] != slow[k][i]) {
                            allEqual = false;
                            if (firstDiffAt < 0) {
                                firstDiffAt = ((long) r << 40) | ((long) poly << 20) | i;
                                System.out.printf("      首个不一致：第 %d 条密文、分量 %d、系数 %d、段 %d："
                                        + "fast=%d slow=%d%n",
                                    r, poly, i, k, fast[k][i], slow[k][i]);
                            }
                        }
                    }
                }
                // 独立校验：Σ digits[k]·B^k ≡ x (mod q)，直接用密文自己的残数重算，不经慢路径
                if (!reconstructs(m, n, data, poly, fast)) {
                    allReconstruct = false;
                }
            }
        }

        report("1. 快慢路径逐位一致", allEqual,
            String.format("对拍 %d 个（系数×段）值，全部相同", coeffsChecked));
        report("2. 切段可精确重构回原值（独立校验，不经慢路径）", allReconstruct,
            "Σ digits[k]·B^k ≡ x (mod q) 对每条密文每个分量成立");

        System.out.printf("%n=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * 独立校验：把切出的平衡位按 {@code Σ d_k·B^k} 在 Z_q 上加回去，必须等于原系数。
     *
     * <p>这条路只用 {@code BigInteger} 做一次线性组合，<b>不复用</b> 慢路径的 CRT 逻辑，
     * 所以两条路一起错的可能性很低。
     */
    private static boolean reconstructs(Mpc4jRgsw m, int n, long[] data, int poly, long[][] digits) {
        int L = m.workingPrimeCount;
        java.math.BigInteger q = m.q;
        java.math.BigInteger B = java.math.BigInteger.valueOf(m.base);
        for (int i = 0; i < n; i++) {
            java.math.BigInteger x = java.math.BigInteger.ZERO;
            java.math.BigInteger pw = java.math.BigInteger.ONE;
            for (int k = 0; k < digits.length; k++) {
                long dv = digits[k][i];
                if (dv >= m.t / 2 + 1) {
                    dv -= m.t;                        // 还原成平衡位（可能是负数）
                }
                x = x.add(java.math.BigInteger.valueOf(dv).multiply(pw)).mod(q);
                pw = pw.multiply(B);
            }
            // 与密文残数在 Z_q 上的值比较：逐素数残数相等即等价
            for (int j = 0; j < L; j++) {
                long mod = m.primes[j].value();
                if (x.mod(java.math.BigInteger.valueOf(mod)).longValueExact()
                    != data[(poly * L + j) * n + i]) {
                    return false;
                }
            }
        }
        return true;
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
        }
        System.out.printf("    [%s] %s%n          %s%n", ok ? "PASS" : "FAIL", name, detail);
    }
}
