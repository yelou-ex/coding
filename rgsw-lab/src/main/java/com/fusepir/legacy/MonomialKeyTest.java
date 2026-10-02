package com.fusepir.legacy;


import com.fusepir.prim.*;
/*
 * !!! ROUTE C - self-built RLWE, DEPRECATED, NOT THE DEFAULT !!!
 *
 * Default implementation (route B): the sibling Mpc4jRgsw.java (RGSW / external
 * product / CMUX) and BlindRotateOps.java (blind rotation). They run on
 * coding/lib/mpc4j-crypto-fhe-seal.jar - MPC4J's pure-Java SEAL port, patched so
 * that the Galois permutation tables are lazily allocated - and are verified at
 * the paper's parameters (N=16384, t=65537, 9 declared primes).
 *
 * This file is kept only as a cross-check tool. See coding/docs/RLWE路线审计.md.
 */


import com.fusepir.rlwe.*;

import java.util.Random;

/**
 * 公开单项式旋转 + 自举密钥 的自检程序。
 *
 * <p>用法：<code>java -cp out com.fusepir.legacy.MonomialKeyTest [scale]</code>
 * 加 scale 参数则在 N=16384、15 素数（论文模数规模）下跑一遍。
 */
public final class MonomialKeyTest {

    private static int failed = 0;

    public static void main(String[] args) {
        boolean scale = args.length > 0 && args[0].equalsIgnoreCase("scale");
        RingParams p = scale ? RingParams.paperParams(16384, 15) : RingParams.lab();
        System.out.println("=== Monomial / BootstrapKey self-test ===");
        System.out.println("[params] " + p.describe());
        System.out.println("         ntt=" + p.nttEnabled() + ", scale=" + scale);
        System.out.println();

        Random rnd = new Random(20260916L);
        RlweKey key = new RlweKey(p, rnd);

        testMonomialSmall(p, key, rnd);
        testMonomialWrap(p, key, rnd);
        testBootstrapKey(p, key, rnd);

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    /** 乘 X^k 后解密，应当得到"明文也乘 X^k"的结果 */
    private static void testMonomialSmall(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        int[] shifts = {0, 1, 7, 33, 511};
        for (int k : shifts) {
            long[] m = randomMessage(p, rnd);
            RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
            RlweCiphertext rotated = MonomialOps.mulMonomial(p, ct, k);
            long[] expected = shiftMessage(p, m, k);
            bad += countDiff(RlweOps.decrypt(p, key, rotated), expected);
        }
        report("Test A  public monomial rotation  X^k  (k < N)", bad == 0,
            "shifts " + java.util.Arrays.toString(shifts) + ", wrong coefficients = " + bad);
    }

    /** k ≥ N 的情形：X^k = −X^(k−N)，必须整体取负 */
    private static void testMonomialWrap(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        int[] shifts = {p.n, p.n + 1, 2 * p.n - 1, 2 * p.n + 5};
        for (int k : shifts) {
            long[] m = randomMessage(p, rnd);
            RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
            RlweCiphertext rotated = MonomialOps.mulMonomial(p, ct, k);
            long[] expected = shiftMessage(p, m, k);
            bad += countDiff(RlweOps.decrypt(p, key, rotated), expected);
        }
        report("Test B  public monomial rotation  X^k  (k >= N, sign flip)", bad == 0,
            "shifts " + java.util.Arrays.toString(shifts) + ", wrong coefficients = " + bad);
    }

    /** 自举密钥：生成若干位，并用其中一位做一次 CMUX */
    private static void testBootstrapKey(RingParams p, RlweKey key, Random rnd) {
        int d = 8;
        int[] bits = new int[d];
        for (int i = 0; i < d; i++) {
            bits[i] = rnd.nextInt(2);
        }
        RgswCiphertext[] bk = BootstrapKey.generate(p, key, bits, rnd);

        // 用第 3 位做一次 CMUX：A + RGSW(s_3)⊗(B−A) → s_3=0 得 A，s_3=1 得 B
        long[] m0 = randomMessage(p, rnd);
        long[] m1 = randomMessage(p, rnd);
        RlweCiphertext a = RlweOps.encryptScaled(p, key, m0, rnd);
        RlweCiphertext b = RlweOps.encryptScaled(p, key, m1, rnd);
        RlweCiphertext diff = sub(p, b, a);
        RlweCiphertext prod = RgswOps.externalProduct(p, bk[3], diff);
        RlweCiphertext res = add(p, a, prod);
        long[] expected = bits[3] == 0 ? m0 : m1;
        long bad = countDiff(RlweOps.decrypt(p, key, res), expected);

        // 同时额外做一次"旋转后再做 CMUX"，模拟盲旋转的一轮
        RlweCiphertext rotated = MonomialOps.mulMonomial(p, a, 5);
        long[] expectedRot = shiftMessage(p, m0, 5);
        long bad2 = countDiff(RlweOps.decrypt(p, key, rotated), expectedRot);

        report("Test C  bootstrap key + CMUX + rotation", bad == 0 && bad2 == 0,
            "d=" + d + ", CMUX wrong = " + bad + ", rotate wrong = " + bad2);

        System.out.println();
        System.out.println("Bootstrap key size (this is the feasibility red line):");
        for (int dim : new int[]{128, 512, 1024}) {
            System.out.printf("   d=%-5d l=%-3d -> %s%n", dim, p.levels, BootstrapKey.describeBytes(p, dim));
        }
        System.out.println("   formula: d x (2l) x (2N) x ceil(qBits/8) bytes");
    }

    // ---------- 工具 ----------

    private static RlweCiphertext add(RingParams p, RlweCiphertext x, RlweCiphertext y) {
        long[][] c0 = new long[p.primes.length][p.n];
        long[][] c1 = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                c0[k][i] = RingOps.addMod(x.c0[k][i], y.c0[k][i], p.primes[k]);
                c1[k][i] = RingOps.addMod(x.c1[k][i], y.c1[k][i], p.primes[k]);
            }
        }
        return new RlweCiphertext(c0, c1);
    }

    private static RlweCiphertext sub(RingParams p, RlweCiphertext x, RlweCiphertext y) {
        long[][] c0 = new long[p.primes.length][p.n];
        long[][] c1 = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                c0[k][i] = RingOps.subMod(x.c0[k][i], y.c0[k][i], p.primes[k]);
                c1[k][i] = RingOps.subMod(x.c1[k][i], y.c1[k][i], p.primes[k]);
            }
        }
        return new RlweCiphertext(c0, c1);
    }

    /** 明文中乘以 X^k（模 t）：与 MonomialOps 的符号约定必须一致 */
    private static long[] shiftMessage(RingParams p, long[] m, int k) {
        long twoN = 2L * p.n;
        long kk = ((k % twoN) + twoN) % twoN;
        boolean negate = kk >= p.n;
        int shift = (int) (kk % p.n);
        long[] out = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            int t = i + shift;
            boolean wrap = t >= p.n;
            if (wrap) {
                t -= p.n;
            }
            long v = m[i];
            if (negate ^ wrap) {
                v = -v;
            }
            out[t] = ((v % p.t) + p.t) % p.t;
        }
        return out;
    }

    private static long[] randomMessage(RingParams p, Random rnd) {
        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = Math.floorMod(rnd.nextLong(), p.t);
        }
        return m;
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

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
    }
}
