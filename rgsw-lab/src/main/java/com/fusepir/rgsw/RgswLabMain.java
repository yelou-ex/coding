package com.fusepir.rgsw;

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
 * RGSW 层自检 / 参数扫描程序。
 *
 * <p>运行模式（由 params.env 里的 RGSW_MODE 决定，也可用环境变量临时覆盖）：
 * <ul>
 *   <li><b>test</b>：跑 5 项正确性自检；</li>
 *   <li><b>scale</b>：在 N=16384（论文的多项式次数）下做一次外部乘积，看耗时与噪声；</li>
 *   <li><b>sweep</b>：扫一批参数组合，输出"噪声余量 / 单次耗时 / 是否正确"对照表，用来做参数优化。</li>
 * </ul>
 *
 * <p>5 项自检的内容：
 * <ol>
 *   <li>切段（跨素数还原后按 B 进制切开）可逆；</li>
 *   <li>RLWE 加解密往返正确；</li>
 *   <li><b>外部乘积：RGSW(μ) ⊗ RLWE(m) 解密得到 μ·m</b>（核心目标）；</li>
 *   <li>单位选择器 μ = X^k（盲旋转里"旋转"的基础）；</li>
 *   <li><b>密文二选一（CMUX）</b>：A + RGSW(μ)⊗(B−A) 在 μ=0 时得 A、μ=1 时得 B
 *       —— 正是盲旋转每一轮要做的事。</li>
 * </ol>
 *
 * <p>控制台输出使用 ASCII 标签，避免 Windows 控制台中文乱码。
 */
public final class RgswLabMain {

    private static int failed = 0;
    private static int trials = 4;

    public static void main(String[] args) {
        LabConfig config = LabConfig.load();
        trials = config.trials;
        String mode = args.length > 0 ? args[0] : config.mode;

        System.out.println("=== RGSW lab (correctness only, NOT a secure parameter set) ===");
        System.out.println("[config] " + config.describe());
        System.out.println();

        switch (mode.toLowerCase()) {
            case "scale":
                scaleCheck(config);
                break;
            case "sweep":
                sweep(config);
                break;
            default:
                runAll(config.toRingParams());
                break;
        }

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    // ---------- 模式 1：正确性自检 ----------

    private static void runAll(RingParams p) {
        Random rnd = new Random(20260916L);
        System.out.println("---------------------------------------------------------------");
        System.out.println("[params] " + p.describe());
        System.out.println("         ntt=" + p.nttEnabled());
        testNtt(p, rnd);
        testDecompose(p, rnd);
        RlweKey key = new RlweKey(p, rnd);
        testRlweRoundtrip(p, key, rnd);
        testExternalProduct(p, key, rnd);
        testSelectorProduct(p, key, rnd);
        testCmux(p, key, rnd);
    }

    // ---------- 模式 2：N=16384 规模检查 ----------

    private static void scaleCheck(LabConfig config) {
        RingParams p = config.toRingParams(config.scaleN);
        System.out.println("---------------------------------------------------------------");
        System.out.println("[scale check] " + p.describe());
        Random rnd = new Random(7L);
        RlweKey key = new RlweKey(p, rnd);
        long[] m = randomMessage(p, rnd);

        long t0 = System.nanoTime();
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
        long tEncrypt = System.nanoTime() - t0;

        RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.constant(p, 1), rnd);

        t0 = System.nanoTime();
        RlweCiphertext res = RgswOps.externalProduct(p, rgsw, ct);
        long tExtProd = System.nanoTime() - t0;

        t0 = System.nanoTime();
        long[] dec = RlweOps.decrypt(p, key, res);
        long tDecrypt = System.nanoTime() - t0;

        t0 = System.nanoTime();
        java.math.BigInteger noise = RlweOps.noiseNorm(p, key, res, m);
        long tNoise = System.nanoTime() - t0;

        long bad = countDiff(dec, m);
        report("Scale check  N=" + config.scaleN + " external product", bad == 0,
            String.format("wrong = %d, noise = %d, limit = %d, margin = %s",
                bad, noise, p.noiseLimit(), marginOf(p, noise)));
        System.out.printf("       stage timing (s): encrypt = %.3f, externalProduct = %.3f, "
                + "decrypt = %.3f, noiseNorm = %.3f%n",
            tEncrypt / 1e9, tExtProd / 1e9, tDecrypt / 1e9, tNoise / 1e9);
    }

    // ---------- 模式 3：参数扫描（参数优化用） ----------

    private static void sweep(LabConfig config) {
        int n = config.sweepN;
        System.out.println("---------------------------------------------------------------");
        System.out.println("[sweep] N=" + n + ", t=" + config.t + ", noiseBits=" + config.noiseBits);
        System.out.println("columns: primes | q(bits) | base | levels | noiseLimit | noise | margin | ms/op | ok");
        System.out.println();
        System.out.printf("%-7s %-8s %-8s %-6s %-12s %-12s %-10s %-9s %s%n",
            "primes", "q(bits)", "base", "levels", "noiseLimit", "noise", "margin", "ms/op", "ok");

        int[] baseList = {2, 4, 16, 256, 65536};
        for (int primeCount = 1; primeCount <= 2; primeCount++) {
            for (int base : baseList) {
                RingParams p;
                try {
                    p = LabConfig.build(n, primeCount, config.primeBits, base, 0, config.noiseBits, config.t);
                } catch (RuntimeException e) {
                    System.out.printf("%-7d %-8s %-8d %-6s  skip: %s%n", primeCount, "-", base, "-", e.getMessage());
                    continue;
                }
                try {
                    Random rnd = new Random(11L);
                    RlweKey key = new RlweKey(p, rnd);
                    long[] m = randomMessage(p, rnd);
                    RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
                    RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.constant(p, 1), rnd);
                    long t0 = System.nanoTime();
                    RlweCiphertext res = RgswOps.externalProduct(p, rgsw, ct);
                    double ms = (System.nanoTime() - t0) / 1e6;
                    java.math.BigInteger noise = RlweOps.noiseNorm(p, key, res, m);
                    long bad = countDiff(RlweOps.decrypt(p, key, res), m);
                    System.out.printf("%-7d %-8d %-8d %-6d %-16s %-16s %-10s %-9.1f %s%n",
                        primeCount, p.qBits, base, p.levels,
                        p.noiseLimit().toString(), noise.toString(), marginOf(p, noise), ms,
                        bad == 0 ? "yes" : ("NO(" + bad + ")"));
                } catch (RuntimeException | OutOfMemoryError e) {
                    System.out.printf("%-7d %-8d %-8d %-6d  failed: %s%n",
                        primeCount, p.qBits, base, p.levels, e.getClass().getSimpleName());
                }
            }
        }
        System.out.println();
        System.out.println("How to read this table:");
        System.out.println("  margin  - higher = more rounds can be chained before decryption breaks;");
        System.out.println("  base    - larger base = fewer levels = faster, but smaller margin;");
        System.out.println("  ok=NO   - noise exceeded the limit, decryption is wrong;");
        System.out.println("  primes  - more primes = much larger modulus = huge margin, at ~2x cost per step.");
    }

    // ---------- 0. NTT 正确性自检（与朴素乘法逐位对照） ----------
    private static void testNtt(RingParams p, Random rnd) {
        if (!p.nttEnabled()) {
            report("Test 0  NTT vs schoolbook multiplication", true,
                "NTT unavailable for these primes, schoolbook path in use");
            return;
        }
        long bad = 0;
        int trials = 5;
        for (int t = 0; t < trials; t++) {
            long[][] f = RingOps.sampleUniform(rnd, p);
            long[][] g = RingOps.sampleUniform(rnd, p);
            long[][] viaNtt = RingOps.mul(f, g, p);
            for (int k = 0; k < p.primes.length; k++) {
                long[] viaSchool = RingOps.mulSchoolbook(f[k], g[k], p, k);
                bad += countDiff(viaNtt[k], viaSchool);
            }
        }
        report("Test 0  NTT vs schoolbook multiplication", bad == 0,
            trials + " random products per prime, mismatched coefficients = " + bad);
    }

    // ---------- 1. 切段自检 ----------
    private static void testDecompose(RingParams p, Random rnd) {
        long bad = 0;
        for (int t = 0; t < 200; t++) {
            java.math.BigInteger[] f = RingOps.crtPoly(p, RingOps.sampleUniform(rnd, p));
            java.math.BigInteger[] back = RgswOps.recompose(p, RgswOps.decompose(p, f));
            for (int i = 0; i < p.n; i++) {
                if (!back[i].equals(f[i])) {
                    bad++;
                }
            }
        }
        report("Test 1  gadget decompose/recompose (after CRT)", bad == 0,
            "200 random polynomials, mismatched coefficients = " + bad);
    }

    // ---------- 2. RLWE 往返 ----------
    private static void testRlweRoundtrip(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        java.math.BigInteger maxNoise = java.math.BigInteger.ZERO;
        for (int t = 0; t < trials; t++) {
            long[] m = randomMessage(p, rnd);
            RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
            bad += countDiff(RlweOps.decrypt(p, key, ct), m);
            maxNoise = maxNoise.max(RlweOps.noiseNorm(p, key, ct, m));
        }
        report("Test 2  RLWE encrypt/decrypt roundtrip", bad == 0,
            trials + " messages, wrong coefficients = " + bad
                + ", max noise = " + maxNoise + " (limit = " + p.noiseLimit() + ")");
    }

    // ---------- 3. 外部乘积（核心） ----------
    private static void testExternalProduct(RingParams p, RlweKey key, Random rnd) {
        long badZero = 0;
        long badOne = 0;
        java.math.BigInteger maxNoise = java.math.BigInteger.ZERO;

        for (int mu = 0; mu <= 1; mu++) {
            for (int t = 0; t < trials; t++) {
                long[] m = randomMessage(p, rnd);
                RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
                RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.constant(p, mu), rnd);
                RlweCiphertext res = RgswOps.externalProduct(p, rgsw, ct);
                long[] expected = mu == 0 ? new long[p.n] : m;
                long wrong = countDiff(RlweOps.decrypt(p, key, res), expected);
                if (mu == 0) {
                    badZero += wrong;
                } else {
                    badOne += wrong;
                }
                maxNoise = maxNoise.max(RlweOps.noiseNorm(p, key, res, expected));
            }
        }
        report("Test 3  external product  mu*ct", badZero == 0 && badOne == 0,
            "mu=0: wrong = " + badZero + " ; mu=1: wrong = " + badOne
                + " ; max noise = " + maxNoise + " (limit = " + p.noiseLimit() + ")");
    }

    // ---------- 4. 单位选择器 μ = X^k ----------
    private static void testSelectorProduct(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        java.math.BigInteger maxNoise = java.math.BigInteger.ZERO;
        int[] shifts = {1, 33, 511};
        for (int t = 0; t < Math.min(3, trials); t++) {
            int k = shifts[t % shifts.length];
            long[] m = randomMessage(p, rnd);
            RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
            RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.oneHot(p, k), rnd);
            RlweCiphertext res = RgswOps.externalProduct(p, rgsw, ct);
            long[] expected = shiftMessage(p, m, k);
            bad += countDiff(RlweOps.decrypt(p, key, res), expected);
            maxNoise = maxNoise.max(RlweOps.noiseNorm(p, key, res, expected));
        }
        report("Test 4  selector mu = X^k", bad == 0,
            "shifts tested = " + Math.min(3, trials) + ", wrong coefficients = " + bad
                + ", max noise = " + maxNoise);
    }

    // ---------- 5. 密文二选一（CMUX） ----------
    private static void testCmux(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        java.math.BigInteger maxNoise0 = java.math.BigInteger.ZERO;
        java.math.BigInteger maxNoise1 = java.math.BigInteger.ZERO;
        for (int t = 0; t < Math.min(3, trials); t++) {
            long[] m0 = randomMessage(p, rnd);
            long[] m1 = randomMessage(p, rnd);
            RlweCiphertext a = RlweOps.encryptScaled(p, key, m0, rnd);
            RlweCiphertext b = RlweOps.encryptScaled(p, key, m1, rnd);

            RlweCiphertext diff = sub(p, b, a);
            for (int mu = 0; mu <= 1; mu++) {
                RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.constant(p, mu), rnd);
                RlweCiphertext prod = RgswOps.externalProduct(p, rgsw, diff);
                RlweCiphertext res = add(p, a, prod);
                long[] expected = mu == 0 ? m0 : m1;
                bad += countDiff(RlweOps.decrypt(p, key, res), expected);
                java.math.BigInteger noise = RlweOps.noiseNorm(p, key, res, expected);
                if (mu == 0) {
                    maxNoise0 = maxNoise0.max(noise);
                } else {
                    maxNoise1 = maxNoise1.max(noise);
                }
            }
        }
        report("Test 5  encrypted 2-way select (CMUX)", bad == 0,
            "pairs tested = " + Math.min(3, trials) + ", wrong coefficients = " + bad
                + " ; max noise mu=0: " + maxNoise0 + ", mu=1: " + maxNoise1
                + " (limit = " + p.noiseLimit() + ")");
    }

    // ---------- 工具 ----------

    /** 噪声余量 = 噪声上限 / 实测噪声；量级太大时用 2 的幂显示 */
    private static String marginOf(RingParams p, java.math.BigInteger noise) {
        if (noise.signum() == 0) {
            return "inf";
        }
        java.math.BigInteger m = p.noiseLimit().divide(noise);
        return m.bitLength() > 40 ? ("2^" + m.bitLength()) : m.toString();
    }

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

    /** 明文中乘以 X^k（模 t）：系数整体平移，越过 X^N 的要变号（因为 X^N = -1） */
    private static long[] shiftMessage(RingParams p, long[] m, int k) {
        long[] out = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            int src = i - k;
            long v = src >= 0 ? m[src] : -m[src + p.n];
            out[i] = ((v % p.t) + p.t) % p.t;
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
