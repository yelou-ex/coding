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

import java.math.BigInteger;
import java.util.Random;

/**
 * RGSW 加密 与 外部乘积（论文中的 RGSW.Enc 与 ExternalProduct）。
 *
 * <h3>外部乘积为什么是对的</h3>
 * 设源密文 ct 的相位为 c0 + c1·s = Δ·m + e（即它是 m 的普通密文）。
 * 把 c0、c1 各自还原成 [0, q) 上的整数后按 B 进制切段：c0 = Σ β_i·g_i，c1 = Σ α_i·g_i（g_i = B^i）。
 * 定义
 * <pre>
 *   dst = Σ_i β_i ⊛ group0[i] + Σ_i α_i ⊛ group1[i]
 * </pre>
 * 取相位：
 * <pre>
 *   phase(dst) = Σ_i β_i·(g_i·μ) + Σ_i α_i·(g_i·μ⊛s)
 *              = μ ⊛ (c0 + s⊛c1) = μ ⊛ (Δ·m + e)
 * </pre>
 * 所以 dst 就是 μ·m 的密文——服务器全程不需要解密，也不需要知道 μ。
 * 这正是盲旋转里"按保密的行号做二选一（CMUX）"所需要的那一步。
 *
 * <h3>切段前必须先跨素数还原</h3>
 * {@link #decompose} 的输入是<b>已经 CRT 还原过的整数</b>，不是某个素数下的余数。
 * 这是本文件最关键的一点：如果对每个素数各自的余数分别切段，外部乘积会静默算错。
 * C++ 实现里对应的是 TFHERNS::CRTDecPoly + basered 那一段。
 */
public final class RgswOps {

    private RgswOps() {
    }

    /** 把 [0, q) 上的整数按 B 进制切成 levels 段（输入必须是 CRT 还原后的值） */
    public static long[][] decompose(RingParams p, BigInteger[] values) {
        long[][] digits = new long[p.levels][p.n];
        BigInteger base = BigInteger.valueOf(p.base);
        for (int i = 0; i < p.n; i++) {
            BigInteger x = values[i];
            for (int k = 0; k < p.levels; k++) {
                digits[k][i] = x.mod(base).longValueExact();
                x = x.divide(base);
            }
        }
        return digits;
    }

    /** 切段的逆运算（自检用）：Σ d_k·B^k 必须等于原值 */
    public static BigInteger[] recompose(RingParams p, long[][] digits) {
        BigInteger base = BigInteger.valueOf(p.base);
        BigInteger[] out = new BigInteger[p.n];
        for (int i = 0; i < p.n; i++) {
            BigInteger x = BigInteger.ZERO;
            for (int k = p.levels - 1; k >= 0; k--) {
                x = x.multiply(base).add(BigInteger.valueOf(digits[k][i]));
            }
            out[i] = x;
        }
        return out;
    }

    /** RGSW 加密（论文 RGSW.Enc）：μ 在实践中是二进制选择器（系数 0/1） */
    public static RgswCiphertext encrypt(RingParams p, RlweKey key, long[] mu, Random rnd) {
        long[][] muPoly = RlweOps.toPrimePoly(p, mu);
        long[][] muS = RingOps.mulSmall(muPoly, key.s, p); // μ ⊛ s（μ 系数 ≤ 1，走快路径）

        RlweCiphertext[] group0 = new RlweCiphertext[p.levels];
        RlweCiphertext[] group1 = new RlweCiphertext[p.levels];
        for (int i = 0; i < p.levels; i++) {
            BigInteger g = p.gadget[i];
            long[][] msg0 = RingOps.scalarMulBig(muPoly, g, p);  // g_i · μ
            long[][] msg1 = RingOps.scalarMulBig(muS, g, p);     // g_i · (μ ⊛ s)
            group0[i] = RlweOps.encryptRawPrime(p, key, msg0, rnd);
            group1[i] = RlweOps.encryptRawPrime(p, key, msg1, rnd);
        }
        return new RgswCiphertext(group0, group1);
    }

    /** 外部乘积：输入一个 RGSW 密文和一个 RLWE 密文，输出 RLWE 密文 */
    public static RlweCiphertext externalProduct(RingParams p, RgswCiphertext rgsw, RlweCiphertext src) {
        if (p.nttEnabled()) {
            return externalProductNtt(p, rgsw, src);
        }
        return externalProductSchoolbook(p, rgsw, src);
    }

    /**
     * NTT 版外部乘积（已发表的标准做法：评估密钥常驻 NTT 域，避免每次重复变换）。
     *
     * <p>每个素数上只需要：把"源密文切段得到的数字多项式"做正向 NTT（每层两个），
     * 与已缓存的 RGSW NTT 逐点乘积累加，最后一次逆变换。
     */
    private static RlweCiphertext externalProductNtt(RingParams p, RgswCiphertext rgsw, RlweCiphertext src) {
        // 先跨素数还原，再切段 —— 顺序不能反
        BigInteger[] v0 = RingOps.crtPoly(p, src.c0);
        BigInteger[] v1 = RingOps.crtPoly(p, src.c1);
        long[][] d0 = decompose(p, v0);
        long[][] d1 = decompose(p, v1);
        long[][][][][] key = rgsw.nttForm(p);

        int primes = p.primes.length;
        long[][] r0 = new long[primes][];
        long[][] r1 = new long[primes][];
        for (int k = 0; k < primes; k++) {
            NttContext ctx = p.ntt[k];
            long[] acc0 = new long[p.n];
            long[] acc1 = new long[p.n];
            for (int i = 0; i < p.levels; i++) {
                long[] digit0 = RlweOps.toPrimePolyOne(p, d0[i], k);
                long[] digit1 = RlweOps.toPrimePolyOne(p, d1[i], k);
                long[] d0Ntt = ctx.forward(digit0);
                long[] d1Ntt = ctx.forward(digit1);
                ctx.pointwiseAccumulate(acc0, d0Ntt, key[0][i][0][k]);
                ctx.pointwiseAccumulate(acc1, d0Ntt, key[0][i][1][k]);
                ctx.pointwiseAccumulate(acc0, d1Ntt, key[1][i][0][k]);
                ctx.pointwiseAccumulate(acc1, d1Ntt, key[1][i][1][k]);
            }
            r0[k] = ctx.inverse(acc0);
            r1[k] = ctx.inverse(acc1);
        }
        return new RlweCiphertext(r0, r1);
    }

    /** 朴素版外部乘积（没有 NTT 上下文时使用） */
    private static RlweCiphertext externalProductSchoolbook(RingParams p, RgswCiphertext rgsw, RlweCiphertext src) {
        BigInteger[] v0 = RingOps.crtPoly(p, src.c0);
        BigInteger[] v1 = RingOps.crtPoly(p, src.c1);
        long[][] d0 = decompose(p, v0);
        long[][] d1 = decompose(p, v1);

        long[][] r0 = RingOps.zero(p);
        long[][] r1 = RingOps.zero(p);
        for (int i = 0; i < p.levels; i++) {
            long[][] d0p = RlweOps.toPrimePolySmall(p, d0[i]);
            long[][] d1p = RlweOps.toPrimePolySmall(p, d1[i]);
            RingOps.addInplace(r0, RingOps.mulSmall(d0p, rgsw.group0[i].c0, p), p);
            RingOps.addInplace(r1, RingOps.mulSmall(d0p, rgsw.group0[i].c1, p), p);
            RingOps.addInplace(r0, RingOps.mulSmall(d1p, rgsw.group1[i].c0, p), p);
            RingOps.addInplace(r1, RingOps.mulSmall(d1p, rgsw.group1[i].c1, p), p);
        }
        return new RlweCiphertext(r0, r1);
    }

    // ---------- 常用选择器 ----------

    /**
     * 常数多项式：只有常数项是 v。
     *
     * <p>必须用大整数取模：q 可能是几百位，BigInteger.longValue() 只返回低 64 位而且是**有符号**的——
     * 低字最高位为 1 时会给负数，系数就变成 p-4 这种垃圾值。这个坑只在素数较多时暴露
     * （实测：15 素数时外部乘积全错，1~2 素数时正常）。
     */
    public static long[] constant(RingParams p, long v) {
        long[] f = new long[p.n];
        f[0] = java.math.BigInteger.valueOf(v).mod(p.q).longValueExact();
        return f;
    }

    /** 单位选择器：只有第 idx 个系数是 1（即乘以 X^idx） */
    public static long[] oneHot(RingParams p, int idx) {
        long[] f = new long[p.n];
        f[Math.floorMod(idx, p.n)] = 1;
        return f;
    }
}
