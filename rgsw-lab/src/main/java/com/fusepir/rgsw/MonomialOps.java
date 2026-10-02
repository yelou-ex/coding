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

/**
 * 公开单项式旋转：把 RLWE 密文乘上 <b>公开</b> 的 X^k。
 *
 * <h3>为什么需要它</h3>
 * 盲旋转的最后一步是"按公开量再旋一次"（CGGI 盲旋转里那个 X^{−b}），
 * 而中间每一轮 CMUX 也要把累加器旋转 X^{a_i·2^i}。这些都是"乘一个公开的单项式"，
 * 不需要任何密钥，是纯粹的系数搬移。
 *
 * <h3>负循环环里的符号约定（容易错的地方）</h3>
 * 环是 Z_q[X]/(X^N+1)，也就是 X^N = −1。于是：
 * <pre>
 *   先约化 k mod 2N：
 *     k &lt; N   → 正常平移 k 位
 *     k ≥ N   → 等价于 −X^(k−N)，即整体取负再平移 k−N 位
 *   平移过程中 i+k ≥ N 的项，因为跨越 X^N 也要变号
 * </pre>
 * 所以最终系数 = 原系数 × (±1)，符号由"是否整体取负"和"是否跨过 X^N"两个条件异或决定。
 */
public final class MonomialOps {

    private MonomialOps() {
    }

    /**
     * 把多项式乘上公开单项式 X^k（每个素数下独立进行）。
     *
     * @param k 可以是任意整数（内部会按 mod 2N 约化）
     */
    public static long[][] mulMonomial(long[][] f, long k, RingParams p) {
        long twoN = 2L * p.n;
        long kk = ((k % twoN) + twoN) % twoN;
        boolean negate = kk >= p.n;      // X^k = -X^(k-N)
        int shift = (int) (kk % p.n);

        long[][] out = new long[p.primes.length][p.n];
        for (int j = 0; j < p.primes.length; j++) {
            long prime = p.primes[j];
            for (int i = 0; i < p.n; i++) {
                int t = i + shift;
                boolean wrap = t >= p.n;   // 跨过 X^N 也要变号
                if (wrap) {
                    t -= p.n;
                }
                long v = f[j][i];
                if (negate ^ wrap) {
                    v = v == 0 ? 0 : prime - v;
                }
                // i → t 是一一映射，可以直接赋值
                out[j][t] = v;
            }
        }
        return out;
    }

    /** 对密文的两个分量同时做公开单项式旋转 */
    public static RlweCiphertext mulMonomial(RingParams p, RlweCiphertext ct, long k) {
        return new RlweCiphertext(
            mulMonomial(ct.c0, k, p),
            mulMonomial(ct.c1, k, p));
    }
}
