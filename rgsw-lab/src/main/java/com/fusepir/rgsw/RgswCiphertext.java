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
 * 一个 RGSW 密文：装着同一个数 μ 在"不同放大倍数"下的两组密文。
 *
 * <p>结构（共 2·l 个 RLWE 密文）：
 * <ul>
 *   <li><b>group0[i]</b>：相位 = g_i·μ　　（把 g_i·μ 加到 c0 上得到）</li>
 *   <li><b>group1[i]</b>：相位 = g_i·(μ ⊛ s)　（把 g_i·(μ⊛s) 加到 c0 上得到）</li>
 * </ul>
 * 其中 g_i = B^i 是 gadget 倍数，l 是层数。
 *
 * <p><b>NTT 域缓存（重要优化）</b>：一次查询里同一个 RGSW 会被外部乘积调用上千次，
 * 而它本身在整个过程中不变。所以这里把它的 NTT 变换结果**首次使用时算一次、之后一直复用**。
 * 这样每次外部乘积只需要变换"源密文切段得到的数字多项式"，不必重复变换评估密钥。
 */
public final class RgswCiphertext {
    /** group0[i]：与源密文 c0 的第 i 段配对 */
    public final RlweCiphertext[] group0;
    /** group1[i]：与源密文 c1 的第 i 段配对 */
    public final RlweCiphertext[] group1;

    /** 惰性计算的 NTT 域形式：[组][层][分量][素数][系数] */
    private long[][][][][] nttCache;

    public RgswCiphertext(RlweCiphertext[] group0, RlweCiphertext[] group1) {
        this.group0 = group0;
        this.group1 = group1;
    }

    public int size() {
        return group0.length + group1.length;
    }

    /**
     * 取 NTT 域形式（首次调用时计算并缓存；换了参数对象会导致缓存失效，因此带上参数校验）。
     */
    public synchronized long[][][][][] nttForm(RingParams p) {
        if (nttCache != null && nttCache.length == 2
            && nttCache[0].length == group0.length
            && nttCache[0][0][0].length == p.primes.length
            && nttCache[0][0][0][0] != null
            && nttCache[0][0][0][0].length == p.n) {
            return nttCache;
        }
        int levels = group0.length;
        int primes = p.primes.length;
        long[][][][][] cache = new long[2][levels][2][primes][];
        for (int g = 0; g < 2; g++) {
            RlweCiphertext[] group = g == 0 ? group0 : group1;
            for (int i = 0; i < levels; i++) {
                for (int c = 0; c < 2; c++) {
                    long[][] comp = c == 0 ? group[i].c0 : group[i].c1;
                    for (int k = 0; k < primes; k++) {
                        cache[g][i][c][k] = p.ntt[k] == null ? null : p.ntt[k].forward(comp[k]);
                    }
                }
            }
        }
        nttCache = cache;
        return cache;
    }
}
