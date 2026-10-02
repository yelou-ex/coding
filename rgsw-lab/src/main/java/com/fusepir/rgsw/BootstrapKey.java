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
 * 自举密钥（盲旋转用的评估材料）。
 *
 * <h3>是什么</h3>
 * 盲旋转要按"加密的行号"逐位做二选一（CMUX），每一轮需要：
 * <ul>
 *   <li>一个 <b>RGSW 密文</b>，加密 LWE 密钥的第 i 位 s_i；</li>
 *   <li>一次"把累加器旋转 X^{a_i·2^i}"（公开量，见 {@link MonomialOps}）。</li>
 * </ul>
 * 所以自举密钥就是 <b>d 个 RGSW 密文</b>（d = LWE 密钥维度），在 Setup 阶段由密钥持有者生成，
 * 作为公开参数交给服务器。
 *
 * <h3>体积是关键约束（必须提前算）</h3>
 * <pre>
 *   单个 RLWE 密文 ≈ 2 · N · (q 的字节数)
 *   单个 RGSW 密文 = 2 · l 个 RLWE 密文
 *   自举密钥       = d 个 RGSW 密文
 * </pre>
 * 论文规模下（N=16384、q=451 位、l=29、d=512）会到 <b>几十 GB</b> 量级——
 * 这就是必须先把 d 和 l 定下来的原因。{@link #bytes} 用来量化这件事。
 */
public final class BootstrapKey {

    private BootstrapKey() {
    }

    /**
     * 生成自举密钥：对 LWE 密钥的每一位生成一个 RGSW。
     *
     * @param lweSecretBits LWE 密钥的二进制表示（每位 0/1）。
     *                      必须用 <b>二进制</b> 密钥：CMUX 是"按位二选一"，
     *                      若密钥取 {0,1,2} 就需要三路选择、密钥结构也得跟着改。
     */
    public static RgswCiphertext[] generate(RingParams p, RlweKey rlweKey,
                                            int[] lweSecretBits, Random rnd) {
        for (int bit : lweSecretBits) {
            if (bit != 0 && bit != 1) {
                throw new IllegalArgumentException(
                    "自举密钥要求二进制 LWE 密钥，收到位值 " + bit);
            }
        }
        RgswCiphertext[] key = new RgswCiphertext[lweSecretBits.length];
        for (int i = 0; i < lweSecretBits.length; i++) {
            key[i] = RgswOps.encrypt(p, rlweKey, RgswOps.constant(p, lweSecretBits[i]), rnd);
        }
        return key;
    }

    /** 自举密钥体积（字节） */
    public static long bytes(RingParams p, int dimension) {
        long bytesPerCoefficient = (p.qBits + 7L) / 8L;
        long perRlweCiphertext = 2L * p.n * bytesPerCoefficient;
        long perRgsw = 2L * p.levels * perRlweCiphertext;
        return (long) dimension * perRgsw;
    }

    /** 体积的可读描述（自动选 KB/MB/GB） */
    public static String describeBytes(RingParams p, int dimension) {
        long b = bytes(p, dimension);
        if (b < (1L << 20)) {
            return String.format("%.1f KB", b / 1024.0);
        }
        if (b < (1L << 30)) {
            return String.format("%.1f MB", b / 1048576.0);
        }
        return String.format("%.2f GB", b / 1073741824.0);
    }
}
