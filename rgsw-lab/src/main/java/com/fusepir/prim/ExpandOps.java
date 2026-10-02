package com.fusepir.prim;


import com.fusepir.probe.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.ParmsId;

import java.math.BigInteger;

/**
 * <b>选择子扩展（SealPIR §3.3 / Chen CDKS21 的 {@code EXPAND}），用于压缩列选择子。</b>
 *
 * <p>原来是「客户端为每条路送 C 个独立密文（一个 {@code Enc(1)} + C−1 个 {@code Enc(0)}）」，
 * 即 {@code k × C} 个密文。本类改成：
 * <ol>
 *   <li>客户端只送 <b>1 个单项式</b> {@code Enc(x^{c_a})}（k 条路 ⇒ k 个密文）；</li>
 *   <li>服务端把它同态扩展成 C 个选择子：<b>恰好一个加密常数 C，其余加密 0</b>。</li>
 * </ol>
 *
 * <h3>★ 为什么最后不用乘 α</h3>
 * SealPIR 原步骤最后要把 {@code Enc(C)} 乘上 {@code α = C^{-1} mod t} 变成 {@code Enc(1)}。
 * 我们<b>不做这一步</b>，而是把 α <b>在明文侧折进服务端的表</b>
 * （{@code P' = α·P mod t}）。因为选择子随后只用来做 {@code CtPtMul}：
 * <pre>
 *   Σ_c CtPtMul(C·1_{c=c*}, α·P_c) = (C·α)·P_{c*} = P_{c*}
 * </pre>
 * 密文侧一次 α 乘法都没有 ⇒ SealPIR Theorem 2 里那个 {@code t} 因子（约 16 bit）消失。
 * SealPIR 做不到这一点，因为它的扩展输出要被直接当答案返回 / 继续做 ct×ct。
 *
 * <h3>实测依据</h3>
 * {@code ExpandProbe} 在 N=4096 / t=65537 / C=4 上跑过 <b>16 PASS / 0 FAIL</b>：
 * Galois 指数实测为 {@code e_j = N/2^j + 1}（论文 Figure 3 印的 {@code N/2^{j+1}+1}
 * <b>整体差一层</b>，照抄会得到「第 0 项对、高阶项全错」的假成功）；
 * 扩展后噪声 51 → 45 bit，折 α 后精确还原 P。
 *
 * <p>⚠️ 这是 <b>CAPE-C / FusePIR-C</b> 的选择子压缩做法（论文 §1.2、Appendix B）：
 * FusePIR-C 用紧凑编码替换 one-hot 选择子、服务端同态扩展，**其余检索流程完全不变**。
 * 基准 CAPE 用的是 C 个独立 one-hot 密文，所以这是一条**已记录的偏差**，不是基准行为。
 */
public final class ExpandOps {

    private ExpandOps() {
    }

    /**
     * Galois 指数序列 {@code e_j = N/2^j + 1}（j = 0 .. log2(C)−1）。
     *
     * <p>第 j 层要满足 {@code d·(e_j−1) ≡ N (mod 2N)}，对第 j 层的相关指数 d 取最小解即得此式。
     * N=4096、C=4 时是 <b>4097、2049</b>。
     */
    public static int[] expsFor(int n, int c) {
        int ell = Integer.numberOfTrailingZeros(c);
        int[] exps = new int[ell];
        for (int j = 0; j < ell; j++) {
            exps[j] = n / (1 << j) + 1;
        }
        return exps;
    }

    /** 为每一层各建一套 Galois 公钥（较贵，务必建一次并复用）。 */
    public static GaloisKeys[] keysFor(Mpc4jRgsw m, int c) {
        int[] exps = expsFor(m.n, c);
        GaloisKeys[] gks = new GaloisKeys[exps.length];
        for (int j = 0; j < exps.length; j++) {
            GaloisKeys gk = new GaloisKeys();
            m.keyGen.createGaloisKeys(new int[]{exps[j]}, gk);
            gks[j] = gk;
        }
        return gks;
    }

    /** {@code α = C^{-1} mod t}（明文侧折叠因子）。 */
    public static long alphaFor(long t, int c) {
        return BigInteger.valueOf(c).modInverse(BigInteger.valueOf(t)).longValueExact();
    }

    /**
     * 把 {@code Enc(x^i)} 扩展成 {@code c} 个选择子。
     *
     * <p>输出语义：<b>恰好第 i 个加密常数 {@code c}，其余加密 0</b>。
     * 与「C 个独立 one-hot 密文」严格等价 —— 只是把 {@code C} 换成 {@code c}，
     * 由调用方在明文侧折 α 抵消。
     */
    public static Ciphertext[] expand(Mpc4jRgsw m, int n, Ciphertext query, int c,
                                      int[] exps, GaloisKeys[] gks) {
        Ciphertext[] cts = {query};
        for (int j = 0, w = 1; w < c; j++, w <<= 1) {
            Ciphertext[] next = new Ciphertext[cts.length * 2];
            for (int k = 0; k < cts.length; k++) {
                Ciphertext c0 = cts[k];
                // mulPlain 出的是 NTT 域、applyGalois 出的是系数域，必须归一后才能 add
                Ciphertext c1 = toCoeff(m, mulPlainCoeffs(m, c0, monomial(m, n, -w)));
                next[k] = m.add(c0, applyGalois(m, c0, exps[j], gks[j]));
                next[k + cts.length] = m.add(c1, applyGalois(m, c1, exps[j], gks[j]));
            }
            cts = next;
        }
        return cts;
    }

    /** 单项式 {@code x^exp} 在 {@code Z_t[x]/(x^N+1)} 里的系数向量。 */
    public static long[] monomial(Mpc4jRgsw m, int n, int exp) {
        long t = m.t;
        int k = ((exp % (2 * n)) + 2 * n) % (2 * n);
        long[] v = new long[n];
        if (k < n) {
            v[k] = 1;
        } else {
            v[k - n] = t - 1;          // x^{k-N}·x^N = −x^{k-N}
        }
        return v;
    }

    private static Ciphertext mulPlainCoeffs(Mpc4jRgsw m, Ciphertext ct, long[] coeffs) {
        Ciphertext ctNtt = toNtt(m, ct);
        Plaintext pt = new Plaintext(coeffs.length);
        for (int i = 0; i < coeffs.length; i++) {
            pt.set(i, coeffs[i]);
        }
        m.evaluator.transformToNttInplace(pt, ctNtt.parmsId());
        Ciphertext out = new Ciphertext();
        m.evaluator.multiplyPlain(ctNtt, pt, out);
        return out;
    }

    private static Ciphertext toNtt(Mpc4jRgsw m, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (!copy.isNttForm()) {
            m.evaluator.transformToNttInplace(copy);
        }
        return copy;
    }

    private static Ciphertext toCoeff(Mpc4jRgsw m, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        return copy;
    }

    /**
     * Galois 自同构 {@code x → x^e}。实测 MPC4J 的 {@code applyGalois} 输出是 NTT 域
     * （与输入形态无关），这里统一归一成系数域返回。
     */
    private static Ciphertext applyGalois(Mpc4jRgsw m, Ciphertext ct, int e, GaloisKeys gk) {
        Ciphertext out = new Ciphertext();
        m.evaluator.applyGalois(toCoeff(m, ct), e, gk, out);
        return toCoeff(m, out);
    }

    /** 供外部判断某个 ParmsId 是否可用（保留给将来扩展）。 */
    public static ParmsId firstParmsId(Mpc4jRgsw m) {
        return m.context.firstParmsId();
    }
}
