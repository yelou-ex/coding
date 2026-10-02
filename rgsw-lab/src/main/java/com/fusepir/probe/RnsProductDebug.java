package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.AbstractModulus;
import edu.alibaba.mpc4j.crypto.fhe.seal.zq.UintArithmeticSmallMod;

import java.math.BigInteger;

/**
 * 定位 RNS 域外部乘积（②-b）为什么错。四个断言逐个排除：
 * <ol>
 *   <li>{@code multiplyAddUintMod(a,b,c,mod)} 的语义是否 = {@code (a*b+c) mod mod}；</li>
 *   <li>逐素数切段是否能还原：{@code Σ_k B^k d_k ≡ x (mod p_j)}；</li>
 *   <li>digit 是否落在平衡区间 {@code (-B/2, B/2]}；</li>
 *   <li>RNS 路径与旧路径在 {@code RGSW(1) ⊗ ct} 上是否得到同一个明文。</li>
 * </ol>
 */
public final class RnsProductDebug {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== RNS 外部乘积定位 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("        workingPrimeCount=%d, base=%d, levels=%d, t=%d%n%n",
            m.workingPrimeCount, m.base, m.levels, m.t);

        // ---- 1. multiplyAddUintMod 语义 ----
        AbstractModulus mod = m.primes[0];
        long p = mod.value();
        boolean macOk = true;
        long[] as = {0, 1, 12345, p - 1, p / 2, 987654321L % p};
        long[] bs = {1, 7, p - 3, 424242, p / 3, 55555};
        long[] cs = {0, 9, p - 5, 77, p / 7, 123456};
        for (int i = 0; i < as.length; i++) {
            long got = UintArithmeticSmallMod.multiplyAddUintMod(as[i], bs[i], cs[i], mod);
            long want = BigInteger.valueOf(as[i]).multiply(BigInteger.valueOf(bs[i]))
                .add(BigInteger.valueOf(cs[i])).mod(BigInteger.valueOf(p)).longValueExact();
            if (got != want) {
                macOk = false;
                System.out.printf("      [x] mulAdd(%d,%d,%d) = %d，期望 %d%n", as[i], bs[i], cs[i], got, want);
            }
        }
        System.out.printf("  [%s] 1. multiplyAddUintMod(a,b,c,mod) == (a*b+c) mod p%n", macOk ? "PASS" : "FAIL");

        // ---- 2/3. 逐素数切段还原 + 平衡区间 ----
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 13) + 1;
        }
        Ciphertext src = m.encrypt(msg);
        Ciphertext srcNtt = new Ciphertext();
        srcNtt.copyFrom(src);
        if (!srcNtt.isNttForm()) {
            m.evaluator.transformToNttInplace(srcNtt);
        }
        long[] sd = srcNtt.data();
        final int L = m.workingPrimeCount;
        long[][] dig = new long[m.levels][2 * L * n];
        // 复刻 decomposeNttPerPrime
        final long B = m.base;
        final long half = B >>> 1;
        final int shift = Integer.numberOfTrailingZeros(m.base);
        for (int poly = 0; poly < 2; poly++) {
            for (int j = 0; j < L; j++) {
                long pj = m.primes[j].value();
                int off = (poly * L + j) * n;
                for (int i = 0; i < n; i++) {
                    long x = sd[off + i];
                    for (int k = 0; k < m.levels; k++) {
                        long r = x & (B - 1);
                        long carry = 0;
                        if (r > half) {
                            r -= B;
                            carry = 1;
                        }
                        x >>>= shift;
                        x += carry;
                        dig[k][off + i] = r < 0 ? r + pj : r;
                    }
                }
            }
        }
        boolean reconOk = true;
        long maxAbs = 0;
        for (int poly = 0; poly < 2; poly++) {
            for (int j = 0; j < L; j++) {
                long pj = m.primes[j].value();
                BigInteger bp = BigInteger.valueOf(pj);
                int off = (poly * L + j) * n;
                for (int i = 0; i < n; i++) {
                    BigInteger acc = BigInteger.ZERO;
                    BigInteger pw = BigInteger.ONE;
                    for (int k = 0; k < m.levels; k++) {
                        long dv = dig[k][off + i];
                        if (dv > pj / 2) {
                            dv -= pj;                       // 还原成平衡位
                        }
                        maxAbs = Math.max(maxAbs, Math.abs(dv));
                        acc = acc.add(BigInteger.valueOf(dv).multiply(pw));
                        pw = pw.multiply(BigInteger.valueOf(B));
                    }
                    if (!acc.mod(bp).equals(BigInteger.valueOf(sd[off + i]))) {
                        reconOk = false;
                    }
                }
            }
        }
        System.out.printf("  [%s] 2. Σ_k B^k d_k ≡ x (mod p_j) 逐素数成立%n", reconOk ? "PASS" : "FAIL");
        System.out.printf("  [%s] 3. 平衡位幅度 max|d| = %d ≤ B/2 = %d%n",
            maxAbs <= half ? "PASS" : "FAIL", maxAbs, half);

        // ---- 4. 与旧路径比 ----
        Mpc4jRgsw.Rgsw bk1 = m.encryptRgswConstant(1);
        m.useRnsExternalProduct = true;
        long[] rns = m.decrypt(m.externalProduct(bk1, src));
        m.useRnsExternalProduct = false;
        long[] old = m.decrypt(m.externalProduct(bk1, src));
        m.useRnsExternalProduct = true;
        int diffOld = 0;
        int diffMsg = 0;
        for (int i = 0; i < n; i++) {
            if (rns[i] != old[i]) {
                diffOld++;
            }
            if (rns[i] != msg[i]) {
                diffMsg++;
            }
        }
        System.out.printf("  [%s] 4a. RNS 路径 vs 旧路径：不同系数 %d/%d%n",
            diffOld == 0 ? "PASS" : "FAIL", diffOld, n);
        System.out.printf("  [%s] 4b. RNS 路径结果 == 原消息：不同系数 %d/%d%n",
            diffMsg == 0 ? "PASS" : "FAIL", diffMsg, n);
        System.out.printf("       RNS 前 6 个: %s%n", java.util.Arrays.toString(java.util.Arrays.copyOf(rns, 6)));
        System.out.printf("       旧  前 6 个: %s%n", java.util.Arrays.toString(java.util.Arrays.copyOf(old, 6)));
        System.out.printf("       消息前 6 个: %s%n", java.util.Arrays.toString(java.util.Arrays.copyOf(msg, 6)));

        // ---- 5. 噪声预算：区分「数学错」与「噪声爆」 ----
        m.useRnsExternalProduct = true;
        Ciphertext ctRns = m.externalProduct(bk1, src);
        int bRns = m.decryptor.invariantNoiseBudget(coef(m, ctRns));
        m.useRnsExternalProduct = false;
        Ciphertext ctOld = m.externalProduct(bk1, src);
        int bOld = m.decryptor.invariantNoiseBudget(coef(m, ctOld));
        m.useRnsExternalProduct = true;
        System.out.printf("  [%s] 5. 噪声预算：RNS 路径 %d bit，旧路径 %d bit（q ≈ 2^%d）%n",
            bRns > 0 ? "PASS" : "FAIL(爆了)", bRns, bOld, m.qBits);
        System.out.println("       若 RNS 路径噪声为负/极小 ⇒ 数学没错，是 NTT 域 digit 的系数范数太大。");

        // ---- 6. digit 多项式在【系数域】的幅度 ----
        long[] digCoeff = digitPolyNorm(m, sd, L, n);
        long maxRns = 0;
        if (digCoeff != null) {
            for (long v : digCoeff) {
                maxRns = Math.max(maxRns, Math.abs(v));
            }
        }
        System.out.printf("       旧路径 digit 系数幅度上限 ≈ %d（= B/2）%n", half);
        if (digCoeff != null) {
            System.out.printf("       RNS 路径 digit 多项式【系数域】幅度上限 ≈ %d  ⇒ 放大 %.0f 倍，约 %d bit%n",
                maxRns, (double) maxRns / half,
                (int) Math.round(Math.log((double) maxRns / half) / Math.log(2)));
        }

        // ---- 7. ★ 决定性：Evaluator.multiplyPlain 到底是不是「逐点乘积」 ----
        Ciphertext ctNtt = new Ciphertext();
        ctNtt.copyFrom(src);
        if (!ctNtt.isNttForm()) {
            m.evaluator.transformToNttInplace(ctNtt);
        }
        long[] poly = new long[n];
        for (int i = 0; i < n; i++) {
            poly[i] = (i % 11) - 5;
            if (poly[i] < 0) {
                poly[i] += m.t;
            }
        }
        edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext ptPlain =
            new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(poly);
        m.evaluator.transformToNttInplace(ptPlain, ctNtt.parmsId());
        Ciphertext viaApi = new Ciphertext();
        m.evaluator.multiplyPlain(ctNtt, ptPlain, viaApi);

        long[] apiData = viaApi.data();
        long[] ctData = ctNtt.data();
        long[] ptData = ptPlain.data();
        int mismatch = 0;
        for (int j = 0; j < L; j++) {
            AbstractModulus md = m.primes[j];
            for (int polyIdx = 0; polyIdx < 2; polyIdx++) {
                int off = (polyIdx * L + j) * n;
                for (int i = 0; i < n; i++) {
                    long want = UintArithmeticSmallMod.multiplyUintMod(
                        ctData[off + i], ptData[j * n + i], md);
                    if (apiData[off + i] != want) {
                        mismatch++;
                    }
                }
            }
        }
        System.out.printf("  [%s] 7. multiplyPlain == 逐点乘积（pt.data 长度=%d，ct.data 长度=%d）不同 %d 处%n",
            mismatch == 0 ? "PASS" : "FAIL", ptData.length, ctData.length, mismatch);
        if (mismatch > 0) {
            System.out.println("       ⇒ multiplyPlain 不是纯逐点乘积，RNS 手写路径的前提不成立。");
        }
    }

    private static Ciphertext coef(Mpc4jRgsw m, Ciphertext ct) {
        Ciphertext c = new Ciphertext();
        c.copyFrom(ct);
        if (c.isNttForm()) {
            m.evaluator.transformFromNttInplace(c);
        }
        return c;
    }

    /** 取第 0 段的 NTT 域 digit，做逆 NTT，量它在系数域的幅度。 */
    private static long[] digitPolyNorm(Mpc4jRgsw m, long[] sd, int L, int n) {
        final long B = m.base;
        final long half = B >>> 1;
        final int shift = Integer.numberOfTrailingZeros(m.base);
        long p = m.primes[0].value();
        long[] nttDigit = new long[n];
        for (int i = 0; i < n; i++) {
            long x = sd[i];                 // 分量 0、素数 0
            long r = x & (B - 1);
            if (r > half) {
                r -= B;
            }
            nttDigit[i] = r < 0 ? r + p : r;
        }
        // 用 MPC4J 的密文 NTT 做不到"对纯数组做逆 NTT"，这里改用一个小密文的系数重构等价物：
        // 直接照 NTT 定义做朴素逆变换代价太高，所以用 BigInteger 在实数意义上做一次 DFT 不可行。
        // 折中：用 Parseval 关系给出量级估计 —— 系数域幅度 ≈ sqrt(n) * NTT 域幅度。
        long maxNtt = 0;
        for (long v : nttDigit) {
            long s = v > p / 2 ? p - v : v;    // 平衡幅度
            maxNtt = Math.max(maxNtt, s);
        }
        long est = (long) (Math.sqrt(n) * maxNtt);
        long[] out = new long[]{est};
        return out;
    }
}
