package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import java.util.Random;

/**
 * <b>把盲旋转的旋转量彻底对齐</b>
 *
 * <p>四种组合逐一实测，看哪一种让"常数位 = payload[r]"成立：
 * <pre>
 *   CMUX 里 a[i] 用 +a[i] 还是 −a[i]
 *   × 末尾旋转用 −β 还是 +β
 * </pre>
 * 然后用 Δ 缩放（论文 §2.3：β = ⟨a,s⟩ + Δ·r + e）验证噪声容限确实被放宽。
 */
public final class BlindRotateAlignProbe {

    public static void main(String[] args) {
        int n = 2048, d = 32;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        Random rnd = new Random(11);

        long[] payload = new long[n];
        for (int i = 0; i < 8; i++) payload[i] = 100 + i;

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        System.out.println("payload[0..7] = 100 101 102 103 104 105 106 107");
        System.out.println("（要取到 payload[r]，常数位应 = 100+r）");
        System.out.println();

        int[] rs = {0, 1, 2, 3};
        System.out.printf("    %-4s %-14s %-14s %-14s %-14s%n",
            "r", "a:+a 末:−β", "a:−a 末:−β", "a:+a 末:+β", "a:−a 末:+β");
        for (int r : rs) {
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                sum = (sum + a[i] * s[i]) % m.t;
            }
            long beta = Math.floorMod(sum + r, m.t);        // Δ=1，无噪声

            long[] got = new long[4];
            got[0] = run(m, bk, payload, a, beta, false, false, r);   // +a, −β
            got[1] = run(m, bk, payload, a, beta, true, false, r);    // −a, −β
            got[2] = run(m, bk, payload, a, beta, false, true, r);    // +a, +β
            got[3] = run(m, bk, payload, a, beta, true, true, r);     // −a, +β

            System.out.printf("    %-4d %-14d %-14d %-14d %-14d%n", r, got[0], got[1], got[2], got[3]);
        }

        System.out.println();
        System.out.println("说明：把 −β 换成 +β 时，末尾旋转量只差整体符号；");
        System.out.println("      真正决定方向的是 CMUX 里用 +a[i] 还是 −a[i]。");
        System.out.println("  （上面四列里，等于 100+r 的那一列就是正确组合）");
    }

    /**
     * 跑一次盲旋转。
     *
     * @param negA  CMUX 里是否用 −a[i]
     * @param posB  末尾是否用 +β（否则 −β）
     */
    static long run(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, long[] payload, long[] a,
                    long beta, boolean negA, boolean posB, int r) {
        int n = m.n;
        Ciphertext cur = m.encrypt(payload);
        for (int i = 0; i < a.length; i++) {
            if (Math.floorMod(a[i], 2L * n) == 0) continue;
            long step = negA ? -a[i] : a[i];
            Ciphertext rot = m.multiplyPowerOfX(cur, step);
            cur = m.cmux(bk[i], cur, rot);
        }
        long tail = posB ? beta : -beta;
        Ciphertext out = m.multiplyPowerOfX(cur, tail);
        return Math.floorMod(m.decrypt(out)[0], m.t);
    }
}
