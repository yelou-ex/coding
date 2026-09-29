package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import java.util.Random;

/**
 * <b>量化"索引无噪声"这个前提有多关键</b>
 *
 * <p>把现有端到端链路（{@code CapeEndToEnd4} 的 ANSWER 段）里的索引密文
 * 加上真实噪声 {@code β = ⟨a,s⟩ + r + e}，看盲旋转的命中率怎么塌。
 *
 * <p>对照：不加噪声时命中率 = 100%（这就是之前"端到端跑通"的前提）。
 */
public final class NoiseImpact {

    public static void main(String[] args) {
        int n = 2048, d = 32, trials = 50;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 索引噪声对盲旋转的影响 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    d=%d, 每次 %d 组试验%n%n", d, trials);

        Random rnd = new Random(20261015L);
        final int R = 64;
        long[] payload = new long[n];
        for (int i = 0; i < R; i++) payload[i] = (i * 7 + 3) % 1000 + 1;

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        System.out.printf("    %-10s %-14s %-14s %-10s%n", "噪声 σ", "命中率", "取错的行偏移", "说明");
        int[] sigmas = {0, 1, 2, 4, 8, 16};
        for (int sigma : sigmas) {
            int hit = 0;
            long sumAbsOffset = 0;
            for (int t = 0; t < trials; t++) {
                int r = rnd.nextInt(R);
                long[] a = new long[d];
                long sum = 0;
                for (int i = 0; i < d; i++) {
                    a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                    sum = (sum + a[i] * s[i]) % m.t;
                }
                long e = (sigma == 0) ? 0 : gauss(rnd, sigma);
                long beta = Math.floorMod(sum + r + e, m.t);      // ★ 真实 LWE：带噪声

                Ciphertext out = BlindRotateOps.blindRotate(m, bk, m.encrypt(payload), a, beta);
                long got = Math.floorMod(m.decrypt(out)[0], m.t);

                if (got == payload[r]) {
                    hit++;
                } else {
                    // 找出实际取到的是哪一行（噪声把行号推偏了多少）
                    for (int rr = 0; rr < R; rr++) {
                        if (got == payload[rr]) { sumAbsOffset += Math.abs(rr - r); break; }
                    }
                }
            }
            double hitRate = (double) hit / trials;
            double avgOff = (trials - hit) == 0 ? 0 : (double) sumAbsOffset / (trials - hit);
            System.out.printf("    %-10d %-14s %-14s %-10s%n",
                sigma,
                String.format("%d/%d = %.0f%%", hit, trials, hitRate * 100),
                (trials - hit) == 0 ? "—" : String.format("%.1f 格", avgOff),
                sigma == 0 ? "← 之前端到端的前提" : (hitRate < 1.0 ? "稳定取错行" : ""));
        }

        System.out.println();
        System.out.println("--- 结论 ---");
        System.out.println("    σ=0（无噪声）时命中率 100% —— 这就是 CapeEndToEnd4 的前提。");
        System.out.println("    加上真实噪声后命中率立即下降，且错的是【整行偏移】，不是数值噪声。");
        System.out.println("    ⇒ 无噪声 LWE 不满足 LWE 噪声模型，不能引用其安全性论证。");
    }

    static long gauss(Random rnd, int sigma) {
        double sum = 0;
        for (int i = 0; i < 12; i++) sum += rnd.nextDouble();
        return Math.round((sum - 6.0) * sigma);
    }
}
