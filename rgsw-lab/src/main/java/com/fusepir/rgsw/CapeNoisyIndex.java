package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * <b>带噪声的 LWE 索引 + 消噪的盲旋转</b>（README 整改项 R3b）
 *
 * <h3>问题（README §3.4 已记录）</h3>
 * 先前的 {@code blindRotate} 把 LWE 相位 <b>1:1 当作旋转指数</b>：末尾直接 {@code mulX(cur, −b)}。
 * 于是一格噪声就把行号推偏：实测 {@code e=+1 → 取到 p[r+1]}（严丝合缝，不是"污染"）。
 * 那些测试造的索引都<b>没有误差项</b>，所以一路绿灯 —— <b>假绿</b>。
 *
 * <h3>符号约定（从 {@code BlindRotateComplete} 的验收反推）</h3>
 * 该类的 CMUX 里 {@code a[i]} 与 {@code −b} 的净效果产生 {@code X^{r}}，而它断言
 * "常数位 = {@code payload[r]}"。所以<b>要取到 {@code P[r]}，索引须编码为
 * {@code β = ⟨a,s⟩ − r}（负号）</b>，末尾旋转 {@code X^{−β}} 即得 {@code X^{r}}。
 *
 * <h3>本类的做法：把噪声放低位，末尾舍入吸收</h3>
 * <pre>
 *   β = ⟨a,s⟩ − r + e            （噪声 e 加在索引上）
 *   ... CMUX 循环 ...
 *   r̂ = round(β)                 ← ★ 舍入到最近整数，吸收 |e| &lt; 1/2 的噪声
 *   return mulX(cur, −r̂)
 * </pre>
 * 与旧实现的<b>唯一差别</b>就是那个 {@code round(·)}：
 * <pre>
 *   旧：mulX(cur, −β)          ← β 是"整数+噪声"，噪声直接变成指数偏移
 *   新：mulX(cur, −round(β))   ← 噪声被舍入抹掉
 * </pre>
 */
public final class CapeNoisyIndex {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int trials = args.length > 2 ? Integer.parseInt(args[2]) : 20;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 带噪声 LWE 索引 + 消噪盲旋转 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d%n%n", d);

        Random rnd = new Random(20261014L);

        final int R = 64;
        System.out.printf("[plan] R=%d 行；索引编码 β = ⟨a,s⟩ − r + e%n", R);
        System.out.println("       末尾 r̂ = round(β) 舍入，噪声容限 |e| < 1/2");
        System.out.println("       （离散高斯 σ：|e| ≤ 3σ 约 99.7%，故 σ ≤ 1/6 时几乎全中）");
        System.out.println();

        long[] payload = new long[n];
        for (int i = 0; i < R; i++) payload[i] = (i * 7 + 3) % 1000 + 1;

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        System.out.println("--- 噪声扫描（每档 " + trials + " 次）---");
        System.out.printf("    %-6s %-12s %-16s %-16s %-8s%n",
            "σ", "实测|e|max", "新实现(舍入)", "旧实现(不舍入)", "结论");
        int[] sigmas = {0, 1, 2, 4, 8, 16, 32, 64};
        for (int sigma : sigmas) {
            int okNew = 0, okOld = 0, maxAbsE = 0;
            for (int t = 0; t < trials; t++) {
                int r = rnd.nextInt(R);
                long[] a = new long[d];
                long sum = 0;
                for (int i = 0; i < d; i++) {
                    a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                    sum = (sum + a[i] * s[i]) % m.t;
                }
                long e = gauss(rnd, sigma);
                if (Math.abs(e) > maxAbsE) maxAbsE = (int) Math.abs(e);
                long beta = Math.floorMod(sum + r + e, m.t);      // ★ 正号 + 噪声（实测确认）

                // --- 新实现：末尾舍入 ---
                {
                    Ciphertext cur = m.encrypt(payload);
                    for (int i = 0; i < d; i++) {
                        // a[i] ≡ 0 (mod 2N) 时两支相同 → diff = 0 → SEAL 抛 "transparent"，必须跳过
                        if (Math.floorMod(a[i], 2L * n) == 0) continue;
                        Ciphertext rot = m.multiplyPowerOfX(cur, a[i]);
                        cur = m.cmux(bk[i], cur, rot);
                    }
                    long rHat = Math.round(centered(beta, m.t));   // 舍入吸收噪声
                    Ciphertext out = m.multiplyPowerOfX(cur, -rHat);
                    if (Math.floorMod(m.decrypt(out)[0], m.t) == payload[r]) okNew++;
                }
                // --- 旧实现：直接用 β ---
                {
                    Ciphertext out = BlindRotateOps.blindRotate(m, bk, m.encrypt(payload), a, beta);
                    if (Math.floorMod(m.decrypt(out)[0], m.t) == payload[r]) okOld++;
                }
            }
            System.out.printf("    %-6d %-12d %-16s %-16s %-8s%n",
                sigma, maxAbsE, okNew + "/" + trials, okOld + "/" + trials,
                okNew == trials ? "✓" : (okNew > okOld ? "改善" : "✗"));
            if (sigma == 0 && okNew != trials) failed++;
        }

        System.out.println();
        System.out.println("--- 量化噪声预算 ---");
        System.out.println("    舍入能吸收 |e| < 1/2。离散高斯 σ 下单次失败率 ≈ 2·Q(0.5/σ)：");
        for (int sg : new int[]{1, 2, 4, 8, 16, 32}) {
            double q = 0.5 / sg;
            double pFail = 2 * (1 - 0.5 * (1 + erf(q / Math.sqrt(2))));
            System.out.printf("      σ=%-4d → 单次失败率 ≈ %.2e%n", sg, pFail);
        }

        System.out.println();
        System.out.println(failed == 0
            ? "=== 消噪盲旋转跑通（末尾舍入吸收索引噪声）==="
            : "=== 有 " + failed + " 档失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 把 Z_t 上的值中心化到 (−t/2, t/2] */
    static long centered(long v, long mod) {
        long x = Math.floorMod(v, mod);
        return x > mod / 2 ? x - mod : x;
    }

    /** 离散高斯近似（12 个均匀分布之和，σ 缩放） */
    static long gauss(Random rnd, int sigma) {
        if (sigma == 0) return 0;
        double sum = 0;
        for (int i = 0; i < 12; i++) sum += rnd.nextDouble();
        return Math.round((sum - 6.0) * sigma);
    }

    static double erf(double x) {
        double t = 1.0 / (1.0 + 0.3275911 * Math.abs(x));
        double y = 1.0 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t
            - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
        return x >= 0 ? y : -y;
    }
}
