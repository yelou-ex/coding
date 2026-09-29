package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import java.util.Random;

/**
 * <b>Δ 缩放的正确用法：先把带噪相位还原成精确的 r，再做纯整数旋转</b>
 *
 * <h3>论文依据（§2.3，L363）</h3>
 * <pre>
 *   b = ⟨a, s⟩ + Δ·m + e     (mod q)
 *   "Δ is a scaling factor determined by the plaintext encoding."
 * </pre>
 * 对 LWE 而言，解码是 {@code m̂ = round((b − ⟨a,s⟩)/Δ)}，噪声容限 {@code |e| &lt; Δ/2}。
 *
 * <h3>为什么不能在"末尾旋转"里顺手还原</h3>
 * {@code blindRotate} 的末尾 {@code mulX(cur, −β)} 是<b>指数上的整数</b>。
 * 若 {@code β} 里含 {@code Δ·r}，直接取负得到 {@code X^{−Δ·r}}——<b>指数被放大了 Δ 倍</b>，
 * 落不到 payload 的位置上。
 *
 * <h3>本类的做法：服务端先做一次"相位还原"</h3>
 * <pre>
 *   1) Acc ← blindRotate(bk, P, a, β)        用【未缩放】的相位 ⟨a,s⟩ 做旋转
 *      （这一步要求把 β 拆成 ⟨a,s⟩ 与 Δ·r 两部分 —— 服务端做不到，所以改为）
 *
 *   2) 客户端把索引"分成两段"发送：
 *        β_idx = ⟨a,s⟩ + Δ·r + e
 *      服务端先用 CMUX 循环把 ⟨a,s⟩ 消掉（这需要知道 Δ·r 的精确值 —— 又绕回来）
 * </pre>
 *
 * <p><b>结论</b>：Δ 缩放要真正生效，需要一个"把带噪 LWE 变成精确整数"的环节
 * —— 也就是 README §3.4 的候选 (c)：{@code BitDecomp} 的舍入测试多项式。
 *
 * <h3>本类转而去量化另一件事：当前实现对噪声的真实容限</h3>
 * 即"用未缩放的 β = ⟨a,s⟩ + r + e，命中率随 σ 怎么变"，
 * 并给出<b>要让 σ=1.79 命中，需要什么条件</b>。
 */
public final class CapeLweScaling {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = 2048, d = 32, trials = 100;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== Δ 缩放 / 噪声容限 量化 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    d=%d, 每档 %d 组%n%n", d, trials);

        Random rnd = new Random(20261016L);
        final int R = 64;
        long[] payload = new long[n];
        for (int i = 0; i < R; i++) payload[i] = (i * 7 + 3) % 1000 + 1;

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        // ---------- 方案 A：当前实现（未缩放，β = ⟨a,s⟩ + r + e）----------
        System.out.println("--- 方案 A：当前实现（Δ=1）---");
        System.out.printf("    %-8s %-16s%n", "σ", "命中率");
        for (int sigma : new int[]{0, 1, 2, 3, 4, 8, 16}) {
            int hit = 0;
            for (int t = 0; t < trials; t++) {
                int r = rnd.nextInt(R);
                long[] a = new long[d];
                long sum = 0;
                for (int i = 0; i < d; i++) {
                    a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                    sum = (sum + a[i] * s[i]) % m.t;
                }
                long beta = Math.floorMod(sum + r + gauss(rnd, sigma), m.t);
                Ciphertext out = BlindRotateOps.blindRotate(m, bk, m.encrypt(payload), a, beta);
                if (Math.floorMod(m.decrypt(out)[0], m.t) == payload[r]) hit++;
            }
            System.out.printf("    %-8d %-16s%n", sigma,
                String.format("%d/%d = %.0f%%", hit, trials, 100.0 * hit / trials));
        }

        // ---------- 方案 A + 载荷重复 D 份（容差放大 D 倍）----------
        System.out.println();
        System.out.println("--- 方案 A + 载荷每行重复 D 份（容差 ∝ D）---");
        System.out.println("    （对应 README §3.4 候选 (a)：载荷布局留间隙）");
        System.out.printf("    %-6s %-10s %-14s %-14s%n", "D", "容限±", "σ=1", "σ=2");
        for (int D : new int[]{1, 2, 4, 8, 16}) {
            // 每行占 D 个连续系数，值重复填满（这样噪声 < D/2 就落回同一行）
            long[] payRep = new long[n];
            for (int i = 0; i < R; i++)
                for (int j = 0; j < D; j++) payRep[i * D + j] = payload[i];

            int h1 = runRep(m, bk, payRep, s, rnd, R, D, 1, trials);
            int h2 = runRep(m, bk, payRep, s, rnd, R, D, 2, trials);
            System.out.printf("    %-6d %-10s %-14s %-14s%n", D, "±" + (D / 2),
                String.format("%.0f%%", 100.0 * h1 / trials),
                String.format("%.0f%%", 100.0 * h2 / trials));
            // D=16 时 σ=1 应当全中
            if (D == 16 && h1 != trials) failed++;
        }

        System.out.println();
        System.out.println("--- 结论 ---");
        System.out.println("    方案 A（Δ=1、一行一系数）：σ=1 就掉到 ~50%，论文 σ≈1.79 时基本不可用。");
        System.out.println("    加 Δ 缩放【不能】靠末尾旋转还原（指数会被放大 Δ 倍）——");
        System.out.println("      要真正生效需要 BitDecomp 的舍入测试多项式（README §3.4 候选 c）。");
        System.out.println("    可行替代：载荷每行重复 D 份（候选 a），容限 ∝ D，D=16 时 σ=1 可全中。");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 噪声容限量化完成 ==="
            : "=== 有 " + failed + " 档失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 载荷每行重复 D 份时的命中率 */
    private static int runRep(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, long[] payRep, int[] s,
                              Random rnd, int R, int D, int sigma, int trials) {
        int hit = 0, n = m.n, d = s.length;
        for (int t = 0; t < trials; t++) {
            int r = rnd.nextInt(R);
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                sum = (sum + a[i] * s[i]) % m.t;
            }
            // 索引乘上 D：落在"第 r 行的块"内
            long beta = Math.floorMod(sum + (long) D * r + gauss(rnd, sigma), m.t);
            Ciphertext out = BlindRotateOps.blindRotate(m, bk, m.encrypt(payRep), a, beta);
            // 读块内任一位置（取常数位；噪声 < D/2 时仍在同一块）
            if (Math.floorMod(m.decrypt(out)[0], m.t) == payRep[r * D]) hit++;
        }
        return hit;
    }

    static long gauss(Random rnd, int sigma) {
        if (sigma == 0) return 0;
        double sum = 0;
        for (int i = 0; i < 12; i++) sum += rnd.nextDouble();
        return Math.round((sum - 6.0) * sigma);
    }
}
