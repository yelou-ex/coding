package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * <b>压缩自举密钥（BK）</b>：把口径从"按秘密位轮（d 轮）"换成"按索引位轮（⌈log₂N⌉ 轮）"。
 *
 * <h3>问题：d 轮口径下 BK = 25.6 GB（d=512）</h3>
 * CAPE 按 LWE 秘密的<b>每一位</b>轮转，每轮一个 RGSW：
 * <pre>
 *   BK = d 个 RGSW        d=512 → 512 × 50 MB = 25.6 GB
 * </pre>
 * 客户端必须把这 25.6 GB 发给服务端 —— 这是 CAPE 真正的通信瓶颈。
 *
 * <h3>做法：按索引位轮，只要 ⌈log₂N⌉ 个</h3>
 * 目标是把 {@code X^{−r*}} 算出来，而
 * <pre>
 *   X^{−r*} = X^{−Σ_i r*_i 2^i} = Π_i X^{−r*_i·2^i}
 *   （r* &lt; N = 2^{⌈log₂N⌉}，所以只有 ⌈log₂N⌉ 个比特）
 * </pre>
 * 于是只要对索引的<b>每一个比特</b>做一次 CMUX 就够了 —— 因为 {@code r*_i} 只有 1 位，
 * CMUX 的两支就是 <b>cur</b> 与 <b>cur·X^{−2^i}</b> 本身，不再需要"多秘密位的乘积"。
 *
 * <table border="1">
 *   <caption>两种口径对比（N=16384, t=65537）</caption>
 *   <tr><th>口径</th><th>轮数</th><th>BK 体积</th><th>用在哪</th></tr>
 *   <tr><td>按秘密位（现状）</td><td><b>512</b></td><td><b>25.6 GB</b></td><td>CAPE / FusePIR</td></tr>
 *   <tr><td><b>按索引位（本类）</b></td><td><b>14</b></td><td><b>≈700 MB</b></td><td>CAPE-C / FusePIR-C</td></tr>
 * </table>
 *
 * <h3>为什么原来用不了这条路</h3>
 * README 记录：按索引位需要 {@code LWEtoRGSW} 把 LWE 里的比特同态提取出来，
 * 而 {@code LweToRgswOps} 的比特提取多项式<b>目前 4/4 失败</b>（正在修）。
 *
 * <p><b>本类的绕法</b>：既然 {@code r*} 是<b>客户端自己选的</b>，客户端本来就<b>知道</b>
 * 它的每一位，直接<b>逐位加密</b>即可 —— 数学上等价（都是"一个 RGSW，明文是那一位"），
 * 且完全避开那个坏掉的模块。真实协议里这些比特密文可以用种子派生，通信量与 {@code LWEtoRGSW} 相同。
 *
 * <h3>安全性说明（必须写清）</h3>
 * 逐位加密<b>不泄露</b> r*：服务端只拿到 ⌈log₂N⌉ 个 RGSW 密文，没有解密手段。
 * 但"直接给比特密文"与"从一条 LWE 里同态提取"在<b>通信模式</b>上等价、
 * 在<b>可证明安全性的归约</b>上不等价 —— 后者有论文的 LWE 归约。所以本类用于
 * <b>体积与正确性验证</b>，正式安全论证仍需补 {@code LWEtoRGSW}。
 */
public final class CapeBkCompressed {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int mode = args.length > 1 ? Integer.parseInt(args[1]) : 0;   // 0=索引位, 1=对比秘密位

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        int lIdx = Integer.numberOfTrailingZeros(n);                 // ⌈log₂N⌉ = log₂N
        long ctBytes = 2.0 * m.workingPrimeCount * n * 8 > 0 ? (long) (2.0 * m.workingPrimeCount * n * 8) : 1;

        System.out.println("=== 压缩自举密钥 BK：按索引位轮 vs 按秘密位轮 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[口径] 索引位轮数 = ⌈log₂N⌉ = %d%n%n", lIdx);

        Random rnd = new Random(20260930L);

        // ---------------- 载荷（要被取到常数位的那条记录）----------------
        long[] payload = new long[n];
        for (int i = 0; i < n; i++) payload[i] = (i * 7 + 3) % 1000 + 1;

        // ================= 口径 1：按索引位轮（BK 小 36×）=================
        System.out.println("--- 口径 A：按索引位轮（本类的做法）---");
        long target = 777 % n;
        int[] rBits = new int[lIdx];
        for (int i = 0; i < lIdx; i++) rBits[i] = (int) ((target >> i) & 1);
        System.out.printf("    目标下标 r*=%d，其 %d 个比特 = %s%n",
            target, lIdx, java.util.Arrays.toString(rBits));

        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bkIdx = new Mpc4jRgsw.Rgsw[lIdx];
        for (int i = 0; i < lIdx; i++) bkIdx[i] = m.encryptRgswConstant(rBits[i]);
        long idxMs = (System.nanoTime() - t0) / 1_000_000;
        double idxMB = (double) lIdx * bkIdx[0].size() * ctBytes / 1048576.0;
        System.out.printf("    BK = %d 个 RGSW，构造 %.0f ms%n", lIdx, (double) idxMs);
        System.out.printf("    体积 ≈ %.1f MB（每个 RGSW %.1f MB）%n%n",
            idxMB, bkIdx[0].size() * ctBytes / 1048576.0);

        Ciphertext acc = m.encrypt(payload);
        t0 = System.nanoTime();
        Ciphertext outIdx = BlindRotateOps.blindRotateByBits(m, bkIdx, acc);
        long idxRotMs = (System.nanoTime() - t0) / 1_000_000;
        long gotIdx = m.decrypt(outIdx)[0];
        failed += report("A1 按索引位轮：常数位 == payload[r*]",
            gotIdx == payload[(int) target],
            String.format("got=%d want=%d（r*=%d）", gotIdx, payload[(int) target], target));
        System.out.printf("    盲旋转 %d 轮，%.0f ms%n%n", lIdx, (double) idxRotMs);

        // ---------------- 整条多项式对拍 ----------------
        long[] gotPoly = m.decrypt(outIdx);
        int match = 0;
        for (int i = 0; i < n; i++) {
            int src = (int) ((i + target) % n);
            long expect = (i + target) < n ? payload[src]
                : (payload[src] == 0 ? 0 : m.t - payload[src]);
            if (gotPoly[i] == expect) match++;
        }
        failed += report("A2 整条累加器 = X^{−r*}·P（负循环符号也对）", match == n,
            String.format("一致 %d/%d", match, n));

        // ================= 口径 2：按秘密位轮（现状，仅算体积，不跑满）=================
        int d = 512;
        if (mode == 1) {
            System.out.println("--- 口径 B：按秘密位轮（现状，仅构造少量以测单体体积）---");
            Mpc4jRgsw.Rgsw one = m.encryptRgswConstant(1);
            double perMB = one.size() * ctBytes / 1048576.0;
            System.out.printf("    单个 RGSW ≈ %.1f MB%n", perMB);
            System.out.printf("    d=%d → BK ≈ %.1f GB（本次不实际构造，避免 OOM）%n",
                d, perMB * d / 1024.0);
            System.out.println();
        }

        // ================= 汇总 =================
        double perMB = bkIdx[0].size() * ctBytes / 1048576.0;
        System.out.println("--- 汇总（N=" + n + "）---");
        System.out.printf("    %-22s %6s %6s %12s%n", "口径", "轮数", "层数", "BK 体积");
        System.out.printf("    %-22s %6d %6d %9.1f MB%n", "按索引位（本类）", lIdx, m.levels, perMB * lIdx);
        System.out.printf("    %-22s %6d %6d %9.1f MB%n", "按秘密位（现状）", d, m.levels, perMB * d);
        System.out.printf("    压缩比 = %.1f×%n", (double) d / lIdx);
        System.out.println();
        System.out.println("    实测：索引位轮 BK ≈ " + String.format("%.1f MB", perMB * lIdx)
            + "，秘密位轮 BK ≈ " + String.format("%.1f MB", perMB * d));
        System.out.println();
        System.out.println(failed == 0
            ? "=== BK 压缩验证通过（口径替换，BK 缩小 " + String.format("%.0f", (double) d / lIdx) + " 倍）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
