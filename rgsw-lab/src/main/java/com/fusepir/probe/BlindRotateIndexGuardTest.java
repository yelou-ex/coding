package com.fusepir.probe;

import com.fusepir.prim.BlindRotateOps;
import com.fusepir.prim.Mpc4jRgsw;

import java.util.Random;

/**
 * <b>盲旋转入口的编码约定绊线自检</b>（{@code 缺陷总表} P0-1 修法②）。
 *
 * <h3>它要证的三件事（三种覆盖率情形分开断言）</h3>
 * <ol>
 *   <li><b>合法输入放行</b>：本项目的「无噪声索引」约定（{@code Δ=1}、{@code q_L = 2N}）
 *       造出来的 {@code (a, β)} 必须通过；</li>
 *   <li><b>P0-1 的真实形态必须被挡</b>：把一条<b>通用 LWE 密文</b>
 *       （{@code a} 均匀于 {@code [0, q)}、{@code q} 远大于 {@code 2N}）直接喂进来 ⇒ 必须抛。
 *       这是这条绊线存在的理由；</li>
 *   <li><b>⚠️ 盲区也必须断言</b>：{@code a} 与 {@code β} 都<b>预先 mod 2N 归约过</b>时，
 *       值域与合法输入<b>完全一样</b> ⇒ 绊线<b>放行</b>。本探针刻意断言"它放行"，
 *       免得读者以为值域检查是完备的；
 *       同时断言<b>完备版</b> {@code requireIndexModulus} 能挡住同一种输入。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.BlindRotateIndexGuardTest 8192}
 */
public final class BlindRotateIndexGuardTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        final long twoN = 2L * n;
        final long delta = 256L;                     // 缺陷总表 P0-1 里的 Δ（q/t 的典型值）

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 盲旋转入口编码约定绊线自检（P0-1 修法②）===");
        System.out.printf("[params] N=%d ⇒ 2N=%d；Δ 取 %d；上下文模数约 2^%d%n%n",
            n, twoN, delta, m.q.bitLength());

        final int d = 16;
        Random rnd = new Random(20261015L);
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }

        // ============ P1 正对照：合法约定必须放行 ============
        System.out.println("--- P1 正对照：合法约定（Δ=1、q_L=2N）必须放行 ---");
        long r = 12345L % (twoN - 1);
        long[][] ok = BlindRotateOps.lweEncryptIndex(s, r, (int) twoN, rnd);
        int p1 = 0;
        p1 += sub("P1.1", "lweEncryptIndex 造出的 (a, β) 通过 requireIndexConvention",
            passesConvention(ok[0], ok[1][0], n));
        p1 += sub("P1.2", "它同时通过完备版 requireIndexModulus(2N, n)",
            passesModulus(twoN, n));
        p1 += sub("P1.3", "[负对照] 同样的输入在【错的】模数声明下必须被拒（声明 q=2^32）",
            !passesModulus(1L << 32, n));
        report("P1 合法输入按预期放行 / 错误声明被拒", p1 == 0, String.format("%d 项未达成", p1));

        // ============ P2 P0-1 的真实形态：通用 LWE 密文直接喂 ============
        System.out.println();
        System.out.println("--- P2 P0-1 的真实形态：通用 LWE 密文（a 均匀于 [0,q)）直接喂必须被挡 ---");
        // 通用 LWE 的 a 均匀于 [0, q)；这里用上下文的模数 q 取随机值来复现那个值域
        java.math.BigInteger q = m.q;
        Random rnd2 = new Random(20261015L);
        int caught = 0;
        final int trials = 64;
        for (int tr = 0; tr < trials; tr++) {
            long[] a = new long[d];
            for (int i = 0; i < d; i++) {
                a[i] = new java.math.BigInteger(q.bitLength(), rnd2).mod(q).longValue();  // 低 64 位即可
            }
            long beta = new java.math.BigInteger(q.bitLength(), rnd2).mod(q).longValue();
            if (throwsConvention(a, beta, n)) {
                caught++;
            }
        }
        report(String.format("P2 通用 LWE 形态的输入 %d/%d 被挡（这就是 P0-1 的直接形态）", trials, caught),
            caught == trials,
            String.format("实测 %d/%d —— 因为 a 均匀于 [0,q)、q ≫ 2N ⇒ 第一个分量就越界（固定种子，可复现）",
                caught, trials));

        // ============ P3 盲区：预先归约过 ⇒ 绊线放行（刻意断言） ============
        System.out.println();
        System.out.println("--- P3 ⚠️ 盲区：a 与 β 都预先 mod 2N 归约过 ---");
        long[] aPre = new long[d];
        for (int i = 0; i < d; i++) {
            aPre[i] = Math.floorMod(rnd2.nextLong(), twoN);
        }
        long betaPre = Math.floorMod(delta * 7L, twoN);              // Δ·r 归约回来的样子
        int p3 = 0;
        p3 += sub("P3.1", "[刻意期望放行] 归约后的输入值域与合法输入无法区分 ⇒ 绊线【抓不住】",
            passesConvention(aPre, betaPre, n));
        p3 += sub("P3.2", "[完备版挡住] 同一输入声明模数为 2^32 ⇒ requireIndexModulus 必须抛",
            !passesModulus(1L << 32, n));
        report("P3 盲区被如实断言，且完备版能挡住同一输入", p3 == 0,
            String.format("%d 项未达成 —— 若 P3.1 也抛，说明绊线比宣称的更强（那也是好事，但要改文档）", p3));

        // ============ P4 β 单独 Δ 缩放：覆盖率实测 192/256 ============
        System.out.println();
        System.out.println("--- P4 只有 β 是 Δ 缩放的（a 已归约）：覆盖率实测 ---");
        long[] aFine = new long[d];
        for (int i = 0; i < d; i++) {
            aFine[i] = Math.floorMod(rnd2.nextLong(), twoN);
        }
        int hit = 0;
        final long rMax = 256;                                       // r ∈ [0, L_BFF)，L_BFF = 256
        for (long rr = 0; rr < rMax; rr++) {
            long beta = delta * rr;                                  // 未经归约的 Δ·r
            if (throwsConvention(aFine, beta, n)) {
                hit++;
            }
        }
        // 解析式：Δ·r < 2N ⟺ r < 2N/Δ ⇒ 漏掉 [0, 2N/Δ) 这一段
        final long missExpected = Math.min(rMax, twoN / delta);
        report(String.format("P4 β 单独缩放时命中 %d/%d（解析式：r < 2N/Δ = %d 的 %d 个漏掉）",
                hit, rMax, twoN / delta, missExpected),
            hit == rMax - missExpected,
            String.format("实测命中 %d、漏 %d；解析预测命中 %d、漏 %d ⇒ 与值域分析一致。"
                + "⚠️ 这 %d 个漏网的正是本绊线的已知不完整之处（要看 P3 的盲区那一条）",
                hit, rMax - hit, rMax - missExpected, missExpected, missExpected));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（含 1 条刻意期望放行的盲区断言 P3.1）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static boolean passesConvention(long[] a, long b, int n) {
        try {
            BlindRotateOps.requireIndexConvention(a, b, n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean throwsConvention(long[] a, long b, int n) {
        return !passesConvention(a, b, n);
    }

    private static boolean passesModulus(long qL, int n) {
        try {
            BlindRotateOps.requireIndexModulus(qL, n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static int sub(String id, String name, boolean ok) {
        System.out.println("      " + (ok ? "[PASS] " : "[FAIL] ") + id + " " + name);
        return ok ? 0 : 1;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
