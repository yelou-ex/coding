package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.bff.CapeDemoData;
import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <b>论文几何 + 真实盲旋转</b> —— "假阴性 0"在**密文侧**的最终验收。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.CapePaperNativeTest [db] [N] [d] [howMany]
 * </pre>
 *
 * <h3>它走的路径就是 A1 ANSWER</h3>
 * <pre>
 *   对每个关键词 K_i，取 (c_a, r_a) = (⌊h_a(K_i)/R⌋, h_a(K_i) mod R)，
 *   跑一次 native ANSWER（列选择 → 盲旋转 → 提取 → 三路相加），
 *   解出来的载荷必须**逐位等于** y_{K_i}。
 * </pre>
 * 任何一位对不上就是假阴性 —— 论文的前提写死"假阴性必须为 0"。
 *
 * <h3>⚠️ 与旧几何探针（{@code CapeDemoSetupProbe}）的关系</h3>
 * 那个用 {@code rIdx[a] = rowOf[0] + a}（同一列连续 k 行），是**旧几何**。
 * 本探针用 {@code h_a} 给的三个**分散**位置，且列号走 {@code ⌊u/R⌋}。
 */
public final class CapePaperNativeTest {

    private static int checks;
    private static int fails;

    private CapePaperNativeTest() {
    }

    public static void main(String[] args) throws Exception {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        final int howMany = args.length > 3 ? Integer.parseInt(args[3]) : 4;
        final int k = 3;

        final CapeDemoData db = CapeDemoData.load(dbPath);
        final long t = db.longMeta("plainModulus", 65537L);
        final int kwCount = db.keywords.size();

        System.out.println("=== 论文几何 + 真实盲旋转（假阴性 0 的密文侧验收）===");
        System.out.println("  DB = " + dbPath + "（关键词 " + kwCount + " 个）");
        System.out.println("  N = " + ringDim + ", d = " + d + ", k = " + k
            + ", t = " + t + ", 抽查 " + Math.min(howMany, kwCount) + " 个关键词");

        final long t0 = System.nanoTime();
        final CapeDemoData.Tables tb = db.buildTablesPaper(ringDim, k, t, 20261013L, 0, 20261014L);
        final BffSetup.Layout lo = tb.layout;
        System.out.println("  建表 " + (System.nanoTime() - t0) / 1_000_000 + " ms，布局 = " + lo);
        System.out.println("  B_pay = " + tb.bPay + "，表 = [" + tb.c + "][" + tb.bPay + "]["
            + ringDim + "]");

        final long[] flat = CapeDemoSetupProbe.flatten(tb.p, ringDim, tb.bPay);

        final long h = NativeBlindRotate.nativeCreateContext(ringDim, t, d);
        final long kh = NativeBlindRotate.nativeBuildBootstrapKey(h, d);
        System.out.println("  native: " + NativeBlindRotate.nativeDescribe(h));

        final int sample = Math.min(howMany, kwCount);
        long worstMs = 0;
        long totalMs = 0;
        int badKeywords = 0;

        for (int i = 0; i < sample; i++) {
            final long[] cIdx = new long[k];
            final long[] rIdx = new long[k];
            for (int a = 0; a < k; a++) {
                final int[] cr = tb.colRow(i, a);
                cIdx[a] = cr[0];
                rIdx[a] = cr[1];
            }
            final long tA = System.nanoTime();
            final long[] rec = NativeBlindRotate.nativeCapeAnswer(
                h, d, tb.c, k, tb.bPay, flat, cIdx, rIdx);
            final long ms = (System.nanoTime() - tA) / 1_000_000;
            totalMs += ms;
            worstMs = Math.max(worstMs, ms);

            int bad = 0;
            int firstBad = -1;
            for (int b = 0; b < tb.bPay; b++) {
                if (rec[b] != tb.payload[i][b]) {
                    if (firstBad < 0) {
                        firstBad = b;
                    }
                    bad++;
                }
            }
            if (bad != 0) {
                badKeywords++;
            }
            System.out.printf("  kw[%3d] %-28s c=%s r=%s  %4d ms  载荷失配 %d/%d%s%n",
                i, db.keywords.get(i), java.util.Arrays.toString(cIdx),
                java.util.Arrays.toString(rIdx), ms, bad, tb.bPay,
                bad == 0 ? "  ✅" : "  ❌ first=" + firstBad);
            if (bad != 0 && firstBad >= 0) {
                final int lo2 = Math.max(0, firstBad - 3);
                final int hi2 = Math.min(tb.bPay, firstBad + 4);
                for (int b = lo2; b < hi2; b++) {
                    System.out.printf("      [%3d] got=%-12d want=%-12d %s%n",
                        b, rec[b], tb.payload[i][b], rec[b] == tb.payload[i][b] ? "" : "<-- dif");
                }
            }
        }

        System.out.println();
        System.out.printf("  ANSWER 平均 %.1f ms/次，最坏 %d ms（C=%d, k=%d, B_pay=%d）%n",
            totalMs / (double) sample, worstMs, tb.c, k, tb.bPay);
        check(badKeywords == 0,
            "★ 密文侧假阴性 0：抽查 %d 个关键词，全部载荷逐位相符（失配 %d 个）",
            (long) sample, (long) badKeywords);

        // ── 负对照：(c,r) 故意错一路 ⇒ 必须失配 ─────────────────────────
        final long[] cIdx = new long[k];
        final long[] rIdx = new long[k];
        for (int a = 0; a < k; a++) {
            final int[] cr = tb.colRow(0, a);
            cIdx[a] = cr[0];
            rIdx[a] = cr[1];
        }
        rIdx[2] = (rIdx[2] + 1) % lo.r;                 // 只把第 2 路挪一格
        long[] rec = NativeBlindRotate.nativeCapeAnswer(
            h, d, tb.c, k, tb.bPay, flat, cIdx, rIdx);
        int bad = 0;
        for (int b = 0; b < tb.bPay; b++) {
            if (rec[b] != tb.payload[0][b]) {
                bad++;
            }
        }
        check(bad > 0, "[负对照] 把第 2 路的行号挪一格 ⇒ 载荷失配 %d/%d 位（检查确实在查）",
            (long) bad, (long) tb.bPay);

        // 只错列号（行号不动）
        rIdx[2] = tb.colRow(0, 2)[1];
        cIdx[2] = (cIdx[2] + 1) % tb.c;
        rec = NativeBlindRotate.nativeCapeAnswer(h, d, tb.c, k, tb.bPay, flat, cIdx, rIdx);
        int bad2 = 0;
        for (int b = 0; b < tb.bPay; b++) {
            if (rec[b] != tb.payload[0][b]) {
                bad2++;
            }
        }
        check(bad2 > 0, "[负对照] 把第 2 路的列号挪一格 ⇒ 载荷失配 %d/%d 位",
            (long) bad2, (long) tb.bPay);

        NativeBlindRotate.nativeDestroyKey(kh);
        NativeBlindRotate.nativeDestroyContext(h);

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        if (fails != 0) {
            System.exit(1);
        }
    }

    private static void check(boolean ok, String fmt, Long a, Long b) {
        checks++;
        final String msg;
        if (a == null) {
            msg = fmt;
        } else if (b == null) {
            msg = String.format(fmt, a);
        } else {
            msg = String.format(fmt, a, b);
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
