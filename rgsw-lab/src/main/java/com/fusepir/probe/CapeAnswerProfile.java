package com.fusepir.probe;

import com.fusepir.fusepir.*;


import com.fusepir.prim.*;
import com.fusepir.bff.*;
import com.fusepir.demo.*;
import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;

/**
 * 分离 CAPE ANSWER 的三部分成本：列选择 / 盲旋转 / 密文相加。
 *
 * <p>做法：nativeCapeAnswer 内部的循环是
 * <pre>
 *   for each of k paths:
 *     for each of B_pay units:
 *       列选择  = C 次 multiply_plain 后相加      <- 随 C 线性
 *       盲旋转  = d 轮 CMUX                       <- 与 C 无关
 * </pre>
 * 所以**只改 C、其它不变**跑几组，耗时随 C 的斜率就是列选择成本，
 * 截距就是盲旋转 + 相加的成本。这样不用改 C++、不用加计时埋点。
 */
public final class CapeAnswerProfile {

    private CapeAnswerProfile() {
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 2 ? args[2] : "cape-demo/db/keywords.json");

        final int R = 16;
        final int K = 3;
        final long T = 65537L;

        CapeDemoData db = CapeDemoData.load(dbPath);
        int maxValues = db.intMeta("maxValues", 3);
        int lBf = db.intMeta("lBf", 35);
        int bPay = 2 + maxValues * (1 + lBf);
        int units = K * bPay;
        int cellsPerCol = FusePirSetup.cellsPerCol(R, maxValues);
        int cMin = Math.max(1, (db.keywords.size() + cellsPerCol - 1) / cellsPerCol);

        System.out.println("=== CAPE ANSWER 成本分离（改 C，看斜率）===");
        System.out.printf("[db] keywords=%d maxValues=%d l_BF=%d B_pay=%d units(k)=%d%n",
            db.keywords.size(), maxValues, lBf, bPay, units);
        System.out.printf("[grid] R=%d => %d cells/col => C 至少 %d%n%n", R, cellsPerCol, cMin);

        // 用同一个 context 跑完所有 C，避免每次重建密钥的固定开销污染斜率
        long h = NativeBlindRotate.nativeCreateContext(n, T, 16);
        System.out.printf("[ctx] %s%n%n", NativeBlindRotate.nativeDescribe(h));

        // 用三个点检验线性：两点拟合看不出曲率，而"改 C 看斜率"这个方法的
        // 全部说服力都建立在 ms(C) 是线性之上。
        // 取 26 / 39 / 52：都在真实所需 C=26 附近，不做远距离外推；
        // 最大的表 C=52 约 366 MB 系数，离 -Xmx4g 还有余量。
        int[] cs = {cMin, (cMin * 3) / 2, cMin * 2};
        long[] ms = new long[cs.length];

        for (int i = 0; i < cs.length; i++) {
            int c = cs[i];
            // 只为把表建出来；表内容对计时无影响（每单元都读同样多的数据）
            CapeDemoData.Tables tb = db.buildTables(n, c, R, K, T, 20261013L);
            long[] flat = CapeDemoSetupProbe.flatten(tb.p, n, bPay);
            long[] cIdx = new long[K];
            long[] rIdx = new long[K];
            for (int a = 0; a < K; a++) {
                cIdx[a] = 0;
                rIdx[a] = a;
            }
            long t0 = System.nanoTime();
            NativeBlindRotate.nativeCapeAnswer(h, d, c, K, bPay, flat, cIdx, rIdx);
            ms[i] = (System.nanoTime() - t0) / 1_000_000;
            System.out.printf("  C=%-3d  ANSWER = %8d ms   (%.1f ms/unit)%n",
                c, ms[i], ms[i] / (double) units);
        }

        // 线性拟合 ms = a*C + b  =>  a = 每列成本, b = 截距
        if (cs.length >= 2) {
            double x1 = cs[0], x2 = cs[cs.length - 1];
            double y1 = ms[0], y2 = ms[ms.length - 1];
            double a = (y2 - y1) / (x2 - x1);
            double b = y1 - a * x1;
            double colTotal = a * cs[cs.length - 1];
            System.out.printf("%n---------------- 分离结果（用 C=%d 与 C=%d 两点拟合）----------------%n",
                cs[0], cs[cs.length - 1]);
            System.out.printf("  斜率 a = %.1f ms / 列%n", a);
            System.out.printf("  截距 b = %.0f ms            <- 盲旋转 + 密文相加%n", b);
            System.out.printf("  列选择(k x B_pay x C) = %.0f ms  (%.1f%%)%n",
                colTotal, 100 * colTotal / ms[ms.length - 1]);
            System.out.printf("  盲旋转 + 相加        = %.0f ms  (%.1f%%)%n",
                b, 100 * b / ms[ms.length - 1]);
            System.out.printf("%n  => 盲旋转占 ANSWER 的 %.1f%%，列选择占 %.1f%%%n",
                100 * b / ms[ms.length - 1], 100 * colTotal / ms[ms.length - 1]);

            // 两点拟合看不出曲率，而"改 C 看斜率"的全部说服力都建立在
            // ms(C) 线性之上，所以用中间点做残差检验。
            if (cs.length >= 3) {
                System.out.printf("%n---------------- 线性检验（中间点残差）----------------%n");
                for (int i = 0; i < cs.length; i++) {
                    double pred = a * cs[i] + b;
                    System.out.printf("  C=%-3d 实测 %8d ms   线性预测 %8.0f ms   残差 %+7.0f ms (%+.1f%%)%n",
                        cs[i], ms[i], pred, ms[i] - pred, 100 * (ms[i] - pred) / ms[i]);
                }
                double res = Math.abs(ms[1] - (a * cs[1] + b)) / ms[1];
                System.out.printf("  中间点残差 %.1f%% => 线性假设 %s%n",
                    100 * res, res < 0.05 ? "成立（<5%）" : "可疑（>=5%），斜率不宜外推");
            }
        }

        NativeBlindRotate.nativeDestroyContext(h);
    }
}
