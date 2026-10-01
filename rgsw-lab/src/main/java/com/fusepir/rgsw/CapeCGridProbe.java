package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;

/**
 * 测"把 R 放大以缩小 C"这个改动 —— 它是 CAPE 网格几何里一个**免费**的杠杆。
 *
 * <h3>为什么这是免费的</h3>
 * ANSWER 的成本由两块组成：
 * <pre>
 *   列选择 = k × B_pay × C   次 multiply_plain     <- 随 C 线性
 *   盲旋转 = k × B_pay × d   次 CMUX               <- 与 C 无关
 * </pre>
 * 而 P 表按 {@code [C][B_pay][N]} 索引，**R 根本不进任何乘法** ——
 * 行选择只是旋转位移量（{@code beta}）。所以把 R 变大只有好处：
 * 每列能放更多 cell，需要的列数 C 变小，列选择随之变便宜。
 *
 * <p>当前参数（N=8192, maxValues=3, 128 关键词）：
 * <pre>
 *   R=16  -> cellsPerCol = floor(16/3) = 5   -> C = ceil(128/5)  = 26
 *   R=64  -> cellsPerCol = floor(64/3) = 21  -> C = ceil(128/21) = 7
 * </pre>
 * 列选择乘次数 8580 -> 2310，降 73%。
 *
 * <h3>这个探针测什么</h3>
 * 对每组 (R, C) 建表 → 跑一次 nativeCapeAnswer → 报告耗时与**正确性**
 * （同一份数据的答案必须与 R/C 无关，所以正确性也必须逐位一致）。
 *
 * <p>用法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeCGridProbe [N] [dbPath]}
 */
public final class CapeCGridProbe {

    private CapeCGridProbe() {
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 1 ? args[1] : "cape-demo/db/keywords.json");

        // 第二个 DB（可选）：同一个 JVM 里依次跑两份数据，消掉跨进程/热漂移，
        // 把「B_pay 变小」这一项单独隔离出来。
        //   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeCGridProbe 8192 A.json B.json
        Path dbPath2 = args.length > 2 ? Path.of(args[2]) : null;

        final int K = 3;
        final long T = 65537L;
        final int R = Integer.getInteger("cape.grid.r", 16);

        System.out.println("=== B_pay 的影响（同 JVM A/B）===");
        System.out.println("R=" + R + "  N=" + n);

        long h = NativeBlindRotate.nativeCreateContext(n, T, 16);
        try {
            runOne(h, dbPath, n, K, T, R, "A");
            if (dbPath2 != null) {
                runOne(h, dbPath2, n, K, T, R, "B");
            }
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }

    private static void runOne(long h, Path dbPath, int n, int k, long t, int r, String tag)
        throws Exception {
        CapeDemoData db = CapeDemoData.load(dbPath);
        int maxValues = db.intMeta("maxValues", 3);
        int lBf = db.intMeta("lBf", 35);
        int bPay = 2 + maxValues * (1 + lBf);
        int units = k * bPay;

        int cellsPerCol = Math.max(1, r / maxValues);
        int c = (db.keywords.size() + cellsPerCol - 1) / cellsPerCol;

        CapeDemoData.Tables tb = db.buildTables(n, c, r, k, t, 20261013L);
        long[] flat = CapeDemoSetupProbe.flatten(tb.p, n, bPay);

        long bestMs = Long.MAX_VALUE;
        int reps = Integer.getInteger("cape.grid.reps", 1);
        int bad = -1;
        for (int rep = 0; rep < reps; rep++) {
            long[] cIdx = new long[k];
            long[] rIdx = new long[k];
            for (int a = 0; a < k; a++) {
                cIdx[a] = tb.colOf[0];
                rIdx[a] = tb.rowOf[0] + a;
            }
            long t0 = System.nanoTime();
            long[] rec = NativeBlindRotate.nativeCapeAnswer(h, 16, c, k, bPay, flat, cIdx, rIdx);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            if (ms < bestMs) {
                bestMs = ms;
            }
            bad = 0;
            for (int b = 0; b < bPay; b++) {
                if (rec[b] != tb.payload[0][b]) {
                    bad++;
                }
            }
        }

        System.out.printf("[%s] %-28s kw=%d maxValues=%d l_BF=%-3d B_pay=%-4d units=%-4d "
                + "cells/col=%-3d C=%-3d tableMB=%6.1f  best=%7d ms  %6.1f ms/unit  %s%n",
            tag, dbPath.getFileName(), db.keywords.size(), maxValues, lBf, bPay, units,
            cellsPerCol, c, (double) c * bPay * n * 8 / (1024 * 1024),
            bestMs, bestMs / (double) units, bad == 0 ? "PASS" : ("FAIL(" + bad + ")"));
    }
}

