package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;

/**
 * 把 CAPE ANSWER 拆成「列选择」与「盲旋转」两段，分别报速度。
 *
 * <h3>为什么这个拆法是可信的</h3>
 * 用 {@code nativeCapeAnswerSplit}：它与 {@code nativeCapeAnswer} 的循环结构、
 * {@code CtPtMul} 次数、CMUX 次数<b>完全一致</b>，只是把两段分别计时。
 * 同一个 {@code accCol} 变量、同一条控制流 ⇒ 两个计时器切分的是<b>一次连续执行</b>，
 * 不存在「先跑 A 再跑 B」那种跨运行漂移。这一点很重要：之前用两个独立进程比较
 * C=26 与 C=7 得到「列选择 1.3% 且方向相反」的结论，其实落在噪声里。
 *
 * <h3>报什么</h3>
 * <pre>
 *   列选择 = k × B_pay × C   次 CtPtMul        （随 C 线性）
 *   盲旋转 = k × B_pay × d   次 CMUX           （与 C 无关）
 * </pre>
 * 再给每个单元、每次 CMUX、每次 CtPtMul 的 ns，方便直接和论文 Fig.2 对照。
 *
 * <p>用法：
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeAnswerSplit [N] [dbPath]
 * </pre>
 */
public final class CapeAnswerSplit {

    private CapeAnswerSplit() {
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 1 ? args[1] : "E:\\学习\\密码赛\\coding\\cape-demo\\db\\keywords.json");

        final int K = 3;
        final long T = 65537L;
        int rSingle = Integer.getInteger("cape.split.r", 0);
        int[] rList = rSingle > 0 ? new int[] {rSingle} : new int[] {16, 64};

        CapeDemoData db = CapeDemoData.load(dbPath);
        int maxValues = db.intMeta("maxValues", 3);
        int lBf = db.intMeta("lBf", 35);
        int maxSet = db.intMeta("maxSetSize", 4);
        int bPay = 2 + maxValues * (1 + lBf);

        long h = NativeBlindRotate.nativeCreateContext(n, T, 16);
        try {
            System.out.println("=== ANSWER 两段剖面（同一次执行内切分）===");
            System.out.printf("[db] %s%n", dbPath.getFileName());
            System.out.printf("     keywords=%d maxValues=%d maxSetSize=%d l_BF=%d B_pay=%d k=%d N=%d d=16%n%n",
                db.keywords.size(), maxValues, maxSet, lBf, bPay, K, n);

            System.out.printf("%5s %5s %12s %14s %14s %10s %10s %11s %11s%n",
                "R", "C", "units", "列选择 ms", "盲旋转 ms", "列占比", "旋转/单元",
                "ms/CMUX", "ms/CtPtMul");

            for (int r : rList) {
                int cellsPerCol = Math.max(1, r / maxValues);
                int c = (db.keywords.size() + cellsPerCol - 1) / cellsPerCol;
                int units = K * bPay;

                CapeDemoData.Tables tb = db.buildTables(n, c, r, K, T, 20261013L);
                long[] flat = CapeDemoSetupProbe.flatten(tb.p, n, bPay);
                long[] cIdx = new long[K];
                long[] rIdx = new long[K];
                for (int a = 0; a < K; a++) {
                    cIdx[a] = tb.colOf[0];
                    rIdx[a] = tb.rowOf[0] + a;
                }

                long[] v = NativeBlindRotate.nativeCapeAnswerSplit(
                    h, 16, c, K, bPay, flat, cIdx, rIdx);
                long colUs = v[0];
                long rotUs = v[1];
                long colCalls = v[2];       // CtPtMul calls = units * C   (counted in C++)
                long rotBrCalls = v[3];     // blind_rotate calls = units  (NOT CMUX count!)

                // v[3] counts blind_rotate invocations, NOT the CMUX operations inside
                // it: one blind_rotate = d CMUX rounds.  Verified against the native
                // self-test (nativeBlindRotateBench), which reports one CMUX at
                // 29.8 ms @N=8192 d=16 - so the per-CMUX divisor must be units*d.
                final int D = 16;
                long rotCalls = rotBrCalls * D;

                double colMs = colUs / 1000.0;
                double rotMs = rotUs / 1000.0;
                double totMs = colMs + rotMs;
                double msPerCmux = rotMs / rotCalls;
                double msPerMul = colMs / colCalls;

                System.out.printf("%5d %5d %12d %14.0f %14.0f %9.1f%% %10.1f %9.3f %9.3f%n",
                    r, c, units, colMs, rotMs, 100.0 * colMs / totMs, rotMs / units,
                    msPerCmux, msPerMul);
                System.out.printf("      -> 合计 %.0f ms = 列选择 %.0f + 盲旋转 %.0f"
                        + "  ⇒ 列选择占 %.1f%%，盲旋转占 %.1f%%%n",
                    totMs, colMs, rotMs, 100.0 * colMs / totMs, 100.0 * rotMs / totMs);
                System.out.printf("         单元构成：C=%d 次 CtPtMul × %.3f ms = %.1f ms"
                        + "　+　d=%d 轮 CMUX × %.2f ms = %.1f ms　⇒ %.0f ms/单元%n",
                    c, msPerMul, c * msPerMul, D, msPerCmux, D * msPerCmux, totMs / units);
                System.out.printf("         调用总次数：CtPtMul %d（=units×C），"
                        + "CMUX %d（=units×d，由 %d 次 blind_rotate 展开）%n%n",
                    colCalls, rotCalls, rotBrCalls);
            }
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }
}
