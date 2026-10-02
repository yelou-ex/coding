package com.fusepir.probe;

import com.fusepir.fusepir.*;


import com.fusepir.prim.*;
import com.fusepir.nativejni.NativeBlindRotate;

/**
 * 盲旋转微基准 —— 用 nativePrepare / nativeRunWithCtx 隔离出<b>纯 native 盲旋转</b>，
 * 不经过 Java 侧的表构建、JNI 大数组搬运和 330 单元的循环。
 *
 * <p>为什么要它：之前用"CapeAnswerProfile 改 C 看斜率"在 Java 层测，两次运行
 * 同一配置差 24%（118 773 vs 146 878 ms），噪声比要测的量还大，分不出差异。
 * 这个基准则把要测的东西缩到最小：一次 prepare，之后只重复跑旋转，
 * 输出**每次 CMUX 的微秒数**，可以直接在两次构建之间对比。
 *
 * <p>用法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.BlindRotateBench [N] [reps]}
 */
public final class BlindRotateBench {

    private BlindRotateBench() {
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int reps = args.length > 1 ? Integer.parseInt(args[1]) : 20;
        final long T = 65537L;

        System.out.println("=== native blind-rotation microbenchmark ===");
        if (!FusePirAnswer.available()) {
            System.out.println("[FAIL] native 不可用");
            System.exit(1);
        }

        long h = NativeBlindRotate.nativeCreateContext(n, T, 16);
        System.out.printf("[ctx] %s%n%n", NativeBlindRotate.nativeDescribe(h));
        System.out.printf("%6s %10s %12s %14s %14s%n",
            "d", "reps", "total ms", "ms/rotate", "ms/CMUX");

        // d=1 是 1 次 CMUX，d=16 是 16 次 —— 两点即可分离出每次 CMUX 的成本。
        int[] ds = {1, 4, 16};
        double[] perCmux = new double[ds.length];
        for (int i = 0; i < ds.length; i++) {
            int d = ds[i];
            long job = NativeBlindRotate.nativePrepare(h, d);
            try {
                NativeBlindRotate.nativeRunWithCtx(h, job, 3);          // 预热
                long t0 = System.nanoTime();
                NativeBlindRotate.nativeRunWithCtx(h, job, reps);
                long el = System.nanoTime() - t0;
                double totalMs = el / 1e6;
                double perRot = totalMs / reps;
                // totalMs is already ms, so per-CMUX in ms is just /(reps*d).
                double perC = totalMs / ((double) reps * d);
                perCmux[i] = perC;
                System.out.printf("%6d %10d %12.1f %14.3f %14.3f%n",
                    d, reps, totalMs, perRot, perC);
            } finally {
                NativeBlindRotate.nativeFreeJob(job);
            }
        }

        // 线性拟合 us/CMUX 应基本恒定；偏差大说明有非 CMUX 的固定开销。
        System.out.printf("%n每次 CMUX： d=1 %.2f ms, d=4 %.2f ms, d=16 %.2f ms%n",
            perCmux[0], perCmux[1], perCmux[2]);
        double spread = (max(perCmux) - min(perCmux)) / min(perCmux) * 100;
        System.out.printf("三者离散度 = %.1f%%  %s%n", spread,
            spread < 10 ? "(一致，说明成本确实由 CMUX 主导)" : "(偏高，存在非 CMUX 固定开销)");

        NativeBlindRotate.nativeDestroyContext(h);
    }

    private static double max(double[] v) {
        double m = v[0];
        for (double x : v) {
            m = Math.max(m, x);
        }
        return m;
    }

    private static double min(double[] v) {
        double m = v[0];
        for (double x : v) {
            m = Math.min(m, x);
        }
        return m;
    }
}
