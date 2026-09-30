package com.fusepir.nativejni;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * <b>路线 A（真 SEAL 4.0.0 C++ 本体）上的 RGSW / CMUX / 盲旋转。</b>
 *
 * <p>对应路线 B（MPC4J 纯 Java 移植）的
 * {@code com.fusepir.rgsw.Mpc4jRgsw.externalProduct/cmux} 与
 * {@code com.fusepir.rgsw.BlindRotateOps.blindRotate}，参数与语义逐项对齐，
 * 目的是**同参同输入下做速度对照**。
 *
 * <h3>为什么需要 C++ 侧实现</h3>
 * MPC4J 全仓库（包括它自带的 {@code mpc4j-native-fhe} JNI 封装）**没有任何 RGSW 实现**，
 * 只有协议级接口。所以这条路线的 RGSW/CMUX/盲旋转必须自己写 —— 就是本文件背后的
 * {@code src/main/cpp/rgsw_blindrotate.cpp}。
 *
 * <h3>C++ 侧相对 Java 侧的三处真实差别</h3>
 * <ol>
 *   <li>CRT 重构用 {@code unsigned __int128}，Java 侧要手写 Montgomery + 双 long；</li>
 *   <li>{@code multiplyPowerOfX} 退化成"把 X^k 当明文做一次 {@code multiply_plain}" ——
 *       <b>没有密钥切换，也没有系数域↔NTT 域往返</b>；Java 侧是 fromNtt + 搬移 + toNtt；</li>
 *   <li>累加器由首个乘积初始化，不再每轮现造零密文。</li>
 * </ol>
 *
 * <h3>范围限制（写在明处）</h3>
 * CRT 只组合到 128 位 ⇒ 本模块**最多支持 2 个工作素数**，即 <b>N ≤ 4096</b>，
 * 正是我们要对照的那一档。更大 N 会直接抛异常。
 *
 * <p>跑法：{@code .\run-native.ps1 4096 16}
 */
public final class NativeBlindRotate {

    static {
        System.loadLibrary("blindrotate");
    }

    private static native long nativeCreateContext(int n, long t, int baseBits);

    private static native void nativeDestroyContext(long h);

    private static native String nativeDescribe(long h);

    private static native long nativeBuildBootstrapKey(long h, int d);

    private static native void nativeDestroyKey(long kh);

    private static native byte[] nativeEncrypt(long h, long[] msg);

    private static native long[] nativeDecrypt(long h, byte[] ct);

    private static native int nativeNoiseBudget(long h, byte[] ct);

    private static native byte[] nativeBlindRotate(long h, long kh, byte[] acc, long[] a, long beta);

    private static native long[] nativeExternalProduct(long h, long kh, byte[] src, int row);

    private static native Long[] nativeSecretBits(long h, int d);

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        int reps = args.length > 2 ? Integer.parseInt(args[2]) : 5;
        long t = 65537L;

        System.out.println("=== 路线 A（真 SEAL C++）RGSW / 盲旋转基准与正确性 ===");
        long h = nativeCreateContext(n, t, 16);
        System.out.println("[params] " + nativeDescribe(h));
        System.out.printf("[目标]   与路线 B 对照：N=%d, d=%d, t=%d, base=2^16%n%n", n, d, t);

        // ---------------- 正确性 ① RGSW(1) ⊗ ct = ct ----------------
        long kh = nativeBuildBootstrapKey(h, d);
        Long[] bits = nativeSecretBits(h, d);
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 7) + 1;
        }
        byte[] ct = nativeEncrypt(h, msg);

        long[] ep1 = nativeExternalProduct(h, kh, ct, 1);   // RGSW(1)
        int bad1 = 0;
        for (int i = 0; i < n; i++) {
            if (ep1[i] != msg[i]) {
                bad1++;
            }
        }
        report(String.format("1. RGSW(1) ⊗ ct = ct（错位 %d/%d）", bad1, n), bad1 == 0,
            "噪声预算 = " + nativeNoiseBudget(h, ct) + " bit");

        long[] ep0 = nativeExternalProduct(h, kh, ct, 0);   // RGSW(0)
        int nz = 0;
        for (int i = 0; i < n; i++) {
            if (ep0[i] != 0) {
                nz++;
            }
        }
        report(String.format("2. RGSW(0) ⊗ ct = 0（非零 %d/%d）", nz, n), nz == 0, "");

        // ---------------- 正确性 ② 盲旋转：one-hot 进去必须 one-hot 出来 ----------------
        SecureRandom rnd = new SecureRandom();
        int r = rnd.nextInt(n);
        long[] oneHot = new long[n];
        oneHot[r] = 1;
        byte[] acc = nativeEncrypt(h, oneHot);
        long[] a = new long[d];
        long twoN = 2L * n;
        long sum = 0;
        for (int i = 0; i < d; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), twoN);
            sum = (sum + a[i] * bits[i]) % twoN;
        }
        long beta = Math.floorMod(sum + r, twoN);

        byte[] rotated = nativeBlindRotate(h, kh, acc, a, beta);
        long[] got = nativeDecrypt(h, rotated);
        int nonZero = 0;
        int unit = 0;
        int where = -1;
        for (int i = 0; i < n; i++) {
            if (got[i] != 0) {
                nonZero++;
                where = i;
                if (got[i] == 1 || got[i] == t - 1) {
                    unit++;
                }
            }
        }
        report(String.format("3. 盲旋转：one-hot 进 → one-hot 出（非零 %d 个，落点 %d，其中单位值 %d 个）",
                nonZero, where, unit),
            nonZero == 1 && unit == 1,
            "噪声预算 = " + nativeNoiseBudget(h, rotated) + " bit");

        // ---------------- 速度 ----------------
        for (int w = 0; w < 2; w++) {                       // 预热
            nativeBlindRotate(h, kh, acc, a, beta);
        }
        double[] times = new double[reps];
        for (int i = 0; i < reps; i++) {
            long t0 = System.nanoTime();
            nativeBlindRotate(h, kh, acc, a, beta);
            times[i] = (System.nanoTime() - t0) / 1e6;
        }
        Arrays.sort(times);
        double med = times[times.length / 2];
        System.out.println();
        System.out.println("---------------- 速度 ----------------");
        System.out.printf("  一次盲旋转（d=%d 轮 CMUX，含编解码）  : %9.1f ms%n", d, med);
        System.out.printf("  单轮 CMUX                              : %9.2f ms%n", med / d);
        System.out.println();
        System.out.println("  路线 B（MPC4J 纯 Java）同参数实测对照：");
        System.out.println("    优化前 单轮 CMUX = 15.55 ms（ANSWER 50 078 ms）");
        System.out.println("    优化后 单轮 CMUX =  6.03 ms（ANSWER 15 407 ms）");

        nativeDestroyKey(kh);
        nativeDestroyContext(h);
        System.out.printf("%n=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
        }
        System.out.printf("    [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (!detail.isEmpty()) {
            System.out.println("          " + detail);
        }
    }
}
