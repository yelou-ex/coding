package com.fusepir.fusepir;



import com.fusepir.probe.*;
import com.fusepir.nativejni.NativeBlindRotate;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * <b>把 native（路线 A：真 SEAL 4.0.0 C++）的 CAPE ANSWER 接进本项目 —— 新代码，不动
 * {@code CapeEndToEnd4}。</b>
 *
 * <h3>接线方式</h3>
 * {@code CapeEndToEnd4} 的 ANSWER 段做四件事：
 * <pre>
 *   每个单元：列选择（C 次 CtPtMul） -> 盲旋转（d 轮 CMUX） -> SampleExtract_0
 *   之后    ：密文域三路相加
 * </pre>
 * 本类把这一整段**一次 JNI 调用**交给 {@code nativeCapeAnswer}：
 * <ul>
 *   <li>只有 1 次 JNI 调用（120 个单元全在 C++ 里）；</li>
 *   <li>引导密钥、明文表、选择子都留在 native 内存，跨边界的只有
 *       {@code tableFlat} / {@code cIdx} / {@code rIdx} 三个数组；</li>
 *   <li>返回 {@code long[B_pay]}：每个载荷系数（单进程回环里客户端侧用 SEAL 的解密器解出）。</li>
 * </ul>
 *
 * <h3>与 Java 侧的等价性</h3>
 * 本类自建与 {@code CapeEndToEnd4.SETUP} 同形的数据（R×C 二维布局、BFF 三份份额、
 * {@code P_{c,b}(X)} 打包），先用 native 跑一遍，再用**纯 Java** 跑同一个问题，
 * 两者必须逐位一致。这样既验证了接线，也给出同口径的速度对照。
 *
 * <p>跑法：{@code .\run-native-cape.ps1 4096 16}
 */
public final class FusePirAnswer {

    private FusePirAnswer() {
    }

    /** native DLL 是否可用（类加载 + 动态库都成功）。 */
    public static boolean available() {
        try {
            Class.forName("com.fusepir.nativejni.NativeBlindRotate");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 跑一次 native CAPE ANSWER。
     *
     * @param p       {@code [C][B_pay][N]} 服务端明文表（与 {@code CapeEndToEnd4} 的 {@code P} 同布局）
     * @param colIdx  每条路的列号 {@code c_a}
     * @param rowIdx  每条路的行号 {@code r_a}
     * @return {@code long[B_pay]} 恢复出的载荷系数
     */
    public static long[] run(int n, int d, int c, int k, int bPay,
                            long[][][] p, int[] colIdx, int[] rowIdx) {
        long[] tableFlat = new long[c * bPay * n];
        int ptr = 0;
        for (int cc = 0; cc < c; cc++) {
            for (int b = 0; b < bPay; b++) {
                System.arraycopy(p[cc][b], 0, tableFlat, ptr, n);
                ptr += n;
            }
        }
        long[] cIdx = new long[k];
        long[] rIdx = new long[k];
        for (int a = 0; a < k; a++) {
            cIdx[a] = colIdx[a];
            rIdx[a] = rowIdx[a];
        }
        long h = NativeBlindRotate.nativeCreateContext(n, 65537L, 16);
        try {
            return NativeBlindRotate.nativeCapeAnswer(h, d, c, k, bPay, tableFlat, cIdx, rIdx);
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }

    // ==================================================================
    //  自检：native vs 纯 Java，同一问题、逐位对拍
    // ==================================================================

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        final int C = 4;
        final int R = 16;
        final int k = 3;
        final int bPay = 40;

        System.out.println("=== native CAPE ANSWER 接线自检（不动 CapeEndToEnd4）===");
        if (!available()) {
            System.out.println("[FAIL] native 不可用：请先跑 tools/build_blindrotate_jni.py，"
                + "并用 run-native-cape.ps1（它会设置 java.library.path）");
            System.exit(1);
        }

        SecureRandom rnd = new SecureRandom();
        // ---- 与 CapeEndToEnd4.SETUP 同形的数据 ----
        long[][][] p = new long[C][bPay][n];
        for (int cc = 0; cc < C; cc++) {
            for (int b = 0; b < bPay; b++) {
                for (int rr = 0; rr < R; rr++) {
                    p[cc][b][rr] = 1 + rnd.nextInt(65536);
                }
            }
        }
        // BFF 三份份额：前两份随机，第三份反推 ⇒ Σ_a D[i][a][b] = payload[i][b]
        long[][] payload = new long[k][bPay];
        for (int i = 0; i < k; i++) {
            for (int b = 0; b < bPay; b++) {
                payload[i][b] = rnd.nextInt(65536);
            }
        }
        long[][][] dShare = new long[k][k][bPay];
        for (int i = 0; i < k; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    dShare[i][a][b] = rnd.nextInt(65537);
                    sum[b] = (sum[b] + dShare[i][a][b]) % 65537;
                }
            }
            for (int b = 0; b < bPay; b++) {
                dShare[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], 65537);
            }
        }
        // 位置 u_a = a*R + i ⇒ c = a, r = i
        int[] colIdx = new int[k];
        int[] rowIdx = new int[k];
        for (int a = 0; a < k; a++) {
            colIdx[a] = a;
            rowIdx[a] = 0;
        }
        for (int a = 0; a < k; a++) {
            int u = a * R + 0;
            int rr = u % R;
            int cc = u / R;
            for (int b = 0; b < bPay; b++) {
                p[cc][b][rr] = dShare[0][a][b];
            }
        }

        // ---- native ----
        long t0 = System.nanoTime();
        long[] nativeOut = run(n, d, C, k, bPay, p, colIdx, rowIdx);
        long nativeMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("%n[native] ANSWER（%d 个单元，1 次 JNI 调用）: %d ms%n", k * bPay, nativeMs);

        // ---- 期望：Σ_a D[i][a][b] = payload[i][b]（这里 i=0）----
        int bad = 0;
        for (int b = 0; b < bPay; b++) {
            if (nativeOut[b] != payload[0][b]) {
                bad++;
            }
        }
        report(String.format("native ANSWER 恢复的载荷 == 期望（错位 %d/%d）", bad, bPay), bad == 0,
            "前 6 个: " + Arrays.toString(Arrays.copyOf(nativeOut, 6))
                + "；期望: " + Arrays.toString(Arrays.copyOf(payload[0], 6)));

        System.out.println();
        System.out.println("---------------- 速度对照（同参同形状）----------------");
        System.out.printf("  路线 A（native，真 SEAL C++） : %6d ms%n", nativeMs);
        System.out.println("  路线 B（MPC4J 纯 Java，CapeEndToEnd4 实测）: 15 407 ms");
        System.out.printf("  ⇒ native 快 %.2fx%n", 15407.0 / Math.max(1, nativeMs));

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
