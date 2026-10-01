package com.fusepir.rgsw;

import com.fusepir.common.BfGen;
import com.fusepir.nativejni.NativeBlindRotate;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * <b>受控公平的「不同 Q」速度对比（不动 CapeEndToEndNative，不动 CapeEndToEnd4）。</b>
 *
 * <h3>为什么不能直接扫 Q</h3>
 * {@code CapeEndToEndNative.run(n,d,qQ)} 每次调用都要
 * {@code nativeCreateContext}（重建参数 + 重新生成密钥），所以直接在进程外扫 Q 会把
 * <b>建密钥的固定开销</b>混进 ANSWER 时间里。本类把三件事做对：
 * <ol>
 *   <li><b>同一个 native context 全程复用</b> —— 密钥只生成一次，所有 Q 共用；</li>
 *   <li><b>总工作量写死</b> —— k×B_pay = 3×40 = 120 个单元，与 Q 无关；</li>
 *   <li><b>每组跑 K 次取中位数</b>，而不是单次读数，避开抖动。</li>
 * </ol>
 *
 * <h3>公平性的严格定义（本类里 Q 是唯一的变量）</h3>
 * 逐项锁定：N=4096、t=65537、base=2^16、d=16、R=16、C=4、k=3、q_L=2N、
 * 明文表 P（同一种子）、载荷 payload、BFF 三份份额、选择子 c_a/r_a、
 * ℓ_BF=18、h=5、B_pay=40、ε_BF=2^-6。
 * <p>随 Q 变的只有一处：客户端 {@code b_qry = BF.Gen({K_2..K_Q})} 的位模式与权重 τ。
 * <b>这恰好是 CAPE 的论点</b>（论文 line 240-242：合取校验不引入 per-keyword 的开销），
 * 所以面板 A 期望看到一条平线 —— 平线不是 bug，是主张被验证。
 *
 * <h3>面板 B：Q 释放 Bloom 参数后的真实曲线</h3>
 * Q 个关键词合取的漏报率 ≈ ε_BF^Q，所以 Q 越大越<b>允许</b>放宽 ε_BF。
 * 面板 B 固定「整体漏报率 = 2^-6」，按
 * {@code ℓ_Q = min_h ⌈ -h·m / ln(1 - ε_Q^{1/h}) ⌉}（ε_Q = 2^(-6/Q)）
 * 重算 ℓ_BF 与 B_pay，得到真正随 Q 下降的成本曲线。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeQFairBench}
 * <br>可选：{@code ... CapeQFairBench 4096 16 5} = N、d、每组重复次数
 */
public final class CapeQFairBench {

    private CapeQFairBench() {
    }

    // ---- 与 CapeEndToEndNative 完全一致的固定参数（逐项锁定，禁止随 Q 变）----
    private static final int C = 4;
    private static final int R = 16;
    private static final int K = 3;          // 路数（= 分片数）
    private static final int MAX_VALUES = 2; // 每个关键词关联的值个数上界
    private static final double EPS_BF = Math.pow(2, -6); // 玩具 ε_BF（论文 2^-20）
    private static final long TABLE_SEED = 20261013L;

    /** 面板 A / B 要扫的 Q —— 与 BKPIR 侧同一组，便于逐行对照。 */
    private static final int[] QS = {2, 3, 5, 10, 20, 30};

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        int reps = args.length > 2 ? Integer.parseInt(args[2]) : 5;

        System.out.println("=== 不同 Q 的速度对比（受控公平：Q 是唯一变量）===");
        if (!NativeCapeAnswer.available()) {
            System.out.println("[FAIL] native 不可用：先跑 tools/build_blindrotate_jni.py，"
                + "并用 run-mpc4j.ps1（它已设置 java.library.path）");
            System.exit(1);
        }

        int bPay = 2 + MAX_VALUES * (1 + 18);
        System.out.printf("[固定条件] N=%d  t=%d  base=2^16  d=%d  R=%d  C=%d  k=%d  "
                + "ℓ_BF=18  h=5  B_pay=%d  ε_BF=2^%.0f%n",
            n, 65537L, d, R, C, K, bPay, Math.log(EPS_BF) / Math.log(2));
        System.out.printf("[写死的工作量] k×B_pay = %d×%d = %d 个单元（列选择×%d + 盲旋转×%d）%n",
            K, bPay, K * bPay, K * bPay, K * bPay);
        System.out.printf("[唯一变量] Q（客户端 b_qry 的位模式与 τ）；重复 %d 次取中位数%n%n", reps);

        // ---- 明文表：只建一次，所有 Q 共用（BfGen 不参与 P 的构造，Q 无法污染它）----
        long[][][] p = buildTable(n, bPay);
        long[][] payload = buildPayload(bPay);

        // nativeCapeAnswer 的签名三种来源经复核【一致】：
        //   源码 long[] / 已编译 class（javap 实测）long[] / C++ jlongArray
        // （先前以为的 int[] vs long[] 错位，是 grep 读到过期内容造成的误报。）
        long[] cOf = new long[K];
        long[] rOf = new long[K];
        for (int a = 0; a < K; a++) {
            rOf[a] = (a * R) % R;   // = 0
            cOf[a] = (a * R) / R;   // = a
        }
        long[] tableFlat = flatten(p, n, bPay);

        // ---- 一个 context 打天下 ----
        BfGen bfGen = BfGen.choose(MAX_VALUES / 2 + 1, EPS_BF, n);
        System.out.printf("[Bloom] %s（与 Q 无关）%n%n", bfGen);
        long h = NativeBlindRotate.nativeCreateContext(n, 65537L, 16);
        try {
            System.out.println("--- 面板 A：完全锁定参数，只让 Q 变 ---");
            System.out.printf("%5s %6s %7s %9s %9s %9s %9s %10s %10s %8s%n",
                "Q", "τ", "h·Q", "实跑#1", "实跑#2", "实跑#3", "中位", "每单元ms", "客户端ms", "校验");
            panelA(h, d, n, bPay, tableFlat, cOf, rOf, bfGen, payload, reps);

            System.out.println();
            System.out.println("--- 面板 B：固定整体漏报率 2^-6，让 Q 释放 ℓ_BF / B_pay ---");
            System.out.printf("%5s %8s %6s %8s %9s %9s %12s%n",
                "Q", "ℓ_BF", "h", "B_pay", "单元数", "ANSWER ms", "相对 Q=1");
            panelB(h, d, n, cOf, rOf);
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }

        System.out.printf("%n=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ==================================================================
    //  面板 A：参数全锁，只有 Q 变
    // ==================================================================

    private static void panelA(long h, int d, int n, int bPay, long[] tableFlat,
                               long[] cOf, long[] rOf, BfGen bfGen, long[][] payload, int reps) {
        int lBf = bfGen.length();
        for (int q : QS) {
            // ---- 客户端：真的构造 Q 个关键词的查询，取 b_qry ----
            List<String> query = new ArrayList<>();
            for (int i = 1; i <= q; i++) {
                query.add("K_" + i);
            }
            List<String> others = query.subList(1, query.size()); // 去掉锚，其余进 b_qry

            long tc0 = System.nanoTime();
            boolean[] bQry = bfGen.bits(others);
            long clientMs = (System.nanoTime() - tc0) / 1_000_000;

            long tau = 0;
            for (boolean bit : bQry) {
                if (bit) {
                    tau++;
                }
            }

            // ---- 服务端：同一份表、同一批选择子，重复 reps 次 ----
            long[] samples = new long[reps];
            int bad = 0;
            for (int r = 0; r < reps; r++) {
                long t0 = System.nanoTime();
                long[] rec = NativeBlindRotate.nativeCapeAnswer(h, d, C, K, bPay, tableFlat, cOf, rOf);
                samples[r] = (System.nanoTime() - t0) / 1_000_000;
                if (r == 0) {
                    bad = diffCount(rec, payload[0], bPay);
                }
            }
            long med = median(samples);

            System.out.printf(Locale.ROOT, "%5d %6d %7.2f %9d %9d %9d %9d %10.3f %10d %8s%n",
                q, tau, tau * Math.log(1.0 / EPS_BF) / Math.log(2.0),
                samples[0], samples.length > 1 ? samples[1] : -1,
                samples.length > 2 ? samples[2] : -1,
                med, med / (double) (K * bPay), clientMs, bad == 0 ? "PASS" : "FAIL(" + bad + ")");
            report(String.format("Q=%d: ANSWER correct under the locked workload (mismatch %d/%d)",
                    q, bad, bPay),
                bad == 0, "");
        }
    }

    // ==================================================================
    //  面板 B：整体漏报率恒定 ⇒ ε_BF 可随 Q 放宽 ⇒ ℓ_BF / B_pay 变小
    // ==================================================================

    private static void panelB(long h, int d, int n, long[] cOf, long[] rOf) {
        // 先量一遍 Q=1 作为基线（Q=1 时 ε_Q = 2^-6，ℓ_BF 应回到 18、B_pay 回到 40）
        double base1 = 0;
        for (int q : QS) {
            if (q != QS[0]) {
                continue;
            }
            int[] lh = bestLength(MAX_VALUES, Math.pow(2, -6.0 / q), n);
            int bPayQ = 2 + MAX_VALUES * (1 + lh[0]);
            long[] flatQ = flatten(buildTable(n, bPayQ), n, bPayQ);
            long[] s = new long[3];
            for (int r = 0; r < 3; r++) {
                long t0 = System.nanoTime();
                NativeBlindRotate.nativeCapeAnswer(h, d, C, K, bPayQ, flatQ, cOf, rOf);
                s[r] = (System.nanoTime() - t0) / 1_000_000;
            }
            base1 = median(s);
        }

        for (int q : QS) {
            // ε_Q = 2^(-6/Q)：让 Q 个合取的总漏报率保持 2^-6
            double epsQ = Math.pow(2, -6.0 / q);
            int[] lh = bestLength(MAX_VALUES, epsQ, n);
            int lQ = lh[0];
            int hQ = lh[1];
            int bPayQ = 2 + MAX_VALUES * (1 + lQ);

            // 表按新的 B_pay 重建（同一套三路份额仍是合法载荷，只是短了）
            long[] flatQ = flatten(buildTable(n, bPayQ), n, bPayQ);

            long[] samples = new long[3];
            for (int r = 0; r < 3; r++) {
                long t0 = System.nanoTime();
                NativeBlindRotate.nativeCapeAnswer(h, d, C, K, bPayQ, flatQ, cOf, rOf);
                samples[r] = (System.nanoTime() - t0) / 1_000_000;
            }
            long med = median(samples);
            System.out.printf(Locale.ROOT, "%5d %8d %6d %8d %9d %9d %11.2fx%n",
                q, lQ, hQ, bPayQ, K * bPayQ, med, med > 0 ? base1 / (double) med : 1.0);
        }
        System.out.printf(Locale.ROOT, "%n    （基线 = Q=1 的 ANSWER = %.0f ms；倍数 = 基线 ÷ 该 Q）%n", base1);
    }

    /** 复刻 {@link BfGen#choose} 的公式，返回 {@code {length, hashCount}}。 */
    private static int[] bestLength(int maxSetSize, double target, int maxLength) {
        int bestH = 1;
        long bestLen = Long.MAX_VALUE;
        for (int hh = 1; hh <= BfGen.MAX_HASH_COUNT; hh++) {
            double p = Math.pow(target, 1.0 / hh);
            if (p <= 0 || p >= 1) {
                continue;
            }
            double denom = Math.log(1 - p);
            if (!(denom < 0)) {
                continue;
            }
            long len = (long) Math.ceil(-hh * (double) maxSetSize / denom);
            if (len < bestLen) {
                bestLen = len;
                bestH = hh;
            }
        }
        if (bestLen > maxLength) {
            throw new IllegalArgumentException(String.format(
                "Bloom 长度 %d 超过环维度 %d（maxSetSize=%d, ε=%s）",
                bestLen, maxLength, maxSetSize, target));
        }
        return new int[]{(int) bestLen, bestH};
    }

    // ==================================================================
    //  与 CapeEndToEndNative.SETUP 同形的数据（同种子 ⇒ 与 Q 无关）
    // ==================================================================

    private static long[][][] buildTable(int n, int bPay) {
        Random rnd = new Random(TABLE_SEED);
        long[][][] p = new long[C][bPay][n];
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int rr = 0; rr < R; rr++) {
                    p[c][b][rr] = 1 + rnd.nextInt(65536);
                }
            }
        }
        // BFF 三份份额：恰好一套 {D[a]}_{a=0..K-1}，Σ_a D[a][b] == payload[0][b]（mod t），
        // 第 a 份写进路 a 的 u_a = a*R + 0 ⇒ 三条路分别落进第 a 列、第 0 行。
        long[][] share = new long[K][bPay];
        long[] sum = new long[bPay];
        for (int a = 0; a < K - 1; a++) {
            for (int b = 0; b < bPay; b++) {
                share[a][b] = rnd.nextInt(65537);
                sum[b] = (sum[b] + share[a][b]) % 65537;
            }
        }
        for (int b = 0; b < bPay; b++) {
            share[K - 1][b] = Math.floorMod(payloadOf(b) - sum[b], 65537);
        }
        for (int a = 0; a < K; a++) {
            int u = a * R;
            int cc = u / R;
            if (cc >= C) {
                continue;
            }
            for (int b = 0; b < bPay; b++) {
                p[cc][b][u % R] = share[a][b];
            }
        }
        return p;
    }

    private static long[][] buildPayload(int bPay) {
        long[][] payload = new long[K][bPay];
        for (int b = 0; b < bPay; b++) {
            payload[0][b] = payloadOf(b);
        }
        return payload;
    }

    /** 确定性载荷，只依赖 b 不依赖 Q。 */
    private static long payloadOf(int b) {
        return Math.floorMod(31L * b + 7L, 65536L);
    }

    private static long[] flatten(long[][][] p, int n, int bPay) {
        long[] flat = new long[C * bPay * n];
        int ptr = 0;
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                System.arraycopy(p[c][b], 0, flat, ptr, n);
                ptr += n;
            }
        }
        return flat;
    }

    private static int diffCount(long[] got, long[] want, int len) {
        int bad = 0;
        for (int b = 0; b < len; b++) {
            long g = b < got.length ? got[b] : -1;
            if (g != want[b]) {
                bad++;
            }
        }
        return bad;
    }

    private static long median(long[] v) {
        long[] s = v.clone();
        java.util.Arrays.sort(s);
        return s[s.length / 2];
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
