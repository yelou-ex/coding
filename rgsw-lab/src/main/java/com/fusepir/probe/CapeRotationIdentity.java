package com.fusepir.probe;


import com.fusepir.bff.*;
import com.fusepir.cape.*;
import com.fusepir.demo.*;
import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * <b>纯算术判据</b>：{@code Σ a_i·s_i(bsk) ≡ β (mod 2N)} 是否成立。
 *
 * <h3>为什么这是对的判据</h3>
 * {@code blind_rotate} 的每一轮做
 * <pre>
 *   cur ← CMUX(bk[i], cur, cur·X^{a_i})
 * </pre>
 * 即「{@code bk[i]} 是 RGSW(1) 就转到 {@code a_i}，是 RGSW(0) 就不动」，
 * 循环结束后再乘 {@code X^{-β}}。所以净旋转量是
 * <pre>
 *   X^{ Σ_i a_i·s_i(bsk) − β }
 * </pre>
 * 要它等于 {@code X^{-r_a}}（把第 {@code r_a} 个系数搬到常数项），**必须**
 * <pre>
 *   Σ_i a_i·s_i(bsk) ≡ β − r_a   (mod 2N)
 * </pre>
 * 这是个**只涉及数组的恒等式**，与 SEAL、与 RGSW、与噪声都无关。
 * 这里不成立的话，后面做什么都是错的；成立了才轮到查密码学。
 *
 * <h3>为什么之前六轮没验</h3>
 * 我一直在验「客户端算的位置 = 服务端算的位置」「β 里含 r_a」这类**端到端一致性**，
 * 却漏了这条**机制本身要求**的等式。教训记在这里。
 *
 * <p>本探针**不调用任何密码学**：只建一个上下文拿 bsk 比特，然后做模乘加法。
 * 因此它几秒内出结果，且结论不受机器负载影响。
 *
 * <p>用法（需要服务在跑，只为拿 bsk 比特）：
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeRotationIdentity 8192 &lt;dbPath&gt; &lt;port&gt;
 * </pre>
 */
public final class CapeRotationIdentity {

    private CapeRotationIdentity() {
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 1 ? args[1] : "E:\\学习\\密码赛\\coding\\cape-demo\\db\\keywords.json");
        int port = args.length > 2 ? Integer.parseInt(args[2]) : 8756;

        final int K = 3;
        final long T = 4294967296L;
        final int B = 32;
        final int D = 16;
        final long twoN = 2L * n;

        CapeDemoData db = CapeDemoData.load(dbPath);
        int maxValues = db.intMeta("maxValues", 3);
        int lBf = db.intMeta("lBf", 18);
        int maxSetSize = db.intMeta("maxSetSize", 2);

        System.out.println("=== 纯算术判据：Σ a_i·s_i(bsk) ≡ β − r_a (mod 2N) ? ===");
        System.out.printf("[db] %s  keywords=%d maxValues=%d lBf=%d maxSetSize=%d%n%n",
            dbPath.getFileName(), db.keywords.size(), maxValues, lBf, maxSetSize);

        // 取一个池内组合做样本
        CapeDemoData.PoolEntry pe = db.pool.get(0);
        List<String> query = Arrays.asList(pe.kws[0], pe.kws[1]);
        System.out.println("查询: " + query);

        long h = NativeBlindRotate.nativeCreateContext(n, T, B);
        try {
            // bsk 比特：与建 bk 用的必须同源
            Long[] b = NativeBlindRotate.nativeSecretBits(h, D);
            int[] bskBits = new int[D];
            for (int i = 0; i < D; i++) {
                bskBits[i] = b[i].intValue();
            }
            int ones = 0;
            for (int v : bskBits) {
                ones += v;
            }
            System.out.println("bsk 比特 = " + Arrays.toString(bskBits) + "  （海明重量 " + ones + "/" + D + "）");

            // 客户端查询（位置 + a + beta）
            CapeQuery.Sealed q = CapeQuery.build(h, n, K, R(db), maxValues, lBf,
                maxSetSize, 0.015625, bskBits, db.keywords, query);

            System.out.println();
            System.out.printf("%4s %8s %12s %10s %12s %12s %10s%n",
                "路a", "r_a", "Σa·s mod 2N", "β", "β−r_a", "左−右", "判定");

            boolean allOk = true;
            for (int a = 0; a < K; a++) {
                long sum = 0;
                for (int i = 0; i < D; i++) {
                    if (bskBits[i] == 1) {
                        sum = (sum + q.a[a][i]) % twoN;
                    }
                }
                long beta = q.beta[a] % twoN;
                long r = q.rowIdx[a];
                long betaMinusR = Math.floorMod(beta - r, twoN);
                long diff = Math.floorMod(sum - betaMinusR, twoN);
                boolean ok = diff == 0;
                allOk &= ok;
                System.out.printf("%4d %8d %12d %10d %12d %12d %10s%n",
                    a, r, sum, beta, betaMinusR, diff, ok ? "OK" : "**FAIL**");
            }

            System.out.println();
            if (allOk) {
                System.out.println("⇒ 恒等式成立：客户端的 a/β 与 bsk 比特是自洽的。");
                System.out.println("   那问题不在算术层，而在 blind_rotate 的实际执行（该加轮级计数器）。");
            } else {
                System.out.println("⇒ 恒等式**不成立** —— 这就是载荷全 0 的原因（旋转量是垃圾）。");
                System.out.println("   修法：让 β 严格按 Σ a_i·s_i(bsk) + r_a 生成。");
            }

            // 再验一条：bk 里到底有几个 RGSW(1) / RGSW(0)
            System.out.println();
            System.out.println("--- 附带核对：bk 里 RGSW 的构造 ---");
            System.out.printf("   bsk 比特里 1 的个数 = %d ⇒ bk 里有 %d 个 RGSW(1)、%d 个 RGSW(0)%n",
                ones, ones, D - ones);
            System.out.println("   （纯 {0,1} 秘密 ⇒ CMUX 每轮都真的在选；这是设计意图）");
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }

    private static int R(CapeDemoData db) {
        return Integer.getInteger("cape.r", 16);
    }
}
