package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>量列选择里"构造明文明文多项式"的两种写法差多少。</b>
 *
 * <h3>为什么要量这个</h3>
 * `CapeEndToEnd4` 单次 ANSWER 实测 **417 ms/单元**，但按 `SelToExtractBench` 的单价
 * （1 次 CMUX ≈ 12 ms @ N=4096，`d=16` ⇒ 盲旋转 ≈ 192 ms）算，**还有 ~225 ms 说不清**。
 * 嫌疑是列选择里的
 * <pre>
 *   Plaintext pPoly = new Plaintext(n);
 *   for (int i = 0; i < n; i++) pPoly.set(i, P[c][b][i]);   // ← 逐元素 set，每单元 4×4096 次
 * </pre>
 * 对比 `SelToExtractBench` 用的**批量构造** `new Plaintext(long[])`。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.PlaintextFillProbe 4096}
 */
public final class PlaintextFillProbe {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int C = 4;                       // CapeEndToEnd4 里的列数
        int reps = 200;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 列选择里「构造明文多项式」两种写法的耗时 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[plan] N=%d，每单元 %d 列，重复 %d 次%n%n", n, C, reps);

        long[][] P = new long[C][n];
        for (int c = 0; c < C; c++) {
            for (int i = 0; i < n; i++) {
                P[c][i] = 1 + ((i * 31L + c) % 65535);
            }
        }

        // ---- ① 逐元素 set() ----
        for (int w = 0; w < 20; w++) {
            Plaintext pt = new Plaintext(n);
            for (int i = 0; i < n; i++) {
                pt.set(i, P[0][i]);
            }
        }
        long t0 = System.nanoTime();
        for (int r = 0; r < reps; r++) {
            for (int c = 0; c < C; c++) {
                Plaintext pt = new Plaintext(n);
                for (int i = 0; i < n; i++) {
                    pt.set(i, P[c][i]);
                }
            }
        }
        double setMs = (System.nanoTime() - t0) / 1e6 / reps;

        // ---- ② 批量构造 ----
        for (int w = 0; w < 20; w++) {
            for (int c = 0; c < C; c++) {
                new Plaintext(P[c]);
            }
        }
        t0 = System.nanoTime();
        for (int r = 0; r < reps; r++) {
            for (int c = 0; c < C; c++) {
                new Plaintext(P[c]);
            }
        }
        double bulkMs = (System.nanoTime() - t0) / 1e6 / reps;

        // ---- ③ 再加一次 NTT（两种写法都要转 NTT）----
        Plaintext pt0 = new Plaintext(P[0]);
        for (int w = 0; w < 5; w++) {
            Plaintext pt = new Plaintext(P[0]);
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        }
        t0 = System.nanoTime();
        int nttReps = 50;
        for (int r = 0; r < nttReps; r++) {
            Plaintext pt = new Plaintext(P[0]);
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        }
        double nttMs = (System.nanoTime() - t0) / 1e6 / nttReps;

        System.out.printf("    ① 逐元素 set()×%d   ： %8.1f ms / %d 列%n", n, setMs, C);
        System.out.printf("    ② 批量 new Plaintext(long[])  ： %8.1f ms / %d 列%n", bulkMs, C);
        System.out.printf("    ③ 一次 transformToNttInplace  ： %8.1f ms / 1 列%n", nttMs);
        System.out.printf("    ⇒ ①/② 倍数 = %.1f×%n%n", setMs / Math.max(bulkMs, 1e-6));

        double perUnitOld = setMs + nttMs * C;
        double perUnitNew = bulkMs + nttMs * C;
        System.out.printf("    单单元列选择的明文侧开销：旧写法 %.1f ms → 新写法 %.1f ms（省 %.1f ms）%n",
            perUnitOld, perUnitNew, perUnitOld - perUnitNew);

        System.out.println();
        System.out.println("    对比实测：CapeEndToEnd4 @N=4096 单次 ANSWER = 417 ms/单元");
        System.out.printf("      盲旋转(d=16, 12ms/CMUX) 约 192 ms%n");
        System.out.printf("      列选择明文侧（旧写法） 约 %.0f ms%n", perUnitOld);
        System.out.printf("      其余（multiplyPlain / 提取 / 变换）约 %.0f ms%n",
            417 - 192 - perUnitOld);
    }
}
