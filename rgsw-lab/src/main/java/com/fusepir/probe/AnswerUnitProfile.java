package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>把 `CapeEndToEnd4` 的"一个 ANSWER 单元"逐段计时，找出 417 ms 花在哪。</b>
 *
 * <p>背景：实测 N=4096、d=16 时单次 ANSWER = 120 单元 / 50 s = **417 ms/单元**。
 * 而按 `SelToExtractBench` 的单价算，盲旋转（16 × 12 ms）只占 192 ms，**剩下 ~225 ms 说不清**。
 * 本类按 `CapeEndToEnd4.columnSelect + blindRotate + sampleExtract` 的真实形状逐段量。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.AnswerUnitProfile 4096 16}
 */
public final class AnswerUnitProfile {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        final int C = 4;
        final int R = 16;
        final int units = 24;          // 3 个 a × 8 个 b，够摊平 JIT

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        Random rnd = new Random(20260930L);
        System.out.println("=== ANSWER 单元逐段计时 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[plan] N=%d, d=%d, C=%d, 计时 %d 个单元%n%n", n, d, C, units);

        // 造素材
        long[][][] P = new long[C][units][n];
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < units; b++) {
                for (int r = 0; r < R; r++) {
                    P[c][b][r] = 1 + rnd.nextInt((int) m.t - 1);
                }
            }
        }
        Ciphertext[][] sel = new Ciphertext[C][1];
        for (int c = 0; c < C; c++) {
            long[] constant = new long[n];
            constant[0] = c == 0 ? 1 : 0;
            sel[c][0] = m.encrypt(constant);
        }
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        int qL = 2 * n;
        long[] a = new long[d];
        long sum = 0;
        for (int i = 0; i < d; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + a[i] * s[i]) % qL;
        }
        long beta = Math.floorMod(sum + 3, qL);

        // 预热
        for (int w = 0; w < 3; w++) {
            Ciphertext acc = columnSelectDetailed(m, n, P, sel, w, C, null);
            if (acc.isNttForm()) {
                m.evaluator.transformFromNttInplace(acc);
            }
            Ciphertext rot = BlindRotateOps.blindRotate(m, bk, acc, a, beta);
            LweRlweBridge.sampleExtract(m, rot, 0);
        }

        double[] tCopyNtt = new double[units];
        double[] tPtNtt = new double[units];
        double[] tMul = new double[units];
        double[] tRot = new double[units];
        double[] tExt = new double[units];
        double[] tTotal = new double[units];

        for (int b = 0; b < units; b++) {
            long t = System.nanoTime();
            Ciphertext acc = null;
            long accCopy = 0;
            long accPt = 0;
            long accMul = 0;
            for (int c = 0; c < C; c++) {
                long t0 = System.nanoTime();
                Ciphertext ct = new Ciphertext();
                ct.copyFrom(sel[c][0]);
                if (!ct.isNttForm()) {
                    m.evaluator.transformToNttInplace(ct);
                }
                accCopy += System.nanoTime() - t0;

                t0 = System.nanoTime();
                Plaintext pt = new Plaintext(n);
                for (int i = 0; i < n; i++) {
                    pt.set(i, P[c][b][i]);
                }
                m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
                accPt += System.nanoTime() - t0;

                t0 = System.nanoTime();
                Ciphertext prod = new Ciphertext();
                m.evaluator.multiplyPlain(ct, pt, prod);
                if (acc == null) {
                    acc = prod;
                } else {
                    m.evaluator.addInplace(acc, prod);
                }
                accMul += System.nanoTime() - t0;
            }
            tCopyNtt[b] = accCopy / 1e6;
            tPtNtt[b] = accPt / 1e6;
            tMul[b] = accMul / 1e6;

            if (acc.isNttForm()) {
                m.evaluator.transformFromNttInplace(acc);
            }
            long t0 = System.nanoTime();
            Ciphertext rot = BlindRotateOps.blindRotate(m, bk, acc, a, beta);
            tRot[b] = (System.nanoTime() - t0) / 1e6;

            t0 = System.nanoTime();
            LweRlweBridge.sampleExtract(m, rot, 0);
            tExt[b] = (System.nanoTime() - t0) / 1e6;

            tTotal[b] = (System.nanoTime() - t) / 1e6;
        }

        double copy = med(tCopyNtt);
        double pt = med(tPtNtt);
        double mul = med(tMul);
        double rot = med(tRot);
        double ext = med(tExt);
        double tot = med(tTotal);

        System.out.println("    分段（中位数，ms/单元）：");
        System.out.printf("      列选择① 选择子密文的 copyFrom + NTT : %8.1f%n", copy);
        System.out.printf("      列选择② 明文构造 + NTT            : %8.1f%n", pt);
        System.out.printf("      列选择③ multiplyPlain + add       : %8.1f%n", mul);
        System.out.printf("      盲旋转（%d 轮 CMUX）              : %8.1f   ⇒ 单轮 %.1f ms%n",
            d, rot, rot / d);
        System.out.printf("      SampleExtract_0                   : %8.1f%n", ext);
        System.out.printf("      ────────────────────────────────────────────%n");
        System.out.printf("      实测单元合计                       : %8.1f%n", tot);
        System.out.printf("      列选择小计                         : %8.1f（占 %.0f%%）%n",
            copy + pt + mul, 100 * (copy + pt + mul) / tot);
        System.out.printf("      盲旋转占比                         : %.0f%%%n%n", 100 * rot / tot);

        double[] series = new double[units];
        for (int b = 0; b < units; b++) {
            series[b] = tRot[b];
        }
        StringBuilder sb = new StringBuilder();
        for (int b = 0; b < units; b++) {
            sb.append(String.format("%.0f ", tRot[b]));
        }
        System.out.println("    盲旋转逐单元序列（ms）：" + sb.toString().trim());
        System.out.printf("    第 1 个单元 %.0f ms，中位数 %.0f ms ⇒ 预热放大 %.2f×%n%n",
            tRot[0], med(series), tRot[0] / med(series));

        System.out.println("    ★ 冗余分析：");
        System.out.printf("      选择子密文的 NTT 每单元重做 %d 次（同一个密文！）%n", C);
        System.out.printf("      明文的 NTT 每个 (c,b) 被 3 个 a 各做 1 次 ⇒ 3× 冗余%n");
        System.out.printf("      ⇒ 若两者都预计算，单单元可省约 %.1f ms（%.0f%%）%n",
            copy + pt * 2.0 / 3.0, 100 * (copy + pt * 2.0 / 3.0) / tot);
    }

    /** 与 CapeEndToEnd4.columnSelect 同形，但把三段耗时回填。 */
    private static Ciphertext columnSelectDetailed(Mpc4jRgsw m, int n, long[][][] P,
                                                   Ciphertext[][] sel, int b, int C, long[] sink) {
        Ciphertext acc = null;
        for (int c = 0; c < C; c++) {
            Ciphertext ct = new Ciphertext();
            ct.copyFrom(sel[c][0]);
            if (!ct.isNttForm()) {
                m.evaluator.transformToNttInplace(ct);
            }
            Plaintext pt = new Plaintext(n);
            for (int i = 0; i < n; i++) {
                pt.set(i, P[c][b][i]);
            }
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            if (acc == null) {
                acc = prod;
            } else {
                m.evaluator.addInplace(acc, prod);
            }
        }
        return acc;
    }

    private static double med(double[] v) {
        double[] c = v.clone();
        java.util.Arrays.sort(c);
        return c[c.length / 2];
    }
}
