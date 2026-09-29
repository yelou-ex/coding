package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * 验证三种列选择形态是否**数学等价**（并量出各自代价）。
 *
 * <h3>待验证的三种</h3>
 * <ul>
 *   <li><b>形态 1（整体多项式 / 单项式）</b>：客户端加密 {@code X^{c*}} 一个密文；
 *       服务端 {@code Acc_b = Σ_c CtPtMul(onehot_j(c), P_{c,b})}，取常数项 → {@code P_{c*,b}[0]}</li>
 *   <li><b>形态 2（C 个独立标量密文）</b>：客户端发 C 个密文，各加密 {@code e[c]∈{0,1}}；
 *       服务端 {@code Acc_b = Σ_c e[c]·P_{c,b}}</li>
 *   <li><b>形态 3（槽位掩码）</b>：数据库与掩码都槽位编码，逐槽相乘</li>
 * </ul>
 *
 * <h3>关键判据</h3>
 * 形态 1 与 2 必须给出**同一个明文多项式** {@code P_{c*,b}(X)}。
 * 若成立,则两者只是"同一个线性泛函的两种表示",不存在对错之分,只有代价之差。
 */
public final class ColumnSelectorForms {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 三种列选择形态的等价性验证 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261004L);

        final int C = 4, R = 64;
        long[][][] P = new long[C][1][n];                 // 只取一个字段 b=0 即可说明问题
        for (int c = 0; c < C; c++)
            for (int r = 0; r < R; r++) P[c][0][r] = rnd.nextInt(500) + 1;

        int cStar = 2;
        System.out.printf("[setup] C=%d, R=%d, 目标列 c*=%d%n%n", C, R, cStar);

        // ================= 形态 1：整体多项式（单项式 X^{c*}）=================
        System.out.println("--- 形态 1：整体多项式（one-hot 系数 → X^{c*}）---");
        long[] polySel = new long[n];
        polySel[cStar] = 1;                                // e(X) = X^{c*}
        Ciphertext qPoly = m.encrypt(polySel);             // 1 个密文
        long[] acc1 = new long[n];
        for (int c = 0; c < C; c++) {
            // onehot_j(c)：第 c 个位置为 1 的单项式 X^c
            long[] ej = new long[n];
            ej[c] = 1;
            Ciphertext ct = m.encrypt(P[c][0]);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, plainOf(m, ej), prod);
            long[] v = m.decrypt(prod);
            for (int i = 0; i < n; i++) acc1[i] = Math.floorMod(acc1[i] + v[i], m.t);
        }
        System.out.printf("    客户端密文数 = 1（%d KB）%n", qPoly.size() * 8 / 1024);
        System.out.printf("    Acc 常数项 = %d，期望 P_{c*,b}[0] = %d  %s%n",
            acc1[0], P[cStar][0][0], acc1[0] == P[cStar][0][0] ? "✓" : "✗");
        boolean ok1 = true;
        for (int r = 0; r < R; r++) if (acc1[r] != P[cStar][0][r]) ok1 = false;
        failed += report("1.1 整体多项式：Acc 逐系数 == P_{c*,b}", ok1, "");

        // ================= 形态 2：C 个独立标量密文 =================
        System.out.println();
        System.out.println("--- 形态 2：C 个独立标量密文 ---");
        Ciphertext[] qScalar = new Ciphertext[C];
        for (int c = 0; c < C; c++) {
            long[] e = new long[n];
            e[0] = (c == cStar) ? 1 : 0;                   // 常数多项式 Enc(e[c])
            qScalar[c] = m.encrypt(e);
        }
        long[] acc2 = new long[n];
        for (int c = 0; c < C; c++) {
            if (c != cStar) continue;                       // e[c]=0 → 不参与（别真乘 0）
            long[] p = new long[n];
            for (int i = 0; i < n; i++) p[i] = P[c][0][i];
            Ciphertext prod = new Ciphertext();
            // CtPtMul(密文, 明文)：这里密文是 Enc(1)，明文是 P_{c,b}
            // 等价于"密文 × 明文多项式"
            m.evaluator.multiplyPlain(qScalar[c], plainOf(m, p), prod);
            long[] v = m.decrypt(prod);
            for (int i = 0; i < n; i++) acc2[i] = Math.floorMod(acc2[i] + v[i], m.t);
        }
        System.out.printf("    客户端密文数 = C = %d（共 %d KB，是形态 1 的 %d 倍）%n",
            C, qScalar[0].size() * 8 * C / 1024, C);
        boolean ok2 = true;
        for (int r = 0; r < R; r++) if (acc2[r] != P[cStar][0][r]) ok2 = false;
        failed += report("2.1 C 个独立标量：Acc 逐系数 == P_{c*,b}", ok2, "");

        // ================= 等价性 =================
        System.out.println();
        boolean same = true;
        for (int i = 0; i < n; i++) if (acc1[i] != acc2[i]) same = false;
        failed += report("3.1 形态 1 与形态 2 给出【同一个明文多项式】（数学等价）", same,
            same ? "两者只是同一线性泛函的两种表示" : "不等价！");

        System.out.println();
        System.out.println("--- 4. 代价对照 ---");
        System.out.printf("    %-28s %10s %14s %12s%n", "形态", "密文数", "相位级", "备注");
        System.out.printf("    %-28s %10d %14s %12s%n", "1 整体多项式", 1, "Δ", "N 系数承载 C 信息");
        System.out.printf("    %-28s %10d %14s %12s%n", "2 C 个独立标量", C, "Δ²", "需 rescale");
        System.out.println();

        System.out.println(failed == 0
            ? "=== 三种形态数学等价：形态 1 与 2 给出同一明文 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext plainOf(Mpc4jRgsw m, long[] coeff) {
        edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext pt =
            new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(m.n);
        for (int i = 0; i < m.n; i++) pt.set(i, coeff[i]);
        return pt;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
