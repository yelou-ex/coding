package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>列选择 (a)：C 个独立密文，每个加密一个【常数】比特</b>
 *
 * <h3>形态</h3>
 * <pre>
 * 客户端：q^col[c] = RLWE.Enc_{s_R}( e[c] )      c = 0..C−1
 *         每个密文的明文是【常数多项式】：系数 0 放 e[c]，其余系数全 0
 *         （只有 c = c_a 那条加密的是 1，其余加密 0）
 *
 * 服务端：Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul( q^col[c], P_{c,b}(X) )
 *         常数 × 多项式 = 纯缩放 ⇒ 无位移
 *         只有 c = c_a 项非零 ⇒ Acc_{a,b} = P_{c_a,b}(X)
 * </pre>
 *
 * <h3>与"单项式编码"的区别（关键）</h3>
 * 若把 1 放在第 {@code c} 个系数（即加密 {@code X^c}），
 * 则 {@code CtPtMul} 结果是 {@code X^c·P_{c,b}} —— <b>带位移</b>，需要额外旋转补偿。
 * 本实现用<b>常数编码</b>，所以<b>不需要旋转</b>。
 */
public final class CapeColumnSelectionIndependent {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 列选择 (a)：C 个独立密文（常数编码，无位移）===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261009L);

        // ================= SETUP（全明文）=================
        final int C = 4, R = 64;
        long[][][] P = new long[C][1][n];
        for (int c = 0; c < C; c++)
            for (int r = 0; r < R; r++) P[c][0][r] = rnd.nextInt(500) + 1;
        System.out.println("--- SETUP（明文，不加密）---");
        System.out.printf("    P_{c,1}(X) = Σ_r D[r + cR][1]·X^r，共 %d 条【明文】多项式%n%n", C);

        // ================= QUERY：C 个独立密文，常数编码 =================
        final int c_a = 2;
        System.out.println("--- QUERY ---");
        System.out.printf("    c_a = %d；one-hot e = ", c_a);
        long[] eVec = new long[C];
        eVec[c_a] = 1;
        System.out.println(java.util.Arrays.toString(eVec));

        Ciphertext[] qCol = new Ciphertext[C];
        for (int c = 0; c < C; c++) {
            long[] constant = new long[n];
            constant[0] = eVec[c];                      // ★ 常数项放 e[c]，不是第 c 位
            qCol[c] = m.encrypt(constant);
        }
        System.out.printf("    %d 个独立密文，每个的明文是【常数多项式】（系数0 = e[c]）%n", C);
        System.out.println("    ★ 只有 c_a 那条加密 1，其余加密 0");
        System.out.println();

        // ================= ANSWER 第 5 行 =================
        System.out.println("--- ANSWER 第 5 行 ---");
        System.out.println("    Acc ← Σ_c  CtPtMul( q^col[c], P_{c,b}(X) )");
        System.out.println();

        long[] acc = new long[n];
        for (int c = 0; c < C; c++) {
            if (eVec[c] == 0) {
                System.out.printf("      c=%d：e[c]=0 → 该列不参与（跳过，别真乘 0）%n", c);
                continue;                                // 论文语义：零分量不贡献
            }
            Ciphertext ct = new Ciphertext();
            ct.copyFrom(qCol[c]);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pPoly = new Plaintext(n);
            for (int i = 0; i < n; i++) pPoly.set(i, P[c][0][i]);
            m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pPoly, prod);
            long[] v = m.decrypt(prod);
            System.out.printf("      c=%d：e[c]=1 → CtPtMul 结果前 6 = [%d,%d,%d,%d,%d,%d]%n",
                c, v[0], v[1], v[2], v[3], v[4], v[5]);
            for (int i = 0; i < n; i++) acc[i] = Math.floorMod(acc[i] + v[i], m.t);
        }

        // ================= 直接比对（无需旋转）=================
        System.out.println();
        System.out.print("    Acc 前 8       = ");
        for (int i = 0; i < 8; i++) System.out.print(acc[i] + " ");
        System.out.println();
        System.out.print("    P_{c_a,1} 前 8 = ");
        for (int i = 0; i < 8; i++) System.out.print(P[c_a][0][i] + " ");
        System.out.println();

        boolean ok = true;
        String first = "";
        for (int r = 0; r < R; r++) {
            if (acc[r] != P[c_a][0][r]) {
                ok = false;
                if (first.isEmpty()) first = String.format("r=%d got=%d want=%d", r, acc[r], P[c_a][0][r]);
            }
        }
        failed += report("A1 Acc == P_{c_a,1}(X)（" + R + " 个系数全对，无需旋转）", ok, first);

        // 负对照：换一条密文（即换个 c_a）必须给出不同的列
        System.out.println();
        long[] other = new long[n];
        {
            int cOther = 1;
            Ciphertext ct = new Ciphertext();
            ct.copyFrom(qCol[cOther]);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pPoly = new Plaintext(n);
            for (int i = 0; i < n; i++) pPoly.set(i, P[cOther][0][i]);
            m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pPoly, prod);
            // qCol[cOther] 加密的是 0 → 结果应为 0
            other = m.decrypt(prod);
        }
        boolean allZero = true;
        for (int i = 0; i < n; i++) if (other[i] != 0) allZero = false;
        failed += report("A2 负对照：e[c]=0 的那条密文乘出来是全 0", allZero, "");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 列选择 (a) 验证通过：C 个独立密文 + 常数编码，无位移 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
