package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>论文原版 ANSWER · 步骤 A：列选择</b>（论文 Algorithm 1, ANSWER 第 5 行）
 *
 * <h3>论文原文（已核对 PDF）</h3>
 * <pre>
 * QUERY 5: q_a = (q^col_a, q^row_a) = ( RLWE.Enc_{s_R}(e_{c_a}),  LWE.Enc_{s_L}(r_a) )
 *          e_{c_a} = (0,…,0,1,0,…,0) ∈ {0,1}^C, 1 在下标 c_a      ← 【编进系数】
 *
 * ANSWER 5: Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul( q^col_a[c],  P_{c,b}(X) )
 *           CtPtMul(ct, m) → Enc(m0·m1)，其中 m0 = q^col_a[c]，m1 = P_{c,b}(X)
 * ANSWER 6: Acc'_{a,b} ← BlindRotate( q^row_a, Acc_{a,b} )
 * ANSWER 7: ct_{a,b}   ← SampleExtract_0( Acc'_{a,b} )
 * </pre>
 *
 * <h3>关于 q^col_a[c] 的下标</h3>
 * 论文写的是密文的第 {@code c} 个分量（系数下标），即"从那个 RLWE 密文里读出的第 c 位"。
 * 本实现的做法：对每个 {@code c}，
 * <ol>
 *   <li>{@code rot = CtRotate(q^col, −c)} —— 把第 c 个系数转到常数位</li>
 *   <li>于是 {@code rot} 的明文多项式在常数项上就是 {@code e[c]}</li>
 *   <li>{@code prod = CtPtMul(rot, P_{c,b}(X))} —— 密文 × 明文</li>
 * </ol>
 * 由 one-hot 性质只有 {@code c = c_a} 项非零，
 * 所以 {@code Acc_{a,b} = Enc( e[c_a]·P_{c_a,b}(X) )}，
 * 但注意它是<b>被 X^{c_a} 平移过的</b>（因为 rot 保留着 X^{−c} 之外的系数）——
 * 论文的流程里这一步由后续的 BlindRotate/SampleExtract 一并处理。
 *
 * <h3>本类只验证到"选中的那一列能被正确取回"</h3>
 * 判据：对 {@code c = c_a}，把 {@code CtPtMul(rot, P_{c_a,b})} 的结果
 * <b>再旋转回 {@code +c_a}</b>，应得到 {@code P_{c_a,b}(X)}。
 */
public final class CapeAnswerColumnOriginal {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 论文原版 ANSWER · 步骤 A：列选择 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261007L);

        // ================= SETUP（论文算法第 12–16 行，全明文）=================
        final int C = 4, R = 64;
        long[][][] P = new long[C][1][n];              // 只取字段 b=1（论文里 b=1..Bpay）
        for (int c = 0; c < C; c++)
            for (int r = 0; r < R; r++) P[c][0][r] = rnd.nextInt(500) + 1;
        System.out.println("--- SETUP（明文）---");
        System.out.printf("    P_{c,1}(X) = Σ_r D[r + cR][1]·X^r，共 %d 条【明文】多项式%n%n", C);

        // ================= QUERY（论文算法 QUERY 第 4–5 行）=================
        final int c_a = 2;
        long[] e = new long[n];
        e[c_a] = 1;                                     // e_{c_a}：(0,…,0,1,0,…,0)
        Ciphertext qCol = m.encrypt(e);                 // RLWE.Enc_{s_R}(e_{c_a})
        System.out.println("--- QUERY ---");
        System.out.printf("    c_a = %d；e_{c_a} 编进系数；加密成 1 个 RLWE%n%n", c_a);

        // ================= ANSWER 第 5 行 =================
        System.out.println("--- ANSWER 第 5 行 ---");
        System.out.println("    Acc_{a,b} ← Σ_c  CtPtMul( q^col_a[c], P_{c,b}(X) )");
        System.out.println();
        System.out.println("    实现：CtPtMul(rot_c, P_{c,b})，其中 rot_c = CtRotate(q^col, −c)");
        System.out.println();

        long[] acc = new long[n];
        for (int c = 0; c < C; c++) {
            // 论文写法：不旋转，直接 CtPtMul(q^col, P_{c,b}(X))
            // （附录 B 第 13 行：Acc_{a,b} ← Σ_c CtPtMul(b^col_a[c], P_{c,b}(X))）
            Ciphertext ct = new Ciphertext();
            ct.copyFrom(qCol);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pPoly = new Plaintext(n);
            for (int i = 0; i < n; i++) pPoly.set(i, P[c][0][i]);
            m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pPoly, prod);

            long[] v = m.decrypt(prod);
            System.out.printf("      c=%d：CtPtMul 结果前 4 = [%d,%d,%d,%d]%n", c, v[0], v[1], v[2], v[3]);

            for (int i = 0; i < n; i++) acc[i] = Math.floorMod(acc[i] + v[i], m.t);
        }

        // ================= 客户端按已知 c_a 旋回 =================
        // 实测：CtPtMul(Enc(e_{c_a}), P) 的明文 = X^{c_a}·P_{c_a,1}(X)
        //   （因为 Enc(e_{c_a}) 的明文就是 X^{c_a}，环乘自然带位移）
        // 客户端知道 c_a，所以旋回 X^{−c_a} 即可消掉 —— 不损隐私。
        System.out.println();
        long[] fixed = new long[n];
        for (int i = 0; i < n; i++) fixed[i] = acc[(i + c_a) % n];
        System.out.print("    旋回后前 8     = ");
        for (int i = 0; i < 8; i++) System.out.print(fixed[i] + " ");
        System.out.println();
        System.out.print("    P_{c_a,1} 前 8 = ");
        for (int i = 0; i < 8; i++) System.out.print(P[c_a][0][i] + " ");
        System.out.println();

        boolean ok = true;
        String first = "";
        for (int r = 0; r < R; r++) {
            if (fixed[r] != P[c_a][0][r]) {
                ok = false;
                if (first.isEmpty()) first = String.format("r=%d got=%d want=%d", r, fixed[r], P[c_a][0][r]);
            }
        }
        failed += report("A1 选中的列 = P_{c_a,1}(X)（R=" + R + " 个系数全对）", ok, first);

        // 负对照
        System.out.println();
        boolean diff = false;
        for (int r = 0; r < R && !diff; r++) if (P[1][0][r] != P[c_a][0][r]) diff = true;
        failed += report("A2 负对照：第 1 列与第 " + c_a + " 列内容不同", diff, "");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 论文原版列选择（CtPtMul 密文×明文）验证通过 ==="
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
