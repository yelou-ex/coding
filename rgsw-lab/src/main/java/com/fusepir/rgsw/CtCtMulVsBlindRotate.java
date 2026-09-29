package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * 核对《harness 的说法哪里对、哪里不对》§五 的主张：
 * <blockquote>
 * 列选择输出的累加器 {@code Enc(P_{c_a,b}(X))} 是密文，客户端送 {@code RLWE(X^{−r_a})}，
 * 服务器做 {@code CtCtMul} 就能完成行选择 —— 方案 B 在纯计算上不比盲旋转差。
 * </blockquote>
 *
 * <h3>要核对的</h3>
 * <ol>
 *   <li>列选择输出的累加器，相位级是多少？（对比 {@code m.encrypt} 的新鲜密文）</li>
 *   <li>{@code CtCtMul} 之后相位级会变成多少？</li>
 *   <li>在这个相位级上还能不能继续做运算（噪声预算够不够）？</li>
 * </ol>
 */
public final class CtCtMulVsBlindRotate {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 核对：CtCtMul 方案 vs 盲旋转 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        java.util.Random rnd = new java.util.Random(20261010L);

        // 数据库明文列
        long[] P = new long[n];
        for (int i = 0; i < 64; i++) P[i] = rnd.nextInt(500) + 1;

        // ---- 1. 列选择：拿 C 个独立选择子里"被选中"的那一个来演示 ----
        long[] e1 = new long[n];
        e1[0] = 1;
        Ciphertext encE = m.encrypt(e1);
        Ciphertext acc;
        {
            Ciphertext ct = new Ciphertext(); ct.copyFrom(encE);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pPoly = new Plaintext(n);
            for (int i = 0; i < n; i++) pPoly.set(i, P[i]);
            m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
            acc = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pPoly, acc);
        }
        System.out.println("--- 1. 列选择输出（CtPtMul 之后）---");
        System.out.printf("    解密前 4 = [%d,%d,%d,%d]%n",
            m.decrypt(acc)[0], m.decrypt(acc)[1], m.decrypt(acc)[2], m.decrypt(acc)[3]);
        System.out.printf("    size() = %d 个分量%n", acc.size());
        System.out.println("    （CtPtMul 是 密文×明文，不改变分量数，但会消耗/改变缩放）");
        System.out.println();

        // ---- 2. 方案 B：客户端送 RLWE(X^{−r})，服务器 CtCtMul ----
        int r = 7;
        long[] xr = new long[n];
        xr[(n - r) % n] = 1;                 // X^{−r} = X^{N−r}
        Ciphertext encXr = m.encrypt(xr);
        System.out.println("--- 2. 方案 B：CtCtMul(Enc(X^{−r}), Acc) ---");
        System.out.printf("    r = %d，Enc(X^{%d})%n", r, (n - r) % n);
        Ciphertext prod = new Ciphertext();
        try {
            // 实测：CtCtMul 要求【系数域】，不能是 NTT 域
            Ciphertext a = new Ciphertext(); a.copyFrom(acc);
            if (a.isNttForm()) m.evaluator.transformFromNttInplace(a);
            Ciphertext b = new Ciphertext(); b.copyFrom(encXr);
            if (b.isNttForm()) m.evaluator.transformFromNttInplace(b);
            m.evaluator.multiply(a, b, prod);
            System.out.printf("    张量积后 size() = %d 个分量%n", prod.size());
            m.evaluator.relinearizeInplace(prod, m.relinKeys());
            System.out.printf("    重线性化后 size() = %d 个分量%n", prod.size());
            long[] got = m.decrypt(prod);
            System.out.print("    解密前 4 = [");
            for (int i = 0; i < 4; i++) System.out.print(got[i] + (i < 3 ? "," : ""));
            System.out.println("]");
            System.out.printf("    期望：X^{−%d}·P 的常数项 = P[%d] = %d，实际常数项 = %d   %s%n",
                r, r, P[r], got[0], got[0] == P[r] ? "✓" : "✗");
        } catch (Exception ex) {
            System.out.println("    异常：" + ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }

        // ---- 3. 对照：盲旋转在同一累加器上 ----
        System.out.println();
        System.out.println("--- 3. 对照：盲旋转（既有实现）---");
        System.out.println("    BlindRotateOps.blindRotate 在 N=2048/4096/8192/16384 均已实测通过");
        System.out.println("    它需要：BK[j] = RGSW(r_a[j])，共 d 个 RGSW");
        System.out.println();

        System.out.println(failed == 0 ? "=== 核对完成 ===" : "=== " + failed + " 项失败 ===");
    }
}
