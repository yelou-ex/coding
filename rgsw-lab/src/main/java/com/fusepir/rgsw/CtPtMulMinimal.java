package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * 最小化验证：{@code CtPtMul(Enc(e_{c*}), P(X)) == P(X)}？
 *
 * <p>论文 Algorithm 1 ANSWER 第 5 行：{@code Acc = Σ_c CtPtMul(q^col_a[c], P_{c,b}(X))}。
 * 当 {@code e_{c*}} 是 one-hot（只有第 {@code c*} 个系数为 1）时，
 * 单独一项 {@code CtPtMul(Enc(e_{c*}), P)} 就应该等于 {@code P}（因为 e 是个"单位"）。
 *
 * <p>本类把这个最小情形单独测，排除列循环带来的干扰。
 */
public final class CtPtMulMinimal {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(1);
        long[] P = new long[n];
        for (int i = 0; i < 16; i++) P[i] = rnd.nextInt(500) + 1;
        System.out.print("P(X) 前 8 = ");
        for (int i = 0; i < 8; i++) System.out.print(P[i] + " ");
        System.out.println();

        // e_{c*}：第 c* 个系数 = 1
        for (int cStar : new int[]{0, 2, 5}) {
            long[] e = new long[n];
            e[cStar] = 1;
            Ciphertext encE = m.encrypt(e);

            // ---- 方式 A：密文与明文都转 NTT 域 ----
            Ciphertext ctA = new Ciphertext(); ctA.copyFrom(encE);
            m.evaluator.transformToNttInplace(ctA);
            Plaintext ptA = new Plaintext(n);
            for (int i = 0; i < n; i++) ptA.set(i, P[i]);
            m.evaluator.transformToNttInplace(ptA, m.context.firstParmsId());
            Ciphertext prodA = new Ciphertext();
            m.evaluator.multiplyPlain(ctA, ptA, prodA);
            long[] vA = m.decrypt(prodA);

            // ---- 方式 B：明文不转 NTT ----
            Ciphertext ctB = new Ciphertext(); ctB.copyFrom(encE);
            m.evaluator.transformToNttInplace(ctB);
            Plaintext ptB = new Plaintext(n);
            for (int i = 0; i < n; i++) ptB.set(i, P[i]);
            Ciphertext prodB = new Ciphertext();
            String errB = "";
            long[] vB = null;
            try {
                m.evaluator.multiplyPlain(ctB, ptB, prodB);
                vB = m.decrypt(prodB);
            } catch (Exception ex) { errB = ex.getMessage(); }

            System.out.println();
            System.out.printf("c*=%d%n", cStar);
            System.out.print("  方式A [NTT+NTT] 前 8 = ");
            for (int i = 0; i < 8; i++) System.out.print(vA[i] + " ");
            System.out.println("   " + (eq(vA, P, n) ? "✓ == P" : "✗"));
            if (vB != null) {
                System.out.print("  方式B [NTT+系数] 前 8 = ");
                for (int i = 0; i < 8; i++) System.out.print(vB[i] + " ");
                System.out.println("   " + (eq(vB, P, n) ? "✓ == P" : "✗"));
            } else {
                System.out.println("  方式B 异常: " + errB);
            }

            // ---- 方式 C：不对 Enc(e) 做旋转，直接乘（论文写法）----
            System.out.printf("  方式A 是否等于 P: %s%n", eq(vA, P, n) ? "是" : "否");
        }

        System.out.println();
        System.out.println(failed == 0 ? "=== 最小情形验证完成 ===" : "=== " + failed + " 项失败 ===");
    }

    private static boolean eq(long[] a, long[] b, int n) {
        for (int i = 0; i < n; i++) if (a[i] != b[i]) return false;
        return true;
    }
}
