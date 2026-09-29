package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/** 系统标定 BFV 的相位级：Enc(P) 与"由样本 Pack 回来的 Enc(e)"相乘后，缩放到底是什么。 */
public final class LevelProbe {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("[params] " + m.describe());
        System.out.println();

        // P: 小值多项式（前 8 个系数）
        long[] P = new long[n];
        for (int i = 0; i < 8; i++) P[i] = 100 + i;
        P[0] = 40;

        Ciphertext encP = m.encrypt(P);
        System.out.println("A. Enc(P) 解密前 4 = " + show(m.decrypt(encP)));

        // --- 用"样本 Pack 回来"的密文（原始级）去乘 ---
        // 先造一个 Enc(X^c) 的 RLWE，抽出第 c 个系数，再 Pack 回第 c 位
        long[] e = new long[n];
        e[2] = 1;
        Ciphertext qCol = m.encrypt(e);
        Ciphertext rot = m.multiplyPowerOfX(qCol, -2);
        long[][] smp = LweRlweBridge.sampleExtract(m, rot, 0);
        Ciphertext ctE = LweRlweBridge.packFromSample(m, smp, 2);
        System.out.println("B. Pack 回来的密文解密前 4 = " + show(m.decrypt(ctE))
            + "   （第 2 位 = " + m.decrypt(ctE)[2] + "）");

        // --- 各种组合 ---
        System.out.println();
        System.out.println("C. CtPtMul(Enc(P), 明文多项式 M) 的缩放标定：");
        System.out.println("   设 M = 明文多项式。试 M = 全 1 / M = P / M = 常数 k");
        for (String tag : new String[]{"ones", "P", "k1", "k2", "k5"}) {
            Plaintext pt = new Plaintext(n);
            switch (tag) {
                case "ones": for (int i = 0; i < n; i++) pt.set(i, 1); break;
                case "P":    for (int i = 0; i < n; i++) pt.set(i, P[i]); break;
                case "k1":   pt.set(0, 1); break;
                case "k2":   pt.set(0, 2); break;
                case "k5":   pt.set(0, 5); break;
            }
            Ciphertext prod = new Ciphertext();
            try {
                m.evaluator.multiplyPlain(encP, pt, prod);
                long[] v = m.decrypt(prod);
                System.out.printf("    M=%-5s → 前 4 = %s%n", tag, show(v));
            } catch (Exception ex) {
                System.out.printf("    M=%-5s → 异常: %s%n", tag, ex.getMessage());
            }
        }

        System.out.println();
        System.out.println("D. 用 Pack 回来的密文 ctE 去乘明文 P：");
        Plaintext ptP = new Plaintext(n);
        for (int i = 0; i < n; i++) ptP.set(i, P[i]);
        Ciphertext prod2 = new Ciphertext();
        try {
            m.evaluator.multiplyPlain(ctE, ptP, prod2);
            System.out.println("    multiplyPlain(ctE, P) → 前 4 = " + show(m.decrypt(prod2)));
        } catch (Exception ex) {
            System.out.println("    异常: " + ex.getMessage());
        }

        System.out.println();
        System.out.println("E. NTT 域下再试（RingPack 的做法）：");
        Ciphertext c1 = new Ciphertext(); c1.copyFrom(encP);
        m.evaluator.transformToNttInplace(c1);
        Ciphertext c2 = new Ciphertext(); c2.copyFrom(ctE);
        m.evaluator.transformToNttInplace(c2);
        Plaintext ptN = new Plaintext(n);
        for (int i = 0; i < n; i++) ptN.set(i, 1);
        Ciphertext prod3 = new Ciphertext();
        try {
            m.evaluator.multiplyPlain(c2, ptN, prod3);
            System.out.println("    multiplyPlain(ctE_ntt, ones) → 前 4 = " + show(m.decrypt(prod3)));
        } catch (Exception ex) {
            System.out.println("    异常: " + ex.getMessage());
        }
    }

    private static String show(long[] v) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 4; i++) sb.append(v[i]).append(i < 3 ? "," : "");
        return sb.append("]").toString();
    }
}
