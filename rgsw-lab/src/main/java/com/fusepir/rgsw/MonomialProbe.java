package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import java.util.Random;

/** 实测：用"单项式明文 X^c"去乘密文，常数项到底是什么。 */
public final class MonomialProbe {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        Random rnd = new Random(1);

        // P(X) = 常数项 40，其余依次
        long[] P = new long[n];
        for (int i = 0; i < 8; i++) P[i] = 100 + i;      // P[0]=100 ...
        P[0] = 40;
        Ciphertext ct = m.encrypt(P);
        long[] base = m.decrypt(ct);
        System.out.print("原密文解密前 8 = ");
        for (int i = 0; i < 8; i++) System.out.print(base[i] + " ");
        System.out.println();

        System.out.println();
        System.out.println("用明文 X^c 去乘（pt.set(c,1)），看常数项：");
        for (int c = 0; c < 4; c++) {
            Plaintext pt = new Plaintext(n);
            pt.set(c, 1);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] v = m.decrypt(prod);
            System.out.printf("  c=%d → 常数项=%d, 前4=[%d,%d,%d,%d]   期望常数项 = -P[8-c] = %d%n",
                c, v[0], v[0], v[1], v[2], v[3], Math.floorMod(-P[8 - c], m.t));
        }
        System.out.println();

        System.out.println("用明文的常数项 = k 去乘（pt.set(0,k)），看缩放：");
        for (long k : new long[]{1, 2, 5}) {
            Plaintext pt = new Plaintext(n);
            pt.set(0, k);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] v = m.decrypt(prod);
            System.out.printf("  k=%d → 常数项=%d   期望 = P[0]*k = %d  %s%n",
                k, v[0], (P[0] * k) % m.t, v[0] == (P[0] * k) % m.t ? "✓" : "✗");
        }
        System.out.println();

        // 关键：明文 X^c 是否等价于"系数域乘 X^c"？
        System.out.println("对照：直接算 P(X)·X^c 的常数项（负循环）");
        for (int c = 0; c < 4; c++) {
            int idx = Math.floorMod(-c, 2 * n);
            long want = idx < n ? P[idx] : Math.floorMod(-P[idx - n], m.t);
            System.out.printf("  c=%d → 常数项应为 %d%n", c, want);
        }
    }
}
