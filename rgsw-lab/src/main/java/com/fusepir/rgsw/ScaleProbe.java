package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/** 实测 multiplyPlain + decrypt 的缩放约定。 */
public final class ScaleProbe {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        System.out.println("[params] " + m.describe());
        System.out.println("[slots] " + be.slotCount());
        System.out.println();

        // 数据库明文（系数域，小值）
        long[] data = new long[n];
        for (int i = 0; i < 16; i++) data[i] = 11 + i;
        Ciphertext ct = m.encrypt(data);
        long[] base = m.decrypt(ct);
        System.out.print("原密文解密（前 8）= ");
        for (int i = 0; i < 8; i++) System.out.print(base[i] + " ");
        System.out.println();
        System.out.print("原始 data    （前 8）= ");
        for (int i = 0; i < 8; i++) System.out.print(data[i] + " ");
        System.out.println("   ← 应一致（encrypt/decrypt 无额外缩放）");
        System.out.println();

        // 逐槽掩码：槽 2 设为 k，其余 0
        System.out.println("掩码 k  →  解密后前 4 槽（期望：槽2 = data[2] = " + data[2] + "，其余 0）");
        for (long k : new long[]{1, 2, 3, 4, 5, 10, 100, 13107, 26214, 32768, 65536}) {
            long[] mask = new long[be.slotCount()];
            mask[2] = k % m.t;
            Plaintext pt = new Plaintext();
            be.encode(mask, pt);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] got = m.decrypt(prod);
            System.out.printf("  k=%-6d → [%d, %d, %d, %d]%n", k % m.t, got[0], got[1], got[2], got[3]);
        }
        System.out.println();

        // 不用 BatchEncoder，直接系数域明文（常数项 = 1，只影响常数位）
        System.out.println("直接系数域明文（常数项 = k）：");
        for (long k : new long[]{1, 2, 3, 5, 65536}) {
            Plaintext pt = new Plaintext(n);
            pt.set(0, k % m.t);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] got = m.decrypt(prod);
            System.out.printf("  k=%-6d → 前 4 槽 [%d, %d, %d, %d]（期望 [%d,0,0,0]）%n",
                k % m.t, got[0], got[1], got[2], got[3], (k * data[0]) % m.t);
        }
    }
}
