package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/** 测 BatchEncoder 槽位编码 + encrypt/decrypt 的往返是否成立。 */
public final class SlotProbe {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();
        System.out.println("[slots] " + slots + "  [t] " + m.t);
        System.out.println();

        // 槽位向量：槽 0 放 219，槽 1 放 11，其余 0
        long[] v = new long[slots];
        v[0] = 219;
        v[1] = 11;
        v[20] = 7;                       // 模拟"下一行的同字段"（slot = row*B_pay + b）

        Plaintext pt = new Plaintext();
        be.encode(v, pt);
        System.out.println("A. BatchEncoder 编解码往返（无加密）");
        long[] dec = new long[slots];
        be.decode(pt, dec);
        System.out.printf("   原始 [0..2] = [%d, %d, %d]%n", v[0], v[1], v[2]);
        System.out.printf("   解码 [0..2] = [%d, %d, %d]%n", dec[0], dec[1], dec[2]);
        System.out.printf("   一致? %s%n%n", (dec[0] == v[0] && dec[1] == v[1] && dec[20] == v[20]) ? "是" : "否");

        System.out.println("B. 加密 → 解密 往返");
        Ciphertext ct = new Ciphertext();
        m.encryptor.encryptSymmetric(pt, ct);
        long[] got = m.decrypt(ct);
        System.out.printf("   m.decrypt 的 [0..2]  = [%d, %d, %d]   ← 这是系数还是槽位？%n", got[0], got[1], got[2]);
        System.out.printf("   期望槽位 [0,1,20] = [%d, %d, %d]%n", v[0], v[1], v[20]);
        System.out.println();

        // 用 BatchEncoder 解密密文
        System.out.println("C. 解密后用 BatchEncoder.decode 读槽位");
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        // decryptor.decrypt 给 Plaintext（NTT 或系数？），先试直接 decode
        Plaintext ptOut = new Plaintext(n);
        m.decryptor.decrypt(copy, ptOut);
        try {
            long[] s = new long[slots];
            be.decode(ptOut, s);
            System.out.printf("   槽位 [0..2] = [%d, %d, %d]，[20] = %d%n", s[0], s[1], s[2], s[20]);
            System.out.printf("   一致? %s%n", (s[0] == v[0] && s[1] == v[1] && s[20] == v[20]) ? "是 ✓" : "否 ✗");
        } catch (Exception e) {
            System.out.println("   decode 失败: " + e.getMessage());
        }
    }
}
