package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * 定 ct_c 的相位级，并找出正确的"升到 Δ 级"方式。
 *
 * <p>已知：
 * <ul>
 *   <li>{@code Enc(P)}：相位 = Δ·P（带缩放级）</li>
 *   <li>{@code ct_c = Pack(smp, c)}：相位 = e[c]·X^c（原始级）</li>
 *   <li>{@code multiplyPlain(Enc(P), 常数 k)} 线性正确 → Δ·P·k</li>
 * </ul>
 * 所以只要能把 {@code ct_c} 提到"Δ 级"，再与 {@code Enc(P)} 相乘就得到 Δ·(e·P)。
 */
public final class LevelProbe2 {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        long[] P = new long[n];
        for (int i = 0; i < 8; i++) P[i] = 100 + i;
        P[0] = 40;

        // ct_c：e(X) = X^c 的第 c 个系数 = 1，Pack 回第 c 位
        int c = 2;
        long[] e = new long[n];
        e[c] = 1;
        Ciphertext qCol = m.encrypt(e);
        Ciphertext rot = m.multiplyPowerOfX(qCol, -c);
        long[][] smp = LweRlweBridge.sampleExtract(m, rot, 0);
        Ciphertext ctE = LweRlweBridge.packFromSample(m, smp, c);
        System.out.println("ct_c 解密：常数项=" + m.decrypt(ctE)[0] + "  第" + c + "位=" + m.decrypt(ctE)[c]
            + "   （相位应为 e[c]·X^c = X^" + c + "，即常数项 0、" + c + " 位 1）");

        System.out.println();
        System.out.println("把 ct_c 升到 Δ 级，各种方式的实测：");
        System.out.println("  目标：让 ct_c 的相位 = Δ·X^c（常数项 0，第 c 位 = Δ=5... 或按库约定）");

        // 方式 1：直接乘常数（明文侧），看相位级如何被放大
        for (long k : new long[]{1, 2, 5, 65537}) {
            Ciphertext ct = new Ciphertext(); ct.copyFrom(ctE);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pt = new Plaintext(n);
            pt.set(0, k % m.t);
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] v = m.decrypt(prod);
            System.out.printf("  乘常数 k=%-6d → 常数项=%d, 第%d位=%d%n", k, v[0], c, v[c]);
        }

        System.out.println();
        System.out.println("方式 2：把 ct_c 与 Enc(1) 相乘（BFV 里乘一个 Δ 级密文 = 升一级）");
        {
            long[] one = new long[n]; one[0] = 1;
            Ciphertext ctOne = m.encrypt(one);
            m.evaluator.transformToNttInplace(ctOne);
            Ciphertext ctC = new Ciphertext(); ctC.copyFrom(ctE);
            m.evaluator.transformToNttInplace(ctC);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiply(ctOne, ctC, prod);
            m.evaluator.relinearizeInplace(prod, m.relinKeys());
            long[] v = m.decrypt(prod);
            System.out.printf("  ct_c ⊗ Enc(1) → 常数项=%d, 第%d位=%d   （期望第%d位 = Δ = 5？）%n",
                v[0], c, v[c], c);
        }

        System.out.println();
        System.out.println("换思路：不升 ct_c，而是【把 Enc(P) 降到原始级】再乘，最后整体缩放：");
        System.out.println("  （BFV 里没有公开的降级原语，所以改用下面的等价做法）");
        System.out.println();
        System.out.println("等价做法：直接用 ct_c 乘【原始级】的 P，再乘 Δ：");
        // 造原始级的 P：常数项为 1 的 0/1 不行；改用 multiplyPlain 的线性性质
        // Enc(P) 乘 常数 1/Δ 不可行（Δ 不一定可逆于 t）。
        // 改：先乘 ct_c（得到 Δ·e·P？还是 e·P？）看看实测
        {
            Ciphertext ct = new Ciphertext(); ct.copyFrom(ctE);
            m.evaluator.transformToNttInplace(ct);
            Plaintext pt = new Plaintext(n);
            for (int i = 0; i < n; i++) pt.set(i, P[i]);
            m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pt, prod);
            long[] v = m.decrypt(prod);
            System.out.print("  multiplyPlain(ct_c, P) → ");
            for (int i = 0; i < 4; i++) System.out.print(v[i] + " ");
            System.out.println("   期望 P 右移 c 位");
            System.out.print("  P 右移 c 位应为 → ");
            for (int i = 0; i < 4; i++) System.out.print(P[(i - c + n) % n] + " ");
            System.out.println();
        }
    }

    private static String show(long[] v) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 4; i++) sb.append(v[i]).append(i < 3 ? "," : "");
        return sb.append("]").toString();
    }
}
