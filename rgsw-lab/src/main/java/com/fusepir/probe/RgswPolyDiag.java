package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.math.BigInteger;

/** 诊断：明文多项式转 NTT 后到底是什么，以及私钥的 NTT 数据布局。 */
public class RgswPolyDiag {

    public static void main(String[] args) {
        int n = 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("[params] " + m.describe());
        System.out.println("workingPrimeCount = " + m.workingPrimeCount
            + ", 首个工作素数 p0 = " + m.primes[0].value());
        System.out.println();

        // 明文 [1,0,0,...]（常数多项式 1），其 NTT 应当每个槽都是 1
        long[] one = new long[n];
        one[0] = 1;
        Plaintext pt = new Plaintext(one);
        m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        long[] ptn = pt.data();
        System.out.println("pt.data().length = " + ptn.length
            + "   (n=" + n + ", n*workingPrimes=" + (n * m.workingPrimeCount) + ")");
        System.out.print("pt NTT 前 8 个: ");
        for (int i = 0; i < 8; i++) {
            System.out.print(ptn[i] + " ");
        }
        System.out.println();

        // 明文的 parmsId 与密文的 parmsId 是否一致
        // （用一条密文对比）
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 100) + 1;
        }
        var ct = m.encrypt(msg);
        System.out.println("ct.size() = " + ct.size() + ", ct.data().length = " + ct.data().length
            + " (=2*n*workingPrimes? " + (ct.data().length == 2L * n * m.workingPrimeCount) + ")");

        // 私钥的 NTT 数据
        long[] sk = m.sk.data().data();
        System.out.println("sk.data().length = " + sk.length
            + "   (n=" + n + ", n*declaredPrimes=" + (n * m.primes.length)
            + ", n*workingPrimes=" + (n * m.workingPrimeCount) + ")");
        System.out.print("sk NTT 前 8 个: ");
        for (int i = 0; i < 8; i++) {
            System.out.print(sk[i] + " ");
        }
        System.out.println();

        // 自举常数版每一步的等价量：encryptRgswConstant 是"每个 NTT 槽都加 g_i"，
        // 检验"常数 1 的 NTT"是否等于"每个槽都为 1"，从而两个实现应当等价
        long p0 = m.primes[0].value();
        boolean allOne = true;
        for (int i = 0; i < n; i++) {
            if (ptn[i] != 1) {
                allOne = false;
                break;
            }
        }
        System.out.println("常数 1 的 NTT 是否全为 1: " + allOne);

        // 私钥在 NTT 域是否真的是 NTT（抽样看是否像均匀值）
        BigInteger q = m.q;
        System.out.println("q 位宽 = " + q.bitLength() + "；sk[0] 位宽 ≈ "
            + BigInteger.valueOf(sk[0]).bitLength() + "（若≈q 位宽则确认是 NTT 域）");
        System.out.println("sk[0] * (常数1的NTT=1) 与 p0 的关系: " + (sk[0] < p0));
    }
}
