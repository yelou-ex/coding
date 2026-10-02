package com.fusepir.probe;

import edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.Modulus;

import java.math.BigInteger;

/**
 * 参数探测工具：把 CAPE 论文设定下的真实模数规模算出来。
 *
 * <p>论文只写了"t = 65537、N = 16384、用 SEAL 默认配置达到 128 位安全"，
 * 没有给出系数模数 q 到底多大。本工具直接调用现成的 Java 同态库，
 * 把 q、缩放因子 Δ、以及解密允许的噪声上限算成位宽，供参数选择时参考。
 *
 * <p>运行方式见 coding/tools/param-probe/README.md
 */
public final class ParamProbe {

    public static void main(String[] args) {
        long t = 65537; // 论文明文模数
        int[] degrees = {8192, 16384, 32768};

        System.out.println("CAPE parameters in the paper's setting (SEAL default config / 128-bit security)");
        System.out.println("plaintext modulus t = " + t);
        System.out.println();

        for (int n : degrees) {
            System.out.println("--- N = " + n + " ---");
            Modulus[] coeffModulus = CoeffModulus.bfvDefault(n);

            BigInteger q = BigInteger.ONE;
            StringBuilder primes = new StringBuilder();
            int totalBits = 0;
            for (Modulus m : coeffModulus) {
                q = q.multiply(BigInteger.valueOf(m.value()));
                int b = 64 - Long.numberOfLeadingZeros(m.value());
                primes.append(b).append(' ');
                totalBits += b;
            }

            System.out.println("  prime count        = " + coeffModulus.length);
            System.out.println("  prime bit sizes    = [" + primes.toString().trim() + "]");
            System.out.println("  total modulus bits = " + totalBits);
            System.out.println("  max bits @128-bit  = " + CoeffModulus.maxBitCount(n));
            System.out.println("  q bit length       = " + q.bitLength());

            BigInteger delta = q.divide(BigInteger.valueOf(t));
            System.out.println("  delta = q/t        ~ " + delta.bitLength() + " bit");

            BigInteger noiseLimit = q.divide(BigInteger.valueOf(2 * t));
            System.out.println("  noise limit q/(2t) ~ " + noiseLimit.bitLength() + " bit");

            try {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
                parms.setPolyModulusDegree(n);
                parms.setCoeffModulus(coeffModulus);
                parms.setPlainModulus(new Modulus(t));
                SealContext context = new SealContext(parms);
                System.out.println("  context check      = " + (context.isParametersSet()
                    ? "OK (key switching: " + context.usingKeySwitching() + ")"
                    : "FAILED: " + context.parametersErrorMessage()));
            } catch (OutOfMemoryError e) {
                System.out.println("  context check      = OUT OF MEMORY");
            }
            System.out.println();
        }

        galoisMemoryTest(t);
    }

    /**
     * 定位一个实测到的真实瓶颈：Java 同态库在建立"上下文"时会为每一层模数各建一个
     * Galois 工具，而该工具内部一次性分配了 N×N 个整数（见 AbstractGaloisTool 第 64 行
     * 的 permutationTables = new int[coeffCount][coeffCount]）。
     * N=16384 时单个就是 1.07 GB，9 层就是约 9.6 GB —— 这就是 N=16384 建上下文失败的根因。
     *
     * <p>本实验固定 N=16384，只改变素数个数（即层数），看需要多少堆内存才能建起来。
     */
    private static void galoisMemoryTest(long t) {
        System.out.println("=== Galois tool memory test (N = 16384) ===");
        System.out.println("Java port allocates coeffCount^2 ints per Galois tool, one tool per modulus level:");
        long perTool = 16384L * 16384L * 4L;
        System.out.printf("  one tool = %d bytes (%.2f GB), so level count dominates%n", perTool, perTool / 1073741824.0);
        System.out.println();

        int[] primeCounts = {2, 4, 9};
        for (int count : primeCounts) {
            int[] bitSizes = new int[count];
            for (int i = 0; i < count; i++) {
                bitSizes[i] = 48;
            }
            Modulus[] cm = CoeffModulus.create(16384, bitSizes);
            long tb = 0;
            for (Modulus m : cm) {
                tb += 64 - Long.numberOfLeadingZeros(m.value());
            }
            long started = System.currentTimeMillis();
            String result;
            try {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
                parms.setPolyModulusDegree(16384);
                parms.setCoeffModulus(cm);
                parms.setPlainModulus(new Modulus(t));
                SealContext context = new SealContext(parms);
                result = context.isParametersSet() ? "OK" : "invalid parameters";
            } catch (OutOfMemoryError e) {
                result = "OUT OF MEMORY";
            }
            System.out.printf("  primes=%-2d (total %-4d bit) -> %-16s  %.1f s%n",
                count, tb, result, (System.currentTimeMillis() - started) / 1000.0);
        }
    }
}
