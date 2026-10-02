/*
 * !!! ROUTE C - self-built RLWE, DEPRECATED, NOT THE DEFAULT !!!
 *
 * Default (route B): Mpc4jRgsw.java / BlindRotateOps.java on coding/lib/mpc4j-crypto-fhe-seal.jar.
 * This demo is kept only as a cross-check tool. See coding/docs/RLWE路线审计.md.
 */
import com.fusepir.rlwe.*;
import com.fusepir.rgsw.*;

import java.math.BigInteger;
import java.util.Random;

/**
 * RLWE / RGSW 库的外部调用示例。
 *
 * 这个文件**故意不放在 com.fusepir.rgsw 包里**，用来证明这套代码可以当库用：
 * 只需要把 rgsw.jar 加进 classpath，然后 import com.fusepir.rgsw.* 即可。
 *
 * 编译运行：
 *   javac -encoding UTF-8 -cp rgsw.jar -d examples\out examples\RlweDemo.java
 *   java -cp "rgsw.jar;examples\out" RlweDemo
 */
public final class RlweDemo {

    public static void main(String[] args) {
        // ---- 1. 选参数：lab 快，paper 对齐论文 ----
        RingParams p = RingParams.lab();
        System.out.println("[params] " + p.describe());
        System.out.println("         ntt=" + p.nttEnabled()
            + ", noiseLimit=" + p.noiseLimit());

        Random rnd = new Random(1);
        RlweKey key = new RlweKey(p, rnd);

        // ---- 2. RLWE 加解密往返 ----
        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = i % 100;                       // 放一点有结构的数据，便于肉眼看
        }
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
        long[] back = RlweOps.decrypt(p, key, ct);
        System.out.println("[RLWE] roundtrip ok = " + java.util.Arrays.equals(m, back)
            + ", 前 5 个 = " + java.util.Arrays.toString(java.util.Arrays.copyOf(back, 5)));

        // ---- 3. 公开单项式旋转（不需要密钥）----
        RlweCiphertext rotated = MonomialOps.mulMonomial(p, ct, 3);
        long[] rb = RlweOps.decrypt(p, key, rotated);
        System.out.println("[monomial] X^3 * m 前 8 个 = "
            + java.util.Arrays.toString(java.util.Arrays.copyOf(rb, 8)));

        // ---- 4. RGSW + 外部乘积（CMUX：A + RGSW(mu)⊗(B-A)）----
        long[] m0 = new long[p.n];
        long[] m1 = new long[p.n];
        java.util.Arrays.fill(m0, 11);
        java.util.Arrays.fill(m1, 22);
        RlweCiphertext a = RlweOps.encryptScaled(p, key, m0, rnd);
        RlweCiphertext b = RlweOps.encryptScaled(p, key, m1, rnd);

        for (int mu = 0; mu <= 1; mu++) {
            RgswCiphertext rgsw = RgswOps.encrypt(p, key, RgswOps.constant(p, mu), rnd);
            RlweCiphertext diff = new RlweCiphertext(
                subP(p, b.c0, a.c0), subP(p, b.c1, a.c1));
            RlweCiphertext prod = RgswOps.externalProduct(p, rgsw, diff);
            RlweCiphertext res = new RlweCiphertext(
                addP(p, a.c0, prod.c0), addP(p, a.c1, prod.c1));
            long[] out = RlweOps.decrypt(p, key, res);
            System.out.println("[CMUX] mu=" + mu + " -> 全部系数 = " + out[0]
                + "（期望 " + (mu == 0 ? 11 : 22) + "）");
        }

        // ---- 5. 自举密钥体积（可行性红线）----
        System.out.println("[bootstrap key] d=512 -> "
            + BootstrapKey.describeBytes(p, 512));

        // ---- 6. 换到论文规模参数（15 素数 / 451 位）----
        RingParams paper = RingParams.paperParams(16384, 15);
        System.out.println("[paper params] " + paper.describe());
        System.out.println("[paper params] bootstrap key d=512 -> "
            + BootstrapKey.describeBytes(paper, 512));
    }

    private static long[][] addP(RingParams p, long[][] x, long[][] y) {
        long[][] r = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                r[k][i] = RingOps.addMod(x[k][i], y[k][i], p.primes[k]);
            }
        }
        return r;
    }

    private static long[][] subP(RingParams p, long[][] x, long[][] y) {
        long[][] r = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                r[k][i] = RingOps.subMod(x[k][i], y[k][i], p.primes[k]);
            }
        }
        return r;
    }
}
