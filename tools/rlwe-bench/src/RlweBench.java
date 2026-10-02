import com.fusepir.rlwe.*;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Encryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Evaluator;
import edu.alibaba.mpc4j.crypto.fhe.seal.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.Modulus;

import java.math.BigInteger;
import java.util.Random;

/**
 * RLWE 效率对照基准：本实现 vs MPC4J（mpc4j-crypto-fhe-seal）。
 *
 * <p>比什么：**"密文 × 明文多项式"** 这一次操作。两侧都做同样的事——
 * 对密文的两个分量各做一次 Z_q[X]/(X^N+1) 上的负循环乘法。
 *
 * <p>为什么这样比才公平：
 * MPC4J 的 `Evaluator.multiplyPlain(ct, pt, dst)` 内部就是每个分量各一次 NTT 乘法；
 * 本实现的等价操作是 `RingOps.mul(c0, ptPoly)` + `RingOps.mul(c1, ptPoly)`。
 * 两者都不含重线性化（乘明文不产生三元密文），所以可以直接比。
 *
 * <p>参数对齐：同为 N=8192、t=65537、系数模数总位宽约 218 位。
 * 一个不对等之处：MPC4J 用 5 个约 44 位素数，本实验层素数 &lt; 2^31，
 * 所以用 7 个 31 位素数凑同等总位宽 —— 素数个数多 40%，对我们是**不利**的。
 */
public final class RlweBench {

    private static final int N = 8192;
    private static final long T = 65537;
    private static final int WARMUP = 3;
    private static final int REPS = 20;

    public static void main(String[] args) {
        System.out.println("=== RLWE efficiency benchmark: this implementation vs MPC4J ===");
        System.out.println("N=" + N + ", t=" + T + ", warmup=" + WARMUP + ", reps=" + REPS);
        System.out.println();

        double mpc4jMs = benchMpc4j();
        double mineMs = benchMine();

        System.out.println();
        System.out.println("-------------------------------------------------------");
        System.out.printf("MPC4J   ciphertext x plaintext : %9.3f ms%n", mpc4jMs);
        System.out.printf("this    ciphertext x plaintext : %9.3f ms%n", mineMs);
        System.out.printf("ratio   (this / MPC4J)         : %9.2fx%n", mineMs / mpc4jMs);
        System.out.println("-------------------------------------------------------");
    }

    // ---------------- MPC4J 侧 ----------------
    private static double benchMpc4j() {
        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        parms.setPolyModulusDegree(N);
        parms.setCoeffModulus(CoeffModulus.bfvDefault(N));
        parms.setPlainModulus(new Modulus(T));
        SealContext context = new SealContext(parms);
        if (!context.isParametersSet()) {
            throw new IllegalStateException("MPC4J params invalid: " + context.parametersErrorMessage());
        }
        System.out.println("[MPC4J] N=" + N + ", coeff modulus bits="
            + context.keyContextData().totalCoeffModulusBitCount()
            + ", primes=" + parms.coeffModulus().length);

        KeyGenerator keyGen = new KeyGenerator(context);
        SecretKey sk = keyGen.secretKey();
        Encryptor encryptor = new Encryptor(context, sk);
        Evaluator evaluator = new Evaluator(context);

        Random rnd = new Random(1);
        long[] coeffs = new long[N];
        for (int i = 0; i < N; i++) {
            coeffs[i] = Math.floorMod(rnd.nextLong(), T);
        }
        Plaintext plain = new Plaintext(coeffs);
        Ciphertext ct = new Ciphertext();
        encryptor.encryptSymmetric(plain, ct);

        Ciphertext dst = new Ciphertext();
        for (int i = 0; i < WARMUP; i++) {
            evaluator.multiplyPlain(ct, plain, dst);
        }
        long t0 = System.nanoTime();
        for (int i = 0; i < REPS; i++) {
            evaluator.multiplyPlain(ct, plain, dst);
        }
        long dt = System.nanoTime() - t0;
        return dt / 1e6 / REPS;
    }

    // ---------------- 本实现侧 ----------------
    private static double benchMine() {
        RingParams p = benchParams(7); // 7 x 31 bit ≈ 217 bit，与 MPC4J 的 218 bit 对齐
        System.out.println("[mine]  " + p.describe());
        System.out.println("[mine]  ntt=" + p.nttEnabled());

        Random rnd = new Random(1);
        RlweKey key = new RlweKey(p, rnd);
        long[] m = new long[N];
        for (int i = 0; i < N; i++) {
            m[i] = Math.floorMod(rnd.nextLong(), T);
        }
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);

        long[] pt = new long[N];
        for (int i = 0; i < N; i++) {
            pt[i] = Math.floorMod(rnd.nextLong(), T);
        }
        long[][] ptPoly = RlweOps.toPrimePoly(p, pt);

        for (int i = 0; i < WARMUP; i++) {
            RingOps.mul(ct.c0, ptPoly, p);
            RingOps.mul(ct.c1, ptPoly, p);
        }
        long t0 = System.nanoTime();
        for (int i = 0; i < REPS; i++) {
            RingOps.mul(ct.c0, ptPoly, p);
            RingOps.mul(ct.c1, ptPoly, p);
        }
        long dt = System.nanoTime() - t0;
        return dt / 1e6 / REPS;
    }

    /** 基准专用参数：primeCount 个 31 位 NTT 友好素数 */
    private static RingParams benchParams(int primeCount) {
        long[] primes = new long[primeCount];
        long cursor = 0;
        for (int i = 0; i < primeCount; i++) {
            primes[i] = NttContext.findPrime(31, N, cursor);
            cursor = primes[i] - (1L << 30) + 1;
        }
        BigInteger q = BigInteger.ONE;
        for (long v : primes) {
            q = q.multiply(BigInteger.valueOf(v));
        }
        return new RingParams("bench", N, primes, T, 1 << 16,
            RingParams.autoLevels(1 << 16, q), 4);
    }
}
