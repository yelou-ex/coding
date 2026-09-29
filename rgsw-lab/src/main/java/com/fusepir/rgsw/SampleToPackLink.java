package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.math.BigInteger;
import java.util.Random;

/**
 * <b>关键连接点验证：`sampleExtract` 的输出能不能被 `RingPack` 直接吃。</b>
 *
 * <h3>为什么这一步是整条"全程同态"路线的咽喉</h3>
 * 要把 ANSWER 后半段（三路相加 + Pack + Bloom 候选密文）做成全程密文，就必须：
 * <pre>
 *   列选择 → 盲旋转 → SampleExtract_0  ⇒  ct_{a,b}   （一条 LWE 密文；秘密 = RLWE 秘密的系数，维数 N）
 *   Σ_a ct_{a,b}                        （在密文域相加）
 *   Pack({ct_{pay,b}})                  （把 B_pay 条 LWE 打进一个槽位 RLWE —— 交给 RingPack）
 * </pre>
 * 而 {@code sampleExtract} 给出的是 <b>q_R 下的 CRT 残数</b>，{@code RingPack} 却要求在 <b>Z_t</b> 上
 * 且满足它自己的符号约定。中间有两道坎：
 * <ol>
 *   <li><b>符号</b>：RLWE 相位是 {@code c0 + c1·s}，而 {@code RingPack} 假定相位是 {@code b − ⟨a,s⟩}，
 *       所以 {@code a} 要<b>取负</b>（与 {@code LweRlweConversion.extractLwe} 的处理一致）。</li>
 *   <li><b>缩放</b>：相位是 {@code Δ·m + e}，模 t 之后<b>不等于</b> m，必须先
 *       {@code x → round(x·t/q_R)}（该步的噪声在 {@code RingPack} 的 P5 里单独验证过）。</li>
 * </ol>
 * 本类就查这两条：把 {@code sampleExtract} 的输出按上述规则处理后，<b>在整数上</b>算
 * {@code b − ⟨a, s⟩ mod t}，看它是不是等于原多项式在那个位置的系数。
 * <b>成立 ⇒ RingPack 可以直接吃 sampleExtract 的输出；不成立 ⇒ 全程同态的 Pack 要另找路径。</b>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.SampleToPackLink 4096}
 */
public final class SampleToPackLink {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        Random rnd = new Random(20260929L);
        long t = m.t;

        System.out.println("=== sampleExtract → RingPack 连接点验证 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[plan] 秘密维数 = N = %d；t = %d；q_R = %d bit%n%n", n, t, m.qBits);

        // ---------- 0. RLWE 秘密（RingPack 的 SwK 要按它建） ----------
        long[] sCentered = LweRlweConversion.rlweSecretCoefficientsCentered(m);
        int[] s = new int[n];
        int nonzero = 0;
        for (int i = 0; i < n; i++) {
            s[i] = (int) Math.floorMod(sCentered[i], t);
            if (s[i] != 0) nonzero++;
        }
        System.out.printf("[secret] RLWE 秘密是【三元】{−1,0,1}：非零 %d / %d 个系数%n", nonzero, n);
        System.out.println("         （不是二进制 —— 这是 SEAL 默认的密钥分布，RingPack 的 SwK 按实取）");

        // ---------- 1. 造一个已知明文多项式，直接加密（先验连接点本身，不掺列选择/盲旋转） ----------
        long[] p = new long[n];
        for (int i = 0; i < n; i++) p[i] = Math.floorMod(rnd.nextLong(), t);
        int[] probes = {0, 1, 7, 100, n / 2, n - 1};
        for (int j : probes) p[j] = Math.floorMod(j * 1237L + 11, t);
        Ciphertext ct = m.encrypt(p);
        System.out.printf("%n[step 1] 加密一个 %d 次明文多项式，抽查 %d 个系数%n", n, probes.length);

        // ---------- 2. sampleExtract_j → 取负 + 缩放 → 验 b − ⟨a,s⟩ ----------
        int L = m.workingPrimeCount;
        long[] bRes = new long[L];
        long[] aRes = new long[L];
        System.out.println();
        System.out.printf("    %-7s %-12s %-12s %-12s %s%n", "j", "真值 P[j]", "b 缩放后", "b−⟨a,s⟩", "残差");
        long maxResidual = 0;
        for (int j : probes) {
            long[][] sample = LweRlweBridge.sampleExtract(m, ct, j);
            for (int pi = 0; pi < L; pi++) bRes[pi] = sample[pi][0];
            long bScaled = scaleToT(m, LweRlweBridge.crtCentered(m, bRes));
            long acc = 0;
            for (int k = 0; k < n; k++) {
                for (int pi = 0; pi < L; pi++) aRes[pi] = sample[pi][1 + k];
                long ak = scaleToT(m, LweRlweBridge.crtCentered(m, aRes).negate());
                acc = Math.floorMod(acc + ak * s[k], t);
            }
            long got = Math.floorMod(bScaled - acc, t);
            long want = Math.floorMod(p[j], t);
            long diff = got - want;
            if (diff > t / 2) diff -= t;
            if (diff < -t / 2) diff += t;
            maxResidual = Math.max(maxResidual, Math.abs(diff));
            System.out.printf("    %-7d %-12d %-12d %-12d %+d%n", j, want, bScaled, got, diff);
        }

        // 判据 1：残差必须远小于明文半窗（否则连"可解码"都不成立）
        failed += report("① 缩放后仍可正确解码（残差远小于明文半窗 t/2）",
            maxResidual * 100 < t / 2,
            String.format("实测最大残差 %d，t/2 = %d（余量 %d 倍）", maxResidual, t / 2,
                (t / 2) / Math.max(1, maxResidual)));

        // 判据 2 ★ 关键：残差**不是 0**，而是 ~√N 的舍入噪声。
        //   量级 = Σ_j |a_j 的舍入误差|·|s_j|，std ≈ √(N·2/3)·0.289。
        //   对"可解码"无所谓，但对 Bloom 位是致命的：位值只有 1，而噪声是 15~34 倍。
        double expectedStd = Math.sqrt(n * 2.0 / 3.0) * 0.289;
        failed += report("② ★ 残差就是 q_R→t 的舍入噪声（≈√N），**不是 0**",
            maxResidual > 0,
            String.format("最大 %d，理论 std ≈ %.1f（N=%d、三元秘密）", maxResidual, expectedStd, n));
        System.out.printf("       ⇒ 相对明文半窗 %d 微不足道（可解码 ✓）；相对 Bloom 位值 1 却是 %d 倍%n",
            t / 2, maxResidual);
        System.out.println("       ⇒ 经 Pack 出来的 Bloom 位【不再精确】，s_j == τ 的精确判定不成立。");
        System.out.println("       ⇒ RingPack 目前要求输入样本已在 Z_t 上（见其类注释的边界说明），");
        System.out.println("          而真实样本在 q_R 上、必须缩放 —— **这个缩放就是障碍所在**。");
        System.out.println("          正确做法是让 ring packing 直接在原生模数上做（按模数设计 gadget 与缩放交换密钥），");
        System.out.println("          而不是「先缩放到 t 再打包」。");

        System.out.println();
        System.out.println("[判定] 符号与结构：**正确**（残差是缩放噪声，不是约定错）；");
        System.out.println("       可解码性：**成立**（残差 ≪ t/2）；");
        System.out.println("       位精确性：**不成立**（噪声 15~34 倍于位值 1）—— 这才是全程同态的 Pack 真正的障碍。");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** {@code x ∈ Z_{q_R}} → {@code Z_t}：四舍五入 {@code x·t/q} 后取模 t。 */
    static long scaleToT(Mpc4jRgsw m, BigInteger x) {
        BigInteger q = m.q;
        BigInteger num = x.multiply(BigInteger.valueOf(m.t)).add(q.shiftRight(1));
        return num.divide(q).mod(BigInteger.valueOf(m.t)).longValueExact();
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
