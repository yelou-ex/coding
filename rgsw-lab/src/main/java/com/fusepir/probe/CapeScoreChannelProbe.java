package com.fusepir.probe;


import com.fusepir.prim.*;
import com.fusepir.bloom.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>选型探针：Bloom 打分那条信道该用哪个明文模数？</b>
 *
 * <h3>为什么需要它</h3>
 * 现状是两套并存的 SEAL：
 * <ul>
 *   <li><b>native</b>（{@code blindrotate.dll}，真 SEAL 4.0.0）—— 跑 ANSWER 的
 *       列选择 / 盲旋转 / SampleExtract，明文模数取自库里的 {@code meta.plainModulus}
 *       （本库是 <b>t = 2³²</b>）；</li>
 *   <li><b>Java</b>（{@code lib/mpc4j-crypto-fhe-seal.jar}）—— {@link BloomScoring}
 *       的 {@code CtCtMul} + 折叠在这里做，而它用 <b>BatchEncoder</b>（槽位编码）。</li>
 * </ul>
 * BatchEncoder 要求明文模数 {@code t} 满足 {@code t ≡ 1 (mod 2N)}（NTT 需要 2N 次单位根）。
 * 而 {@code t = 2³²} <b>不是素数、更不满足这个同余</b> ⇒ 直觉上这套 Java 打分只能跑在
 * {@code t = 65537}（= 1 + 2¹⁶，且 65537 是素数，2N | t−1 对 N ≤ 32768 都成立）。
 *
 * <p>本探针就是把这个"直觉"变成实测：分别在 {@code t = 2³²} 与 {@code t = 65537} 下
 * 试着构造上下文、做一次 BatchEncoder 编解码 + 编密文 + 解密，并把耗时打出来。
 * <b>结论直接决定 {@link BloomScoring} 能不能挂到 demo 服务上、以及要不要求服务换 t。</b>
 *
 * <h3>还要测的第二件事：Galois 密钥有多贵</h3>
 * 打分需要 {@code log₂N} 个步长的 Galois 密钥（{@link BloomScoring#galoisKeysFor}）。
 * 这是 SETUP 的一次性成本，但它决定"服务启动要多等多久"。一并量出来。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeScoreChannelProbe 8192}
 */
public final class CapeScoreChannelProbe {

    private CapeScoreChannelProbe() {
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        System.out.println("=== Bloom 打分信道选型探针 ===");
        System.out.printf("[N] %d%n%n", n);

        tryT(n, 4294967296L, "库里的 t（native 路径用的）");
        System.out.println();
        tryT(n, 65537L, "BatchEncoder 友好（1 + 2^16，素数）");

        System.out.println();
        System.out.println("=== 探针结束 ===");
    }

    private static void tryT(int n, long t, String why) {
        System.out.printf("---------------- t = %d  (%s) ----------------%n", t, why);
        Mpc4jRgsw m;
        long t0 = System.nanoTime();
        try {
            m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        } catch (Throwable e) {
            System.out.printf("  [构造失败] %s%n", e);
            return;
        }
        System.out.printf("  [context] %.0f ms  %s%n",
            (System.nanoTime() - t0) / 1e6, m.describe());

        // ---- BatchEncoder 能不能用 ----
        BatchEncoder be;
        int slots;
        try {
            be = new BatchEncoder(m.context);
            slots = be.slotCount();
        } catch (Throwable e) {
            System.out.printf("  [BatchEncoder 构造失败] %s%n", e);
            System.out.println("  ⇒ 该 t 下**无法做槽位域打分**（CtCtMul + 折叠需要 BatchEncoder）");
            return;
        }
        System.out.printf("  [slots] %d%n", slots);
        long[] want = new long[slots];
        for (int i = 0; i < slots; i += 7) {
            want[i] = 1;
        }
        long tau = 0;
        for (long v : want) {
            tau += v;
        }
        try {
            Plaintext pt = new Plaintext();
            be.encode(want, pt);
            long[] back = new long[slots];
            be.decode(pt, back);
            int bad = 0;
            for (int i = 0; i < slots; i++) {
                if (back[i] != want[i]) {
                    bad++;
                }
            }
            System.out.printf("  [encode/decode] 失配槽 %d / %d  %s%n",
                bad, slots, bad == 0 ? "OK" : "✗ 编码不可用");
        } catch (Throwable e) {
            System.out.printf("  [encode/decode 抛异常] %s%n", e);
            return;
        }

        // ---- 编密文 → 解密，确认槽位域真的能来回 ----
        try {
            long t1 = System.nanoTime();
            Ciphertext ct = BloomScoring.encryptBloomVector(m, want);
            System.out.printf("  [encrypt] %.0f ms%n", (System.nanoTime() - t1) / 1e6);
            long got = BloomScoring.decodeScore(m, ct);
            System.out.printf("  [decrypt] 槽0 = %d（期望 %d）%n", got, want[0]);
        } catch (Throwable e) {
            System.out.printf("  [加密/解密抛异常] %s%n", e);
            return;
        }

        // ---- Galois 密钥成本 + 打分往返 ----
        try {
            long t2 = System.nanoTime();
            GaloisKeys gk = BloomScoring.galoisKeysFor(m);
            double keyMs = (System.nanoTime() - t2) / 1e6;
            System.out.printf("  [galois] %.0f ms（%d 个步长）%n",
                keyMs, Integer.numberOfTrailingZeros(n));

            Ciphertext qBF = BloomScoring.encryptBloomVector(m, want);
            Ciphertext ctBF = BloomScoring.encryptBloomVector(m, want);
            long t3 = System.nanoTime();
            Ciphertext score = BloomScoring.bloomScore(m, gk, qBF, ctBF);
            double scoreMs = (System.nanoTime() - t3) / 1e6;
            long got = BloomScoring.decodeScore(m, score);
            System.out.printf("  [score] %.0f ms，得分 = %d（期望 τ = %d）  %s%n",
                scoreMs, got, tau, got == tau ? "OK ✓" : "✗ 不等于 τ");
        } catch (Throwable e) {
            System.out.printf("  [galois/score 抛异常] %s%n", e);
        }
    }
}
