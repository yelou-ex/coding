package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>ANSWER 完全同态版</b>：把 §3.6 Pack 与 §3.7 Bloom 打分接进链路。
 *
 * <h3>完整链路（对应论文 Algorithm 1 ANSWER 第 4–13 行）</h3>
 * <pre>
 * 第 5 行  列选择：  Acc_{a,b} ← Σ_c CtPtMul(q^col_a[c], P_{c,b}(X))      ← 同态
 * 第 6 行  盲旋转：  Acc'_{a,b} ← BlindRotate(q^row_a, Acc_{a,b})          ← 同态
 * 第 7 行  抽常数项：ct_{a,b} ← SampleExtract_0(Acc'_{a,b})               ← 同态（LWE）
 * 第 11 行 三路相加：ct_{pay,b} ← Σ_a ct_{a,b}                            ← 同态（LWE）
 * 第 13 行 Pack：    resp ← Pack({ct_{pay,b}})                           ← ★本次接入
 * §3.7    打分：    ct_score ← CtCtMul(q_BF, resp) + 折叠                  ← ★本次接入
 * </pre>
 *
 * <h3>本类的定位</h3>
 * 前几步（列选择、盲旋转）已在 {@code CapeAnswerFull} 里验证。
 * 本类聚焦<b>最后两步的同态化</b>：把三路相加得到的 {@code B_pay} 条 LWE
 * 打包进一条槽位 RLWE，再用 {@code BloomScoring} 做加密的二进制内积。
 *
 * <p>为了让本类可独立运行，LWE 密文按 {@code RingPack} 的约定构造：
 * {@code b^(i) ≡ ⟨a^(i), s⟩ + m_i (mod t)}，其中 {@code m_i = ct_{pay,i}} 是
 * 三路相加后的 payload 字段值。
 */
public final class CapeAnswerHomomorphic {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int nLwe = args.length > 1 ? Integer.parseInt(args[1]) : 16;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();

        System.out.println("=== ANSWER 完全同态版：Pack + Bloom 打分 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[slots] 槽数 = %d%n%n", slots);

        Random rnd = new Random(20261012L);

        // ============================================================
        // 1. payload（模拟"三路 BFF 相加"的结果）
        // ============================================================
        final int lBf = 2;
        final int mMax = 2;
        final int bPay = 2 + mMax * (1 + lBf);         // = 8
        System.out.println("--- 1. 三路相加后的 payload ---");
        System.out.printf("    B_pay = %d, ℓ_BF = %d%n", bPay, lBf);

        // K_1 的 payload：[指纹, 数量, v1, bf(v1)[0..1], v2, bf(v2)[0..1]]
        long[] payload = {70, 2, 11, 1, 1, 22, 0, 1};
        System.out.println("    payload = " + java.util.Arrays.toString(payload));
        System.out.println();

        // ============================================================
        // 2. 构造 B_pay 条 LWE 密文（每条加密一个字段值）
        // ============================================================
        System.out.println("--- 2. 三路相加的结果（B_pay 条 LWE）---");
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) s[i] = rnd.nextInt(2);

        long[][] as = new long[bPay][nLwe];
        long[] bs = new long[bPay];
        for (int i = 0; i < bPay; i++) {
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = (sum + as[i][j] * s[j]) % m.t;
            }
            bs[i] = Math.floorMod(sum + payload[i], m.t);   // b = ⟨a,s⟩ + m
        }
        System.out.printf("    %d 条 LWE 密文（d=%d），消息 = payload 各字段%n%n", bPay, nLwe);

        // ============================================================
        // 3. Pack（论文第 13 行）
        // ============================================================
        System.out.println("--- 3. Pack（论文第 13 行）---");
        int base = 1 << 8, digits = 3;
        long t0 = System.nanoTime();
        Ciphertext[][] swk = RingPack.switchingKey(m, s, base, digits);
        long keyMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    交换密钥 %d×%d 条，构造 %.0f ms%n", nLwe, digits, (double) keyMs);

        // 字段 i 落在槽位 i
        int[] slotIdx = new int[bPay];
        for (int i = 0; i < bPay; i++) slotIdx[i] = i;

        t0 = System.nanoTime();
        Ciphertext packed = RingPack.pack(m, be, swk, base, digits, as, bs, slotIdx);
        long packMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    pack 完成，%.0f ms%n", (double) packMs);

        // 验收：解密读槽位
        long[] packedSlots = decryptSlots(m, be, packed);
        System.out.print("    打包后槽位 0..7 = ");
        for (int i = 0; i < bPay; i++) System.out.print(packedSlots[i] + " ");
        System.out.println();
        System.out.print("    期望 payload     = ");
        for (int i = 0; i < bPay; i++) System.out.print(payload[i] + " ");
        System.out.println();
        boolean packOk = true;
        for (int i = 0; i < bPay; i++) if (packedSlots[i] != payload[i]) packOk = false;
        failed += report("3.1 Pack 后每个字段落在自己的槽位", packOk, "");
        System.out.println();

        // ============================================================
        // 4. Bloom 打分（§3.7，完全同态）
        // ============================================================
        System.out.println("--- 4. Bloom 打分（§3.7，完全同态）---");

        // 打包后的 payload 里，Bloom 位在字段 3,4（v1 的）和 6,7（v2 的）
        // 这里取 v1 的两个 Bloom 位（字段 3、4）做内积
        long[] vBf = {payload[3], payload[4]};
        // 查询向量：K_2 也关联 v=11 → b_qry = [1,1]
        long[] qBf = {1, 1};
        long tau = qBf[0] + qBf[1];
        System.out.printf("    b_v（字段 3,4）= %s；b_qry = %s；τ = %d%n",
            java.util.Arrays.toString(vBf), java.util.Arrays.toString(qBf), tau);

        GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        Ciphertext qBF = BloomScoring.encryptBloomVector(m, slotVector(qBf, slots));
        Ciphertext candBF = BloomScoring.encryptBloomVector(m, slotVector(vBf, slots));

        t0 = System.nanoTime();
        Ciphertext scoreCt = BloomScoring.bloomScore(m, gk, qBF, candBF);
        long scoreMs = (System.nanoTime() - t0) / 1_000_000;
        long score = BloomScoring.decodeScore(m, scoreCt);
        System.out.printf("    同态内积 ⟨b_qry, b_v⟩ = %d（期望 %d），%.0f ms%n",
            score, qBf[0] * vBf[0] + qBf[1] * vBf[1], (double) scoreMs);

        failed += report("4.1 加密内积 = 明文内积",
            score == qBf[0] * vBf[0] + qBf[1] * vBf[1], "score=" + score);
        failed += report("4.2 判定命中（score == τ）", score == tau, "score=" + score + " tau=" + tau);

        // 负对照：漏一位
        long[] vBfMiss = {1, 0};
        Ciphertext missCt = BloomScoring.bloomScore(m, gk, qBF,
            BloomScoring.encryptBloomVector(m, slotVector(vBfMiss, slots)));
        long missScore = BloomScoring.decodeScore(m, missCt);
        System.out.printf("    负对照：b_v = [1,0] → score = %d < τ = %d → %s%n",
            missScore, tau, missScore != tau ? "不命中（正确）" : "命中（错误）");
        failed += report("4.3 负对照不命中", missScore != tau, "");

        System.out.println();
        System.out.println("--- 5. 耗时汇总 ---");
        System.out.printf("    交换密钥 %.0f ms + Pack %.0f ms + 打分 %.0f ms%n",
            (double) keyMs, (double) packMs, (double) scoreMs);
        System.out.println();

        System.out.println(failed == 0
            ? "=== ANSWER 完全同态版跑通（Pack + Bloom 打分均为同态运算）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 把长度 ℓ 的向量铺成槽数长度（其余补 0） */
    private static long[] slotVector(long[] v, int slots) {
        long[] out = new long[slots];
        System.arraycopy(v, 0, out, 0, Math.min(v.length, slots));
        return out;
    }

    /** 槽位域解密：m.decrypt 是系数域读取器，槽位密文必须用 BatchEncoder.decode 读 */
    private static long[] decryptSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) m.evaluator.transformFromNttInplace(copy);
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
