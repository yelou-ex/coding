package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.bloom.BloomScoring;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.prim.Mpc4jRgsw;
import com.fusepir.prim.RingPack;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>真实载荷（{@code B_pay} 个 16-bit limb）过 Pack，再过打分器 —— 判据实验。</b>
 *
 * <h3>为什么要这个探针</h3>
 * {@code RingPack} 的 P1/P2 打的是 <b>1-bit 消息</b>、{@code B_pay = 16}；
 * {@code CapeAnswerHomomorphic} 打的是 <b>1-bit 消息</b>、{@code B_pay = 8}。
 * 两者的共同缺口是：**真实载荷是 16-bit limb，而且有 61 个**（MAP §18.5）。
 * 本类只问三件事，每件都必须有正/负对照：
 * <ol>
 *   <li><b>搬运</b>：61 个 {@code Z_t} 里的 limb（含最大值 {@code t−1}）能否一个不差地进槽；</li>
 *   <li><b>可算</b>：哪些槽**允许**参与同态内积，哪些只是"被搬运"；</li>
 *   <li><b>折叠够不够得着</b>：论文形状的 {@code ⌈log2 ℓ_BF⌉} 轮折叠，能不能覆盖这些槽。</li>
 * </ol>
 *
 * <h3>载荷布局（按 {@link FusePirSetup} 的算式，不手写下标）</h3>
 * <pre>
 *   t = 65537, ℓ_BF = 18, m = 3 个值
 *   fpSlots  = fpSlots(t)        = 3        (40 bit 指纹 / 每槽 16 bit)
 *   perValue = perValue(ℓ_BF)    = 1 + 18 = 19
 *   B_pay    = payloadBpay(3,3,19) = 3 + 1 + 3·19 = 61
 *   槽布局： [fp 0..2] [m_i 3] [v_0 4][bv_0 5..22] [v_1 23][bv_1 24..41] [v_2 42][bv_2 43..60]
 * </pre>
 * ⇒ <b>三个 Bloom 段分别从槽 5 / 24 / 43 开始</b>，这一点是本探针的核心。
 *
 * <h3>判据（跑之前先说清楚，免得事后编解释）</h3>
 * <ol>
 *   <li><b>搬运</b>应当精确 —— 与 {@code RingPack} P5a 同口径（打包不额外引误差）；</li>
 *   <li><b>只有二进制段可算</b>：槽里放 16-bit 值时内积 {@code Σ q_i v_i} 在
 *       {@code t = 65537} 上会<b>回绕</b>。判据是「回绕后的值 == 真值 mod t」，
 *       负对照是「每个 limb 自己搬运是精确的」⇒ 结论必须是
 *       <b>单个 limb 没问题、求和有问题</b>，不能含糊成"16-bit 不能打包"；</li>
 *   <li><b>折叠轮数要按"参与槽的最高下标"算，不能按 {@code ℓ_BF} 算。</b>
 *       {@code ⌈log2 18⌉ = 5} 轮只够到槽 {@code [0,32)}，而 {@code bv_1} 的高位在槽
 *       39..41、{@code bv_2} 全段在槽 43..60 ⇒ <b>会静默漏算</b>。
 *       本探针把这个漏算当<b>断言</b>钉住（P4/P6 期望"错成 0"）：
 *       哪天有人修好了折叠，这两条会变红，提醒他更新结论。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.PackLimbPayloadTest 8192 16}
 */
public final class PackLimbPayloadTest {

    private static int failed = 0;

    /** 命中查询：{@code bv} 的 1 都在段内 {@code {15,16,17}} 上。 */
    private static long[] matchQuery(int slots, int base) {
        long[] q = new long[slots];
        for (int p = 15; p <= 17; p++) {
            q[base + p] = 1;
        }
        return q;
    }

    /** 不命中查询：该段只有 {@code {15,16,17}} 是 1，查 {@code {0,1,2}} ⇒ 应当得 0。 */
    private static long[] missQuery(int slots, int base) {
        long[] q = new long[slots];
        for (int p = 0; p <= 2; p++) {
            q[base + p] = 1;
        }
        return q;
    }

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        final int nLwe = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        final long t = 65537L;
        final int lBf = 18;
        final int mCount = 3;

        final int fpSlots = FusePirSetup.fpSlots(t);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);

        Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        final int slots = be.slotCount();

        System.out.println("=== 真实载荷（16-bit limb x B_pay）过 Pack 再过打分器 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[layout] t=%d, lBf=%d, m=%d, fpSlots=%d, perValue=%d, B_pay=%d, slots=%d%n%n",
            t, lBf, mCount, fpSlots, perValue, bPay, slots);

        // ============ P0 布局常量对账（把 §18.5 那张表变成断言）============
        System.out.println("--- P0 载荷布局常量（对 §18.5 / FusePirSetup）---");
        int p0 = 0;
        p0 += sub("P0.1", "fpSlots(65537) == 3", fpSlots == 3);
        p0 += sub("P0.2", "perValue(18) == 19", perValue == 19);
        p0 += sub("P0.3", "B_pay == 61", bPay == 61);
        p0 += sub("P0.4", "B_pay <= slots", bPay <= slots);
        report("P0 布局常量与 §18.5 一致", p0 == 0, String.format("%d 项未达成", p0));

        // ============ 构造载荷 ============
        final String kw = "cape-pack-limb-payload-2026";
        long[] payload = new long[bPay];
        long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);
        for (int i = 0; i < fpSlots; i++) {
            payload[i] = fpD[i];
        }
        payload[FusePirSetup.countOffset(fpSlots)] = mCount;
        // 值：前两个 < t/2，第三个取 t-1（最大可表示的 limb）
        long[] vals = {30000L, 31000L, t - 1};
        for (int j = 0; j < mCount; j++) {
            payload[FusePirSetup.valueOffset(fpSlots, j, perValue)] = vals[j];
            int bo = FusePirSetup.bloomOffset(fpSlots, j, perValue);
            for (int p = 15; p <= 17; p++) {
                payload[bo + p] = 1;                    // 每段只有 {15,16,17} 是 1
            }
        }
        int[] segBase = new int[mCount];
        for (int j = 0; j < mCount; j++) {
            segBase[j] = FusePirSetup.bloomOffset(fpSlots, j, perValue);
        }
        System.out.printf("%n[payload] fp 三段 = %s（合起来 40 bit 的指纹）%n", Arrays.toString(fpD));
        System.out.printf("[payload] 值 = %s；Bloom 段起点 = %s（每段只在 +15..17 处置 1）%n%n",
            Arrays.toString(vals), Arrays.toString(segBase));

        // ============ 造 B_pay 条 LWE 密文并 Pack ============
        Random rnd = new Random(20261015L);
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        final int base = 1 << 8;
        final int digits = 3;
        long[][] as = new long[bPay][nLwe];
        long[] bs = new long[bPay];
        for (int i = 0; i < bPay; i++) {
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), t);
                sum = Math.floorMod(sum + as[i][j] * s[j], t);
            }
            bs[i] = Math.floorMod(sum + payload[i], t);
        }
        int[] slotIdx = new int[bPay];
        for (int i = 0; i < bPay; i++) {
            slotIdx[i] = i;                            // 字段 i -> 槽 i，与 CapeAnswerHomomorphic 同口径
        }
        long t0 = System.nanoTime();
        Ciphertext[][] swk = RingPack.switchingKey(m, s, base, digits);
        Ciphertext packed = RingPack.pack(m, be, swk, base, digits, as, bs, slotIdx);
        long packMs = (System.nanoTime() - t0) / 1_000_000;

        long[] got = decodeSlots(m, be, packed);
        System.out.println("--- P1 Pack 的搬运精度（16-bit limb，含 t-1）---");
        int wrong = 0;
        StringBuilder firstBad = new StringBuilder();
        for (int i = 0; i < bPay; i++) {
            if (got[i] != payload[i]) {
                if (wrong < 4) {
                    firstBad.append(String.format(" [slot%d got=%d want=%d]", i, got[i], payload[i]));
                }
                wrong++;
            }
        }
        int leak = 0;
        for (int i = bPay; i < slots; i++) {
            if (got[i] != 0) {
                leak++;
            }
        }
        report("P1.1 B_pay=61 个 Z_t limb 逐槽精确搬运（错 " + wrong + " 个）", wrong == 0 && leak == 0,
            String.format("%.0f ms；未写入的槽非零 %d 个%s", (double) packMs, leak, firstBad));

        long fpBack = BffSetup.fpFromDigits(got, 0, fpSlots, t);
        report("P1.2 40-bit 指纹经 Pack 往返一致", fpBack == BffSetup.fp(kw),
            String.format("原文=%d 往返=%d", BffSetup.fp(kw), fpBack));

        // ============ P2/P3：可算槽 = 二进制 Bloom 段 ============
        GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        int paperRounds = roundsFor(lBf);
        System.out.printf("%n--- P2/P3 二进制 Bloom 段的内积（论文形状折叠：lBf=%d => %d 轮 => 够到槽 [0,%d)）---%n",
            lBf, paperRounds, 1 << paperRounds);

        long s0 = scorePaper(m, gk, matchQuery(slots, segBase[0]), packed, lBf);
        report("P2 段 0 命中（参与槽 20..22 在 [0,32) 内）=> 得分 = 3", s0 == 3,
            String.format("得分 = %d，期望 3", s0));

        long s0m = scorePaper(m, gk, missQuery(slots, segBase[0]), packed, lBf);
        report("P3 负对照：段 0 换成不命中的查询 => 得分 = 0", s0m == 0,
            String.format("得分 = %d，期望 0（P2 是 3，所以得分确实随查询变）", s0m));

        // ============ P4/P5：折叠够不着 —— 静默漏算 ============
        int hi1 = segBase[1] + 17;
        System.out.printf("%n--- P4/P5 折叠够不着：段 1 的命中位在槽 %d..%d（>= 32）---%n",
            segBase[1] + 15, hi1);
        long s1paper = scorePaper(m, gk, matchQuery(slots, segBase[1]), packed, lBf);
        report("P4 [缺陷断言] 段 1 命中，论文形状折叠仍得 0（槽 39..41 在 [0,32) 之外）",
            s1paper == 0,
            String.format("得分 = %d；真值应为 3 => 漏算被复现（不是噪声，是范围不够）", s1paper));

        long s1deep = scoreReaching(m, gk, matchQuery(slots, segBase[1]), packed, lBf, hi1);
        report("P5 改用 bloomScoreReaching（按最高参与槽 " + hi1 + " 取轮数）=> 正确得 3", s1deep == 3,
            String.format("得分 = %d，期望 3", s1deep));

        long s1small = scoreReaching(m, gk, matchQuery(slots, segBase[1]), packed, lBf, 31);
        report("P5b 负对照：同一方法把最高参与槽谎报成 31 => 必须重现漏算（证明该参数真的在起作用）",
            s1small == 0,
            String.format("得分 = %d，期望 0 —— 若这里也得 3，说明新入口的参数是摆设", s1small));

        int hi2 = segBase[2] + 17;
        System.out.printf("%n--- P6/P7 同理：段 2 的命中位在槽 %d..%d ---%n",
            segBase[2] + 15, hi2);
        long s2paper = scorePaper(m, gk, matchQuery(slots, segBase[2]), packed, lBf);
        report("P6 [缺陷断言] 段 2 命中，论文形状折叠仍得 0（槽 58..60 在 [0,32) 之外）",
            s2paper == 0,
            String.format("得分 = %d；真值应为 3", s2paper));

        long s2deep = scoreReaching(m, gk, matchQuery(slots, segBase[2]), packed, lBf, hi2);
        report("P7 改用 bloomScoreReaching（最高参与槽 " + hi2 + " => 6 轮）=> 正确得 3", s2deep == 3,
            String.format("得分 = %d，期望 3", s2deep));

        long s2small = scoreReaching(m, gk, matchQuery(slots, segBase[2]), packed, lBf, 31);
        report("P7b 负对照：段 2 把最高参与槽谎报成 31 => 同样必须重现漏算", s2small == 0,
            String.format("得分 = %d，期望 0", s2small));

        // ============ P8：16-bit limb 不能进内积（求和回绕）============
        System.out.println();
        System.out.println("--- P8 16-bit limb 进同态内积会回绕（查询权重 3）---");
        long[] vq = new long[slots];
        for (int j = 0; j < mCount; j++) {
            vq[FusePirSetup.valueOffset(fpSlots, j, perValue)] = 1;
        }
        long trueSum = 0;
        for (int j = 0; j < mCount; j++) {
            trueSum += vals[j];
        }
        long vScore = scoreAll(m, gk, vq, packed);
        report("P8 三个 16-bit 值求和：解出的就是真值 mod t，不是真值 => 只有二进制段可进内积",
            vScore == Math.floorMod(trueSum, t) && vScore != trueSum,
            String.format("真值 %d、t=%d、解出 %d（= 真值 mod t = %d）；而 P1 已证明每个 limb 单独搬运"
                + "是精确的 => 结论是「单个 limb 没问题、求和有问题」",
                trueSum, t, vScore, Math.floorMod(trueSum, t)));

        // ============ P9：正确的折叠轮数怎么算 ============
        System.out.println();
        int highest = bPay - 1;
        int needRounds = roundsFor(highest + 1);
        int allRounds = roundsFor(slots / 2) + 1;
        System.out.println("--- P9 折叠轮数 ---");
        System.out.printf("      参与槽最高下标 = %d => 要够到 %d => %d 轮（够到 [0,%d)）%n",
            highest, 1 << needRounds, needRounds, 1 << needRounds);
        System.out.printf("      论文形状（lBf=%d）%d 轮；折满全部槽 %d 轮%n",
            lBf, paperRounds, allRounds);
        report("P9 正确轮数应取 ceil(log2(最高参与槽+1)) = 6 轮，介于论文形状 5 轮与折满 13 轮之间",
            needRounds == 6 && needRounds > paperRounds && needRounds < allRounds,
            String.format("实测 %d 轮 vs 论文 %d 轮 vs 折满 %d 轮", needRounds, paperRounds, allRounds));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（含 2 条缺陷断言：P4/P6 刻意期望漏算发生）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** {@code ceil(log2 x)}：与 {@code BloomScoring.foldSlots} 的轮数算法同口径。 */
    private static int roundsFor(int x) {
        int r = 0;
        for (int step = 1; step < x; step *= 2) {
            ++r;
        }
        return r;
    }

    /** 论文形状的打分：折叠 {@code ⌈log2 lBf⌉} 轮（候选支撑在 {@code [0, lBf)} 时才正确）。 */
    private static long scorePaper(Mpc4jRgsw m, GaloisKeys gk, long[] q, Ciphertext packed, int lBf) {
        return BloomScoring.decodeScore(m,
            BloomScoring.bloomScore(m, gk, BloomScoring.encryptBloomVector(m, q), asCoeff(m, packed), lBf));
    }

    /** 按"最高参与槽"取轮数的打分 —— 候选是 Pack 产物时用这一条。 */
    private static long scoreReaching(Mpc4jRgsw m, GaloisKeys gk, long[] q, Ciphertext packed,
                                      int lBf, int highestSlotInclusive) {
        return BloomScoring.decodeScore(m,
            BloomScoring.bloomScoreReaching(m, gk, BloomScoring.encryptBloomVector(m, q),
                asCoeff(m, packed), highestSlotInclusive));
    }

    /** 折满全部槽的那一版（不知道支撑在哪时的兜底）。 */
    private static long scoreAll(Mpc4jRgsw m, GaloisKeys gk, long[] q, Ciphertext packed) {
        return BloomScoring.decodeScore(m,
            BloomScoring.bloomScore(m, gk, BloomScoring.encryptBloomVector(m, q), asCoeff(m, packed)));
    }

    /** 打包产物是 NTT 形态，而 ct×ct 要求非 NTT 形态 ⇒ 先转回来。 */
    private static Ciphertext asCoeff(Mpc4jRgsw m, Ciphertext packed) {
        Ciphertext cand = new Ciphertext();
        cand.copyFrom(packed);
        if (cand.isNttForm()) {
            m.evaluator.transformFromNttInplace(cand);
        }
        return cand;
    }

    private static long[] decodeSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static int sub(String id, String name, boolean ok) {
        System.out.println("      " + (ok ? "[PASS] " : "[FAIL] ") + id + " " + name);
        return ok ? 0 : 1;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
