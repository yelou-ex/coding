package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.bloom.BloomScoring;
import com.fusepir.fusepir.FusePirPackSlot;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>A1 ANSWER 13 槽位域适配器（{@link FusePirPackSlot}）的自检。</b>
 *
 * <h3>它要证的四件事</h3>
 * <ol>
 *   <li><b>搬运</b>：{@code B_pay} 个字段逐槽落位、精确（含最大 limb {@code t−1}）；</li>
 *   <li><b>打分</b>：Bloom 段能被同态内积算对，<b>且必须走 {@code scoreWithLayout}</b>
 *       —— 论文形状的折叠会静默漏算（负对照，把这条钉住）；</li>
 *   <li><b>两道前置检查会炸</b>：{@code t} 不可批处理（{@code 2^32}）、gadget 覆盖不足；</li>
 *   <li><b>形状不齐会炸</b>：{@code a} 行长度不一、{@code B_pay} 对不上。</li>
 * </ol>
 *
 * <h3>范围</h3>
 * 本探针<b>不</b>碰 FusePIR 主路径（用户指示：只补缺口、不接线）。
 * LWE 样本是<b>合成</b>的（已在 {@code Z_t} 内），所以它验的是<b>适配器本身</b>，
 * 不是 {@code SampleExtract → Pack} 那条链（那条链的开缺口见 MAP §22 第 1 条与 P1-3 第二半）。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirPackSlotTest 8192 16}
 */
public final class FusePirPackSlotTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        final int nLwe = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        final long t = FusePirParams.NATIVE_PLAINTEXT_MODULUS;      // 65537
        final int lBf = 18;
        final int mCount = 3;
        final int base = 1 << 8;
        final int digits = 3;

        final int fpSlots = FusePirSetup.fpSlots(t);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);

        Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);

        System.out.println("=== A1 ANSWER 13 槽位域适配器自检（只补缺口，不接线）===");
        System.out.println("[variant] " + FusePirPackSlot.describe());
        System.out.println("[params ] " + m.describe());
        System.out.printf("[layout ] t=%d（= FusePirParams.NATIVE_PLAINTEXT_MODULUS）、lBf=%d、m=%d、"
            + "fpSlots=%d、perValue=%d、B_pay=%d、slots=%d%n%n",
            t, lBf, mCount, fpSlots, perValue, bPay, be.slotCount());

        // ============ P0 前置检查：可批处理（含 §18.2 那条不可能的参数） ============
        System.out.println("--- P0 「t 必须可批处理」前置检查 ---");
        int p0 = 0;
        p0 += sub("P0.1", "t=65537 在 N=8192 上可批处理（65536 = 4·16384）",
            FusePirPackSlot.isBatchable(65537L, 8192));
        p0 += sub("P0.2", "t=65537 在 N=16384（论文的 N）上也可批处理",
            FusePirPackSlot.isBatchable(65537L, 16384));
        // 负对照：CAPE 演示服务那条通道的载荷模数 —— 槽位选择子根本不存在（MAP §18.2）
        p0 += sub("P0.3", "[负对照] t=2^32 必须被拒（不是素数，且 §18.2 证明选择子不存在）",
            !FusePirPackSlot.isBatchable(1L << 32, 8192));
        p0 += sub("P0.4", "[负对照] t=65537 在 N=4096 上 t-1=65536 是 2N=8192 的倍数 ⇒ 仍可批处理",
            FusePirPackSlot.isBatchable(65537L, 4096));
        p0 += sub("P0.5", "[负对照] t=65539（≈素数但不满足 t≡1 mod 2N）必须被拒",
            !FusePirPackSlot.isBatchable(65539L, 8192));
        report("P0 前置检查按预期放行/拒绝", p0 == 0, String.format("%d 项未达成", p0));

        // ============ 造载荷（用 FusePirSetup 的算式算下标，不手写） ============
        final String kw = "fusepir-packslot-2026";
        long[] payload = new long[bPay];
        long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);
        for (int i = 0; i < fpSlots; i++) {
            payload[i] = fpD[i];
        }
        payload[FusePirSetup.countOffset(fpSlots)] = mCount;
        long[] vals = {30000L, 31000L, t - 1};                  // 含最大可表示 limb
        for (int j = 0; j < mCount; j++) {
            payload[FusePirSetup.valueOffset(fpSlots, j, perValue)] = vals[j];
            int bo = FusePirSetup.bloomOffset(fpSlots, j, perValue);
            for (int p = 15; p <= 17; p++) {
                payload[bo + p] = 1;                            // 每段只有 {15,16,17} 是 1
            }
        }
        int[] segBase = new int[mCount];
        for (int j = 0; j < mCount; j++) {
            segBase[j] = FusePirSetup.bloomOffset(fpSlots, j, perValue);
        }
        System.out.printf("%n[payload] fp = %s；值 = %s；Bloom 段起点 = %s（每段只在 +15..17 置 1）%n%n",
            Arrays.toString(fpD), Arrays.toString(vals), Arrays.toString(segBase));

        // ============ 合成 B_pay 条 Z_t 上的 LWE 样本并打包 ============
        Random rnd = new Random(20261015L);
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        Ciphertext[][] swk = FusePirPackSlot.keyGen(m, s, base, digits);
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

        FusePirPackSlot.Packed packed =
            FusePirPackSlot.pack(m, be, swk, base, digits, mCount, lBf, as, bs);
        System.out.println();
        System.out.println("--- P1 适配器的搬运精度 ---");
        System.out.println("      " + packed);
        System.out.println("      " + FusePirPackSlot.keyCost(m, nLwe, digits));

        long[] got = FusePirPackSlot.decodePayload(m, be, packed, bPay);
        int wrong = 0;
        StringBuilder bad = new StringBuilder();
        for (int i = 0; i < bPay; i++) {
            if (got[i] != payload[i]) {
                if (wrong < 4) {
                    bad.append(String.format(" [槽%d got=%d want=%d]", i, got[i], payload[i]));
                }
                wrong++;
            }
        }
        report(String.format("P1.1 B_pay=%d 个字段逐槽精确（错 %d 个）", bPay, wrong), wrong == 0,
            String.format("最高参与槽 = %d%s", packed.highestSlot(), bad));

        long fpBack = BffSetup.fpFromDigits(got, 0, fpSlots, t);
        report("P1.2 40-bit 指纹经适配器往返一致", fpBack == BffSetup.fp(kw),
            String.format("原文=%d 往返=%d", BffSetup.fp(kw), fpBack));

        // ============ P2/P3 打分：必须走 scoreWithLayout ============
        GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        final int target = 2;                                   // 段 2 起点 43，命中位在槽 58..60
        long[] q = new long[be.slotCount()];
        for (int p = 15; p <= 17; p++) {
            q[segBase[target] + p] = 1;
        }
        System.out.printf("%n--- P2/P3 打分（段 %d 的命中位在槽 %d..%d）---%n",
            target, segBase[target] + 15, segBase[target] + 17);

        long viaLayout = FusePirPackSlot.scoreWithLayout(m, gk, q, packed);
        report("P2 scoreWithLayout 得 3（按最高参与槽 60 取 6 轮折叠）", viaLayout == 3,
            String.format("得分 = %d，期望 3", viaLayout));

        // 负对照：论文形状的 ℓ_BF 轮折叠（只够到槽 31）—— 必须重现漏算
        Ciphertext cand = new Ciphertext();
        cand.copyFrom(packed.ct());
        if (cand.isNttForm()) {
            m.evaluator.transformFromNttInplace(cand);
        }
        long paperFolded = BloomScoring.decodeScore(m, BloomScoring.bloomScore(m, gk,
            BloomScoring.encryptBloomVector(m, q), cand, lBf));
        report("P3 [缺陷断言] 论文形状折叠（lBf=18 ⇒ 5 轮 ⇒ 够到槽 31）必须漏算成 0",
            paperFolded == 0,
            String.format("得分 = %d；真值 3 ⇒ 漏算被复现，证明适配器带上最高参与槽是【必需】的", paperFolded));

        // ============ P4-P7 负对照：坏输入必须炸 ============
        System.out.println();
        System.out.println("--- P4-P7 负对照：坏输入必须炸（而不是静默给垃圾）---");
        int p4 = 0;
        long[][] ragged = new long[bPay][];
        for (int i = 0; i < bPay; i++) {
            ragged[i] = as[i].clone();
        }
        ragged[7] = Arrays.copyOf(as[7], nLwe - 1);             // 一行短一格
        p4 += sub("P4.1", "a 的行长度不齐 ⇒ 必须抛", throwsPack(m, be, swk, base, digits, mCount, lBf, ragged, bs));

        long[] shortBs = Arrays.copyOf(bs, bPay - 1);
        p4 += sub("P4.2", "b 分量条数 ≠ B_pay ⇒ 必须抛", throwsPack(m, be, swk, base, digits, mCount, lBf, as, shortBs));

        // gadget 覆盖：2^8 · 2 = 65536 < 65537（只差 1）—— RingPack 的守卫必须炸
        p4 += sub("P4.3", "gadget 只覆盖 65536 < t ⇒ 必须抛（不是静默截断高位）",
            throwsPack(m, be, swk, base, 2, mCount, lBf, as, bs));

        Ciphertext[][] thinSwk = new Ciphertext[nLwe - 1][];
        System.arraycopy(swk, 0, thinSwk, 0, nLwe - 1);
        p4 += sub("P4.4", "交换密钥行数 < 样本维数 ⇒ 必须抛（少的维数不会报错、只会静默少减）",
            throwsPack(m, be, thinSwk, base, digits, mCount, lBf, as, bs));

        // 上下文混用：拿一个槽数不同的 BatchEncoder 进来（本项目里"两个 t / 两个上下文"
        // 是登记过的真实危险源，见缺陷总表 D11）—— 必须炸，而不是按错误的 N 去编码选择子
        Mpc4jRgsw other = null;
        BatchEncoder beOther = null;
        try {
            other = new Mpc4jRgsw(n / 2, t, 0, 1 << 16);
            beOther = new BatchEncoder(other.context);
        } catch (RuntimeException e) {
            System.out.println("      [P4.5 无法构造对照上下文] " + e);
        }
        if (beOther == null) {
            p4 += 1;
        } else {
            p4 += sub("P4.5", "[负对照] 槽数 " + beOther.slotCount() + " ≠ 环维度 " + n
                + " 的 BatchEncoder ⇒ 必须抛（防止跨上下文混用）",
                throwsPack(m, beOther, swk, base, digits, mCount, lBf, as, bs));
        }
        report("P4 坏输入全部按预期被拒", p4 == 0, String.format("%d 项未达成", p4));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（含 1 条缺陷断言 P3：刻意期望论文形状折叠漏算）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 负对照助手：这次调用是否抛（抛 = true）。 */
    private static boolean throwsPack(Mpc4jRgsw m, BatchEncoder be, Ciphertext[][] swk,
                                      int base, int digits, int mCount, int lBf,
                                      long[][] as, long[] bs) {
        try {
            FusePirPackSlot.pack(m, be, swk, base, digits, mCount, lBf, as, bs);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
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
