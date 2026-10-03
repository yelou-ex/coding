package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.fusepir.FusePirPackSlot;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.LweRlweConversion;
import com.fusepir.prim.Mpc4jRgsw;
import com.fusepir.prim.RingPack;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;
import edu.alibaba.mpc4j.crypto.fhe.seal.utils.ValCheck;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>把 {@code s_L} 铺成 {@code s_R}（规范 §0.5）之后，Pack 的交换密钥能不能从 N 行降到 d 行？</b>
 *
 * <h3>依据</h3>
 * {@code coding/docs/CAPE-数学规范-SETUP到ANSWER.md} §0.5：
 * <pre>
 *   s_L = (s_L[0],…,s_L[d−1]) ∈ {0,1}^d      LWE 私钥
 *   s_R(X) = Σ_{j&lt;d} s_L[j]·X^j ∈ R_q          RLWE 私钥（同源）
 * </pre>
 * 规范原话："<b>同源</b>"是整条链能闭合的关键；C9 注"<b>{@code s_R} 按 {@code s_L} 铺开</b>"。
 *
 * <h3>它要证的一件事（本探针的全部价值）</h3>
 * {@code s_R} 只在 {@code [0,d)} 上非零 ⇒ {@code SampleExtract_0} 的相位只由
 * {@code a_0..a_{d−1}} 贡献 ⇒ <b>Pack 用 {@code d} 行交换密钥就够</b>。
 * 而本仓库此前用的是<b>全 N 系数</b>三元秘密 ⇒ 要 N 行 ⇒ 12.0 GB。
 *
 * <ol>
 *   <li><b>正例</b>：铺开后的 ключ + 真实 {@code SampleExtract_0} 输出，<b>只带前 d 项</b>，
 *       用 {@code d} 行交换密钥 ⇒ 解得回来（大值字段在容差内）；</li>
 *   <li><b>负对照</b>：<b>全支撑</b>秘密的同一套流程、同样只带前 d 项 ⇒ <b>必须解错</b>。
 *       没有这一条，P4 的"解得回来"可能只是碰巧。</li>
 * </ol>
 *
 * ⚠️ 容差来自 {@code q_R → Z_t} 的缩放残差（≈数十），与维度无关；本探针**只比大值字段**
 * （≥1000），因为二进制字段在该缩放下必然不精确（MAP §24.4 已登记）。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirSecretLiftTest 8192}
 */
public final class FusePirSecretLiftTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        final long t = FusePirParams.NATIVE_PLAINTEXT_MODULUS;
        final int lBf = 18;
        final int mCount = 1;
        final int d = 16;                                   // 规范的 d；⚠️ 玩具值（安全性由 d 定）
        final int base = 1 << 8;
        final int digits = 3;
        final long tol = t / 64;                            // 1024，与 §24 的口径一致

        final int fpSlots = FusePirSetup.fpSlots(t);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);

        Mpc4jRgsw ref = new Mpc4jRgsw(n, t, 0, 1 << 16);     // 全支撑秘密（本仓库旧口径）
        BatchEncoder be = new BatchEncoder(ref.context);

        System.out.println("=== s_L → s_R 铺开：Pack 的交换密钥能否从 N 行降到 d 行 ===");
        System.out.println("[params] " + ref.describe());
        System.out.printf("[spec  ] s_R(X) = Σ_{j<d} s_L[j]·X^j（规范 §0.5）；本探针取 d=%d%n", d);
        System.out.printf("[layout] t=%d、lBf=%d、m=%d、B_pay=%d、容差=t/64=%d%n%n",
            t, lBf, mCount, bPay, tol);

        // ============ P1 现状：默认秘密是【全 N 支撑】 ============
        System.out.println("--- P1 本仓库默认的秘密（全 N 三元）不满足规范的『同源铺开』---");
        long[] sRefOld = LweRlweConversion.rlweSecretCoefficientsCentered(ref);
        int nzRef = 0;
        int maxNz = -1;
        for (int i = 0; i < n; i++) {
            if (sRefOld[i] != 0) {
                nzRef++;
                maxNz = i;
            }
        }
        report(String.format("P1 默认秘密：非零 %d/%d 个，最高非零下标 %d ⇒ 不 ⊆ [0,%d)",
                nzRef, n, maxNz, d),
            maxNz >= d && nzRef > d,
            String.format("⇒ SampleExtract_0 的相位由全部 %d 个系数贡献 ⇒ Pack 要 nLwe=N=%d 行"
                + "（N=8192 ⇒ 12.0 GB）。**这就是 §18.4 那个 8–12 GB 的真正来源**", n, n));

        // ============ P2 铺开后的密钥：可用、且支撑恰在 [0,d) ============
        System.out.println();
        System.out.println("--- P2 铺开后的密钥 ---");
        Random rnd = new Random(20261015L);
        int[] sL = new int[d];
        for (int i = 0; i < d; i++) {
            sL[i] = rnd.nextInt(2);
        }
        SecretKey skLift = LweRlweConversion.liftLweSecretToRlwe(ref, sL);
        // 诊断：ValCheck 是公开的，直接问它哪一项不过，比猜快
        System.out.printf("      [diag] coeffCount=%d（期望 %d）· bufferValid=%s · metaValid=%s · valid=%s%n",
            skLift.data().coeffCount(), ref.n * ref.primes.length,
            ValCheck.isBufferValid(skLift), ValCheck.isMetaDataValidFor(skLift, ref.context),
            ValCheck.isValidFor(skLift, ref.context));
        System.out.printf("      [diag] sk.parmsId=%s · data.parmsId=%s · ctx.firstParmsId=%s%n",
            skLift.parmsId(), skLift.data().parmsId(), ref.context.firstParmsId());
        System.out.printf("      [diag] equals(sk,first)=%s · ==(sk,first)=%s · equals(data,first)=%s%n",
            java.util.Objects.equals(skLift.parmsId(), ref.context.firstParmsId()),
            skLift.parmsId() == ref.context.firstParmsId(),
            java.util.Objects.equals(skLift.data().parmsId(), ref.context.firstParmsId()));
        SecretKey skLib = ref.keyGen.secretKey();
        System.out.printf("      [diag] 库自带密钥：coeffCount=%d · metaValid=%s · parmsId=%s%n",
            skLib.data().coeffCount(), ValCheck.isMetaDataValidFor(skLib, ref.context), skLib.parmsId());
        System.out.printf("      [diag] isNttForm：我方=%s · 库自带=%s · 库自带 metaValid=%s%n",
            skLift.data().isNttForm(), skLib.data().isNttForm(),
            ValCheck.isMetaDataValidFor(skLib, ref.context));
        Mpc4jRgsw mLift = new Mpc4jRgsw(n, t, 0, 1 << 16, skLift);

        long[] sLift = LweRlweConversion.rlweSecretCoefficientsCentered(mLift);
        int nzLift = 0;
        int maxLift = -1;
        boolean prefixOk = true;
        for (int i = 0; i < n; i++) {
            if (sLift[i] != 0) {
                nzLift++;
                maxLift = i;
            }
            if (i < d && sLift[i] != sL[i]) {
                prefixOk = false;
            }
        }
        int p2 = 0;
        p2 += sub("P2.1", "非零系数全部落在 [0,d)：非零 " + nzLift + " 个、最高下标 " + maxLift,
            maxLift < d && nzLift == countOnes(sL));
        p2 += sub("P2.2", "前 d 个系数就是 s_L（逐位相同）", prefixOk);

        long[] msg = new long[n];
        msg[0] = 12345;
        Ciphertext ctRt = mLift.encrypt(msg);
        boolean rtOk = mLift.decrypt(ctRt)[0] == 12345;
        p2 += sub("P2.3", "该密钥是【可用的】：加密→解密往返正确（12345）", rtOk);
        p2 += sub("P2.4", "它是与默认密钥不同的另一把（不是碰巧相等）",
            !Arrays.equals(sLift, sRefOld));
        report("P2 铺开后的密钥可用，且支撑恰为 [0,d)", p2 == 0, String.format("%d 项未达成", p2));

        // ============ P3 负对照：坏 s_L 必须炸 ============
        System.out.println();
        System.out.println("--- P3 负对照：坏 s_L 必须炸 ---");
        int p3 = 0;
        p3 += sub("P3.1", "s_L 长于 N ⇒ 必须抛（C9：d ≤ N）", throwsLift(ref, new int[n + 1]));
        int[] bad = sL.clone();
        bad[3] = 2;
        p3 += sub("P3.2", "s_L 里有 2 ⇒ 必须抛（规范是 {0,1}^d）", throwsLift(ref, bad));
        p3 += sub("P3.3", "s_L 为空 ⇒ 必须抛", throwsLift(ref, new int[0]));
        report("P3 坏 s_L 全部被拒", p3 == 0, String.format("%d 项未达成", p3));

        // ============ P4 关键对照：d 行交换密钥 ---- ============
        System.out.println();
        System.out.println("--- P4 关键对照：真实 SampleExtract_0 只带前 d 项，交换密钥只用 d 行 ---");
        final String kw = "fusepir-secret-lift-2026";
        long[] payload = new long[bPay];
        long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);
        System.arraycopy(fpD, 0, payload, 0, fpSlots);
        payload[FusePirSetup.countOffset(fpSlots)] = mCount;
        payload[FusePirSetup.valueOffset(fpSlots, 0, perValue)] = 30000L;
        int bo = FusePirSetup.bloomOffset(fpSlots, 0, perValue);
        for (int p : new int[]{15, 16, 17}) {
            payload[bo + p] = 1;
        }
        long[] msgP = new long[n];
        System.arraycopy(payload, 0, msgP, 0, bPay);

        // ---- 正例：铺开后的密钥 ----
        long[] rLift = runTruncated(mLift, be, sL, msgP, payload, d, bPay, t, lBf, mCount, base, digits, fpSlots, perValue);
        long worstLift = rLift[0];
        report(String.format("P4.1 正例：铺开后 + 只带前 %d 项 + %d 行交换密钥 ⇒ 大值字段解得回来（最大偏差 %d ≤ %d）",
                d, d, worstLift, tol),
            worstLift >= 0 && worstLift <= tol,
            worstLift < 0 ? "有字段偏差超容差" : String.format("最大偏差 %d / t=%d ⇒ 相对 %.3f%%",
                worstLift, t, 100.0 * worstLift / t));

        // ---- ⭐ P4.1b：位字段是否也变精确了？（残差随 d 收缩的直接后果） ----
        report(String.format("P4.1b ⭐ 位/小值字段：%d/%d 个【恰好相等】，最大偏差 %d（MAP §24.4 曾判它们不可用）",
                rLift[1], rLift[2], rLift[3]),
            rLift[1] > 0 && rLift[3] <= 4,
            String.format("缩放残差 ≈ Σδ_j·s_j 只累加 d=%d 项 ⇒ 理论 std ≈ √(d·2/3)·0.289 ≈ %.1f，"
                + "而 N 项时是 ≈20（§24 实测 30–60）。⇒ 铺开【顺带】把位字段救回来了",
                d, Math.sqrt(d * 2.0 / 3.0) * 0.289));

        // ---- 负对照：全支撑密钥（本仓库旧口径）同样只带前 d 项 ----
        int[] sStd16 = new int[d];
        for (int i = 0; i < d; i++) {
            sStd16[i] = (int) Math.floorMod(sRefOld[i], 2);
        }
        long[] rFull = runTruncated(ref, be, sStd16, msgP, payload, d, bPay, t, lBf, mCount, base, digits, fpSlots, perValue);
        long worstFull = rFull[0];
        report(String.format("P4.2 [负对照] 全支撑秘密 + 同样只带前 %d 项 ⇒ 必须解错（大值字段最大偏差 %s）",
                d, worstFull < 0 ? "超容差" : String.valueOf(worstFull)),
            worstFull < 0 || worstFull > tol,
            "若这条也解得回来，说明 P4.1 的『解得回来』与铺开无关 —— 那本探针就不算证明了什么");

        // ============ P5 成本 ============
        System.out.println();
        System.out.println("--- P5 交换密钥成本（同一把上下文，只改 nLwe）---");
        System.out.println("      " + FusePirPackSlot.keyCost(ref, d, digits) + "   ← 铺开后的规范口径");
        System.out.println("      " + FusePirPackSlot.keyCost(ref, n, digits) + "   ← 全支撑（旧口径）");
        System.out.printf("      ⇒ 比值 N/d = %d 倍。⚠️ 但 d **由安全级别定**：已知支撑的 d 元秘密"
            + "等价于 d 维 LWE，d=16 是玩具（论文实验 d=512）%n", n / d);

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（P4.2 刻意期望『解错』：它通过 = 负对照成立）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    /**
     * 跑一次"只带前 {@code d} 项 + {@code d} 行交换密钥"的打包，返回
     * {@code {大值字段最大偏差, 小值/位字段恰好相等的个数, 小值字段总数, 小值字段最大偏差}}；
     * 大值字段若超容差则第一个元素返回 {@code -1}。
     */
    private static long[] runTruncated(Mpc4jRgsw m, BatchEncoder be, int[] sForKey, long[] msg,
                                       long[] payload, int d, int bPay, long t, int lBf, int mCount,
                                       int base, int digits, int fpSlots, int perValue) {
        Ciphertext ct = m.encrypt(msg);
        long[][] as = new long[bPay][];
        long[] bs = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            long[][] rns = LweRlweBridge.sampleExtract(m, ct, b);
            long[] zt = FusePirPackSlot.rnsToT(m, rns);          // [β, a_0..a_{N−1}]
            // 只带前 d 项：规范下这就够了（s_R 在 [d,N) 上为 0）
            long[] ztD = Arrays.copyOf(zt, d + 1);
            bs[b] = ztD[0];
            as[b] = Arrays.copyOfRange(ztD, 1, ztD.length);
        }
        Ciphertext[][] swk = RingPack.switchingKey(m, sForKey, base, digits);
        FusePirPackSlot.Packed packed =
            FusePirPackSlot.pack(m, be, swk, base, digits, mCount, lBf, as, bs);
        long[] got = FusePirPackSlot.decodePayload(m, be, packed, bPay);
        long worst = 0;
        long worstSmall = 0;
        long exactSmall = 0;
        long smallCount = 0;
        boolean anyLarge = false;
        for (int b = 0; b < bPay; b++) {
            long dev = Math.abs(centered(got[b], t) - centered(payload[b], t));
            if (payload[b] >= 1000) {
                anyLarge = true;
                worst = Math.max(worst, dev);
            } else {
                smallCount++;
                worstSmall = Math.max(worstSmall, dev);
                if (got[b] == payload[b]) {
                    exactSmall++;
                }
            }
        }
        if (!anyLarge) {
            throw new IllegalStateException("载荷里没有大值字段，判据无效");
        }
        return new long[]{worst <= t / 64 ? worst : -1, exactSmall, smallCount, worstSmall};
    }

    private static long centered(long v, long t) {
        long x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    private static int countOnes(int[] a) {
        int c = 0;
        for (int v : a) {
            if (v != 0) {
                c++;
            }
        }
        return c;
    }

    private static boolean throwsLift(Mpc4jRgsw m, int[] sL) {
        try {
            LweRlweConversion.liftLweSecretToRlwe(m, sL);
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
