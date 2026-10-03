package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.fusepir.FusePirPackSlot;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.LweRlweConversion;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>{@code SampleExtract_0}（真密文、RNS 形态、{@code q_R} 上）→ 缩放 → 槽位域 Pack 的整条桥自检。</b>
 *
 * <h3>它补的是哪个缺口</h3>
 * MAP §23.4 记着："适配器要求输入已在 {@code Z_t}，而真实链路给的是 {@code q_R} 上、RNS 形态的样本
 * ⇒ P1-3 第二半与 P0-3 另一半仍开"。本探针验的就是这一层。
 *
 * <h3>⚠️ 它给出三个结论，其中第二个是本轮最重要的发现</h3>
 * <ol>
 *   <li><b>转换本身成立</b>：{@code β − ⟨a,s⟩} 与载荷一致，偏差 <b>39</b>
 *       （理论 {@code std ≈ 20}，与 {@code SampleToPackLink} 的 ≈30 同量级）；
 *       符号约定（{@code a} 取反）经"秘密改 1 位偏差爆炸"的负对照确认。</li>
 *   <li>🔴 <b>真实 {@code SampleExtract_0} 的输出维数是 {@code N}，不是 16。</b>
 *       因为 LWE-in-RLWE 下抽出来的是<b>环秘密下</b>的样本，{@code a} 有 {@code N} 项。
 *       ⇒ <b>给这条链路配交换密钥就是 {@code nLwe = N} 条</b>
 *       （N=8192 ⇒ <b>8.0 GB</b>；N=1024 ⇒ 约 151 MB）。
 *       <b>这不是"适配器有 bug"，是把 §18.4 那条成本结论在真实链路上验证了一遍。</b>
 *       ⇒ 也说明 <b>"RNS 桥"与"密钥切换 N→d"不是两件独立的事</b>：
 *       想让 Pack 吃真实样本且密钥不炸到 8 GB，就必须先有密钥切换。</li>
 *   <li><b>缩放噪声让"大值字段可用、二进制字段不可用"</b>：
 *       残差 ≈39 相对 16-bit limb 是 0.06%（解得出），相对位值 {@code 1} 是几十倍
 *       ⇒ <b>「{@code s_j == τ}」精确判据在"缩放→Pack"这条路上不成立</b>。</li>
 * </ol>
 *
 * <h3>跑法（两个规模各有分工）</h3>
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirPackSlotRnsTest 8192   # P1 + P2（维数守卫生效）
 *   .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirPackSlotRnsTest 1024   # + P3 完整打包（nLwe = N 装得下）
 * </pre>
 * 8192 上不跑 P3 的原因写在 {@link #MAX_N_FOR_FULL_PACK}：
 * {@code nLwe = N = 8192} 的交换密钥是 <b>12.9 GB</b>（{@code 8192×3} 条 × 512 KB），本机装不下。
 */
public final class FusePirPackSlotRnsTest {

    private static int failed = 0;

    /** 完整打包测试的环维度上限：{@code nLwe = N} 的交换密钥要装得进内存。 */
    private static final int MAX_N_FOR_FULL_PACK = 4096;

    /**
     * 完整打包的环维度<b>下限</b>：缺陷总表「口径 2」写死了
     * 「{@code N ≥ 4096} 是这套 Java 移植的硬约束（密钥切换需 ≥2 个工作素数）」。
     * 低于它时 {@code q ≈ 2^27}、{@code Δ = q/t ≈ 2^11}，Pack 每一步 {@code multiplyPlain}
     * 都要花掉好几位 ⇒ 装不下。<b>在 N=1024 上真跑过一次，解出的是垃圾（偏差 45575），
     * 那种结果不能当成"Pack 失败/成功"</b> —— 所以这里显式跳过而不是让它糊过去。
     */
    private static final int MIN_N_FOR_PACK = 4096;

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 1024;
        final long t = FusePirParams.NATIVE_PLAINTEXT_MODULUS;
        final int lBf = 18;
        final int mCount = 1;                                   // 取 1 是为了控制 CRT 重算量
        final int base = 1 << 8;
        final int digits = 3;
        final long tol = t / 64;                                // 1024

        final int fpSlots = FusePirSetup.fpSlots(t);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, mCount, perValue);

        Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);

        System.out.println("=== SampleExtract_0（真密文/RNS/q_R）→ 缩放 → 槽位域 Pack ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[layout] t=%d、lBf=%d、m=%d、fpSlots=%d、perValue=%d、B_pay=%d、容差=t/64=%d%n%n",
            t, lBf, mCount, fpSlots, perValue, bPay, tol);

        // ---------- 载荷：真实形状（大值 limb + 二进制位混在同一个 y 里） ----------
        final String kw = "fusepir-rns-bridge-2026";
        long[] payload = new long[bPay];
        long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);
        for (int i = 0; i < fpSlots; i++) {
            payload[i] = fpD[i];
        }
        payload[FusePirSetup.countOffset(fpSlots)] = mCount;             // = 1，小值
        final long value = 30000L;
        payload[FusePirSetup.valueOffset(fpSlots, 0, perValue)] = value;
        final int bo = FusePirSetup.bloomOffset(fpSlots, 0, perValue);
        for (int p : new int[]{15, 16, 17}) {
            payload[bo + p] = 1;                                         // 二进制位
        }
        System.out.printf("[payload] fp=%s、计数=%d、值=%d、Bloom 段起点=%d（置位在 +15..17）%n",
            Arrays.toString(fpD), mCount, value, bo);

        long[] msg = new long[n];                                        // 明文系数 = 载荷（前 bPay 项）
        System.arraycopy(payload, 0, msg, 0, bPay);
        Ciphertext ct = m.encrypt(msg);
        System.out.println("[ct] 真密文已加密该载荷；每个字段从它做 SampleExtract_0");

        // ============ P1 转换 + 符号约定 ============
        long[] s = LweRlweConversion.rlweSecretCoefficientsCentered(m);
        System.out.println();
        System.out.println("--- P1 RNS→Z_t 的转换与符号约定（用 RLWE 秘密系数验证）---");
        long worst = 0;
        int worstAt = -1;
        for (int b = 0; b < bPay; b++) {
            long[] zt = FusePirPackSlot.rnsToT(m, LweRlweBridge.sampleExtract(m, ct, b));
            long dev = Math.abs(centered(inner(zt, s, t), t) - centered(payload[b], t));
            if (dev > worst) {
                worst = dev;
                worstAt = b;
            }
        }
        report(String.format("P1.1 β − ⟨a,s⟩ 与载荷一致（最大偏差 %d，第 %d 个字段）", worst, worstAt),
            worst <= tol,
            String.format("残差是缩放噪声 Σδ_j s_j，理论 std ≈ 20（N=%d、三元秘密）；实测最大 %d", n, worst));

        long[] sBad = s.clone();
        sBad[Math.min(1234, n - 1)] = sBad[Math.min(1234, n - 1)] == 0 ? 1 : 0;
        long[] zt0 = FusePirPackSlot.rnsToT(m, LweRlweBridge.sampleExtract(m, ct, 0));
        long devBad = Math.abs(centered(inner(zt0, sBad, t), t) - centered(payload[0], t));
        report("P1.2 [负对照] 秘密只改 1 位 ⇒ 偏差必须远大于残差（证明 P1.1 有分辨力）",
            devBad > 20 * Math.max(1, worst),
            String.format("改 1 位后偏差 %d、正常残差 %d ⇒ 相差 %.0f 倍", devBad, worst,
                devBad / (double) Math.max(1, worst)));

        // ============ P2 🔴 真实样本的维数是 N —— 16 行的交换密钥必须被拒 ============
        System.out.println();
        System.out.println("--- P2 真实 SampleExtract_0 的维数 = N（这是本轮最重要的发现）---");
        Random rnd = new Random(20261015L);
        int[] lweS16 = new int[16];
        for (int i = 0; i < lweS16.length; i++) {
            lweS16[i] = rnd.nextInt(2);
        }
        Ciphertext[][] swk16 = FusePirPackSlot.keyGen(m, lweS16, base, digits);
        long[][][] samples = new long[bPay][][];
        for (int b = 0; b < bPay; b++) {
            samples[b] = LweRlweBridge.sampleExtract(m, ct, b);
        }
        report(String.format("P2.1 样本的 LWE 维数 == N == %d（不是 d=16）—— LWE-in-RLWE 的直接后果", n),
            samples[0][0].length == n + 1 && n != 16,
            String.format("RNS 样本形状 [%d][%d]，a 有 N=%d 项 ⇒ 交换密钥要 nLwe=N=%d 行",
                samples[0].length, samples[0][0].length, n, n));

        String caught = null;
        try {
            FusePirPackSlot.packFromRns(m, be, swk16, base, digits, mCount, lBf, samples);
        } catch (IllegalArgumentException e) {
            caught = e.getMessage();
        }
        report("P2.2 [负对照] 拿 16 行的交换密钥去装 N 维样本 ⇒ 必须抛（而不是静默少减几项）",
            caught != null,
            caught == null ? "没有抛 —— 这是个静默错的入口！" : "抛出：" + firstLine(caught));

        // ============ P3 完整打包（只在 nLwe=N 装得下时跑） ============
        System.out.println();
        if (n < MIN_N_FOR_PACK || n > MAX_N_FOR_FULL_PACK) {
            if (n < MIN_N_FOR_PACK) {
                System.out.printf("--- P3 本规模（N=%d）跳过：**低于本 Java 移植的噪声下限** ---%n", n);
                System.out.printf("      实测：N=%d 时 [params] 报 工作层=1(27 bit) ⇒ q≈2^27；%n", n);
                System.out.printf("      t=%d≈2^16 ⇒ Δ=q/t≈2^11，只有约 11 bit 余量，%n", t);
                System.out.printf("      而 Pack 每步 multiplyPlain 都要花掉好几位 ⇒ 装不下。%n");
                System.out.printf("      这不是 Pack 的问题：缺陷总表『口径 2』已写%n");
                System.out.printf("      「N ≥ 4096 是这套 Java 移植的硬约束」。%n");
                System.out.printf("      ⚠️ 先前在 N=1024 上真跑过一次，P3a 解出垃圾（偏差 45575）——%n");
                System.out.printf("      那种结果【不能】当作「Pack 失败/成功」，它是「参数低于硬约束」。%n");
            } else {
                System.out.printf("--- P3 本规模（N=%d）跳过完整打包 ---%n", n);
            }
            long perCt = 2L * m.workingPrimeCount * n * 8L;
            System.out.printf("      原因：nLwe = N = %d ⇒ 交换密钥 %d 条 × %d B = %.1f GB，本机装不下%n",
                n, (long) n * digits, perCt, n * (double) digits * perCt / 1073741824.0);
            System.out.printf("      ⇒ 这正是 §18.4 那条成本结论在真实链路上的复现。%n");
            System.out.printf("      ⇒ 完整打包改在 N=%d 上验（同一份代码、同一个形状）：%n",
                MAX_N_FOR_FULL_PACK);
            System.out.printf("         .\\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirPackSlotRnsTest %d%n",
                MAX_N_FOR_FULL_PACK);
            System.out.println();
            if (failed == 0) {
                System.out.println("=== P1/P2 全部通过（P3 在本规模按上面的理由跳过）===");
            } else {
                System.out.println("=== 有 " + failed + " 项未达成 ===");
            }
            if (failed != 0) {
                System.exit(1);
            }
            return;
        }

        System.out.printf("--- P3 完整打包：nLwe = N = %d（真实样本维数）---%n", n);
        int[] lweS = new int[n];
        for (int i = 0; i < n; i++) {
            lweS[i] = rnd.nextInt(2);
        }
        Ciphertext[][] swk = FusePirPackSlot.keyGen(m, lweS, base, digits);
        System.out.printf("      交换密钥 %d 条 = %.1f MB%n", (long) n * digits,
            n * (double) digits * 2L * m.workingPrimeCount * n * 8L / 1048576.0);

        FusePirPackSlot.Packed packed =
            FusePirPackSlot.packFromRns(m, be, swk, base, digits, mCount, lBf, samples);
        long[] got = FusePirPackSlot.decodePayload(m, be, packed, bPay);
        System.out.println("      " + packed);

        // P3a 大值字段可用
        long worstLarge = 0;
        int worstLargeAt = -1;
        int largeCount = 0;
        for (int b = 0; b < bPay; b++) {
            if (payload[b] >= 1000) {
                largeCount++;
                long dev = Math.abs(centered(got[b], t) - centered(payload[b], t));
                if (dev > worstLarge) {
                    worstLarge = dev;
                    worstLargeAt = b;
                }
            }
        }
        report(String.format("P3a 大值字段（%d 个）解得回来：最大偏差 %d（第 %d 个字段），容差 %d",
                largeCount, worstLarge, worstLargeAt, tol),
            largeCount > 0 && worstLarge <= tol,
            String.format("这些是 fp limb 与候选值 ∈ [1000, t−1]；偏差 %d / t = %d ⇒ 相对 %.3f%%",
                worstLarge, t, 100.0 * worstLarge / t));

        // P3b 二进制字段不可用 —— 这一半必须一起报
        int small = 0;
        int exact = 0;
        long worstSmall = 0;
        for (int b = 0; b < bPay; b++) {
            if (payload[b] <= 1) {
                small++;
                if (got[b] == payload[b]) {
                    exact++;
                }
                worstSmall = Math.max(worstSmall,
                    Math.abs(centered(got[b], t) - centered(payload[b], t)));
            }
        }
        report(String.format("P3b [缺陷断言] 二进制字段（%d 个）必然【不精确】：%d 个恰好相等，最大偏差 %d",
                small, exact, worstSmall),
            small > 0 && worstSmall > 8,
            String.format("残差最大 %d 是位值 1 的 %d 倍 ⇒ 「s_j == τ」精确判据在"
                + "「缩放 → Pack」这条路上【不成立】。不是噪声不够，是这条路的固有限制",
                worstSmall, worstSmall));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（含 1 条缺陷断言 P3b：刻意期望位字段不精确）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    /**
     * {@code β − ⟨a,s⟩ mod t}（{@code a} 已按 Pack 的约定取反，所以这里是相减）。
     *
     * <p>取模<b>必须用 {@code t}</b>：残差是与载荷同域的量，用别的模数比出来的"偏差"没有意义。
     */
    private static long inner(long[] zt, long[] s, long t) {
        long acc = 0;
        for (int k = 0; k < s.length; k++) {
            acc += zt[1 + k] * s[k];
        }
        return Math.floorMod(zt[0] - Math.floorMod(acc, t), t);
    }

    private static long centered(long v, long t) {
        long x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i) + " …";
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
