package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirSetup;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>A1 SETUP 6 的载荷装配 / 解析自检</b>（{@code padValuesToM} + {@code assemblePayload} + {@code parsePayload}）。
 *
 * <h3>它补的是哪两个缺口</h3>
 * 逐行核对 Algorithm 1 时发现的两处"没有具名函数"：
 * <ul>
 *   <li>{@code SETUP 6} 的 <b>{@code Pad V_{K_i} to m values}</b> ——
 *       此前只在 demo 资产的 private 方法里内联；</li>
 *   <li>{@code SETUP 6} 的 <b>{@code y_{K_i} ← fp ‖ m_i ‖ v…}</b> 装配 ——
 *       能装配的只有 {@code CapeDemoData.buildPayload}（<b>private</b>），
 *       于是 {@code probe/CoeffPackTest:481} 只能"同分布重写"一遍。</li>
 * </ul>
 *
 * <h3>依据</h3>
 * {@code coding/docs/CAPE-数学规范-SETUP到ANSWER.md} §1.3（字段顺序与索引约定、
 * {@code m = max_i m_i（不足处补 0）}）与 §四（DECODE 的字段解析）。
 * ⚠️ 该规范把"个数"写成 2 个 limb，本仓库一直是 1 个 —— **这是待决口径，见 MAP §25.2**；
 * 本探针按本仓库现有口径测，**不去暗改 B_pay**。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirPayloadLayoutTest}
 */
public final class FusePirPayloadLayoutTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final long t = FusePirParams.NATIVE_PLAINTEXT_MODULUS;      // 65537
        final int lBf = 18;
        final int m = 3;
        final int fpSlots = FusePirSetup.fpSlots(t);
        final int perValue = FusePirSetup.perValue(lBf);
        final int bPay = FusePirSetup.payloadBpay(fpSlots, m, perValue);

        System.out.println("=== A1 SETUP 6：载荷装配 / 解析自检 ===");
        System.out.printf("[layout] t=%d、lBf=%d、m=%d ⇒ fpSlots=%d、perValue=%d、B_pay=%d%n%n",
            t, lBf, m, fpSlots, perValue, bPay);

        final String kw = "fusepir-payload-layout-2026";
        long[] fpD = BffSetup.fpDigits(kw, t, fpSlots);

        // ============ P1 pad 到 m ============
        System.out.println("--- P1 Pad V_{K_i} to m values ---");
        int p1 = 0;
        long[] two = FusePirSetup.padValuesToM(new long[]{7001, 7002}, m);
        p1 += sub("P1.1", "2 个值补齐到 m=3 ⇒ 长度 3 且补的是 0（不是复制）",
            two.length == m && two[2] == 0 && two[0] == 7001 && two[1] == 7002);
        long[] full = FusePirSetup.padValuesToM(new long[]{1, 2, 3}, m);
        p1 += sub("P1.2", "恰好 m 个值 ⇒ 原样返回（正对照）", Arrays.equals(full, new long[]{1, 2, 3}));
        p1 += sub("P1.3", "[负对照] 4 个值 > m=3 ⇒ 必须抛（静默截断会丢值）",
            throwsPad(new long[]{1, 2, 3, 4}, m));
        p1 += sub("P1.4", "[负对照] m=0 ⇒ 必须抛", throwsPad(new long[]{}, 0));
        report("P1 pad 到 m 按预期（含两条负对照）", p1 == 0, String.format("%d 项未达成", p1));

        // ============ P2 装配：字段落在约定的下标上 ============
        System.out.println();
        System.out.println("--- P2 y_{K_i} 的装配：每个字段落在约定下标 ---");
        Random rnd = new Random(20261015L);
        long[] vals = FusePirSetup.padValuesToM(new long[]{30000, 31000}, m);
        long[][] bloom = new long[m][lBf];
        for (int j = 0; j < m; j++) {
            for (int i : new int[]{1, 5, 9}) {
                bloom[j][i] = 1;
            }
        }
        long[] y = FusePirSetup.assemblePayload(fpD, 2, vals, bloom, lBf);
        int p2 = 0;
        p2 += sub("P2.1", "B_pay 长度正确（= fpSlots+1+m·perValue = " + bPay + "）", y.length == bPay);
        p2 += sub("P2.2", "指纹段落在 [0, fpSlots)", sliceEquals(y, 0, fpD));
        p2 += sub("P2.3", "个数落在 countOffset(" + fpSlots + ") = " + FusePirSetup.countOffset(fpSlots)
            + "，值 = 2", y[FusePirSetup.countOffset(fpSlots)] == 2);
        boolean valOk = true;
        for (int j = 0; j < m; j++) {
            valOk &= y[FusePirSetup.valueOffset(fpSlots, j, perValue)] == vals[j];
        }
        p2 += sub("P2.4", "三个值分别落在 valueOffset(fpSlots, j, " + perValue + ")", valOk);
        boolean bloomOk = true;
        for (int j = 0; j < m; j++) {
            int bo = FusePirSetup.bloomOffset(fpSlots, j, perValue);
            for (int i = 0; i < lBf; i++) {
                bloomOk &= y[bo + i] == bloom[j][i];
            }
        }
        p2 += sub("P2.5", "Bloom 段落在 bloomOffset(...) 起 " + lBf + " 个下标，逐位一致", bloomOk);
        report("P2 装配的下标全部走 FusePirSetup 的偏移函数", p2 == 0, String.format("%d 项未达成", p2));

        // ============ P3 装配/解析互逆 ============
        System.out.println();
        System.out.println("--- P3 assemblePayload 与 parsePayload 严格互逆 ---");
        FusePirSetup.Payload back = FusePirSetup.parsePayload(y, m, t, lBf);
        int p3 = 0;
        p3 += sub("P3.1", "指纹段逐位回来", Arrays.equals(back.fpDigits, fpD));
        p3 += sub("P3.2", "个数回来（2）", back.count == 2);
        p3 += sub("P3.3", "三个值逐位回来（含补的那个 0）", Arrays.equals(back.values, vals));
        boolean bloomBack = true;
        for (int j = 0; j < m; j++) {
            bloomBack &= Arrays.equals(back.bloom[j], bloom[j]);
        }
        p3 += sub("P3.4", "Bloom 段逐位回来", bloomBack);
        // 重装配必须逐位相同（避免"能解回来但装配不唯一"）
        long[] again = FusePirSetup.assemblePayload(back.fpDigits, back.count, back.values,
            back.bloom, lBf);
        p3 += sub("P3.5", "再装配一次与原 y 逐位相同", Arrays.equals(y, again));
        report("P3 装配↔解析互逆（含重装配逐位一致）", p3 == 0, String.format("%d 项未达成", p3));

        // ============ P4 负对照：坏输入必须炸 ============
        System.out.println();
        System.out.println("--- P4 负对照：坏载荷必须炸 ---");
        int p4 = 0;
        long[][] badBit = new long[m][lBf];
        badBit[1][3] = 2;                                    // 非二进制位
        p4 += sub("P4.1", "Bloom 位写成 2 ⇒ 必须抛（非二进制会让内积判据失去意义）",
            throwsAssemble(fpD, 2, vals, badBit, lBf));
        long[][] shortBloom = new long[m][];
        shortBloom[0] = new long[lBf - 1];
        shortBloom[1] = new long[lBf];
        shortBloom[2] = new long[lBf];
        p4 += sub("P4.2", "某值的 Bloom 段短一位 ⇒ 必须抛", throwsAssemble(fpD, 2, vals, shortBloom, lBf));
        p4 += sub("P4.3", "count=4 > m=3 ⇒ 必须抛", throwsAssemble(fpD, 4, vals, bloom, lBf));
        p4 += sub("P4.4", "count=-1 ⇒ 必须抛", throwsAssemble(fpD, -1, vals, bloom, lBf));

        long[] shortY = Arrays.copyOf(y, bPay - 1);
        boolean parseThrew;
        try {
            FusePirSetup.parsePayload(shortY, m, t, lBf);
            parseThrew = false;
        } catch (IllegalArgumentException e) {
            parseThrew = true;
        }
        p4 += sub("P4.5", "y 短于 B_pay ⇒ parsePayload 必须抛（不是当成缺省 0）", parseThrew);

        long[] badCount = y.clone();
        badCount[FusePirSetup.countOffset(fpSlots)] = m + 1;
        boolean countThrew;
        try {
            FusePirSetup.parsePayload(badCount, m, t, lBf);
            countThrew = false;
        } catch (IllegalArgumentException e) {
            countThrew = true;
        }
        p4 += sub("P4.6", "y 里的个数越界 ⇒ parsePayload 必须抛（载荷与布局不同源）", countThrew);
        report("P4 坏输入全部被拒", p4 == 0, String.format("%d 项未达成", p4));

        // ============ P5 与 B_pay 口径的关系（登记，不改） ============
        System.out.println();
        System.out.println("--- P5 ⚠️ 与《数学规范》§1.3 的口径差（只登记，不暗改）---");
        int specBpay = fpSlots + 2 + m * (1 + lBf);
        report("P5 《数学规范》的 B_pay = β_fp + 2 + m(1+ℓ_BF) 与本仓库的 +1 口径【不一致】，已登记待决",
            specBpay != bPay,
            String.format("规范口径 = %d，本仓库口径 = %d，差 %d（规范把『个数』写成 2 个 limb）。"
                + "两者不可能同时对；本探针**不**改 B_pay —— 改了会静默打破既有 DB、"
                + "`CapeDemoData`、`CapeAlgorithm2Diag` 等全部载荷消费者。见 MAP §25.2",
                specBpay, bPay, specBpay - bPay));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过（P5 刻意断言『两条口径不一致』：它通过 = 差异仍存在且已被登记）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static boolean sliceEquals(long[] y, int off, long[] want) {
        for (int i = 0; i < want.length; i++) {
            if (y[off + i] != want[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean throwsPad(long[] values, int m) {
        try {
            FusePirSetup.padValuesToM(values, m);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static boolean throwsAssemble(long[] fp, int count, long[] values, long[][] bloom, int lBf) {
        try {
            FusePirSetup.assemblePayload(fp, count, values, bloom, lBf);
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
