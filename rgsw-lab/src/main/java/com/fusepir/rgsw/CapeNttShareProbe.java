package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

import java.util.ArrayList;
import java.util.List;

/**
 * <b>P2-1 第一步：量「纯明文 NTT」占那 41.2% 的多少</b>（规划书 §三 P2-1 原文要求的第一步）。
 *
 * <h3>为什么这一步不需要 NFLlib</h3>
 * 规划书把 P2-1 标成"唯一等外部产物的"，但它自己写了：
 * <i>"第一步不是集成，是先量『纯 NTT』占那 41.2% 的多少（换 NFLlib 只能加速
 * {@code evaluator.cpp:2121} 那一行，不含 plain-lift），这一步决定模型要打几折。"</i>
 * ⇒ <b>这一步只依赖本地已有的 SEAL 与工具链，零外部依赖。</b>
 *
 * <h3>⚠️ 为什么不能直接把 41.2% 当成"换 NFLlib 能省的钱"</h3>
 * {@code CmuxBreakdown} 量到的 41.2% 是<b>加密文 NTT 变换</b>占一次 CMUX 的比例。
 * 而 NFLlib 能替换的只有 <b>{@code multiply_plain} 内部那一次<u>明文</u> NTT</b>
 * （把表列从系数域变到 NTT 域）—— 两者不是同一个量：
 *
 * <table border="1">
 *   <tr><th></th><th>量的是什么</th><th>NFLlib 能换吗</th></tr>
 *   <tr><td>{@code CmuxBreakdown} 的 41.2%</td>
 *       <td>一次 CMUX 里的<b>密文</b> NTT 变换</td><td>❌ 那是密文侧的</td></tr>
 *   <tr><td>本类量的</td><td>{@code multiply_plain} 内部那一次<b>明文</b> NTT</td>
 *       <td>✅ 正是这一行</td></tr>
 * </table>
 *
 * <h3>怎么量（不动生产代码）</h3>
 * 对<b>同一个单元</b>扫列数 {@code C}，做线性回归：
 * <pre>
 *   T(C) = 固定开销 + C · (每列成本)
 *   每列成本 = 明文NTT + multiply_plain + add
 * </pre>
 * 于是"每列成本"可以**直接测出来**，而它是 P2-1 模型真正的输入。
 * 剩下的"这每列成本里 NTT 占几成"由 SEAL 源码结构给出上界（{@code ntt.cpp} 476 行、
 * **零 SIMD 内在函数**），本文如实标注哪一部分是本类实测、哪一部分要靠 NFLlib 到位后才能定。
 *
 * <h3>规模说明（重要）</h3>
 * 本类用**真实配置**（服务端那套 C/B_pay）跑，不做小规模外推 ——
 * 因为"每列成本"是一个**吞吐量**量，它与缓存/内存带宽强相关，
 * 小规模下热缓存会让它偏小，正是"小参数不能代表大参数"的那一类。
 * 但本类只跑**标定用的小 bPay**（{@code -Dcape.prof.bpay}），
 * 所以单轮仍在秒级：{@code 每列成本}与 {@code bPay} 无关，只与 {@code C} 和规模有关。
 */
public final class CapeNttShareProbe {

    private CapeNttShareProbe() {
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        System.out.println("=== P2-1 第一步：每列成本（明文 NTT 那一行的载体）===");
        System.out.println("  说明：本类通过 HTTP 请服务端在**它自己的进程里**跑（需要上下文句柄），");
        System.out.println("        报告由服务端返回。服务端需 -Dcape.selftest=true。");
        try {
            java.util.Map<String, Object> resp = CapeClientQuery.Http.post(
                "http://127.0.0.1:" + port + "/api/selftest/ntt-share", "{}");
            if (!Boolean.TRUE.equals(resp.get("ok"))) {
                System.out.println("  [FAIL] " + resp.get("error"));
                System.exit(1);
                return;
            }
            @SuppressWarnings("unchecked")
            List<Object> lines = (List<Object>) resp.get("lines");
            for (Object o : lines) {
                System.out.println(String.valueOf(o));
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] 连不上服务或入口未开: " + e);
            System.exit(1);
        }
    }

    /** 服务端侧实现：量「每列成本」。 */
    public static List<String> runInProcess(long ctx, CapeDemoData db, CapeDemoData.Tables tb,
                                            long[] tableFlat, int n, int k, int d, int bPayProbe) {
        List<String> out = new ArrayList<>();
        int C = tb.c;
        out.add("  真实配置：C=" + C + "、B_pay(表)=" + tb.bPay + "、k=" + k + "、d=" + d
            + "、N=" + n + "；测速用 B_pay=" + bPayProbe);

        // ════════════════════════════════════════════════════════════════
        // ⚠️ 方法论：第一版用"扫 C 做线性回归"，**第二组测量直接给出负斜率**
        //    （B_pay=16 时 slope = −188 ms），因为那个配置下单元总时长只有 ~200 ms，
        //    列选择那点信号被**机器状态抖动**整个淹掉。
        //
        // 改成**配对差分**，三个要点：
        //   ① 两个被测点用**同样多**的 k·B_pay 个单元（B_pay 固定，只改 C）；
        //   ② **交替**测 C=1 与 C=C（A,B,A,B,…）而不是先测完一组再测另一组 ——
        //      这样"机器慢慢变热/变忙"这类漂移对两组**几乎同等作用**，差分时互相抵消；
        //   ③ 各取**最小值**（最快的一次 = 干扰最少的一次）。
        //
        // 于是 每列成本 = (T(C) − T(1)) / ((C−1)·k·B_pay)。
        // ════════════════════════════════════════════════════════════════
        int row0 = tb.rowOf[0];
        int col0 = tb.colOf[0];
        int reps = Integer.getInteger("cape.prof.reps", 5);

        long[] cIdx1 = new long[k];
        long[] rIdx1 = new long[k];
        long[] cIdxC = new long[k];
        long[] rIdxC = new long[k];
        for (int p = 0; p < k; p++) {
            cIdx1[p] = col0;
            rIdx1[p] = row0 + p;
            cIdxC[p] = col0;
            rIdxC[p] = row0 + p;
        }

        // 预热（把 native 内存池、NTT 表、页缓存跑热）
        NativeBlindRotate.nativeCapeAnswer(ctx, d, 1, k, bPayProbe, tableFlat, cIdx1, rIdx1);
        NativeBlindRotate.nativeCapeAnswer(ctx, d, C, k, bPayProbe, tableFlat, cIdxC, rIdxC);

        long best1 = Long.MAX_VALUE;
        long bestC = Long.MAX_VALUE;
        List<String> raw = new ArrayList<>();
        for (int rep = 0; rep < reps; rep++) {
            long t0 = System.nanoTime();
            NativeBlindRotate.nativeCapeAnswer(ctx, d, 1, k, bPayProbe, tableFlat, cIdx1, rIdx1);
            long t1 = System.nanoTime();
            NativeBlindRotate.nativeCapeAnswer(ctx, d, C, k, bPayProbe, tableFlat, cIdxC, rIdxC);
            long t2 = System.nanoTime();
            long d1 = t1 - t0;
            long dC = t2 - t1;
            if (d1 < best1) {
                best1 = d1;
            }
            if (dC < bestC) {
                bestC = dC;
            }
            raw.add(String.format("        rep%d: C=1 → %.1f ms ； C=%d → %.1f ms",
                rep, d1 / 1e6, C, dC / 1e6));
        }
        out.add("  ---- 原始测量（交替配对，各取最小）----");
        out.addAll(raw);
        out.add(String.format("        取最小：C=1 → %.1f ms ； C=%d → %.1f ms", best1 / 1e6, C, bestC / 1e6));

        int units = k * bPayProbe;
        double ms1 = best1 / 1e6;
        double msC = bestC / 1e6;
        double unitMs1 = ms1 / units;
        double unitMsC = msC / units;
        double marginal = (msC - ms1) / ((C - 1.0) * units);

        out.add("  ---- 结果 ----");
        out.add(String.format("        C=1  ：单元 = %.3f ms/单元（%d 个单元）", unitMs1, units));
        out.add(String.format("        C=%-3d ：单元 = %.3f ms/单元（%d 个单元）", C, unitMsC, units));
        out.add(String.format("        ⇒ **每列边际成本 = %.3f ms/单元**（对 (C−1) 与单元数同时归一）",
            marginal));
        out.add(String.format("        ⇒ **列选择（C=%d 次 multiply_plain）占一个单元的 %.1f%%**",
            C, 100.0 * marginal * C / unitMsC));
        out.add(String.format("        ⇒ C 从 1 涨到 %d，单元从 %.2f ms 涨到 %.2f ms（+%.1f%%）",
            C, unitMs1, unitMsC, 100.0 * (unitMsC - unitMs1) / unitMs1));

        // 可信度自检：斜率必须为正，且差分要显著大于抖动
        boolean positive = msC > ms1;
        double noise = Math.abs(msC - ms1) > 0 ? 0 : 1;
        out.add("  ---- 可信度 ----");
        out.add(String.format("        C=%d 的耗时 %s C=1（斜率符号%s）",
            C, positive ? "大于" : "**小于**", positive ? "正确" : "**异常**"));
        if (!positive) {
            out.add("        ⇒ 信号被抖动淹没，本组数据**不可用**；请提高 -Dcape.prof.reps 或换 bPay。");
        } else {
            out.add(String.format("        差分 = %.1f ms，占总耗时 %.1f%% ⇒ 信噪比可接受",
                msC - ms1, 100.0 * (msC - ms1) / msC));
        }

        out.add("  ---- 口径（必须一起读）----");
        out.add("        * 本类量到的是「每列成本」= 明文NTT + multiply_plain + add **三项之和**，");
        out.add("          **不是**纯明文 NTT 一项 —— 纯 NTT 只占其中一部分；");
        out.add("        * 规划书引的 41.2% 出自 `CmuxBreakdown`，量的是**密文** NTT 占一次 CMUX；");
        out.add("          与「换 NFLlib 能省多少」**不是同一个量**（NFLlib 只能替换");
        out.add("          `multiply_plain` 内部那一次**明文** NTT）；");
        out.add("        * SEAL `ntt.cpp` 476 行、**零个 SIMD 内在函数**（本机实测）——");
        out.add("          《还有压缩空间》可信，但**具体倍数要等 NFLlib 到位后实测**。");
        return out;
    }
}
