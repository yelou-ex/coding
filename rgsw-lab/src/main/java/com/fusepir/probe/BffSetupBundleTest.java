package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.bff.BffSetupBundle;

import java.util.Random;

/**
 * <b>A1 SETUP 1 的单一入口验收</b> —— {@link BffSetupBundle#setup} 与
 * {@link BffSetupBundle#sampleSeeds}（A3 SETUP 8）。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.BffSetupBundleTest [n] [ringDim] [B_pay]
 * </pre>
 *
 * <h3>这个探针防的是什么</h3>
 * 审计说"没有单一的 {@code BFF.Setup} 入口"会卡住调用方 —— 把 6 处产物装进一个对象之后，
 * <b>真正的风险换成了"装错"</b>：{@code L_BFF} 与 {@code RC} 是两个不同的数
 * （{@code D} 是 {@code RC} 长的网格，{@code L_BFF} 只是它前面那一段），
 * 而 {@code H} 里的 {@code (L_BFF, s)} 又必须与 {@code Layout} 里的一致 ——
 * 这三处只要有一处串了，症状都是**静默查错槽**。所以下面逐条对。
 */
public final class BffSetupBundleTest {

    private static int checks;
    private static int fails;

    /**
     * A3 SETUP 8 的位置函数种子 {@code ρ_H} —— 本轮改成 {@code setup} 的<b>入参</b>之后，
     * 探针必须与 {@code BffHash.positions(kws, 20261014L, r.h)} 时代的种子保持一致，
     * 否则下面那条"建表侧位置表 vs 独立重算"的对表就变成了两个不同函数相比。
     */
    private static final long RHO_H = 20261014L;

    private BffSetupBundleTest() {
    }

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int bPay = args.length > 2 ? Integer.parseInt(args[2]) : 60;
        final int k = 3;

        System.out.println("=== A1 SETUP 1 的单一入口（BffSetupBundle）===");
        System.out.println("  n = " + n + ", N = " + ringDim + ", B_pay = " + bPay + ", k = " + k);

        final BffSetupBundle.SetupResult r =
            BffSetupBundle.setup(n, k, bPay, ringDim, 0, true, RHO_H);
        System.out.println("  " + r);

        // ── ① 三个长度必须各就各位 ────────────────────────────────────
        check(r.d.length == (int) r.layout.rc(),
            "D 的形状是 [RC][B_pay]（%d 行 == RC=%d）—— A3 SETUP 11-12 写的是 RC 长的网格",
            (long) r.d.length, r.layout.rc());
        check(r.d[0].length == bPay, "D 每个条目宽 B_pay=%d", (long) bPay, null);
        check(r.lBff == r.h.lBff && r.lBff == r.layout.lBff,
            "L_BFF 在三个地方是同一个数（bundle=%d, H=%d, Layout=%d）",
            r.lBff, r.h.lBff, r.layout.lBff);
        check(r.s == r.h.s && r.s == r.layout.s,
            "段长 s 在两处一致（bundle=%d, H=%d）", r.s, r.h.s);

        // ── ② L_BFF 与 RC 是**两个不同的数**（串了就是静默查错槽）────────
        //     这条同时是"为什么不直接拿 d.length 当 L_BFF"的可执行证据。
        check(r.layout.rc() >= r.lBff,
            "A1 SETUP 4 的约束 RC ≥ L_BFF 成立（%d ≥ %d）；且二者相等当且仅当 tail=0",
            r.layout.rc(), r.lBff);
        System.out.println("      RC=" + r.layout.rc() + " vs L_BFF=" + r.lBff
            + "（tail=" + r.layout.tailLen() + "）—— **不是同一个数**");

        // ── ③ D 初值：A3 SETUP 11-12 `D[u] ← ⊥` ──────────────────────
        long nonZero = 0;
        for (long[] row : r.d) {
            for (long v : row) {
                if (v != 0) {
                    nonZero++;
                }
            }
        }
        check(nonZero == 0, "D 初值全 0（A3 SETUP 11-12 的 D[u] ← ⊥）", null, null);

        // ── ④ fp 是 40-bit，且与 BffSetup.fp 同源 ────────────────────
        long maxFp = 0;
        boolean sameSource = true;
        final java.util.List<String> kws = new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            kws.add("bff-bundle-kw-" + i);
        }
        for (String kw : kws) {
            final long a = r.fp.applyAsLong(kw);
            if (a != BffSetup.fp(kw)) {
                sameSource = false;
            }
            maxFp = Math.max(maxFp, a);
        }
        check(sameSource, "fp 这个函数与 BffSetup.fp 逐位同源（%d 个关键词）", (long) n, null);
        check(maxFp >= (1L << 32),
            "fp 用到了 32 bit 以上的位（max=%d）—— 40-bit 指纹（论文 §5.1 μ=40）", maxFp, null);

        // ── ⑤ 闭式对照值与默认值**确实不同**（否则"对照"就没意义）────
        check(r.closedForm.lBff != r.lBff,
            "闭式 L_BFF(%d) ≠ 默认路径的 L_BFF(%d) —— 两者都被带出来正是为了能对照",
            r.closedForm.lBff, r.lBff);

        // ── ⑥ 位置函数：范围与互异（H 真的能用）──────────────────────
        // ⚠️ 2026-10-15 本轮：这里原来是 `BffHash.positions(kws, 20261014L, r.h)`
        //    —— ρ_H 另外当参数传。现在 H 自己带 ρ_H（A3 SETUP 9 的四个入参一起给的），
        //    所以直接调 `r.h.positions(kws)`。两者**逐位等价**（同种子、同段结构），
        //    但后者把"位置函数"与"它的种子"绑在一起，传不错。
        final int[][] pos = r.h.positions(kws);
        // 顺带钉住种子确实<b>进到了 H 里面</b>：拿旧的两调用形态重算一遍必须逐位相同。
        // 否则"ρ_H 装进 HashGen"这件事只是签名好看，值可能没接上。
        check(r.rhoH == RHO_H && r.h.rhoH == RHO_H,
            "ρ_H 装进了 H（bundle.rhoH=%d == h.rhoH=%d == 传进去的 %d）",
            r.rhoH, r.h.rhoH, RHO_H);
        final int[][] viaOldForm = BffHash.positions(kws, RHO_H, r.h);
        boolean sameAsOldForm = true;
        for (int i = 0; i < n; i++) {
            if (!java.util.Arrays.equals(pos[i], viaOldForm[i])) {
                sameAsOldForm = false;
            }
        }
        check(sameAsOldForm,
            "★ 单次调用形态 H.positions(K) 与旧的两调用形态 positions(K, ρ_H, H) 逐位一致（%d 个关键词）",
            (long) n, null);
        boolean inRange = true;
        boolean distinct = true;
        for (int i = 0; i < n; i++) {
            for (int a = 0; a < k; a++) {
                if (pos[i][a] < 0 || pos[i][a] >= r.lBff) {
                    inRange = false;
                }
            }
            for (int a = 0; a < k; a++) {
                for (int b2 = a + 1; b2 < k; b2++) {
                    if (pos[i][a] == pos[i][b2]) {
                        distinct = false;
                    }
                }
            }
        }
        check(inRange, "H 给出的位置全部落在 [0, L_BFF) = [0, %d)", r.lBff, null);
        check(distinct, "同一个关键词的 k 个位置互异", null, null);

        // ── ⑦ A3 SETUP 8：两个种子独立采样 ──────────────────────────
        final BffSetupBundle.Seeds s1 = BffSetupBundle.sampleSeeds(new Random(1L));
        final BffSetupBundle.Seeds s2 = BffSetupBundle.sampleSeeds(new Random(1L));
        final BffSetupBundle.Seeds s3 = BffSetupBundle.sampleSeeds(new Random(2L));
        System.out.println("  " + s1);
        check(s1.independent(), "ρ_H ≠ ρ_fp（论文要求 independent）", null, null);
        check(s1.rhoH == s2.rhoH && s1.rhoFp == s2.rhoFp,
            "[正对照] 同随机种子 ⇒ 同一对种子（探针可复现）", null, null);
        check(s1.rhoH != s3.rhoH || s1.rhoFp != s3.rhoFp,
            "[负对照] 换随机种子 ⇒ 种子对确实变了（采样不是常量）", null, null);

        // ── ⑧ 负对照：把不成立的参数喂进去必须**抛**，不许静默出结果 ──
        checkThrows(() -> BffHash.hashGen(155, 64, k),
            "[负对照] (L_BFF=155, s=64) 描述不出 BFF 布局 ⇒ hashGen 抛异常");
        // ⚠️ 这里我第一版写错了期望：以为 N=8 会抛，实测**不抛** ——
        //    自动策略是「R = min(N, 2^⌊log2√L_BFF⌋)」，也就是**夹到 N**，
        //    夹完仍然满足 R ≤ N 且 RC ≥ L_BFF（R=8, C=32, RC=256）⇒ 合法。
        //    真正该抛的是**显式**指定的 forceR > N（那时是调用方给错了参数）。
        //    所以改成：一条正对照（自动夹到 N 合法）+ 一条负对照（显式 forceR>N 抛）。
        boolean clampedOk = false;
        try {
            final BffSetup.Layout clamped = BffSetup.layout(256, 64, 8, 0);
            clampedOk = clamped.r == 8 && clamped.rc() >= 256;
        } catch (Throwable ignored) {
            clampedOk = false;
        }
        check(clampedOk,
            "[正对照] N=8 时自动策略把 R **夹到 N=8**（R=%d, RC 仍 ≥ L_BFF）—— 合法，不该抛",
            (long) 8, null);
        checkThrows(() -> BffSetup.layout(256, 64, 8, 16),
            "[负对照] 显式 forceR=16 > N=8 ⇒ layout 抛（A1 SETUP 4 的 R ≤ N）");
        checkThrows(() -> BffSetupBundle.sampleSeeds(null),
            "[负对照] 采样不传随机源 ⇒ 抛（不许悄悄用默认随机源）");

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        System.out.println("   覆盖：A1 SETUP 1/2/4、A3 SETUP 2/3/8/9/10/11-12/14");
        if (fails != 0) {
            System.exit(1);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Throwable;
    }

    private static void checkThrows(ThrowingRunnable body, String what) {
        checks++;
        try {
            body.run();
            System.out.println("  [FAIL] " + what + "  —— 竟然没抛");
            fails++;
        } catch (Throwable e) {
            System.out.println("  [PASS] " + what + "  —— " + e.getClass().getSimpleName()
                + ": " + String.valueOf(e.getMessage()).substring(0,
                    Math.min(70, String.valueOf(e.getMessage()).length())));
        }
    }

    /**
     * ⚠️ 用 <b>varargs</b> + 格式化兜底。
     * 本仓库的其它探针用过固定两参数的版本，结果因为占位符数与参数个数不匹配
     * 抛 {@code MissingFormatArgumentException}，把"检查失败"伪装成"探针崩溃"
     * （还让后面的检查根本没跑）。这里不再犯。
     */
    private static void check(boolean ok, String fmt, Object... args) {
        checks++;
        String msg;
        try {
            msg = args == null || args.length == 0 ? fmt : String.format(fmt, args);
        } catch (RuntimeException e) {
            msg = fmt + "   [⚠️ 格式化失败：" + e.getClass().getSimpleName() + "]";
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
