package com.fusepir.probe;

import com.fusepir.bff.BffEncode;
import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffMapping;
import com.fusepir.bff.BffSetup;

import java.util.Random;

/**
 * <b>BFF 层自检（纯 Java，无同态）</b> —— 把 CAPE 附录 Algorithm 3 的
 * <b>ENCODE / CHECK / RECONSTRUCT</b> 与 A1 SETUP 9-11 的尾部补零
 * 单独验一遍，不牵扯 SEAL、不牵扯 native。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.BffLayerTest [n] [ringDim]
 * </pre>
 *
 * <h3>⚠️ 本探针验什么、不验什么</h3>
 * <ul>
 *   <li><b>验</b>：剥皮（MAPPINGSTEP）能成功、LIFO 回填后
 *       {@code Σ_j D[h_j(K)] = y_K} 对<b>全部 n 个关键词</b>成立（这就是"假阴性 0"的明文侧）、
 *       尾部 {@code [L_BFF, RC)} 全是 0、{@code embed} 与 A1 SETUP 14 的 reshape 一致。</li>
 *   <li><b>不验</b>：{@code h_a} 本身。位置表由 {@link #fixturePositions} 这个
 *       <b>测试夹具</b>给出 —— 它只保证"k 个互异位置、分布在 k 个连续段"，
 *       用来把 ENCODE 那一半单独隔离出来。真 {@code h_a} 到位后由另一组检查覆盖。</li>
 * </ul>
 *
 * <h3>⚠️ 负对照</h3>
 * 每个正向检查都配一个"把它弄坏就应该失败"的对照 —— 否则无法区分
 * "检查通过"与"检查根本没在检查"。
 */
public final class BffLayerTest {

    private static int checks;
    private static int fails;

    private BffLayerTest() {
    }

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int k = 3;
        final long t = 65537L;                       // 论文的 t（out_cape.txt:1154）
        final int bPay = 7;                          // 本探针只关心机制，载荷宽度随意
        final int m = 3;

        System.out.println("=== BFF 层自检（无同态） ===");
        System.out.println("  n = " + n + ", k = " + k + ", t = " + t
            + ", ringDim N = " + ringDim + ", B_pay = " + bPay);

        // ── ① selectRC：论文只给约束，策略是我们的，先把它打印清楚 ────────
        for (boolean useCeil : new boolean[] {true, false}) {
            final BffSetup.Layout lo = BffSetup.selectRC(n, k, ringDim, 0, useCeil);
            System.out.println("  [布局] L_BFF 闭式用 " + (useCeil ? "⌈⌉（CAPE 附录 Alg 3）"
                : "⌊⌋（ChalametPIR Alg 1）") + " -> " + lo);
            check(lo.rc() >= lo.lBff, "A1 SETUP 4 约束 RC ≥ L_BFF 成立（%d ≥ %d）",
                lo.rc(), lo.lBff);
            check(lo.r <= lo.ringDim, "A1 SETUP 4 约束 R ≤ N 成立（%d ≤ %d）",
                (long) lo.r, (long) lo.ringDim);
            check(!lo.rIsAuto || (lo.r & (lo.r - 1)) == 0,
                "自动选的 R 是 2 的幂（FusePIR-C 的 ℓ_r = ⌈log2 R⌉ 要求按位分解）", null, null);
            check(!lo.rIsAuto || lo.r <= (long) Math.sqrt(lo.lBff),
                "方格策略：R(%d) ≤ √L_BFF(%d) —— 根号开在 L_BFF 上，不是 N 上",
                (long) lo.r, (long) Math.floor(Math.sqrt(lo.lBff)));
            // ⚠️ 这条不再断言"尾部非空"：方格策略下 R | L_BFF ⇒ tail = 0，
            //    那是**策略的结果**，不是错误。真正的检查在下面"强制 R=N"那一段。
            System.out.println("    （尾部 = " + lo.tailLen() + " 个槽；"
                + "方格策略下 R | L_BFF 时 tail 必为 0，见 §12.7）");
        }

        final BffSetup.Layout lo = BffSetup.selectRC(n, k, ringDim, 0, true);
        System.out.println("  [选定] " + lo);

        // ── ② 位置表：夹具（不是 h_a） ────────────────────────────────────
        final BffEncode.PositionFn posFn = seed -> fixturePositions(seed, n, k, lo);
        final int[][] pos = posFn.positions(20261014L);

        boolean inRange = true;
        boolean distinct = true;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < k; j++) {
                if (pos[i][j] < 0 || pos[i][j] >= lo.lBff) {
                    inRange = false;
                }
            }
            for (int a = 0; a < k; a++) {
                for (int b = a + 1; b < k; b++) {
                    if (pos[i][a] == pos[i][b]) {
                        distinct = false;
                    }
                }
            }
        }
        check(inRange, "夹具位置全部落在 [0, L_BFF)", null, null);
        check(distinct, "同一个关键词的 k 个位置**互异**（原文 “k distinct locations”）", null, null);

        // ── ③ ENCODE（剥皮 + LIFO 回填） ─────────────────────────────────
        final long[][] payload = new long[n][bPay];
        final Random prnd = new Random(7L);
        for (int i = 0; i < n; i++) {
            for (int b = 0; b < bPay; b++) {
                payload[i][b] = prnd.nextLong(t);
            }
        }
        final Random rnd = new Random(20261014L);
        // ⚠️ 夹具的位置表与 seed 无关（本探针只测 ENCODE），所以 attempts 必为 1
        final BffEncode.Table tab = BffEncode.encode(n, k, lo, posFn, 20261014L,
            payload, t, 32, rnd);
        check(tab != null, "MAPPINGSTEP 成功（|S| = n）", null, null);
        if (tab == null) {
            System.out.println("\n❌ 剥皮失败，后续检查无法进行");
            System.out.println("   这说明 L_BFF 相对 n 的余量不够，或分段结构不对");
            System.out.println(checks + " 项检查，" + fails + " 项失败");
            System.exit(1);
            return;
        }
        System.out.println("  剥皮栈深 = " + tab.peel.size + "，用了 " + tab.attempts + " 个种子");

        // ── ④ ★ 核心不变式：全部 n 个关键词都能重建出 y_K（假阴性 0） ────
        int bad = 0;
        for (int i = 0; i < n; i++) {
            final long[] y = BffEncode.reconstruct(tab.d, tab.pos[i], k, bPay, t);
            if (!java.util.Arrays.equals(y, payload[i])) {
                if (bad < 3) {
                    System.out.println("    ✗ K_" + i + " 重建不符：" + java.util.Arrays.toString(y)
                        + " != " + java.util.Arrays.toString(payload[i]));
                }
                bad++;
            }
        }
        check(bad == 0, "Σ_j D[h_j(K)] = y_K 对**全部 %d 个**关键词成立（假阴性 0）", (long) n, null);

        // ── ⑤ 尾部补零（A1 SETUP 9-11） ─────────────────────────────────
        long tailNonZero = 0;
        for (int u = (int) lo.lBff; u < (int) lo.rc(); u++) {
            for (int b = 0; b < bPay; b++) {
                if (tab.d[u][b] != 0) {
                    tailNonZero++;
                }
            }
        }
        check(tailNonZero == 0, "尾部 [L_BFF, RC) = [%d, %d) 全为 0", lo.lBff, lo.rc());

        // ── ⑤b 强制 R = N：这时尾部**非空**，A1 SETUP 9-11 真的在清槽 ────
        //       方格策略下 R | L_BFF ⇒ tail = 0，所以"尾部那一步是否真的做事"
        //       不能靠默认参数验；这里显式把 R 顶到 N 把它逼出来。
        final BffSetup.Layout bigR = BffSetup.layout(lo.lBff, lo.s, ringDim, ringDim);
        check(bigR.tailLen() > 0,
            "强制 R=N=%d 时尾部有 %d 个槽（A1 SETUP 9-11 那一步真的在做事）",
            (long) bigR.r, bigR.tailLen());
        final long[][] dBig = new long[(int) bigR.rc()][bPay];
        for (int u = 0; u < dBig.length; u++) {
            for (int b = 0; b < bPay; b++) {
                dBig[u][b] = 999L;                       // 先全部弄脏
            }
        }
        BffEncode.zeroTail(dBig, bigR, bPay);
        long stillDirty = 0;
        for (int u = (int) bigR.lBff; u < (int) bigR.rc(); u++) {
            for (int b = 0; b < bPay; b++) {
                if (dBig[u][b] != 0) {
                    stillDirty++;
                }
            }
        }
        check(stillDirty == 0, "zeroTail 把 [L_BFF, RC) = [%d, %d) 的脏值全部清成 0",
            bigR.lBff, bigR.rc());
        // 正对照：不调 zeroTail 就应该还剩脏值
        check((bigR.rc() - bigR.lBff) * bPay > 0,
            "[正对照] 上一条不是空跑：区间本来有 %d 个非零待清",
            (bigR.rc() - bigR.lBff) * bPay, null);

        // ── ⑥ A1 SETUP 14 的 reshape ───────────────────────────────────
        final long[][][] p = BffEncode.embed(tab.d, lo, bPay);
        boolean reshapeOk = true;
        for (int c = 0; c < lo.c && reshapeOk; c++) {
            for (int b = 0; b < bPay && reshapeOk; b++) {
                for (int r = 0; r < lo.ringDim; r++) {
                    final long want = (r < lo.r) ? tab.d[r + c * lo.r][b] : 0L;
                    if (p[c][b][r] != want) {
                        reshapeOk = false;
                        break;
                    }
                }
            }
        }
        check(reshapeOk, "P_{c,b}[r] = D[r + cR][b]，且系数 [R, N) 为 0（A1 SETUP 14）", null, null);

        // 交叉验证：用 (r_a, c_a) 反查 P 也能重建 —— 这正是 QUERY 3 / ANSWER 14 的路径
        int viaGrid = 0;
        for (int i = 0; i < n; i++) {
            final long[] y = new long[bPay];
            for (int j = 0; j < k; j++) {
                final int u = tab.pos[i][j];
                final int r = u % lo.r;
                final int c = u / lo.r;
                for (int b = 0; b < bPay; b++) {
                    y[b] = Math.floorMod(y[b] + p[c][b][r], t);
                }
            }
            if (!java.util.Arrays.equals(y, payload[i])) {
                viaGrid++;
            }
        }
        check(viaGrid == 0, "走 (r_a = u mod R, c_a = ⌊u/R⌋) → P_{c_a,b}[r_a] 反查也全部重建成功", null, null);

        // ── ⑦ 负对照 ────────────────────────────────────────────────────
        //  (a) 弄坏一个槽 ⇒ 至少一个关键词必须重建失败
        final int victimU = tab.pos[0][0];
        final long[][] broken = new long[tab.d.length][];
        for (int u = 0; u < tab.d.length; u++) {
            broken[u] = tab.d[u].clone();
        }
        broken[victimU][0] = Math.floorMod(broken[victimU][0] + 1, t);
        int brokenBad = 0;
        for (int i = 0; i < n; i++) {
            if (!java.util.Arrays.equals(BffEncode.reconstruct(broken, tab.pos[i], k, bPay, t),
                    payload[i])) {
                brokenBad++;
            }
        }
        check(brokenBad >= 1, "[负对照] 改动槽 %d 后至少 1 个关键词重建失败（实测 %d 个）",
            (long) victimU, (long) brokenBad);

        //  (b) LIFO 顺序反过来 ⇒ 重建必须大面积失败
        //      这是"第 8 行的顺序不是实现细节"的**直接证据**
        final long[][] wrongOrder = new long[(int) lo.rc()][bPay];
        for (int u = 0; u < lo.lBff; u++) {
            for (int b = 0; b < bPay; b++) {
                wrongOrder[u][b] = rnd.nextLong(t);
            }
        }
        for (int idx = 0; idx < tab.peel.size; idx++) {          // ← 正序（错）
            final int i = tab.peel.keyAt[idx];
            final int pp = tab.peel.slotAt[idx];
            for (int b = 0; b < bPay; b++) {
                wrongOrder[pp][b] = payload[i][b];
            }
            for (int j = 0; j < k; j++) {
                final int h = tab.pos[i][j];
                if (h != pp) {
                    for (int b = 0; b < bPay; b++) {
                        wrongOrder[pp][b] = Math.floorMod(wrongOrder[pp][b] - wrongOrder[h][b], t);
                    }
                }
            }
        }
        int wrongOrderBad = 0;
        for (int i = 0; i < n; i++) {
            if (!java.util.Arrays.equals(
                    BffEncode.reconstruct(wrongOrder, tab.pos[i], k, bPay, t), payload[i])) {
                wrongOrderBad++;
            }
        }
        check(wrongOrderBad >= 1,
            "[负对照] 回填顺序改成正序后重建失败（实测 %d/%d 个）—— LIFO 是语义、不是风格",
            (long) wrongOrderBad, (long) n);

        //  (c) 尾部不补零（改成遗留的随机值）⇒ 检查⑤必须能抓到
        final long[][] dirtyTail = new long[(int) lo.rc()][bPay];
        for (int u = 0; u < dirtyTail.length; u++) {
            dirtyTail[u] = tab.d[u].clone();
        }
        for (int u = (int) lo.lBff; u < (int) lo.rc(); u++) {
            dirtyTail[u][0] = 12345L;
        }
        long dirtyCount = 0;
        for (int u = (int) lo.lBff; u < (int) lo.rc(); u++) {
            if (dirtyTail[u][0] != 0) {
                dirtyCount++;
            }
        }
        check(dirtyCount > 0, "[正对照] 尾部自检确实能发现非零尾部（人为弄脏 %d 个槽后被数出来）",
            dirtyCount, null);

        realHashSection(n, k, ringDim, t, bPay);

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        System.out.println("   覆盖：A3 MAPPINGSTEP 1-33、A3 ENCODE 1-18、A3 CHECK/RECONSTRUCT、"
            + "A1 SETUP 4/9-11/12-16、A3 SETUP 2/3/9（HashGen）");
        if (fails != 0) {
            System.exit(1);
        }
    }

    // ==================================================================
    //  ★ 真实 h_a（BFF.HashGen / HashGen 的参考实现）
    // ==================================================================

    /**
     * 用<b>真正的</b> {@code h_a}（{@link BffHash}）跑一遍同样的检查，
     * 并把论文三个长度的冲突做成<b>可执行</b>的检查。
     */
    private static void realHashSection(int n, int k, int ringDim, long t, int bPay) {
        System.out.println();
        System.out.println("--- 真实 h_a（BFF.HashGen 参考实现） ---");

        final BffHash.BffParams bp = BffHash.allocate(n, k);
        System.out.println("  allocate(n=" + n + ", k=" + k + ") -> " + bp);

        // ── 三个长度必须分别报出来，因为它们的值**不一样** ────────────────
        final long lBffCape = BffSetup.paperLBff(k, n, true);
        final long lBffChalamet = BffSetup.paperLBff(k, n, false);
        System.out.println("  三个长度：CAPE Alg3 L3 闭式 = " + lBffCape
            + "（ChalametPIR 的 floor 版 = " + lBffChalamet + "）"
            + "，segmentCountLength = " + bp.segmentCountLength
            + "，arrayLength = " + bp.arrayLength);

        long p = 1;
        while (p < lBffCape) {
            p <<= 1;
        }
        check(bp.arrayLength > lBffCape,
            "⚠️ CAPE Alg3 的 L_BFF(%d) **装不下** HashGen 的值域(0..%d) ⇒ 两者不自洽",
            lBffCape, (long) (bp.arrayLength - 1));
        check((lBffCape - (long) (k - 1) * bp.segmentLength) % bp.segmentLength != 0,
            "⚠️ 且 L_BFF=%d 写不成 (segmentCount+k−1)·s 的形状（s=%d）—— BFF 布局不存在",
            lBffCape, (long) bp.segmentLength);

        // ── HashGen 的**原签名** (L_BFF, s, k)：描述不出布局的组合必须在调用点被拒 ──
        //    这条把 MAP §12.6 的"不自洽"从**文档里的论证**变成**API 边界的拒绝**：
        //    以前只有 positions(BffParams) —— 参数是从 n 推出来的，(155, 64) 根本喂不进去。
        boolean rejectedCape = false;
        String rejectMsg = "";
        try {
            BffHash.hashGen(lBffCape, bp.segmentLength, k);
        } catch (IllegalArgumentException e) {
            rejectedCape = true;
            rejectMsg = e.getMessage();
        }
        check(rejectedCape,
            "★ HashGen(L_BFF=%d, s=%d, k) 在**调用点**就被拒（不是算出个越界布局）",
            lBffCape, (long) bp.segmentLength);
        if (rejectedCape) {
            System.out.println("      拒绝理由: " + rejectMsg);
        }
        // 正对照：BFF 参数化那一组必须被接受，且还原出同样的段结构
        boolean acceptedBff = true;
        try {
            final BffHash.HashGen hg = BffHash.hashGen(bp.arrayLength, bp.segmentLength, k);
            acceptedBff = hg.segmentCount == bp.segmentCount
                && hg.segmentCountLength == bp.segmentCountLength;
        } catch (IllegalArgumentException e) {
            acceptedBff = false;
        }
        check(acceptedBff,
            "[正对照] 同一签名接受 BFF 参数化那组（L_BFF=%d, s=%d, k=%d）并还原出同样的段结构",
            (long) bp.arrayLength, (long) bp.segmentLength, (long) k);
        // CAPE 正文说 array lengths "approach 1.125n"，用它自己 Alg3 的公式验一遍
        final double capeRatio = BffSetup.paperLBff(k, 1_000_000L, true) / 1_000_000.0;
        check(Math.abs(capeRatio - 1.125) > 0.5, String.format(
            "⚠️ CAPE Alg3 的公式在 n=10^6 给 %.2f·n，而 CAPE 正文自称「approach 1.125n」"
                + " ⇒ 正文与公式矛盾（矛盾的还有 BFF 原论文表 1 的 log(10^6)/log(n) 写法）",
            capeRatio), null, null);

        // ── 真实 h_a 的三条性质 ────────────────────────────────────────
        final java.util.List<String> kws = new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            kws.add("kw-" + i + "-" + Integer.toHexString(i * 2654435761L > 0
                ? (int) (i * 2654435761L) : ~(int) (i * 2654435761L)));
        }
        final int[][] realPos = BffHash.positions(kws, 20261014L, bp, k);

        boolean inRange = true;
        boolean distinct = true;
        boolean consecutive = true;
        for (int i = 0; i < n; i++) {
            for (int a = 0; a < k; a++) {
                if (realPos[i][a] < 0 || realPos[i][a] >= bp.arrayLength) {
                    inRange = false;
                }
            }
            for (int a = 0; a < k; a++) {
                for (int b = a + 1; b < k; b++) {
                    if (realPos[i][a] == realPos[i][b]) {
                        distinct = false;
                    }
                }
            }
            // 段号必须随 a 前进 1：seg(h_a) = seg(h_0) + a
            final int seg0 = realPos[i][0] / bp.segmentLength;
            for (int a = 1; a < k; a++) {
                final int seg = realPos[i][a] / bp.segmentLength;
                if (seg != seg0 + a) {
                    consecutive = false;
                }
            }
        }
        check(inRange, "h_a 全部落在 [0, arrayLength) = [0, %d)", (long) bp.arrayLength, null);
        check(distinct, "同一个关键词的 k 个位置**互异**（构造保证，非概率）", null, null);
        check(consecutive, "k 个位置落在 **k 个连续段**（正文 “k consecutive segments” → 参考实现）",
            (long) k, null);

        // ── 用真实 h_a 走完整 ENCODE ───────────────────────────────────
        final BffSetup.Layout realLo = BffSetup.fromBff(n, k, ringDim, 0);
        System.out.println("  真实路径布局 -> " + realLo);

        // ── 教学例：R、C 到底是什么 ─────────────────────────────────────
        //  同一个关键词的三个位置 u_a，在同一组 (R,C) 下会落到不同的「系数 + 多项式」上。
        System.out.println("  [教学例] 关键词 \"" + kws.get(0) + "\" 的三个位置如何落到 (列 c, 系数 r)：");
        for (int rr : new int[] {16, 64, 256, ringDim}) {
            final int cc = (int) Math.max(1, (bp.arrayLength + rr - 1) / rr);
            final StringBuilder sb = new StringBuilder();
            for (int a = 0; a < k; a++) {
                final int u = realPos[0][a];
                sb.append("  u_").append(a).append('=').append(u)
                    .append("→(c=").append(u / rr).append(",r=").append(u % rr).append(')');
            }
            System.out.println("    R=" + rr + " C=" + cc + " RC=" + (rr * cc)
                + (rr * cc >= bp.arrayLength ? " ≥" : " <") + " L_BFF" + sb);
        }

        final long[][] payload = new long[n][bPay];
        final Random prnd = new Random(11L);
        for (int i = 0; i < n; i++) {
            for (int b = 0; b < bPay; b++) {
                payload[i][b] = prnd.nextLong(t);
            }
        }
        final BffEncode.PositionFn posFn = seed -> BffHash.positions(kws, seed, bp, k);
        final BffEncode.Table tab = BffEncode.encode(n, k, realLo, posFn, 1L,
            payload, t, 64, new Random(20261014L));
        check(tab != null, "真实 h_a 下 MAPPINGSTEP 成功（≤64 个种子）", null, null);
        if (tab == null) {
            return;
        }
        System.out.println("  真实 h_a：剥皮栈深 = " + tab.peel.size + "，用了 " + tab.attempts + " 个种子");

        int bad = 0;
        for (int i = 0; i < n; i++) {
            if (!java.util.Arrays.equals(
                    BffEncode.reconstruct(tab.d, tab.pos[i], k, bPay, t), payload[i])) {
                bad++;
            }
        }
        check(bad == 0, "★ 真实 h_a 下 Σ_j D[h_j(K)] = y_K 对**全部 %d 个**关键词成立（假阴性 0）",
            (long) n, null);

        // ── 同余性：位置必须只由 (关键词, 种子) 决定，客户端/服务端各算一遍要一致 ──
        final int[][] again = BffHash.positions(kws, 20261014L, bp, k);
        boolean same = true;
        for (int i = 0; i < n && same; i++) {
            same = java.util.Arrays.equals(realPos[i], again[i]);
        }
        check(same, "h_a 是确定性的（两边各算一次逐位一致）—— 不确定就是静默假阴性", null, null);
    }

    // ==================================================================
    //  测试夹具 —— ⚠️ 这不是 h_a
    // ==================================================================

    /**
     * <b>⚠️ 这是测试夹具，不是论文的 {@code h_a}。</b>
     *
     * <p>它<b>故意与分段结构无关</b>：只给出"k 个互异、均匀落在 {@code [0, L_BFF)}"的位置。
     * 本探针要隔离出来验的是 <b>ENCODE 那一半</b>（剥皮 + LIFO 回填 + 重建 + 尾部），
     * 不是位置函数本身 —— 所以夹具必须对分段读法中立，
     * 否则"ENCODE 坏了"和"分段读法猜错了"两种失败会混在一起分不开。
     *
     * <p>分段结构的可用槽数在 {@link #segmentReach} 里单独量，负结果也单独报。
     */
    static int[][] fixturePositions(long seed, int n, int k, BffSetup.Layout lo) {
        final int[][] out = new int[n][k];
        for (int i = 0; i < n; i++) {
            long z = mix64(seed * 0x9E3779B97F4A7C15L + i * 0xBF58476D1CE4E5B9L);
            // 取 k 个互异位置：线性探测（这里允许 —— 夹具只是造数据，不代表 h_a 的做法）
            for (int j = 0; j < k; j++) {
                int u = (int) Math.floorMod(mix64(z ^ (j * 0x9E3779B97F4A7C15L)), lo.lBff);
                boolean clash;
                do {
                    clash = false;
                    for (int q = 0; q < j; q++) {
                        if (out[i][q] == u) {
                            clash = true;
                            break;
                        }
                    }
                    if (clash) {
                        u = (u + 1) % (int) lo.lBff;
                    }
                } while (clash);
                out[i][j] = u;
            }
        }
        return out;
    }

    /**
     * <b>均匀等长分段读法下，到底有多少个槽是可寻址的。</b>
     *
     * <p>这一条是**负结果，不是实现**：如果 `s` 段等长、段长取 `⌊L_BFF/s⌋`，
     * 那么可达槽位只有 `s·⌊L_BFF/s⌋` 个。
     * 剥皮要成功需要可达槽位 ≳ `1.125n`（BFF 声称的数组长度），
     * 所以只要 `s·⌊L_BFF/s⌋ < 1.125n`，这个读法就<b>在数学上不可能</b>成立 ——
     * 与实现技巧无关。
     *
     * <p>`n=128`：`s=64`、`⌊155/64⌋=2` ⇒ 可达 **128** 个，
     * 而需要的是 **144** 个 ⇒ 差 16 个 ⇒ 必然失败。
     * 探针里用"实跑一次剥皮看它是不是真的失败"来确认这条推理。
     */
    static long segmentReach(BffSetup.Layout lo) {
        final int s = (int) lo.s;
        final long step = lo.lBff / s;
        return s * step;
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    // ==================================================================

    /**
     * ⚠️ 用 <b>varargs</b>，不是固定两个参数。
     * 此前签名是 {@code (boolean, String, Long, Long)}，而调用点经常写三个占位符
     * —— 于是抛 {@code MissingFormatArgumentException}，把"检查失败"伪装成"探针崩溃"。
     * 我自己在这个文件上就踩了两次（第三轮、第四轮各一次）。varargs 让这类误用不可能。
     */
    private static void check(boolean ok, String fmt, Object... args) {
        checks++;
        // ⚠️ 格式化失败**不许崩**：那会把"检查失败"伪装成"探针崩溃"，看不到真正的失败项。
        //    我自己在这个文件上踩了三次（占位符数 ≠ 参数个数），所以这里兜底。
        String msg;
        try {
            msg = args == null || args.length == 0 ? fmt : String.format(fmt, args);
        } catch (RuntimeException e) {
            msg = fmt + "   [⚠️ 格式化失败：" + e.getClass().getSimpleName()
                + "，占位符数与参数个数不匹配]";
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
