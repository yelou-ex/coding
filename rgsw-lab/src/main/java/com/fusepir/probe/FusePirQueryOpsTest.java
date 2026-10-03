package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.bff.CapeDemoData;
import com.fusepir.fusepir.FusePirQuery;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * <b>A1 QUERY 3 / QUERY 4 收成具名函数之后的等价性验收（纯 Java：无同态、无服务、无 HTTP、无 native）</b>。
 *
 * <pre>
 *   Run（cwd = coding\rgsw-lab，即 run-mpc4j.ps1 所在目录）:
 *     .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirQueryOpsTest "..\cape-demo\db\keywords.json" 8192
 * </pre>
 *
 * <h3>它在验什么</h3>
 * <table border="1">
 *   <tr><th>论文行</th><th>内联在哪</th><th>抽到哪</th><th>本探针怎么验</th></tr>
 *   <tr><td><b>A1 QUERY 3</b></td>
 *       <td>{@code CapeQuery.buildPaper} 里的 {@code u / lo.r} 与 {@code u % lo.r}</td>
 *       <td>{@link FusePirQuery#split}</td>
 *       <td>对 DB 里<b>每个</b>关键词、每条路的 {@code u}，把
 *           {@code split(u,R,C)} 的 {@code (c,r)} 与<b>原表达式现场重算</b>的结果、
 *           以及建表侧的 {@code Tables.colRow} 三边逐位比</td></tr>
 *   <tr><td><b>A1 QUERY 4</b></td>
 *       <td>{@code CapeQuery.encryptColumnSelectors} 里的
 *           {@code e[a*c + cc] = (cc == colIdx[a]) ? 1 : 0}</td>
 *       <td>{@link FusePirQuery#oneHot}</td>
 *       <td>比 128 个关键词各自拼接出来的 {@code k·C} 长向量，并验 one-hot 结构</td></tr>
 * </table>
 *
 * <h3>为什么必须有负对照（本项目已经栽过）</h3>
 * 「编译 0 错误」不是等价性的证据：{@code CapeQuery.build} 上一次重构时，
 * 一个正则替换静默吃掉两行赋值，代码照样编译通过。所以本探针的等价性断言
 * <b>每一条都配一条负对照</b> —— 一个故意写错的实现（方向反了 / {@code R} 换了 /
 * 列号取错路 / 布局换成了列优先）必须让同一个断言<b>失败</b>。
 * 没有负对照的等价性检查是恒真的检查。
 *
 * <h3>⚠️ 本探针**不**验的东西（别把它当成端到端验收）</h3>
 * <ul>
 *   <li>它<b>只比明文索引与明文 one-hot</b>，不碰密文。所以它能离线跑；
 *       但「{@code q_a^col} 加密后服务器选中的列就是 {@code c_a}」这条**不在这里验**
 *       —— 那条要 native + 服务，归 {@code CapeDemoService.selftestSealed()} /
 *       {@code CapeSealedFlowTest}。</li>
 *   <li>它不比 {@code CapeQuery.encryptColumnSelectors} 的**字节流**（那需要 native 上下文句柄）。
 *       改动的那三行（把内联循环换成 {@code oneHot} + {@code arraycopy}）是**代码复核**过的：
 *       拷贝的是同长度的全零数组，元素只可能是 0/1，{@code System.arraycopy} 与逐项赋值等价。
 *       探针能做的是把改动后的那段循环<b>复写一遍</b>再比明文结果，那条在下面。</li>
 *   <li>它不验 {@code h_a} 本身（那是 {@code bff/BffHash} 的事，{@code BffLayerTest} 覆盖）；
 *       它只吃 {@code buildTablesPaper} 产出的位置表，并顺手核对那张表确实来自
 *       {@code BffHash.positions}。</li>
 *   <li>它<b>不</b>验 A1 SETUP 4 对 {@code (R,C)} 的推导（{@code R·C ≥ L_BFF}、{@code R ≤ N}）
 *       —— 那条在 {@code CapePaperGeometryTest} 里。本探针只把 {@code R·C ≥ L_BFF} 当**前置**断言。</li>
 * </ul>
 */
public final class FusePirQueryOpsTest {

    private static int checks;
    private static int fails;

    private static final int K = 3;
    private static final long TABLE_SEED = 20261013L;
    /** {@code CapePaperGeometryTest} 用的位置函数种子 {@code ρ_H} —— 必须同源才能对位置表。 */
    private static final long HASH_SEED = 20261014L;

    private FusePirQueryOpsTest() {
    }

    public static void main(String[] args) {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "../cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int forceR = args.length > 2 ? Integer.parseInt(args[2]) : 0;

        try {
            run(dbPath, ringDim, forceR);
        } catch (Exception | AssertionError e) {
            System.out.println("[FAIL] 探针自身抛异常（这本身就是一项失败）：");
            e.printStackTrace(System.out);
            fails++;
        }

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        System.out.println("   覆盖：A1 QUERY 3（split + 边界 + 往返 + 3 条负对照）、"
            + "A1 QUERY 4（oneHot + 边界 + 3 条负对照）、与论文几何表的对表");
        if (fails != 0) {
            System.exit(1);
        }
    }

    private static void run(Path dbPath, int ringDim, int forceR) throws Exception {
        final CapeDemoData db = CapeDemoData.load(dbPath);
        final long t = db.longMeta("plainModulus", 65537L);
        final int kwCount = db.keywords.size();

        // ── 建表（论文几何），拿到 (R, C) 与位置表 ────────────────────────
        final CapeDemoData.Tables tb = db.buildTablesPaper(ringDim, K, t, TABLE_SEED, forceR, HASH_SEED);
        final BffSetup.Layout lo = tb.layout;
        final int r = lo.r;
        final int c = lo.c;

        System.out.println("=== A1 QUERY 3 / 4 具名化之后的等价性验收 ===");
        System.out.println("  数据库 = " + dbPath + "（关键词 " + kwCount + " 个）");
        System.out.println("  N = " + ringDim + ", k = " + K + ", t = " + t
            + ", forceR = " + (forceR == 0 ? "0（方格策略）" : String.valueOf(forceR)));
        System.out.println("  布局 = " + lo);
        System.out.println("  R = " + r + ", C = " + c + ", R·C = " + lo.rc()
            + ", L_BFF = " + lo.lBff + ", 尾部补零槽数 = " + lo.tailLen());
        System.out.println("  改动的两处表达式：");
        System.out.println("    QUERY 3  u/R, u%R       → FusePirQuery.split(u, R, C)   "
            + "（" + (kwCount * K) + " 项要一致）");
        System.out.println("    QUERY 4  (cc==c_a)?1:0  → FusePirQuery.oneHot(C, c_a)   "
            + "（" + (kwCount * K) + " 条 one-hot，每条 " + c + " 项，拼接后 "
            + (K * c) + " 长）");

        check(kwCount > 0, "DB 载入成功（关键词 %d 个）", (long) kwCount, null);
        // ⚠️ 这一条是**防"检查是空的"**：本轮验收口径就是「128 关键词 × 3 路 = 384 项」。
        check(kwCount == 128,
            "验收口径：关键词数 = 128 ⇒ %d 个关键词 × %d 路 = %d 项",
            (long) kwCount, (long) K, (long) (kwCount * K));
        // ⚠️ 前置：A1 SETUP 4 的 R·C ≥ L_BFF。若它不成立，split 的边界断言会比
        //    「u < L_BFF」那条更松，下面的等价性结论就要另说 —— 所以先钉住。
        check(lo.rc() >= lo.lBff,
            "前置：A1 SETUP 4 的 R·C ≥ L_BFF（%d ≥ %d）—— split 的边界断言才有意义",
            lo.rc(), lo.lBff);

        positionsComeFromHashGen(db, tb, kwCount);
        positionDomainSection(tb, kwCount);

        final long bad3 = query3Section(tb, kwCount);
        query3NegativeControls(tb, kwCount, bad3);
        query3BoundarySection(r, c, tb, kwCount);

        final long bad4 = query4Section(tb, kwCount);
        query4NegativeControls(tb, kwCount);
        query4BoundarySection(c);
        diffAgainstCapeQueryShape(tb, kwCount);
    }

    // ==================================================================
    //  前置：位置表确实来自 BFF.HashGen（否则下面的对比是在对一张来路不明的表）
    // ==================================================================

    /**
     * 核对 {@code tb.pos} 与直接调 {@code BffHash.positions} 的结果逐位相同。
     *
     * <p>为什么值得单独一条：本探针吃的是**建表侧**的位置表。若这张表的来路与
     * QUERY 侧会调用的那个位置函数不是同一个（种子或参数不同），那么「拆解一致」
     * 证明的只是拆解算术本身，而不是「查询真的打到建表时的槽」。
     */
    private static void positionsComeFromHashGen(CapeDemoData db, CapeDemoData.Tables tb, int kwCount) {
        final BffHash.BffParams bp = BffHash.allocate(kwCount, K);
        final BffHash.HashGen hg = BffHash.hashGen(bp.arrayLength, bp.segmentLength, K);
        long bad = 0;
        for (int i = 0; i < kwCount; i++) {
            final int[] want = BffHash.positions(db.keywords.get(i), HASH_SEED, hg);
            if (!Arrays.equals(want, tb.pos[i])) {
                bad++;
            }
        }
        check(bad == 0,
            "前置：建表的 %d 个位置与 BffHash.positions(K, ρ_H, HashGen) 逐位一致",
            (long) kwCount, HASH_SEED);
    }

    /**
     * {@code u} 的值域：{@code h_j : K → [L_BFF]}（{@code A3 SETUP 9}）。
     *
     * <p>顺带打印<b>实测的 {@code u} 覆盖范围</b> —— 若 {@code u} 都挤在一小段里，
     * 「384 项等价」虽然仍成立，但覆盖面就名不副实。
     */
    private static void positionDomainSection(CapeDemoData.Tables tb, int kwCount) {
        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        long outOfLBff = 0;
        long outOfRc = 0;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < K; a++) {
                final long u = tb.pos[i][a];
                min = Math.min(min, u);
                max = Math.max(max, u);
                if (u < 0 || u >= tb.layout.lBff) {
                    outOfLBff++;
                }
                if (u < 0 || u >= tb.layout.rc()) {
                    outOfRc++;
                }
            }
        }
        check(outOfLBff == 0, "全部 h_a(K) 落在 [0, L_BFF) = [0, %d)", tb.layout.lBff, null);
        check(outOfRc == 0, "全部 h_a(K) 落在 [0, R·C) = [0, %d)", tb.layout.rc(), null);
        System.out.println("    实测 u 范围 = [" + min + ", " + max + "]，"
            + "覆盖 " + (max - min + 1) + " 个不同槽位区间 / 网格 R·C = " + tb.layout.rc());
    }

    // ==================================================================
    //  A1 QUERY 3
    // ==================================================================

    /**
     * <b>★ 核心等价性</b>：{@code FusePirQuery.split(u,R,C)} 与**原内联表达式**逐位一致。
     *
     * <p>「原内联表达式」在这里是<b>现场重算</b>的（{@code u / R}、{@code u % R}），
     * 不是从别处调来的函数 —— 否则就是拿新函数跟自己比，恒真。
     *
     * <p>顺带读第三个证人 {@code tb.colRow(i,a)}：它与 {@code CapeQuery.buildPaper} 是
     * <b>同一套几何的另一份实现</b>（建表侧）。三者一致才说明这次抽取没引入漂移。
     *
     * @return 失配项数（负对照要用它做「正确实现在同一比较下 0 项失配」的旁证）
     */
    private static long query3Section(CapeDemoData.Tables tb, int kwCount) {
        final int r = tb.layout.r;
        final int c = tb.layout.c;
        long bad = 0;
        long witness = 0;              // 非平凡项：c_a≠0 且 r_a≠0，正反两种拆法必然不同的那种
        int firstBadKw = -1;

        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < K; a++) {
                final int u = tb.pos[i][a];

                // ---- 原表达式（现场重算，一行不改）----
                final long origC = u / r;
                final long origR = u % r;

                // ---- 新函数 ----
                final FusePirQuery.CellIndex cr = FusePirQuery.split(u, r, c);

                final int[] tableCr = tb.colRow(i, a);
                if (cr.c() != origC || cr.r() != origR
                    || cr.c() != tableCr[0] || cr.r() != tableCr[1]) {
                    if (firstBadKw < 0) {
                        firstBadKw = i;
                    }
                    bad++;
                }
                if (origC != 0 && origR != 0) {
                    witness++;
                }
            }
        }

        System.out.println();
        System.out.println("--- A1 QUERY 3：split(u,R,C) vs 内联 u/R, u%R vs 建表 colRow ---");
        System.out.println("    非平凡项（c_a≠0 且 r_a≠0，两种拆法必然不同的那种）= "
            + witness + "/" + (kwCount * K));
        // ⚠️ 这一条证明上面的等价性声明**不是恒真**：若样本里的 u 大多是 R 的整数倍或
        //    小于 R（c_a = 0 或 r_a = 0），那么正着拆和反着拆会给出同样的结果，
        //    「384 项全等」就退化成一个空洞的声明。这里把这条下界也钉成断言。
        check(witness > (long) (kwCount * K) / 2,
            "样本非退化：%d/%d 项是 c_a≠0 且 r_a≠0 的非平凡项（> 一半）⇒ 等价性声明不是恒真",
            witness, (long) (kwCount * K));
        check(bad == 0,
            "★ split 的 (c_a,r_a) 与内联表达式、与建表侧 colRow 三者对"
                + "**全部 %d 个关键词 × %d 路 = %d 项**逐位一致",
            (long) kwCount, (long) K, (long) (kwCount * K));
        if (firstBadKw >= 0) {
            System.out.println("    首个不一致：kw=" + firstBadKw);
        }
        return bad;
    }

    /**
     * <b>负对照</b>：三条故意写错的实现，必须让上一条断言失败。
     *
     * <ol>
     *   <li><b>方向反了</b>：{@code c = u mod C}、{@code r = ⌊u/C⌋}。
     *       注意 {@code R = C} 时它仍然通过「往返」与「范围」检查（那两条只是必要条件），
     *       <b>只有对表比位置</b>才抓得到 —— 这正是本探针存在的理由。</li>
     *   <li><b>{@code R} 换了</b>：用它拆出来的 {@code (c,r)} 必须大面积变。</li>
     *   <li><b>位置错位一个关键词</b>：拿 {@code i+1} 号关键词的 {@code h_0} 当 {@code i} 号的。</li>
     * </ol>
     * 阈值写「≥ 一半」而不是「全部」：碰撞是可能的（{@code h_0} 允许共用同一个槽），
     * 写死「必须全部失配」会变成假失败。实测值一律打印。
     */
    private static void query3NegativeControls(CapeDemoData.Tables tb, int kwCount, long badCount) {
        final int r = tb.layout.r;
        final int c = tb.layout.c;
        final long total = (long) kwCount * K;

        // (1) 方向反了 —— 本轮拆解最容易犯、且最会静默的那种错
        long reverseBad = 0;
        boolean printed = false;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < K; a++) {
                final int u = tb.pos[i][a];
                final long revC = u % c;                 // ← 故意写反
                final long revR = u / c;                 // ← 故意写反
                if (revC != u / r || revR != u % r) {
                    reverseBad++;
                    if (!printed) {
                        System.out.println("    反例：kw=" + i + " 第 " + a + " 路 u=" + u
                            + "，正确拆 " + FusePirQuery.split(u, r, c)
                            + "，写反成 (c=" + revC + ", r=" + revR + ")");
                        printed = true;
                    }
                }
            }
        }
        check(reverseBad > total / 2,
            "[负对照] 拆解方向写反（u mod C, u div C）⇒ %d/%d 项对不上"
                + "（正确实现在同一比较下 %d 项失配）",
            reverseBad, total, badCount);

        // (2) R 换一个值
        final int otherR = (r == 4) ? 8 : 4;
        long otherRBad = 0;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < K; a++) {
                final int u = tb.pos[i][a];
                if (u / otherR != (long) (u / r) || u % otherR != (long) (u % r)) {
                    otherRBad++;
                }
            }
        }
        check(otherRBad > total / 2,
            "[负对照] 把 R 从 %d 换成 %d ⇒ %d/%d 项变了（比较确实按 R 在走）",
            Long.valueOf(r), Long.valueOf(otherR), Long.valueOf(otherRBad), Long.valueOf(total));

        // (3) 位置错位一个关键词
        long swappedBad = 0;
        for (int i = 0; i < kwCount; i++) {
            final int mine = tb.pos[i][0];
            final int theirs = tb.pos[(i + 1) % kwCount][0];
            final FusePirQuery.CellIndex cr = FusePirQuery.split(theirs, r, c);
            if (cr.c() != mine / r || cr.r() != mine % r) {
                swappedBad++;
            }
        }
        check(swappedBad > kwCount / 2,
            "[负对照] 位置错位一个关键词（拿 i+1 号的 h_0 当 i 号的）⇒ %d/%d 个索引对不上",
            swappedBad, (long) kwCount);
    }

    /**
     * <b>边界（越界 {@code u} 会静默读到别人的槽）</b>：{@code A1 QUERY 3} 要求 {@code 0 ≤ u < R·C}。
     *
     * <p>验三件事：
     * <ol>
     *   <li>{@code u = R·C}、{@code R·C + 1}、{@code −1} ⇒ 必须抛
     *       （尾部补零槽 A1 SETUP 9-11，读它就是假阴性）；</li>
     *   <li>{@code u = R·C − 1}（最大合法值）⇒ 必须不抛，且拆成 {@code (C−1, R−1)}；</li>
     *   <li>往返：全部真实 {@code u} 满足 {@code split(u).recombine(R) == u}
     *       —— 这就是 {@code A1 SETUP 14} 的 {@code P_{c,b}[r] ↔ D[r + cR]} 对应关系。</li>
     * </ol>
     */
    private static void query3BoundarySection(int r, int c, CapeDemoData.Tables tb, int kwCount) {
        System.out.println();
        System.out.println("--- A1 QUERY 3 的边界（0 ≤ u < R·C = " + ((long) r * c) + "）---");

        final long rc = (long) r * c;
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.split(rc, r, c);
            }
        }), "u = R·C = %d 必须抛 IllegalArgumentException（那是尾部补零槽）", rc, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.split(rc + 1, r, c);
            }
        }), "u = R·C + 1 = %d 必须抛", rc + 1, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.split(-1, r, c);
            }
        }), "u = −1 必须抛（负数不能被当成大位置）", null, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.split(0, 0, c);
            }
        }), "R = 0 必须抛（否则 u/R 除零）", null, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.split(0, r, 0);
            }
        }), "C = 0 必须抛（否则 R·C = 0，一切 u 都越界）", null, null);

        final FusePirQuery.CellIndex top = FusePirQuery.split(rc - 1, r, c);
        check(top.c() == c - 1 && top.r() == r - 1,
            "u = R·C − 1 = %d（最大合法值）拆成 (c,r) = (%d, %d)，即 (C−1, R−1)",
            rc - 1, (long) top.c(), (long) top.r());

        long roundTripBad = 0;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < K; a++) {
                final int u = tb.pos[i][a];
                if (FusePirQuery.split(u, r, c).recombine(r) != u) {
                    roundTripBad++;
                }
            }
        }
        check(roundTripBad == 0,
            "★ 往返：split(u,R,C).recombine(R) == u 对全部 %d 项成立"
                + "（即 A1 SETUP 14 的 P_{c,b}[r] ↔ D[r + cR] 对应关系）",
            (long) (kwCount * K), null);
    }

    // ==================================================================
    //  A1 QUERY 4
    // ==================================================================

    /**
     * <b>★ 核心等价性</b>：{@code k} 条 {@link FusePirQuery#oneHot} 拼出来的 {@code k·C} 长向量
     * 与**原内联表达式**（{@code e[a*c+cc] = (cc == colIdx[a]) ? 1 : 0}）逐位一致。
     *
     * <p>内联表达式同样是现场重算的（{@link #inlineOneHotFlat}），
     * 而不是去调 {@code CapeQuery.encryptColumnSelectors} —— 后者需要 native 上下文句柄，
     * 输出还是密文，逐位比对没有意义。
     *
     * <p>同时验 one-hot 的<b>结构</b>：每条路恰好一个 1、没有非 0/1 的元素、
     * 全向量恰好 {@code k} 个 1、置 1 的下标恰好是 {@code a·C + c_a}（路优先）。
     *
     * @return 失配的关键词数
     */
    private static long query4Section(CapeDemoData.Tables tb, int kwCount) {
        final int r = tb.layout.r;
        final int c = tb.layout.c;
        long bad = 0;
        long structureBad = 0;      // 某条路 1 的个数 != 1（含非 0/1 元素）
        long offsetBad = 0;         // 置 1 的下标 != a*C + c_a
        long totalBad = 0;          // 全向量 1 的个数 != k
        int firstBadKw = -1;

        for (int i = 0; i < kwCount; i++) {
            final long[] colIdx = new long[K];
            for (int a = 0; a < K; a++) {
                colIdx[a] = FusePirQuery.split(tb.pos[i][a], r, c).c();
            }

            final long[] got = newSelectorsFromOneHot(c, colIdx);
            final long[] want = inlineOneHotFlat(K, c, colIdx);

            if (!Arrays.equals(got, want)) {
                if (firstBadKw < 0) {
                    firstBadKw = i;
                }
                bad++;
            }

            long ones = 0;
            for (int a = 0; a < K; a++) {
                int perPath = 0;
                int oneAt = -1;
                for (int cc = 0; cc < c; cc++) {
                    final long v = got[a * c + cc];
                    if (v == 1L) {
                        perPath++;
                        oneAt = cc;
                    } else if (v != 0L) {
                        perPath += 100;                 // 非 0/1 的元素同样算结构错
                    }
                }
                if (perPath != 1) {
                    structureBad++;
                }
                if (oneAt != (int) colIdx[a]) {
                    offsetBad++;
                }
                ones += perPath;
            }
            if (ones != K) {
                totalBad++;
            }
        }

        System.out.println();
        System.out.println("--- A1 QUERY 4：k 条 oneHot(C,c_a) 拼接 vs 内联表达式 ---");
        System.out.println("    向量长度 k·C = " + (K * c) + "，共 " + (kwCount * K)
            + " 条 one-hot（每条 C = " + c + " 项）");
        check(bad == 0,
            "★ 拼接后的 k·C 长向量与内联表达式对**全部 %d 个关键词**逐位一致（%d 条 one-hot × %d 项）",
            (long) kwCount, (long) (kwCount * K), (long) c);
        check(structureBad == 0 && totalBad == 0,
            "结构：每条路恰好一个 1、元素只可能是 0/1、全向量恰好 %d 个 1（%d 条向量全部满足）",
            (long) K, (long) kwCount);
        check(offsetBad == 0,
            "结构：置 1 的下标恰好是 a·C + c_a（路优先，与 nativeCapeAnswerSealedC 的解析顺序一致）",
            null, null);
        if (firstBadKw >= 0) {
            System.out.println("    首个不一致：kw=" + firstBadKw);
        }
        return bad;
    }

    /**
     * <b>负对照</b>：三条故意写错的 one-hot，必须让上一条断言失败。
     *
     * <ol>
     *   <li><b>列号取错路</b>：第 {@code a} 路用第 {@code (a+1) mod k} 路的列号
     *       （近似「{@code colIdx} 与 {@code rowIdx} 串了」这种真实失误）；</li>
     *   <li><b>路优先写成列优先</b>：下标用 {@code cc·k + a} 而不是 {@code a·C + cc}
     *       （与 native 解析顺序不一致 ⇒ 服务器会选中别的列）；</li>
     *   <li><b>one-hot 位置偏移 1</b>：{@code 1} 落在 {@code c_a + 1} 上。</li>
     * </ol>
     */
    private static void query4NegativeControls(CapeDemoData.Tables tb, int kwCount) {
        final int r = tb.layout.r;
        final int c = tb.layout.c;
        long wrongPathBad = 0;
        long colMajorBad = 0;
        long offByOneBad = 0;

        for (int i = 0; i < kwCount; i++) {
            final long[] colIdx = new long[K];
            for (int a = 0; a < K; a++) {
                colIdx[a] = FusePirQuery.split(tb.pos[i][a], r, c).c();
            }
            final long[] want = inlineOneHotFlat(K, c, colIdx);

            // (1) 列号取错路
            final long[] wrongPath = new long[K * c];
            for (int a = 0; a < K; a++) {
                final long[] ea = FusePirQuery.oneHot(c, colIdx[(a + 1) % K]);   // ← 故意取错
                System.arraycopy(ea, 0, wrongPath, a * c, c);
            }
            if (!Arrays.equals(wrongPath, want)) {
                wrongPathBad++;
            }

            // (2) 路优先写成列优先（下标 cc·k + a）
            final long[] colMajor = new long[K * c];
            for (int a = 0; a < K; a++) {
                final long[] ea = FusePirQuery.oneHot(c, colIdx[a]);
                for (int cc = 0; cc < c; cc++) {
                    colMajor[cc * K + a] = ea[cc];                             // ← 故意换布局
                }
            }
            if (!Arrays.equals(colMajor, want)) {
                colMajorBad++;
            }

            // (3) 差一位
            final long[] offByOne = new long[K * c];
            for (int a = 0; a < K; a++) {
                final long[] ea = FusePirQuery.oneHot(c, (colIdx[a] + 1) % c);    // ← 故意 +1
                System.arraycopy(ea, 0, offByOne, a * c, c);
            }
            if (!Arrays.equals(offByOne, want)) {
                offByOneBad++;
            }
        }

        System.out.println();
        System.out.println("--- A1 QUERY 4 的负对照（写错的 one-hot 必须被抓到）---");
        check(wrongPathBad > kwCount / 2,
            "[负对照] 第 a 路用第 a+1 路的列号 ⇒ %d/%d 个关键词的选择子变了",
            wrongPathBad, (long) kwCount);
        check(colMajorBad > kwCount / 2,
            "[负对照] 路优先写成列优先（下标 cc·k+a）⇒ %d/%d 个关键词的选择子变了",
            colMajorBad, (long) kwCount);
        check(offByOneBad > kwCount / 2,
            "[负对照] one-hot 位置差 1（c_a+1）⇒ %d/%d 个关键词的选择子变了",
            offByOneBad, (long) kwCount);
    }

    /**
     * <b>边界</b>：{@code A1 QUERY 4} 要求 {@code 0 ≤ c_a < C}。
     *
     * <p>为什么必须存在：越界时内联表达式给出的是**全零**向量，而全零是合法输入
     * —— 加密不会失败、服务器照样算，只是 {@code Acc_{a,b} = 0}、载荷全 0。
     * 也就是说「列号写错」在这里的表现是**静默假阴性**，不是异常。
     *
     * <p>顺带钉住 {@code C = 1} 的退化情形（MAP §12.7 / §13.3：论文自己那组实验是 {@code C = 1}，
     * 此时列选择子是 {@code RLWE.Enc([1])}，不携带查询信息）。
     */
    private static void query4BoundarySection(int c) {
        System.out.println();
        System.out.println("--- A1 QUERY 4 的边界（0 ≤ c_a < C = " + c + "）---");

        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.oneHot(c, c);
            }
        }), "c_a = C = %d 必须抛（否则得到全零选择子 ⇒ 载荷静默全 0）", (long) c, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.oneHot(c, -1);
            }
        }), "c_a = −1 必须抛", null, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.oneHot(0, 0);
            }
        }), "C = 0 必须抛（否则得到一个长度为 0 的选择子）", null, null);

        final long[] head = FusePirQuery.oneHot(c, 0);
        long sum = 0;
        for (long v : head) {
            sum += v;
        }
        check(head.length == c && head[0] == 1L && sum == 1L,
            "c_a = 0 给出 [1, 0, …, 0]（长度 %d，元素和 = 1）", (long) c, null);

        final long[] only = FusePirQuery.oneHot(1, 0);
        check(only.length == 1 && only[0] == 1L,
            "C = 1 退化情形：oneHot(1, 0) = [1]（论文那组实验的 C = 1，见 MAP §13.3）", null, null);
        check(throwsIae(new Runnable() {
            @Override
            public void run() {
                FusePirQuery.oneHot(1, 1);
            }
        }), "C = 1 时 c_a = 1 必须抛", null, null);
    }

    /**
     * <b>改动后 {@code CapeQuery.encryptColumnSelectors} 的那段循环在探针里复写一遍，与内联版比。</b>
     *
     * <p>它补的是上一节的一个缺口：上一节比的是「oneHot 的明文输出」，
     * 而 {@code CapeQuery} 里真正改掉的是「怎么把 {@code k} 条 one-hot 拼成 {@code k·C} 长向量」。
     * 这里把改动后的拼法（{@code arraycopy 到 a*c}）与改动前的拼法（双重循环赋值）都跑一遍，
     * 对全部关键词逐位比 —— <b>钉住「拼法」这一半</b>。
     *
     * <p>⚠️ 仍然不是对 {@code CapeQuery} 字节流的验证（那要 native）。
     * 三行改动的字面正确性靠复核：{@code e} 是全零、{@code ea} 长度 {@code c}、
     * 拷贝区间 {@code [a*c, a*c+c)} 不重叠。
     */
    private static void diffAgainstCapeQueryShape(CapeDemoData.Tables tb, int kwCount) {
        final int r = tb.layout.r;
        final int c = tb.layout.c;
        long bad = 0;
        for (int i = 0; i < kwCount; i++) {
            final long[] colIdx = new long[K];
            for (int a = 0; a < K; a++) {
                colIdx[a] = FusePirQuery.split(tb.pos[i][a], r, c).c();
            }
            if (!Arrays.equals(newSelectorsFromOneHot(c, colIdx), inlineOneHotFlat(K, c, colIdx))) {
                bad++;
            }
        }
        check(bad == 0,
            "★ 拼法等价：'oneHot + arraycopy 到 a·c'（改动后）与 '双重循环赋值'（改动前）"
                + "对全部 %d 个关键词逐位一致",
            (long) kwCount, null);
    }

    // ==================================================================
    //  原/新表达式的**现场重算**（逐字照抄两段循环）
    // ==================================================================

    /**
     * 改动<b>前</b> {@code CapeQuery.encryptColumnSelectors} 里那段循环的逐字重算：
     * <pre>
     *   long[] e = new long[k * c];
     *   for (int a = 0; a &lt; k; a++)
     *       for (int cc = 0; cc &lt; c; cc++)
     *           e[a * c + cc] = (cc == colIdx[a]) ? 1L : 0L;
     * </pre>
     */
    private static long[] inlineOneHotFlat(int k, int c, long[] colIdx) {
        final long[] e = new long[k * c];
        for (int a = 0; a < k; a++) {
            for (int cc = 0; cc < c; cc++) {
                e[a * c + cc] = (cc == colIdx[a]) ? 1L : 0L;
            }
        }
        return e;
    }

    /**
     * 改动<b>后</b>那段循环的逐字重算（{@code oneHot} + {@code arraycopy}）。
     *
     * <p>注意它<b>不是</b>在调 {@code CapeQuery}（那个方法要 native 上下文句柄），
     * 而是把改动后的循环在这里复写一遍。
     */
    private static long[] newSelectorsFromOneHot(int c, long[] colIdx) {
        final long[] e = new long[K * c];
        for (int a = 0; a < K; a++) {
            final long[] ea = FusePirQuery.oneHot(c, colIdx[a]);
            System.arraycopy(ea, 0, e, a * c, c);
        }
        return e;
    }

    // ==================================================================
    //  工具
    // ==================================================================

    /** 断言 {@code body} 抛 {@link IllegalArgumentException}（越界必须报错，不能静默算下去）。 */
    private static boolean throwsIae(Runnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        } catch (RuntimeException e) {
            return false;                     // 抛了别的异常也算不合格
        }
    }

    /** 与 {@code CapePaperGeometryTest} 同一形状的检查计数（1 个 / 2 个 / 3 个参数的三个重载）。 */
    private static void check(boolean ok, String fmt, Long a, Long b) {
        checks++;
        final String msg;
        if (a == null) {
            msg = fmt;
        } else if (b == null) {
            msg = String.format(fmt, a);
        } else {
            msg = String.format(fmt, a, b);
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }

    private static void check(boolean ok, String fmt, Long a, Long b, Long c) {
        checks++;
        final String msg = (a == null) ? fmt : String.format(fmt, a, b, c);
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }

    private static void check(boolean ok, String fmt, Long a, Long b, Long c, Long d) {
        checks++;
        final String msg = (a == null) ? fmt : String.format(fmt, a, b, c, d);
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
