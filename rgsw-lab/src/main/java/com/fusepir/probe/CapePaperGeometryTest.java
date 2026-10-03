package com.fusepir.probe;

import com.fusepir.bff.BffSetup;
import com.fusepir.bff.CapeDemoData;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <b>论文几何的建表验收（纯 Java，无同态）</b> —— 把
 * {@link CapeDemoData#buildTablesPaper} 产出的表逐项验一遍。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.CapePaperGeometryTest [db] [N] [forceR]
 * </pre>
 *
 * <h3>本探针验的那一条，就是 ANSWER 真正做的事</h3>
 * ANSWER 的形状是
 * <pre>
 *   Acc_{a,b} ← Σ_c CtPtMul(q_a^col[c], P_{c,b}(X))     （选出第 c_a 列）
 *   Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b})        （把第 r_a 个系数转到常数项）
 *   ct_{a,b} ← SampleExtract_0(Acc'_{a,b})              （取出来）
 *   ct_{pay,b} ← Σ_a ct_{a,b}                            （三路相加）
 * </pre>
 * 所以明文侧它取到的就是 {@code Σ_a P_{c_a,b}[r_a]}，必须**逐位等于** {@code y_{K}[b]}。
 * 本探针把这条路在明文上走一遍：<b>任何一个关键词任何一个载荷位对不上，就是假阴性。</b>
 *
 * <h3>⚠️ 与旧几何探针（{@code CapeTableDiag}）的关系</h3>
 * {@code CapeTableDiag} 验的是旧几何（1 位置 + 连续 k 行），它仍然会通过
 * —— 那套代码还在。**本探针才是论文几何的验收**，两者不是同一个东西。
 */
public final class CapePaperGeometryTest {

    private static int checks;
    private static int fails;

    private CapePaperGeometryTest() {
    }

    public static void main(String[] args) throws Exception {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int forceR = args.length > 2 ? Integer.parseInt(args[2]) : 0;
        final int k = 3;
        final long tableSeed = 20261013L;
        final long hashSeed = 20261014L;

        final CapeDemoData db = CapeDemoData.load(dbPath);
        final long t = db.longMeta("plainModulus", 65537L);
        final int kwCount = db.keywords.size();

        System.out.println("=== 论文几何建表验收 ===");
        System.out.println("  DB = " + dbPath + "（关键词 " + kwCount + " 个）");
        System.out.println("  N = " + ringDim + ", k = " + k + ", t = " + t
            + ", forceR = " + (forceR == 0 ? "0（方格策略）" : String.valueOf(forceR)));

        final long t0 = System.nanoTime();
        final CapeDemoData.Tables tb = db.buildTablesPaper(ringDim, k, t, tableSeed, forceR, hashSeed);
        final long buildMs = (System.nanoTime() - t0) / 1_000_000;

        final BffSetup.Layout lo = tb.layout;
        System.out.println("  建表耗时 = " + buildMs + " ms");
        System.out.println("  布局 = " + lo);
        System.out.println("  B_pay = " + tb.bPay + ", maxValues = " + tb.maxValues
            + ", lBf = " + tb.lBf);
        System.out.println("  表形状 = [" + tb.c + "][" + tb.bPay + "][" + ringDim + "]"
            + " = " + ((long) tb.c * tb.bPay * ringDim / 1024 / 1024) + " M long");

        check(tb.isPaperGeometry(), "走的是论文几何（Tables.pos 非 null）", null, null);
        check(lo.rc() >= lo.lBff, "A1 SETUP 4 约束 RC ≥ L_BFF（%d ≥ %d）", lo.rc(), lo.lBff);
        check(lo.r <= ringDim, "A1 SETUP 4 约束 R ≤ N（%d ≤ %d）", (long) lo.r, (long) ringDim);

        // ── 位置：范围 + 互异 ───────────────────────────────────────────
        boolean inRange = true;
        boolean distinct = true;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < k; a++) {
                final int u = tb.pos[i][a];
                if (u < 0 || u >= lo.lBff) {
                    inRange = false;
                }
            }
            for (int a = 0; a < k; a++) {
                for (int bb = a + 1; bb < k; bb++) {
                    if (tb.pos[i][a] == tb.pos[i][bb]) {
                        distinct = false;
                    }
                }
            }
        }
        check(inRange, "全部 h_a(K) 落在 [0, L_BFF) = [0, %d)", lo.lBff, null);
        check(distinct, "同一个关键词的 k 个位置互异", null, null);

        // ── ★ 核心：Σ_a P[c_a][r_a] == y_K（这才是 ANSWER 的明文侧） ─────
        int badCells = 0;
        int firstBadKw = -1;
        int firstBadBit = -1;
        for (int i = 0; i < kwCount; i++) {
            final long[] y = new long[tb.bPay];
            for (int a = 0; a < k; a++) {
                final int[] cr = tb.colRow(i, a);
                for (int b = 0; b < tb.bPay; b++) {
                    y[b] = Math.floorMod(y[b] + tb.p[cr[0]][b][cr[1]], tb.t);
                }
            }
            for (int b = 0; b < tb.bPay; b++) {
                if (y[b] != tb.payload[i][b]) {
                    if (firstBadKw < 0) {
                        firstBadKw = i;
                        firstBadBit = b;
                    }
                    badCells++;
                }
            }
        }
        check(badCells == 0,
            "★ Σ_a P_{c_a,b}[r_a] = y_K[b] 对**全部 %d 个关键词 × %d 个载荷位**成立（假阴性 0）",
            (long) kwCount, (long) (kwCount * tb.bPay));
        if (firstBadKw >= 0) {
            System.out.println("    首个失配：kw=" + firstBadKw + "（" + db.keywords.get(firstBadKw)
                + "）bit=" + firstBadBit);
        }

        // ── 尾部补零（A1 SETUP 9-11）：系数 [R, N) 必须全 0 ─────────────
        long outsideRadius = 0;
        for (int c = 0; c < tb.c; c++) {
            for (int b = 0; b < tb.bPay; b++) {
                for (int r = lo.r; r < ringDim; r++) {
                    if (tb.p[c][b][r] != 0) {
                        outsideRadius++;
                    }
                }
            }
        }
        check(outsideRadius == 0, "系数 [R, N) = [%d, %d) 全为 0（只有前 R 个系数有数据）",
            (long) lo.r, (long) ringDim);

        // ── 几何确实是二维的：关键词的三条路应落在不同列 ────────────────
        //    若 C = 1 则必然同列 —— 那种情况下这一条不适用，直接报出来。
        long sameCol = 0;
        for (int i = 0; i < kwCount; i++) {
            final int c0 = tb.colRow(i, 0)[0];
            for (int a = 1; a < k; a++) {
                if (tb.colRow(i, a)[0] == c0) {
                    sameCol++;
                }
            }
        }
        if (lo.c == 1) {
            System.out.println("    （C = 1，列选择子退化为 Enc([1])，同列是必然的 —— 见 MAP §12.7）");
            check(sameCol == (long) kwCount * (k - 1), "C = 1 时三条路必然同列（%d 个）", sameCol, null);
        } else {
            check(sameCol < (long) kwCount * (k - 1),
                "多列几何下三路确实分散在不同列（同列仅 %d/%d）",
                sameCol, (long) (kwCount * (k - 1)));
        }

        // ── 确定性：同种子重建必须逐位相同 ──────────────────────────────
        final CapeDemoData.Tables tb2 = db.buildTablesPaper(ringDim, k, t, tableSeed, forceR, hashSeed);
        boolean sameTable = tb2.layout.r == lo.r && tb2.layout.c == lo.c
            && tb2.layout.lBff == lo.lBff;
        for (int i = 0; i < kwCount && sameTable; i++) {
            sameTable = java.util.Arrays.equals(tb.pos[i], tb2.pos[i]);
        }
        for (int c = 0; c < tb.c && sameTable; c++) {
            for (int b = 0; b < tb.bPay && sameTable; b++) {
                sameTable = java.util.Arrays.equals(tb.p[c][b], tb2.p[c][b]);
            }
        }
        check(sameTable, "同种子重建逐位一致（固定种子下 demo 表可复现）", null, null);

        // ── 负对照：改一个被读到的系数 ⇒ 必有关键词失配 ─────────────────
        final int vi = 0;
        final int[] vcr = tb.colRow(vi, 0);
        final long[][][] corrupt = new long[tb.c][][];
        for (int c = 0; c < tb.c; c++) {
            corrupt[c] = new long[tb.bPay][];
            for (int b = 0; b < tb.bPay; b++) {
                corrupt[c][b] = tb.p[c][b].clone();
            }
        }
        corrupt[vcr[0]][0][vcr[1]] = Math.floorMod(corrupt[vcr[0]][0][vcr[1]] + 1, tb.t);
        int corruptBad = 0;
        for (int i = 0; i < kwCount; i++) {
            final long[] y = new long[tb.bPay];
            for (int a = 0; a < k; a++) {
                final int[] cr = tb.colRow(i, a);
                for (int b = 0; b < tb.bPay; b++) {
                    y[b] = Math.floorMod(y[b] + corrupt[cr[0]][b][cr[1]], tb.t);
                }
            }
            if (!java.util.Arrays.equals(y, tb.payload[i])) {
                corruptBad++;
            }
        }
        check(corruptBad >= 1, "[负对照] 改动一个被读到的系数（kw=0, 第 0 路）⇒ %d 个关键词失配",
            (long) corruptBad, null);

        // ── 负对照：把 (c,r) 反算错（用旧几何的行公式）⇒ 必须大面积失配 ──
        //    这条防的是"新表配旧索引"这种静默错配。
        int oldStyleBad = 0;
        for (int i = 0; i < kwCount; i++) {
            final long[] y = new long[tb.bPay];
            for (int a = 0; a < k; a++) {
                final int u = tb.pos[i][a];
                final int c = u / lo.c;                  // ← 故意写错
                final int r = (u % lo.c) * Math.max(1, tb.maxValues) + a;
                if (c < tb.c && r < ringDim) {
                    for (int b = 0; b < tb.bPay; b++) {
                        y[b] = Math.floorMod(y[b] + tb.p[c][b][r], tb.t);
                    }
                }
            }
            if (!java.util.Arrays.equals(y, tb.payload[i])) {
                oldStyleBad++;
            }
        }
        check(oldStyleBad >= 1, "[负对照] 用错的行/列公式反算 ⇒ %d/%d 个关键词失配（新表配旧索引会被抓到）",
            (long) oldStyleBad, (long) kwCount);

        // ── ★ 跨端一致性：CapeQuery 算的索引必须与建表时的 colRow 逐位一致 ──
        //    这是最危险的一类错：客户端与服务端各算一套，**两边都不报错**，
        //    只是查错槽 ⇒ 载荷全 0 或假阴性。所以对**全部**关键词都过一遍。
        final int maxSetSize = db.intMeta("maxSetSize", 4);
        final double epsBf = db.meta.get("epsBf") instanceof Number
            ? ((Number) db.meta.get("epsBf")).doubleValue() : Math.pow(2, -6);
        final int[] bskBits = new int[16];              // 本检查不看 β，只要形状对

        int mismatch = 0;
        int firstMismatchKw = -1;
        for (int i = 0; i < kwCount; i++) {
            final com.fusepir.cape.CapeQuery.Sealed q = com.fusepir.cape.CapeQuery.buildPaper(
                0L, ringDim, k, lo, tb.pos, tb.kwIndex, tb.lBf, maxSetSize, epsBf, bskBits,
                java.util.List.of(db.keywords.get(i)), false);
            for (int a = 0; a < k; a++) {
                final int[] want = tb.colRow(i, a);
                if (q.colIdx[a] != want[0] || q.rowIdx[a] != want[1]) {
                    if (firstMismatchKw < 0) {
                        firstMismatchKw = i;
                    }
                    mismatch++;
                }
            }
        }
        check(mismatch == 0,
            "★ CapeQuery.buildPaper 的 (c_a, r_a) 与建表的 colRow 对**全部 %d 个关键词 × %d 路**逐位一致",
            (long) kwCount, (long) (kwCount * k));
        if (firstMismatchKw >= 0) {
            System.out.println("    首个不一致：kw=" + firstMismatchKw);
        }

        // ── 负对照：把位置表整体换成**另一个关键词**的 ⇒ 索引必须对不上 ──
        final int[][] swapped = new int[kwCount][];
        for (int i = 0; i < kwCount; i++) {
            swapped[i] = tb.pos[(i + 1) % kwCount];
        }
        int swapBad = 0;
        // ⚠️ 期望值不是 kwCount：**位置函数允许两个关键词共用同一个 h_0**
        //    （那正是要剥皮的原因）。错位后若 h_0 撞上，索引当然还对得上。
        //    所以精确期望 = kwCount − 撞上的个数。第一版我写成 == kwCount，
        //    实测 126/128，是**期望写错**而不是代码错。
        int collided = 0;
        for (int i = 0; i < kwCount; i++) {
            if (tb.pos[(i + 1) % kwCount][0] == tb.pos[i][0]) {
                collided++;
            }
        }
        for (int i = 0; i < kwCount; i++) {
            final com.fusepir.cape.CapeQuery.Sealed q = com.fusepir.cape.CapeQuery.buildPaper(
                0L, ringDim, k, lo, swapped, tb.kwIndex, tb.lBf, maxSetSize, epsBf, bskBits,
                java.util.List.of(db.keywords.get(i)), false);
            final int[] want = tb.colRow(i, 0);
            if (q.colIdx[0] != want[0] || q.rowIdx[0] != want[1]) {
                swapBad++;
            }
        }
        check(swapBad == kwCount - collided, String.format(
            "[负对照] 位置表错位一个关键词 ⇒ %d/%d 个索引对不上"
                + "（余下 %d 个是 h_0 本来就撞了，属预期）",
            swapBad, kwCount, collided), null, null);

        legacyEquivalenceSection(db, ringDim, k, t, maxSetSize, epsBf, bskBits);
        fingerprint40Section(db, tb, t);

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        System.out.println("   覆盖：A3 SETUP 2/3/9、A1 SETUP 4/6/8/9-11/12-16、A1 QUERY 3、"
            + "跨端索引一致性");
        if (fails != 0) {
            System.exit(1);
        }
    }

    /**
     * <b>旧几何分支的等价性回归</b>：{@code CapeQuery.build} 被拆成
     * "先算几何 → 再交给 {@code buildWithIndices}"，**必须逐位等价**。
     *
     * <p>为什么必须有这一条：那个重构只保证"编译通过"，而**服务的默认路径正在用它**。
     * "编译 0 错误"不是等价性的证据 —— 本轮我已经被这条教训咬过一次
     * （一个正则替换静默吃掉两行赋值，代码照样编译）。
     * 所以这里把旧建表的 {@code (colOf, rowOf)} 与客户端算出的 {@code (c_a, r_a)} 逐个对。
     */
    private static void legacyEquivalenceSection(CapeDemoData db, int ringDim, int k, long t,
                                                 int maxSetSize, double epsBf, int[] bskBits) {
        System.out.println();
        System.out.println("--- 旧几何分支的等价性（CapeQuery.build 重构后仍逐位一致？）---");
        final int legacyR = 16;
        final int maxValues = db.intMeta("maxValues", 3);
        final int cellsPerCol = com.fusepir.fusepir.FusePirSetup.cellsPerCol(legacyR, maxValues);
        final int legacyC = com.fusepir.fusepir.FusePirSetup.columns(db.keywords.size(), cellsPerCol);
        final CapeDemoData.Tables old = db.buildTables(ringDim, legacyC, legacyR, k, t, 20261013L);
        final int lBf = db.intMeta("lBf", 35);
        System.out.println("  旧建表：R=" + legacyR + ", cellsPerCol=" + cellsPerCol
            + ", C=" + legacyC + ", L_BFF=" + (cellsPerCol * legacyC)
            + ", 表 = [" + old.c + "][" + old.bPay + "][" + ringDim + "]");

        int bad = 0;
        int firstBad = -1;
        for (int i = 0; i < db.keywords.size(); i++) {
            final com.fusepir.cape.CapeQuery.Sealed q = com.fusepir.cape.CapeQuery.build(
                0L, ringDim, k, legacyR, maxValues, lBf, maxSetSize, epsBf, bskBits,
                db.keywords, java.util.List.of(db.keywords.get(i)), false);
            for (int a = 0; a < k; a++) {
                if (q.colIdx[a] != old.colOf[i] || q.rowIdx[a] != old.rowOf[i] + a) {
                    if (firstBad < 0) {
                        firstBad = i;
                    }
                    bad++;
                }
            }
        }
        check(bad == 0, String.format(
            "★ CapeQuery.build 重构后与旧建表逐位一致（%d 关键词 × %d 路 = %d 项）",
            db.keywords.size(), k, db.keywords.size() * k), null, null);
        if (firstBad >= 0) {
            System.out.println("    首个不一致：kw=" + firstBad + "（" + db.keywords.get(firstBad) + "）");
        }

        // 负对照：把 R 换成另一个值 ⇒ 索引必须大面积变
        final int otherR = 8;
        int otherBad = 0;
        for (int i = 0; i < db.keywords.size(); i++) {
            final com.fusepir.cape.CapeQuery.Sealed q = com.fusepir.cape.CapeQuery.build(
                0L, ringDim, k, otherR, maxValues, lBf, maxSetSize, epsBf, bskBits,
                db.keywords, java.util.List.of(db.keywords.get(i)), false);
            if (q.colIdx[0] != old.colOf[i] || q.rowIdx[0] != old.rowOf[i]) {
                otherBad++;
            }
        }
        check(otherBad > 0, String.format(
            "[负对照] 把 R 从 %d 换成 %d ⇒ %d/%d 个索引变了（检查确实在比对）",
            legacyR, otherR, otherBad, db.keywords.size()), null, null);
    }

    /**
     * <b>40-bit 指纹的验收</b>（论文 §5.1：μ = 40）。
     *
     * <p>2026-10-14 深夜把 {@code fp} 从 32-bit {@code String.hashCode} 改成 40-bit。
     * 关键点是 <b>40 bit 装不进一个 {@code Z_t} 槽</b>（论文自己的 `t = 65537` 也是
     * 16 bit/槽）⇒ {@code fp} 占 {@code fpSlots = ⌈40/⌊log2 t⌋⌉} 个槽。
     *
     * <p>所以这一节要验三件事，缺一不可：
     * <ol>
     *   <li>{@code fpSlots} 算对（`t = 2^32` ⇒ 2；论文的 `t = 65537` ⇒ 3）；</li>
     *   <li><b>拆—拼往返</b>：从载荷里拼回的 40-bit 值 == {@code BffSetup.fp(K)}；</li>
     *   <li><b>A1 DECODE 6 的 ⊥ 判据真的会拒</b>：拿**别的**关键词去校验必须 false
     *       —— 没有这条负对照，"校验通过"与"校验根本没在查"分不开。</li>
     * </ol>
     */
    private static void fingerprint40Section(CapeDemoData db, CapeDemoData.Tables tb, long t) {
        System.out.println();
        System.out.println("--- 40-bit 指纹（论文 §5.1 μ=40）---");
        final int fpSlots = com.fusepir.fusepir.FusePirSetup.fpSlots(t);
        System.out.println("  t = " + t + " ⇒ 每槽 " + com.fusepir.fusepir.FusePirSetup.slotBits(t)
            + " bit ⇒ fpSlots = " + fpSlots
            + "（论文的 t=65537 ⇒ fpSlots = "
            + com.fusepir.fusepir.FusePirSetup.fpSlots(65537L) + "）");
        System.out.println("  B_pay = " + tb.bPay + " = fpSlots(" + fpSlots + ") + 1 + m·perValue");
        System.out.println("  指纹种子 ρ_fp = " + com.fusepir.bff.BffSetup.FP_SEED
            + "（与位置函数的 ρ_H 独立，见 A3 SETUP 8）");

        check(fpSlots == 2, "t=2^32 时 fpSlots = 2（40 > 32，装不进一个槽）", null, null);
        check(com.fusepir.fusepir.FusePirSetup.fpSlots(65537L) == 3,
            "论文的 t=65537（16 bit/槽）⇒ fpSlots = 3", null, null);

        // ── 拆—拼往返 ───────────────────────────────────────────────────
        int bad = 0;
        long maxFp = 0;
        for (int i = 0; i < db.keywords.size(); i++) {
            final String kw = db.keywords.get(i);
            final long want = com.fusepir.bff.BffSetup.fp(kw);
            final long got = com.fusepir.bff.BffSetup.fpFromDigits(tb.payload[i], 0, fpSlots, t);
            if (want != got) {
                if (bad < 3) {
                    System.out.println("    ✗ kw=" + i + "（" + kw + "）拼回 " + got + " != " + want);
                }
                bad++;
            }
            maxFp = Math.max(maxFp, want);
        }
        check(bad == 0, "拆—拼往返：全部 %d 个关键词的 40-bit 指纹都能从载荷拼回",
            (long) db.keywords.size(), null);
        check(maxFp >= (1L << 32),
            "指纹最大值 %d ≥ 2^32 —— 确实用到了 32 bit 以上的位（32-bit 版做不到）",
            maxFp, null);

        // ── A1 DECODE 6 的 ⊥ 判据 ───────────────────────────────────────
        int okCount = 0;
        for (int i = 0; i < db.keywords.size(); i++) {
            if (com.fusepir.fusepir.FusePirDecode.fingerprintOk(
                    db.keywords.get(i), tb.payload[i], t)) {
                okCount++;
            }
        }
        check(okCount == db.keywords.size(),
            "★ 正确的关键词：fingerprintOk 对全部 %d 个都通过（假阴性 0）",
            (long) db.keywords.size(), null);

        // 负对照：拿别的关键词的指纹去校验 ⇒ 必须拒
        int rejCount = 0;
        for (int i = 0; i < db.keywords.size(); i++) {
            final String wrongKw = db.keywords.get((i + 1) % db.keywords.size());
            if (!com.fusepir.fusepir.FusePirDecode.fingerprintOk(wrongKw, tb.payload[i], t)) {
                rejCount++;
            }
        }
        check(rejCount == db.keywords.size(),
            "[负对照] 用错的关键词去校验 ⇒ %d/%d 全部被拒（⊥ 判据真的在查）",
            (long) rejCount, (long) db.keywords.size());

        // 负对照：改动指纹槽的一位 ⇒ 必须拒
        final long[] tampered = tb.payload[0].clone();
        tampered[0] = (tampered[0] + 1) % t;
        check(!com.fusepir.fusepir.FusePirDecode.fingerprintOk(
                db.keywords.get(0), tampered, t),
            "[负对照] 把指纹槽改 1 ⇒ 校验失败（不是恒真）", null, null);
    }

    private static void check(boolean ok, String fmt, Long a, Long b) {        checks++;
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
}
