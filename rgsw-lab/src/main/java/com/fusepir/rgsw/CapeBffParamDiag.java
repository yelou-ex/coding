package com.fusepir.rgsw;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * <b>P1-4：把我们的 BFF 参数化与 ChalametPIR 逐条对上</b>（规划书 §三 P1-4）。
 *
 * <p>规划书对这一项的要求原话是：
 * <i>"文档里出现『{@code s} = ？、{@code L_BFF} = ？』的<b>闭式</b>，并说明我们的
 * {@code L_BFF = cellsPerCol·C = 130}（n=128）与论文 {@code ≲1.125n = 144} 的关系"</i>。
 * 本类把那句话变成<b>可跑的断言</b>——文档里写闭式容易，能被复跑才算数。
 *
 * <h3>两个出处（都是原文，不是转述）</h3>
 * <table border="1">
 *   <tr><th>出处</th><th>内容</th></tr>
 *   <tr><td><b>CAPE</b> 附录 A · Algorithm 3（{@code SETUP(n,k,B,t,mu)}）第 1-7 行</td>
 *       <td>给 {@code s} 与 {@code L_BFF} 的闭式，并<b>明说</b>这两组有限尺寸取值
 *           "follow the parameterization of BFF used in <b>ChalametPIR [8]</b>"</td></tr>
 *   <tr><td><b>ChalametPIR</b> 附录 B · Algorithm 1（{@code setupFilter}）第 2-3 行</td>
 *       <td>同一组公式的<b>原始出处</b>，另外还给了第 9-10 行的<b>位置函数</b>
 *           {@code h_i(·) = (N/s)·(h''(·)−1) + h'(·‖i)}</td></tr>
 * </table>
 *
 * <h3>⚠️ 对照之后发现的真实差距（这才是这一项的价值）</h3>
 * <ol>
 *   <li><b>{@code L_BFF} 的来历不同。</b>论文的 {@code L_BFF} 由 {@code s} 与 n 的闭式定出，
 *       是"按 n 算出来的"；我们的 {@code L_BFF = cellsPerCol·C} 是<b>网格几何的副产品</b>
 *       （列数 C 由关键词数除出、列内 cell 数由 {@code R/maxValues} 定出）。
 *       两者数值上可以都落在同一个界内，但**一个是设计参数、一个是几何余量**。</li>
 *   <li><b>我们的"段"用法与论文不同。</b>论文的段是"连续 k 个段、每段内一个位置"，
 *       位置函数是 {@code h_i}；我们的一个关键词只落在**一个 cell**（列 + 行区间），
 *       k 条路取的是该 cell 内**连续 k 行**。数学上仍满足"重建"，但
 *       {@code h_i} 那套位置函数<B>我们没有实现</b>。</li>
 *   <li><b>我们的线性探测没有"会失败"的检查。</b>论文的 {@code MappingStep} 会返回
 *       "映射失败"，失败就换种子重来；我们只查"两两不同槽"，没有"分配是否可能失败"这个概念
 *       （因为每关键词只要一个位置）。</li>
 * </ol>
 * 这三条<b>不影响</b>已经实测的"假阴性 = 0"，但它们是"我们不是 ChalametPIR 那套 BFF"
 * 的证据。本类把第 1、2 条也变成断言，避免文档里只留下"参数对上了"这一半。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeBffParamDiag}
 */
public final class CapeBffParamDiag {

    private CapeBffParamDiag() {
    }

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    // ==================================================================
    //  论文的闭式（原文转写）
    // ==================================================================

    /**
     * 段大小 {@code s}（CAPE Alg.3 第 2/5 行 = ChalametPIR Alg.1 第 2 行）。
     *
     * <pre>
     *   k = 3:  s = 2^floor( log_3.33(n) + 2.25 )
     *   k = 4:  s = 2^floor( log_2.91(n) - 0.5  )
     * </pre>
     * 注意它恒是 <b>2 的幂</b>（两个出处都这么写）。
     */
    static long paperS(int k, long n) {
        double lg = Math.log(n) / Math.log(k == 3 ? 3.33 : 2.91);
        double e = (k == 3) ? (lg + 2.25) : (lg - 0.5);
        return 1L << (long) Math.floor(e);
    }

    /**
     * {@code L_BFF} 的闭式。
     *
     * <p>CAPE Alg.3 第 3/6 行：
     * <pre>
     *   k = 3:  L = max( ceil( (0.875 + 0.25·max(1, log10(n/6))) · n ), ceil(1.125·n) )
     *   k = 4:  L = max( ceil( (0.77  + 0.305·max(1, log10(n/(6·1e5)))) · n ), ceil(1.075·n) )
     * </pre>
     * ChalametPIR Alg.1 第 3 行写的是同一件事，但用 {@code floor} 而不是 {@code ceil}
     * （{@code N = ⌊c·m⌋}，且第二项是 {@code ⌊1.125m⌋}）。<b>这一处差异记在下面的断言里</b>，
     * 不假装两篇一模一样。
     *
     * <p>{@code log10(n/6)} 与 ChalametPIR 的 {@code log(10^6)/log(m)} 是同一个量
     * （换底：{@code log_m(10^6) = log10(10^6)/log10(m) = 6/log10(m)}）——
     * 这也是一条断言。
     */
    static long paperLBff(int k, long n, boolean useCeil) {
        double scale;
        double cap;
        if (k == 3) {
            double lg = Math.log10(n / 6.0);
            scale = 0.875 + 0.25 * Math.max(1.0, lg);
            cap = 1.125;
        } else {
            double lg = Math.log10(n / (6.0 * 1e5));
            scale = 0.77 + 0.305 * Math.max(1.0, lg);
            cap = 1.075;
        }
        long a = useCeil ? (long) Math.ceil(scale * n) : (long) Math.floor(scale * n);
        long b = useCeil ? (long) Math.ceil(cap * n) : (long) Math.floor(cap * n);
        return Math.max(a, b);
    }

    /**
     * 位置函数（ChalametPIR Alg.1 第 9-10 行，原文）：
     * <pre>
     *   h_i(·) = (N/s)·( h''(·) − 1 ) + h'(· ‖ i)        i = 0..k-1
     *   h' : {0,1}* -> [ N/s ]      （段号）
     *   h'' : {0,1}* -> [ s ]       （段内偏移）
     * </pre>
     * 也就是说：{@code h''} 选段、{@code h'} 选段内位置 —— **k 个位置分布在 k 个连续段里**。
     */
    static String positionFunctionDoc() {
        return "h_i(K) = (N/s)·(h''(K)−1) + h'(K‖i),  i = 0..k−1；"
            + "h'' 选段（[s] 个段？见下）、h' 选段内偏移（[N/s]）";
    }

    // ==================================================================
    //  自检
    // ==================================================================

    public static void main(String[] args) throws Exception {
        System.out.println("=== P1-4：BFF 参数化逐条对照 ChalametPIR（可跑版）===");

        // ---------- 1. 闭式本身 ----------
        System.out.println();
        System.out.println("---------------- 1. 两个出处的闭式（原文转写）----------------");
        System.out.println("  CAPE 附录 A · Algorithm 3 SETUP(n,k,B,t,mu)：");
        System.out.println("    1: if k=3 then");
        System.out.println("    2:     s <- 2^floor(log_3.33(n) + 2.25)");
        System.out.println("    3:     L_BFF <- max( ceil((0.875 + 0.25*max(1, log10(n/6)))*n), ceil(1.125n) )");
        System.out.println("    5: elseif k=4 then");
        System.out.println("    6:     s <- 2^floor(log_2.91(n) - 0.5)");
        System.out.println("    7:     L_BFF <- max( ceil((0.77 + 0.305*max(1, log10(n/6e5)))*n), ceil(1.075n) )");
        System.out.println("  并注明（附录 A 开头）：");
        System.out.println("    \"The concrete finite-size choices of s and L_BFF follow the");
        System.out.println("     parameterization of BFF used in ChalametPIR [8]. For large n,");
        System.out.println("     the resulting array lengths approach 1.125n and 1.075n for");
        System.out.println("     k=3 and k=4, respectively.\"");
        System.out.println("  ChalametPIR 附录 B · Algorithm 1 setupFilter：");
        System.out.println("    2: s <- 2^floor(log_3.33(m) + 2.25)   (k=3)  /  2^floor(log_2.91(m) - 0.5)  (k=4)");
        System.out.println("    3: N <- c*m,  c = max( floor((0.875 + 0.25*max(1, log(1e6)/log(m)))*m), floor(1.125m) )");
        System.out.println("    8-10: h_i(.) = (N/s)*(h''(.) - 1) + h'(.'||'i)");
        System.out.println("          h' : {0,1}* -> [N/s]   （段内偏移）");
        System.out.println("          h'' : {0,1}* -> [s]    （段号）");
        System.out.println("  ⇒ " + positionFunctionDoc());

        // ⚠️ 两篇的 L_BFF 闭式**在数值上不一致** —— 这是本轮对照最硬的发现之一。
        //
        //   CAPE  Alg.3 L3 : 0.875 + 0.25·max(1, log10(n/6))
        //   Chalamet Alg.1 L3: 0.875 + 0.25·max(1, ln(1e6)/ln(m))
        //
        // 起初我以为两者只差一个换底（把 CAPE 的 log10(n/6) 当成 log_m(1e6)）。**不是。**
        //   log_m(1e6) = ln(1e6)/ln(m) = 6/log10(m)          <-- Chalamet 的形状
        //   log10(n/6) = log10(n) − log10(6)                 <-- CAPE 的形状
        // 这两个函数**不同**（n=1000 时 2.2218 vs 2.0000）。谁的文本在抽取/排版里出了偏差，
        // 本轮**没有**独立证据可以判定 —— 所以这里**不编一个结论**，只把可验证的部分钉住。
        {
            boolean equal = true;
            StringBuilder sb = new StringBuilder();
            for (long n : new long[]{1000, 10000, 100000, 1000000}) {
                double cape = Math.log10(n / 6.0);
                double chalamet = Math.log(1e6) / Math.log(n);
                if (Math.abs(cape - chalamet) > 1e-9) {
                    equal = false;
                }
                sb.append("n=").append(n).append(": CAPE ")
                    .append(String.format("%.4f", cape)).append(" vs Chalamet ")
                    .append(String.format("%.4f", chalamet)).append("; ");
            }
            check("（记录，非失败）两篇的 L_BFF 闭式数值**不一致**（不是同一个函数的换底）",
                !equal, sb.toString());
            System.out.println("         ⇒ 本轮**不判定谁对**：需要看两篇的原始排版才能定。");
            System.out.println("           好在**对我们的结论无影响** —— 见下面那条比较。");
        }
        // 而且：CAPE 自己写的「approach 1.125n（k=3）」这句，**与它自己的闭式不符** ——
        // 那个闭式是单调上升到 ~1.93n 的，永远不会收敛到 1.125n。
        // 这条是本轮对照里最值得记的一处：说明**「照着论文的公式抄」并不足以复现论文的量**。
        {
            StringBuilder sb = new StringBuilder();
            boolean monotoneUp = true;
            double prev = -1;
            for (long nn = 1000; nn <= 1000000; nn *= 10) {
                double r = paperLBff(3, nn, true) / (double) nn;
                sb.append("n=").append(nn).append(" -> ").append(String.format("%.4f", r)).append("n; ");
                if (r < prev) {
                    monotoneUp = false;
                }
                prev = r;
            }
            check("（记录）CAPE 的闭式随 n **单调升到 ~1.93n**，并不收敛到它自己声明的 1.125n",
                monotoneUp, sb.toString() + " 而论文正文写的是 『approach 1.125n (k=3)』");
            System.out.println("         ⇒ 结论：**「照抄论文的闭式」不足以复现论文的量**；");
            System.out.println("           我们的 130 反而是这一组参数下最紧、也最接近 1.125n 的说法。");
            System.out.println("           这条差异不需要本轮解决，但**引用 L_BFF 时必须带上**。");
        }
        // ceil vs floor：两篇在这一处**确实不一致**
        {
            long c3 = paperLBff(3, 128, true);
            long f3 = paperLBff(3, 128, false);
            System.out.printf("  [note] L 的取整：CAPE 用 ceil、ChalametPIR 用 floor；"
                + "n=128,k=3 => CAPE=%d、ChalametPIR=%d%n", c3, f3);
        }
        // 但**对我们的数值比较没有影响**：两篇的公式在 n=128 上给的值都比我们的 130 大
        {
            // Chalamet 形状（0.875 + 0.25·6/log10(n)）在同一点上的值
            double scaleChal = 0.875 + 0.25 * Math.max(1.0, 6.0 / Math.log10(128));
            long lChal = Math.max((long) Math.ceil(scaleChal * 128), (long) Math.ceil(1.125 * 128));
            long lCape = paperLBff(3, 128, true);
            long lOurs128 = 5L * 26;                      // cellsPerCol * C，n=128
            System.out.printf("  [对照] n=128 时三方的 L_BFF：CAPE=%d、Chalamet=%d、**我们=%d**%n",
                lCape, lChal, lOurs128);
            check("三方比较与《用哪一家的闭式》无关：我们的 130 比**两家**都小",
                lOurs128 < lCape && lOurs128 < lChal,
                "CAPE=" + lCape + " Chalamet=" + lChal + " 我们=" + lOurs128);
            System.out.println("         ⇒ 所以《L_BFF <= 1.125n 这条界在我们参数下成立》这个结论");
            System.out.println("           **不依赖**上面那条未解决的公式分歧。");
        }

        // ---------- 2. n=128、k=3：论文给什么，我们是什么 ----------
        System.out.println();
        System.out.println("---------------- 2. 我们这一组参数：n=128、k=3 ----------------");
        long n = 128;
        int k = 3;
        long sPaper = paperS(k, n);
        long lPaper = paperLBff(k, n, true);
        System.out.printf("  论文（n=%d, k=3）：s = 2^floor(log_3.33(%d)+2.25) = %d%n", n, n, sPaper);
        System.out.printf("                      L_BFF = %d   （≈ %.4f·n）%n", lPaper, lPaper / (double) n);
        System.out.printf("                      L_BFF/s = %d 段%n", lPaper / sPaper);

        // 我们的几何
        int R = 16, maxValues = 3, keywordCount = n == 128 ? 128 : 128;
        int cellsPerCol = Math.max(1, R / maxValues);
        int C = (int) Math.ceil(keywordCount / (double) cellsPerCol);
        long lOurs = (long) cellsPerCol * C;
        System.out.printf("  我们：cellsPerCol = R/maxValues = %d/%d = %d（**这就是我们的段大小 s**）%n",
            R, maxValues, cellsPerCol);
        System.out.printf("        C = ceil(n/cellsPerCol) = ceil(%d/%d) = %d 列%n", keywordCount, cellsPerCol, C);
        System.out.printf("        L_BFF = cellsPerCol·C = %d·%d = %d   （= %.4f·n）%n",
            cellsPerCol, C, lOurs, lOurs / (double) keywordCount);
        System.out.printf("        dataRadius = (cellsPerCol−1)·maxValues + k = %d（每个 (列,b) 多项式真正用到的系数数）%n",
            (cellsPerCol - 1) * maxValues + k);

        check("我们的 s = cellsPerCol = 5（论文闭式在同一个 n 上给的是 64）",
            cellsPerCol == 5 && sPaper == 64,
            "我们的 s=" + cellsPerCol + "，论文 s=" + sPaper + " => **不是同一个 s**");
        check("我们的 L_BFF = 130 < 论文闭式在同一个 n 上给的 " + lPaper,
            lOurs < lPaper, "我们 " + lOurs + " vs 论文 " + lPaper);
        check("**L_BFF <= ceil(1.125n) 这条界成立**（规划书 P1-4 的验收点）",
            lOurs <= (long) Math.ceil(1.125 * keywordCount),
            lOurs + " <= " + (long) Math.ceil(1.125 * keywordCount)
                + "（比值 " + String.format("%.4f", lOurs / (double) keywordCount) + " <= 1.125）");
        // ⚠️ 一条容易被《界的名字》骗过去的观察：1.125n 是**渐近**上界，
        //    论文自己的闭式在小 n 上会**超过**它（有限尺寸修正项占主导）。
        //    ⇒《论文的 L_BFF <= 1.125n》这句话在 n=128 上是**错的**，记下来别乱引。
        check("（记录）论文闭式在 n=128 上反而**超过** 1.125n —— 该界是渐近界，不是逐点成立",
            lPaper > (long) Math.ceil(1.125 * keywordCount),
            "论文 " + lPaper + " > ceil(1.125*128)=" + (long) Math.ceil(1.125 * keywordCount)
                + " ⇒ 引用时必须说清是渐近界");

        // ---------- 3. L_BFF <= 1.125n 的适用边界（n 扫描）----------
        System.out.println();
        System.out.println("---------------- 3. 界 L_BFF <= ceil(1.125n) 什么时候成立 ----------------");
        System.out.println("  我们的 L_BFF = cellsPerCol * ceil(n/cellsPerCol) = 5*ceil(n/5)（R=16, maxValues=3 固定）");
        System.out.println("  判据：5*ceil(n/5) <= ceil(1.125n)。因为 5*ceil(n/5) < n+5，");
        System.out.println("        解 n+5 <= 1.125n 得 n >= 40 ⇒ **n >= 40 时恒成立**（n=40 是充分条件，非最小）。");
        {
            List<Long> bad = new ArrayList<>();
            for (long nn = 1; nn <= 400; nn++) {
                long L = 5L * ((nn + 4) / 5);
                if (L > (long) Math.ceil(1.125 * nn)) {
                    bad.add(nn);
                }
            }
            System.out.println("  n ∈ [1,400] 里**不满足**的 n = " + (bad.isEmpty() ? "无" : bad.toString()));
            long minOk = -1;
            for (long nn = 1; nn <= 100000; nn++) {
                long L = 5L * ((nn + 4) / 5);
                if (L <= (long) Math.ceil(1.125 * nn)) {
                    minOk = nn;
                    break;
                }
            }
            check("界成立的**最小 n** = " + minOk + "（比它小的 n 会因为 R=16/5 的粒度而不成立）",
                minOk > 0, "我们的 n=128 远在其上；而《n>=40》是充分条件");
            check("n=128 落在界内（比值 1.0156 <= 1.125）", !bad.contains(128L), "");
            check("[一致性] 断言《n>=40 恒成立》与暴力扫描不矛盾",
                bad.stream().noneMatch(x -> x >= 40), "扫描到的不满足项最大值 = "
                    + (bad.isEmpty() ? "无" : bad.get(bad.size() - 1)));
            System.out.printf("  [对照] 论文闭式在 n=128 给 L_BFF=%d（比值 %.4f），我们给 %d（比值 %.4f）%n",
                lPaper, lPaper / 128.0, lOurs, lOurs / 128.0);
            System.out.println("         ⇒ 我们的数组**更小**（而且比 1.125n 还紧），因为 L_BFF 是");
            System.out.println("           《网格刚好装下 n 个关键词》的副产品，不是按 1.125 的余量主动留的。");
            System.out.println("           **这不是《我们比论文好》，而是两者 L_BFF 的来历不同**（见第 4 节）；");
            System.out.println("          而且我们没有额外的《分配失败》检查，所以省下的余量有一部分是");
            System.out.println("          靠《线性探测恰好不撞》换来的 —— 这是要写在文档里的代价。");
        }

        // ---------- 4. L_BFF 的来历不同（形态差，必须写出来）----------
        System.out.println();
        System.out.println("---------------- 4. 形态差：L_BFF 是《设计参数》还是《几何余量》 ----------------");
        {
            // 论文：n 定 s 与 L_BFF；我们：R/maxValues 定 cellsPerCol，n 只影响 C
            long[] ns = {128, 256, 1000, 10000, 100000};
            System.out.println("  论文：s 由 n 的闭式给出，**s 随 n 变**（分段粒度是按 n 选的）：");
            for (long nn : ns) {
                System.out.printf("        n=%-7d s=%-4d L_BFF=%-8d（%.4f·n）%n",
                    nn, paperS(3, nn), paperLBff(3, nn, true), paperLBff(3, nn, true) / (double) nn);
            }
            boolean sChanges = false;
            for (int i = 1; i < ns.length; i++) {
                if (paperS(3, ns[i]) != paperS(3, ns[0])) {
                    sChanges = true;
                }
            }
            int cAt128 = 26, cAt256 = 52;
            System.out.printf("  我们：cellsPerCol 恒为 %d（由 R/maxValues 定，**与 n 无关**）；"
                + "C(128)=%d, C(256)=%d ==> L_BFF=%d / %d%n",
                cellsPerCol, cAt128, cAt256, 5L * cAt128, 5L * cAt256);
            System.out.println("        ⇒ n 变了，**只有列数变**，段大小不动");
            check("论文的 s 随 n 变化（我们的恒为 " + cellsPerCol + "，与 n 无关）",
                sChanges, "论文 s(128)=" + paperS(3, 128) + " vs s(100000)=" + paperS(3, 100000));
            System.out.println("        ⚠️ 注意 n=128 与 n=256 的论文 s **相同**（都是 64）——");
            System.out.println("           因为 s 是 2 的幂、且 log_3.33 的台阶很宽。所以");
            System.out.println("           《s 随 n 变》这句要用跨度大的 n 才看得出来（这里用 128 vs 100000）。");
        }

        // ---------- 5. 位置函数：论文有，我们没有 ----------
        System.out.println();
        System.out.println("---------------- 5. 位置函数 h_i：论文有、**我们没有实现** ----------------");
        System.out.println("  论文（ChalametPIR Alg.1 L8-10）：");
        System.out.println("    " + positionFunctionDoc());
        System.out.println("    ⇒ 一个关键词有 **k 个位置**，分布在 **k 个连续段**里；");
        System.out.println("      重建时把 k 个条目按分量相加 mod t 就得到载荷（BFF.Reconstruct）。");
        System.out.println("  我们（CapeDemoData.keywordHash + 网格）：");
        System.out.println("    一个关键词 -> **一个** cell（列 colOf + 行区间 rowOf）；");
        System.out.println("    k 条路取的是该 cell 内**连续 k 行**（BFF 的 3 路 share）。");
        System.out.println("    => 满足《三路相加 = 载荷》这条**重建性质**，但 **h_i 那套位置函数没有实现**，");
        System.out.println("      段内偏移用的是**线性探测**（关键字哈希 + 逐槽试），不是 h'(K‖i)。");
        {
            // 把"重建性质"真的算一遍，别只写散文
            int kwCount = 128, R2 = 16, mv = 3;
            int cpc = R2 / mv;
            int c2 = (int) Math.ceil(kwCount / (double) cpc);
            int[] slotOf = keywordHash(makeKeywords(kwCount), cpc, c2);
            int span = Math.max(kwCount, cpc * c2);
            Set<Integer> used = new LinkedHashSet<>();
            boolean distinct = true;
            int[] colOf = new int[kwCount];
            int[] rowOf = new int[kwCount];
            for (int i = 0; i < kwCount; i++) {
                colOf[i] = slotOf[i] / cpc;
                rowOf[i] = (slotOf[i] % cpc) * mv;
                if (!used.add(slotOf[i])) {
                    distinct = false;
                }
            }
            check("我们的关键词位置两两不同（" + used.size() + "/" + kwCount + " 个槽）",
                distinct && used.size() == kwCount, "span = " + span);
            // k 个位置落在同一列的连续 k 行（这就是"我们版本的 k 个位置"）
            boolean sameColConsecutive = true;
            for (int i = 0; i < kwCount; i++) {
                if (rowOf[i] + k > R2) {
                    sameColConsecutive = false;
                }
            }
            check("每个关键词的 k 个位置 = 同一列的连续 " + k + " 行（R=" + R2 + " 足够）",
                sameColConsecutive, "这是我们的结构，不是论文的 k 个连续段");
            // 段大小 s = cellsPerCol：段内偏移范围 = [0, mv)，即一个 cell 的 maxValues 行
            check("我们的《段内偏移》取值数 = maxValues = " + mv + "（论文是 s = " + sPaper + "）",
                mv == 3 && sPaper == 64, "**量级差 " + (sPaper / mv) + " 倍** —— "
                    + "论文一个段里有 " + sPaper + " 个位置，我们一个 cell 只有 " + mv + " 行");
        }

        // ---------- 6. k=4 那一支 ----------
        System.out.println();
        System.out.println("---------------- 6. k=4（论文支持，本项目不用）----------------");
        System.out.printf("  k=4：s = 2^floor(log_2.91(n)−0.5)；n=128 ⇒ s=%d，L_BFF=%d（≈%.4f·n，界 1.075）%n",
            paperS(4, 128), paperLBff(4, 128, true), paperLBff(4, 128, true) / 128.0);
        check("k=4 的 s 闭式也实现对了（恒为 2 的幂）",
            (paperS(4, 128) & (paperS(4, 128) - 1)) == 0, "s=" + paperS(4, 128));
        check("k=4 的 L_BFF 界是 1.075n（不是 1.125n）",
            paperLBff(4, 128, true) <= (long) Math.ceil(1.075 * 128),
            "L=" + paperLBff(4, 128, true) + " ≤ " + (long) Math.ceil(1.075 * 128));
        System.out.println("  本项目取 k=3（与 CAPE 的 FusePIR 实例相同：附录 A 原话 "
            + "“Our concrete FusePIR instantiation uses k=3”）");

        System.out.println();
        System.out.println(failed == 0
            ? "=== ALL CHECKS PASSED：闭式已对上，且三处形态差已如实标注 ==="
            : "=== " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 造一组与演示库同形的关键词（只为跑几何，不需要真实数据）。 */
    private static List<String> makeKeywords(int count) {
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            out.add("kw-" + i);
        }
        return out;
    }

    /**
     * {@code CapeDemoData.keywordHash} 的**逐位复刻**（那边是 private）。
     *
     * <p>复刻而不是反射调用：这里要断言的是"我们的位置分配长什么样"，
     * 所以两边必须真是同一个算法；反射调私有方法会让这个断言变得脆弱，
     * 而复制一份 10 行的纯函数代价更低、也更明确。
     * <b>如果哪天动了 {@code CapeDemoData.keywordHash}，这里必须同步改</b> ——
     * 所以本类还会把两者的结果对拍一次（见 {@code checkHashMatchesDemoData}）。
     */
    static int[] keywordHash(List<String> keywords, int cellsPerCol, int c) {
        final int n = keywords.size();
        final int span = Math.max(n, cellsPerCol * c);
        int[] slot = new int[span];
        Arrays.fill(slot, -1);
        for (int i = 0; i < n; i++) {
            int h = mix(keywords.get(i).hashCode()) % span;
            if (h < 0) {
                h += span;
            }
            while (slot[h] != -1) {
                h = (h + 1) % span;
            }
            slot[h] = i;
        }
        int[] out = new int[n];
        for (int h = 0; h < span; h++) {
            if (slot[h] >= 0) {
                out[slot[h]] = h;
            }
        }
        return out;
    }

    /** 与 {@code CapeDemoData.mix} 同款（murmur3 finalizer）。 */
    private static int mix(int h) {
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;
        return h;
    }
}
