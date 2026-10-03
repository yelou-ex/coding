package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.bloom.BloomChannel;
import com.fusepir.common.BfGen;
import com.fusepir.fusepir.FusePirClientState;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirServerState;
import com.fusepir.fusepir.FusePirSetup;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * <b>{@code pp} / {@code st_S} / {@code st_C} 三个状态束的离线自检（无服务、无 HTTP、无 SEAL 上下文）</b>
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirStateTest [n] [ringDim]
 *
 *   A1 SETUP 17: pp ← (H, fp, R, C, N, d, t, q).
 *   A1 SETUP 18: st_S ← ({P_{c,b}}_{c,b}, pp).
 *   A1 QUERY  7: q := (q_0, q_1, q_2),  st_C ← K.
 *   A2 SETUP 12: pp ← (pp_F, ℓ_BF, G, m).
 *   A2 SETUP 13: st_S ← st^F_S.
 *   A2 QUERY  6: st_C ← (st^anc_C, τ).
 * </pre>
 *
 * <h3>⚠️ 本探针验什么、不验什么</h3>
 * <ul>
 *   <li><b>验</b>：三个类型是否真的装下了论文那一行要求的每一项（逐项读回、逐位对照
 *       {@code P_{c,b}(X) = Σ_r D[r + cR][b]·X^r}）、{@code H}/{@code fp}/{@code G}
 *       是否是函数（同一个函数在两个关键词上给出不同结果），以及
 *       "关键词 / {@code τ} 不许出现在服务端状态与公开参数里"这类结构性质。</li>
 *   <li><b>不验</b>：任何同态运算（{@code CtPtMul} / {@code BlindRotate} /
 *       {@code SampleExtract_0}）、任何 SEAL/native 上下文、{@code q} 与真实系数模数链的
 *       一致性、{@code τ} 与真实 {@code Dec(ct_score)} 的相等性。这些仍由
 *       {@code CapeBloomScore} / {@code CapePaperNativeTest} / {@code CapeEndToEnd4} 覆盖。
 *       <b>本探针一行同态代码都没有。</b></li>
 * </ul>
 *
 * <h3>⚠️ 负对照：本探针每一项断言都配一个"弄坏它就必须失败"的对照</h3>
 * 判据都抽成 helper，<b>正反两边跑同一段代码</b> —— 所以"检查通过"不可能只是
 * "检查没在检查"。逐个说明"哪条检查抓哪种错误"：
 *
 * <table border="1">
 *   <tr><th>负对照</th><th>模拟的错误</th><th>抓它的检查</th></tr>
 *   <tr><td>N1-1</td><td>把 {@code H} 存成常量（不管关键词都返回同一组位置）</td>
 *       <td>P1-2 {@code H(K1) ≠ H(K2)}</td></tr>
 *   <tr><td>N1-2</td><td>把 {@code fp} 存成常量</td><td>P1-3 {@code fp(K1) ≠ fp(K2)}</td></tr>
 *   <tr><td>N1-3</td><td>{@code pp} 里预展开了位置表（会出现 {@code int[][]} 字段）</td>
 *       <td>P1-1a {@code pp} 无数组字段（对照：一个故意带 {@code int[][]} 的类必须被判真）</td></tr>
 *   <tr><td>N1-4</td><td>{@code d} 存错 / 构造函数把 {@code d}、{@code m} 传反（两个 int，编译期查不出来）</td>
 *       <td>P1-4 数值项摘要必须逐字等于传进去的那组</td></tr>
 *   <tr><td>N1-5</td><td>把关键词塞进 {@code pp}（公开参数会到处传）</td>
 *       <td>P1-1b {@code pp} 没有 {@code String} 字段（对照：{@code st_C} 有 ⇒ 判据有分辨力）</td></tr>
 *   <tr><td>N3-1</td><td>行下标写成 {@code r·C + c} 而不是论文的 {@code r + cR}</td>
 *       <td>P3-2 {@code polynomial(c,b)[r] == D[r + cR][b]} 的全量对照</td></tr>
 *   <tr><td>N3-2</td><td>表里出现 {@code X^r}（{@code r ≥ R}）的非零系数</td>
 *       <td>P3-3 {@code ofTable} 必须抛（A1 SETUP 14 的推论，走 {@code BffEncode.checkDataRadius}）</td></tr>
 *   <tr><td>N3-3</td><td>表少一列 / 系数个数不是 {@code N}；以及"总是抛"的假阳性</td>
 *       <td>P3-1 形状自检必须抛 + 正对照（形状正确时不抛）</td></tr>
 *   <tr><td>N3-4</td><td>{@code D} 比 {@code RC} 短（会读到别的关键词的份额）</td>
 *       <td>P3-5 {@code ofGrid} 必须抛</td></tr>
 *   <tr><td>N4-1</td><td>{@code st_C} 忘了存 {@code K}（于是所有 {@code st_C} 都相等）</td>
 *       <td>P4-2 不同 {@code K} 的 {@code st_C} 必须不相等</td></tr>
 *   <tr><td>N4-2</td><td>{@code toString()} 里打出了关键词（日志泄露）</td>
 *       <td>P4-3 用含关键词的串作对照，证明该检测器能报出泄露</td></tr>
 *   <tr><td>N5-1</td><td>对已经是 CAPE 的 {@code pp} 再加宽一次</td>
 *       <td>P5-2 {@code extendBloom} 必须抛</td></tr>
 *   <tr><td>N5-2</td><td>{@code ℓ_BF > N/2}（Bloom 位铺不进 SEAL 槽位）</td>
 *       <td>P5-3 {@code extendBloom} 必须抛（对照：{@code ℓ_BF = N/2} 不抛）</td></tr>
 *   <tr><td>N5-3</td><td>{@code ℓ_BF} 与 {@code G} 不同源（{@code G} 的值域比 {@code ℓ_BF} 大）</td>
 *       <td>P5-5 {@code G} 的 h 个位置必须全落在 {@code [0, ℓ_BF)}</td></tr>
 *   <tr><td>N5-4</td><td>{@code m} 存错（{@code B_pay} 跟着错 ⇒ 载荷被切错位）</td>
 *       <td>P5-6 {@code Cape.bPay()} 必须等于 {@code st_S.bPay()} 且等于按 {@code (ℓ_BF,m,t)} 重算的值</td></tr>
 *   <tr><td>N6-1</td><td>把加宽后的 {@code pp} 塞进 {@code st_S}（改掉 A2 SETUP 13 的语义）</td>
 *       <td>P6-1 {@code st_S.params() == pp_F}</td></tr>
 *   <tr><td>N6-2</td><td>{@code st_S} 里出现 {@code keyword}/{@code tau}/{@code anchor} 字段</td>
 *       <td>P6-2 字段集必须恰为 {@code {table, params}}（对照：{@code st_C(A2)} 的字段集不是 2 个）</td></tr>
 *   <tr><td>N7-1</td><td>{@code τ} 与 {@code b_qry} 不配对（存了别的量、或别的查询的权重）</td>
 *       <td>P7-1 {@code τ == BfGen.hammingWeight(b_qry)}</td></tr>
 *   <tr><td>N7-2</td><td>{@code b_qry} 的长度不是 {@code ℓ_BF}（例如错用环维度 {@code N}）</td>
 *       <td>P7-3 {@code fromQuery} 必须抛</td></tr>
 *   <tr><td>N7-3</td><td>{@code τ} 存到了另一个域（本实现有两个 {@code t}，D11）</td>
 *       <td>P7-2 {@code tauModulus() == BloomChannel.SCORE_T}（对照：换成 native 域 {@code 2^32} 必须判假）</td></tr>
 *   <tr><td>N7-4</td><td>{@code τ} 落在域外（例如把 {@code t} 本身当阈值）</td>
 *       <td>P7-4 构造器必须抛（对照：{@code τ = t−1} 不抛）</td></tr>
 *   <tr><td>N7-5</td><td>两个只有 {@code τ} 不同的 {@code st_C} 被判成相等（{@code τ} 没真正存下来）</td>
 *       <td>P7-5 必须不相等</td></tr>
 *   <tr><td>N7-6</td><td>把 A2 的 {@code st_C} 当成 A1 的 {@code st_C} 用</td>
 *       <td>P7-7 两个类型之间没有继承关系（A2 DECODE 1 是显式 parse）</td></tr>
 * </table>
 *
 * <h3>⚠️ 已知边界（本探针没覆盖的）</h3>
 * <ul>
 *   <li>本探针是为这三个类型写的，<b>不是</b>端到端验收：它不碰 {@code cape/}、
 *       不碰 native、不起服务。三个类型在生产路径上<b>目前没有任何调用方</b>
 *       （本轮不许动 {@code cape/}），所以"接上以后仍然对"这句话本探针证不了。</li>
 *   <li>{@code q} 只用 {@link BigInteger} 存读，<b>没有</b>与真实
 *       {@code Mpc4jRgsw.q} / {@code CoeffModulus.bfvDefault(N)} 对账。</li>
 *   <li>{@code d} 只用 {@code int} 存读，<b>没有</b>与 native 上下文的 {@code d} 对账。</li>
 * </ul>
 */
public final class FusePirStateTest {

    private static int checks;
    private static int fails;
    /** 最近一次"应当抛异常"的调用真正抛出的信息（诊断用）。 */
    private static String lastThrow;

    private FusePirStateTest() {
    }

    public static void main(String[] args) {
        // ── 参数：只用 A1 SETUP 3-4 与 A2 SETUP 1-2 需要的那几样；N 取小值（本探针不跑同态） ──
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 1024;
        final int k = 3;                                   // A3 SETUP：论文定死 k=3
        final int d = 16;                                  // A1 SETUP 3 的 LWE 维数（论文未给，MAP §13.1）
        final long t = 1L << 32;                           // A1 SETUP 3 的 t（native 载荷域）
        final BigInteger q = BigInteger.ONE.shiftLeft(60).multiply(BigInteger.valueOf(0x1FFFFFFFFFFFFF1L));
        final int lBf = 18;                                // A2 SETUP 1 的 ℓ_BF（demo 口径）
        final int h = 5;                                   // A2 SETUP 1 的 |G|（demo 口径）
        final int m = 3;                                   // A2 SETUP 2 的 m（demo 口径）
        final long scoreT = BloomChannel.SCORE_T;          // 打分信道的 t（τ 的域）

        // 关键词取"绝不会在别处偶然出现"的串：本探针的泄露检测用的是子串判定。
        final String k1 = "kw-alpha-Zx9";
        final String k2 = "kw-beta-Q7q";
        final String k3 = "kw-gamma-V3v";

        System.out.println("=== pp / st_S / st_C 状态束自检（离线，无同态、无服务） ===");
        System.out.println("  n = " + n + ", k = " + k + ", N = " + ringDim + ", d = " + d
            + ", t = " + t + ", q = " + q.bitLength() + " bit");
        System.out.println("  ℓ_BF = " + lBf + ", h = |G| = " + h + ", m = " + m
            + ", 打分信道 t = " + scoreT);

        // ── A3 SETUP 9-10 的两件材料：段结构 + 种子；A2 SETUP 1 的 G ──
        final long rhoH = 20261015L;
        final BffHash.HashGen hg = BffHash.allocate(n, k).hashGen();
        final BffSetup.Layout layout = BffSetup.layout(hg.lBff, hg.s, ringDim, 0);
        final BfGen bf = new BfGen(h, lBf);
        final FusePirParams.BloomHashFamily gFn = FusePirParams.BloomHashFamily.of(bf);
        System.out.println("  BFF: " + hg);
        System.out.println("  布局: " + layout);
        System.out.println("  G 的来源: " + bf);

        // ================================================================
        //  §1  A1 SETUP 17 —— pp ← (H, fp, R, C, N, d, t, q)
        // ================================================================
        System.out.println("\n---------------- 1. A1 SETUP 17：pp 的 8 项 ----------------");

        final FusePirParams.BffHashFamily hFn = FusePirParams.bffPositions(rhoH, hg);
        final FusePirParams.Fingerprint fpFn = FusePirParams.fingerprint();
        final FusePirParams ppF = new FusePirParams(hFn, fpFn, layout, d, t, q);

        // P1-1：字段集必须覆盖 A1 SETUP 17（R/C/N 由 layout 承载，见 FusePirParams 类注释）
        final Set<String> ppFields = declaredFields(FusePirParams.class);
        check(ppFields.containsAll(Arrays.asList("h", "fp", "layout", "d", "t", "q")),
            "P1-1 pp 声明了 A1 SETUP 17 的每一项（H=h, fp=fp, R/C/N=layout, d, t, q）：%s", ppFields);
        // P1-1a：H/fp 是函数 ⇒ pp 里不该有**数组**字段（预展开的位置表就会是数组）
        check(!hasArrayField(FusePirParams.class),
            "P1-1a pp 没有数组字段（H/fp 是函数，不许预展开成位置表）");
        // P1-1b：pp 是公开参数 ⇒ 不该有 String 字段（否则关键词可能被塞进去）
        check(fieldNamesOfType(FusePirParams.class, String.class).isEmpty(),
            "P1-1b pp 没有 String 字段（公开参数里不该有关键词）");
        // 负对照：两个检测器都必须"有分辨力"
        check(hasArrayField(PositionTableHolder.class),
            "N1-3（对照）同一个判据在**故意带 int[][] 的类**上必须为真 —— 否则 P1-1a 是空检查");
        check(!fieldNamesOfType(FusePirClientState.class, String.class).isEmpty(),
            "N1-5（对照）同一个判据在 st_C 上必须**能**查出 String 字段：%s",
            fieldNamesOfType(FusePirClientState.class, String.class));

        // P1-2：H 是函数（同一个 H 在两个关键词上给出不同位置），且与 BFF 层**同一份实现**
        final int[] uK1 = ppF.h().positions(k1);
        final int[] uK2 = ppF.h().positions(k2);
        check(!Arrays.equals(uK1, uK2),
            "P1-2 H 是函数：H(%s)=%s ≠ H(%s)=%s", k1, Arrays.toString(uK1), k2, Arrays.toString(uK2));
        check(uK1.length == k && Arrays.equals(uK1, BffHash.positions(k1, rhoH, hg)),
            "P1-2b pp 里的 H 与 BffHash.positions(·, ρ_H, hg) 逐位同一份实现：%s", Arrays.toString(uK1));
        check(inRange(uK1, 0, (int) hg.lBff),
            "P1-2c H 的值域是 [0, L_BFF)=[0,%d)（A3 SETUP 9 的 {h_j : K → [L_BFF]}）", (long) hg.lBff);
        // 负对照：常量函数必须让 P1-2 的判据为假
        final FusePirParams.BffHashFamily constH = kw -> new int[] {7, 7, 7};
        check(Arrays.equals(constH.positions(k1), constH.positions(k2)),
            "N1-1（对照）常量 H 会让 P1-2 的判据为假 —— 该判据确实在分辨'是不是函数'");

        // P1-3：fp 是函数，且与 BffSetup.fp 同一份实现
        final long f1 = ppF.fp().of(k1);
        final long f2 = ppF.fp().of(k2);
        check(f1 != f2 && f1 == BffSetup.fp(k1) && f2 == BffSetup.fp(k2),
            "P1-3 fp 是函数且等于 BffSetup.fp：fp(%s)=%d, fp(%s)=%d（40-bit，A3 SETUP 10）", k1, f1, k2, f2);
        final FusePirParams.Fingerprint constFp = kw -> 7L;
        check(constFp.of(k1) == constFp.of(k2),
            "N1-2（对照）常量 fp 会让 P1-3 的判据为假 —— 该判据确实在分辨'是不是函数'");

        // P1-4：数值项逐项读回（摘要逐字相等）
        final FusePirParams.Cape ppC = ppF.extendBloom(lBf, gFn, m);
        final String wantDigest = dataDigest(d, t, q, layout, lBf, m);
        check(dataDigest(ppC).equals(wantDigest),
            "P1-4 (d,t,q,R,C,N,ℓ_BF,m) 逐项读回 == 传进去的那组：%s", dataDigest(ppC));
        // 负对照 a：只把 d 改一位（B_pay 不变 ⇒ 差异只可能来自 d）
        final FusePirParams.Cape ppD =
            new FusePirParams(hFn, fpFn, layout, d + 1, t, q).extendBloom(lBf, gFn, m);
        check(!dataDigest(ppD).equals(wantDigest) && ppD.bPay() == ppC.bPay(),
            "N1-4a（对照）只把 d 改成 %d ⇒ 摘要必须不同、而 B_pay 不变（证明摘要查的是 d）：%s",
            d + 1, dataDigest(ppD));
        // 负对照 b：d 与 m 传反（两个都是 int ⇒ 编译期查不出来）
        final FusePirParams.Cape swapped =
            new FusePirParams(hFn, fpFn, layout, m, t, q).extendBloom(lBf, gFn, d);
        check(!dataDigest(swapped).equals(wantDigest),
            "N1-4b（对照）把 d 与 m 传反后摘要必须不同：%s", dataDigest(swapped));

        // P1-5：A1 SETUP 4 的两条约束在 pp 上仍成立（R/C 来自同一次 layout）
        check(ppF.r() <= ppF.n() && ppF.layout().rc() >= ppF.layout().lBff,
            "P1-5 A1 SETUP 4：R(%d) ≤ N(%d) 且 RC(%d) ≥ L_BFF(%d)",
            (long) ppF.r(), (long) ppF.n(), ppF.layout().rc(), ppF.layout().lBff);

        // ================================================================
        //  §3  A1 SETUP 12-18 —— st_S ← ({P_{c,b}}, pp)
        // ================================================================
        System.out.println("\n---------------- 3. A1 SETUP 12-18：st_S = ({P_{c,b}}, pp) ----------------");

        final int bPay = FusePirSetup.payloadBpay(FusePirSetup.fpSlots(t), m,
            FusePirSetup.perValue(lBf));
        final int rc = (int) layout.rc();
        final long[][] dGrid = new long[rc][bPay];
        for (int u = 0; u < rc; u++) {
            for (int b = 0; b < bPay; b++) {
                dGrid[u][b] = Math.floorMod(mix64(u * 0x9E3779B97F4A7C15L + b * 0xBF58476D1CE4E5B9L), t);
            }
        }
        System.out.println("  D 的形状 = [" + rc + "][" + bPay + "]，B_pay = "
            + FusePirSetup.fpSlots(t) + " + 1 + " + m + "×" + (1 + lBf) + " = " + bPay);

        final FusePirServerState stS = FusePirServerState.ofGrid(dGrid, ppF, bPay);
        System.out.println("  " + stS);

        // P3-1：形状自检（C / B_pay / N / R 四个数）
        check(stS.columns() == layout.c && stS.bPay() == bPay && stS.ringDim() == ringDim
                && stS.rows() == layout.r,
            "P3-1 表形状 = [C=%d][B_pay=%d][N=%d]，R=%d（A1 SETUP 14/18）",
            stS.columns(), stS.bPay(), stS.ringDim(), stS.rows());
        // P3-2：A1 SETUP 14 逐位对照 P_{c,b}[r] == D[r + cR][b]
        int mismatch = 0;
        int wrongMappingMismatch = 0;
        for (int c = 0; c < stS.columns(); c++) {
            for (int b = 0; b < bPay; b++) {
                final long[] poly = stS.polynomial(c, b);
                for (int r = 0; r < layout.r; r++) {
                    if (poly[r] != dGrid[r + c * layout.r][b]) {
                        mismatch++;
                    }
                    // 故意用 r·C + c 作对照（另一种"看起来合理"的层叠）
                    if (poly[r] != dGrid[r * stS.columns() + c][b]) {
                        wrongMappingMismatch++;
                    }
                }
            }
        }
        check(mismatch == 0,
            "P3-2 A1 SETUP 14 逐位成立：P_{c,b}[r] == D[r + cR][b]，共 %d 项全等",
            (long) stS.columns() * bPay * layout.r);
        check(wrongMappingMismatch > 0,
            "N3-1（对照）换成 r·C+c 的层叠后 %d 项不符 —— P3-2 的判据确实能分辨层叠方式",
            (long) wrongMappingMismatch);
        // P3-3：系数 [R, N) 全 0（A1 SETUP 14 的求和上界是 R−1）
        int nonZeroAboveR = 0;
        for (int c = 0; c < stS.columns(); c++) {
            for (int b = 0; b < bPay; b++) {
                final long[] poly = stS.polynomial(c, b);
                for (int r = layout.r; r < ringDim; r++) {
                    if (poly[r] != 0) {
                        nonZeroAboveR++;
                    }
                }
            }
        }
        check(nonZeroAboveR == 0, "P3-3 系数 [R,N) 全为 0（P_{c,b} 只用到 X^0..X^(R−1)）");
        // P3-4：st_S 持有的就是同一个 pp 对象（A1 SETUP 18 的第二个分量）
        check(stS.params() == ppF, "P3-4 st_S.params() 就是 A1 SETUP 17 的那一个 pp 对象");
        check(stS.polynomial(0, 0) == stS.table()[0][0],
            "P3-6 polynomial/table 交的是内部数组（登记过的边界：不做防御性拷贝）");

        // ── N3-2：表里塞一个 r ≥ R 的非零系数 ⇒ ofTable 必须抛 ──
        final long[][][] badTable = new long[layout.c][bPay][ringDim];
        badTable[0][0][layout.r] = 1;
        check(throwsRuntime(() -> FusePirServerState.ofTable(badTable, ppF)),
            "N3-2 表中出现 X^R 的非零系数 ⇒ ofTable 必须抛（%s）", lastThrow);
        // ── N3-3a：表少一列 ⇒ 必须抛 ──
        check(throwsRuntime(() -> FusePirServerState.ofTable(new long[layout.c - 1][bPay][ringDim], ppF)),
            "N3-3a 表少一列（C−1）⇒ ofTable 必须抛（%s）", lastThrow);
        // ── N3-3b：某条多项式的系数个数不是 N ⇒ 必须抛 ──
        final long[][][] shortPoly = new long[layout.c][bPay][ringDim];
        shortPoly[3][7] = new long[ringDim - 1];
        check(throwsRuntime(() -> FusePirServerState.ofTable(shortPoly, ppF)),
            "N3-3b 某条 P_{c,b} 的系数个数 ≠ N ⇒ ofTable 必须抛（%s）", lastThrow);
        // ── N3-3c：正对照（形状正确时不抛）—— 证明上面三条不是"总是抛" ──
        check(!throwsRuntime(() -> FusePirServerState.ofTable(stS.table(), ppF)),
            "N3-3c（对照）形状正确时 ofTable 不抛 —— 上面三条不是'总是抛'");
        // ── N3-4：D 比 RC 短 ⇒ ofGrid 必须抛 ──
        final long[][] shortD = new long[rc - 1][bPay];
        check(throwsRuntime(() -> FusePirServerState.ofGrid(shortD, ppF, bPay)),
            "N3-4 D 短于 RC ⇒ ofGrid 必须抛（%s）", lastThrow);

        // ================================================================
        //  §4  A1 QUERY 7 —— st_C ← K
        // ================================================================
        System.out.println("\n---------------- 4. A1 QUERY 7：st_C ← K ----------------");

        final FusePirClientState stC1 = new FusePirClientState(k1);
        final FusePirClientState stC2 = new FusePirClientState(k2);
        // P4-1：K 读回（A1 DECODE 1 的 K ← st_C 靠它）
        check(k1.equals(stC1.keyword()), "P4-1 K 逐字读回：st_C.keyword() = %s", stC1.keyword());
        // P4-2：不同 K ⇒ 不相等；同一个 K ⇒ 相等；hashCode 与之一致
        check(!stC1.equals(stC2), "P4-2a 不同 K 的两个 st_C 不相等（忘了存 K 会表现为全都相等）");
        check(stC1.equals(new FusePirClientState(k1)),
            "P4-2b 同一个 K 的两个 st_C 相等（equals 按 K）");
        check(stC1.hashCode() == new FusePirClientState(k1).hashCode()
                && stC1.hashCode() != stC2.hashCode(),
            "P4-2c hashCode 与 equals 一致");
        // P4-3：打印串里不许出现关键词（客户端私有）
        check(!leaks(stC1.toString(), k1) && !leaks(stS.toString(), k1) && !leaks(ppC.toString(), k1),
            "P4-3 st_C / st_S / pp 的 toString() 都不含关键词：st_C=%s", stC1);
        check(leaks("K=" + k1, k1),
            "N4-2（对照）同一个泄露检测器在含关键词的串上必须为真 —— P4-3 不是空检查");

        // ================================================================
        //  §5  A2 SETUP 12 —— pp ← (pp_F, ℓ_BF, G, m)
        // ================================================================
        System.out.println("\n---------------- 5. A2 SETUP 12：pp ← (pp_F, ℓ_BF, G, m) ----------------");

        // P5-1：加宽的字段集 = pp_F 的 6 项 + A2 SETUP 12 的 3 项
        final Set<String> extra = new TreeSet<>(declaredFields(FusePirParams.Cape.class));
        extra.removeAll(ppFields);
        check(extra.equals(new TreeSet<>(Arrays.asList("lBf", "G", "m"))),
            "P5-1 A2 SETUP 12 在 pp_F 之上恰好加了 {ℓ_BF=lBf, G, m}：%s", extra);
        check(!declaredFields(FusePirParams.class).contains("lBf"),
            "P5-1b A1 的 pp 里没有 ℓ_BF（A1 SETUP 17 只列 H,fp,R,C,N,d,t,q）");
        // P5-2：加宽不改 pp_F 的任何一项（算法 2 全程把 pp_F 当 pp 用）
        check(ppC.r() == ppF.r() && ppC.c() == ppF.c() && ppC.n() == ppF.n()
                && ppC.d() == ppF.d() && ppC.t() == ppF.t() && ppC.q().equals(ppF.q()),
            "P5-2 pp_C 的 (R,C,N,d,t,q) 与 pp_F 逐项相同（A2 SETUP 12 是加宽，不是替换）");
        check(Arrays.equals(ppC.h().positions(k1), ppF.h().positions(k1))
                && ppC.fp().of(k1) == ppF.fp().of(k1),
            "P5-3 pp_C 的 H / fp 与 pp_F 是同一份函数（同一对象的方法引用，不是副本）");
        check(ppC.lBf() == lBf && ppC.m() == m && ppC.g() == gFn,
            "P5-4 ℓ_BF/G/m 逐项读回：ℓ_BF=%d, m=%d, G 为同一对象", ppC.lBf(), ppC.m());
        // P5-5：G 是函数，h 个位置、值域 [0, ℓ_BF)，且与 BfGen 同一份实现
        final int[] bitsK1 = gFn.positions(k1);
        check(bitsK1.length == h && inRange(bitsK1, 0, lBf)
                && Arrays.equals(bitsK1, bf.positions(k1)) && bf.length() == ppC.lBf(),
            "P5-5 G 是函数（h=%d 个位置、值域 [0,ℓ_BF=%d)、与 BfGen.positions 同一份实现）：%s",
            h, lBf, Arrays.toString(bitsK1));
        // 负对照：G 与 ℓ_BF 不同源（G 取自 ℓ=N 的 BfGen）
        final FusePirParams.BloomHashFamily gMismatch =
            FusePirParams.BloomHashFamily.of(new BfGen(h, ringDim));
        check(!inRange(gMismatch.positions(k1), 0, lBf),
            "N5-3（对照）G 取自 ℓ=%d 的 BfGen 而 pp 的 ℓ_BF=%d ⇒ 位置越界必须被判出（P5-5 有分辨力）",
            ringDim, lBf);
        // P5-6：B_pay 对账（参数侧算出的宽度 == 服务端表宽 == 探针独立重算的值）
        check(ppC.bPay() == bPay && stS.bPay() == bPay,
            "P5-6 B_pay 对账：pp_C.bPay()=%d == st_S.bPay()=%d == 独立重算的 %d",
            ppC.bPay(), stS.bPay(), bPay);
        final FusePirParams.Cape ppOther = ppF.extendBloom(lBf, gFn, m + 1);
        check(ppOther.bPay() != stS.bPay(),
            "N5-4（对照）把 m 改成 m+1 后 B_pay=%d ≠ 表宽=%d —— 该对账确实在查 m",
            ppOther.bPay(), stS.bPay());
        // 边界：ℓ_BF > N/2 必须抛；ℓ_BF = N/2 不抛；m = 0 必须抛；重复加宽必须抛
        check(throwsRuntime(() -> ppF.extendBloom(ringDim / 2 + 1, gFn, m)),
            "N5-2 ℓ_BF = N/2+1 ⇒ extendBloom 必须抛（%s）", lastThrow);
        check(!throwsRuntime(() -> ppF.extendBloom(ringDim / 2, gFn, m)),
            "N5-2b（对照）ℓ_BF = N/2 不抛 —— 上一条不是'总是抛'");
        check(throwsRuntime(() -> ppF.extendBloom(lBf, gFn, 0)),
            "N5-5 m = 0 ⇒ extendBloom 必须抛（%s）", lastThrow);
        check(throwsRuntime(() -> ppC.extendBloom(lBf, gFn, m)),
            "N5-1 对已经是 CAPE 的 pp 再加宽 ⇒ 必须抛（%s）", lastThrow);

        // ================================================================
        //  §6  A2 SETUP 13 —— st_S ← st^F_S
        // ================================================================
        System.out.println("\n---------------- 6. A2 SETUP 13：st_S ← st^F_S（CAPE 不改 st_S） ----------------");

        final FusePirServerState stSwithCapePp = FusePirServerState.ofTable(stS.table(), ppC);
        // P6-1：论文的接线 —— st_S 引用 pp_F，而**不是**加宽后的 pp
        check(isPaperA2Wiring(stS, ppF, ppC),
            "P6-1 A2 SETUP 13：st_S.params() == pp_F 且 != 加宽后的 pp");
        // N6-1：反过来（把加宽后的 pp 塞进 st_S）同一条判据必须为假
        check(!isPaperA2Wiring(stSwithCapePp, ppF, ppC),
            "N6-1（对照）把加宽后的 pp 存进 st_S 后，同一条判据必须为假");
        // P6-2：st_S 的字段恰好是 {table, params}
        final Set<String> stSFields = declaredFields(FusePirServerState.class);
        check(stSFields.equals(new TreeSet<>(Arrays.asList("table", "params"))),
            "P6-2 A1 SETUP 18 的 st_S 恰好是 (表, pp) 两项：%s", stSFields);
        check(!stSFields.contains("keyword") && !stSFields.contains("tau") && !stSFields.contains("anchor"),
            "P6-3 st_S 里没有 keyword/tau/anchor 字段（K 与 τ 都是客户端私有）");
        check(declaredFields(FusePirClientState.Cape.class).size() != 2,
            "N6-2（对照）同一个'恰好 2 个字段'的判据在 st_C(A2) 上不成立：%s",
            declaredFields(FusePirClientState.Cape.class));

        // ================================================================
        //  §7  A2 QUERY 6 / DECODE 1 —— st_C ← (st^anc_C, τ)
        // ================================================================
        System.out.println("\n---------------- 7. A2 QUERY 6：st_C ← (st^anc_C, τ) ----------------");

        final FusePirClientState stAnc = new FusePirClientState(k1);      // A2 QUERY 1：st^anc_C
        final boolean[] bQry = bf.bits(Arrays.asList(k2, k3));            // A2 QUERY 2：BF.Gen(0,{K_2..K_Q})
        final FusePirClientState.Cape stCape =
            FusePirClientState.Cape.fromQuery(stAnc, bQry, lBf, scoreT);  // A2 QUERY 3/6
        System.out.println("  b_qry（ℓ_BF=" + lBf + " 位，" + k2 + " + " + k3 + "）= "
            + Arrays.toString(bQry));
        System.out.println("  " + stCape);

        // P7-1：τ == ‖b_qry‖₁（走同一个 BfGen.hammingWeight）
        check(stCape.tau() == BfGen.hammingWeight(bQry),
            "P7-1 τ == ‖b_qry‖₁ = %d（A2 QUERY 3；算式来自 BfGen.hammingWeight 那一份）", stCape.tau());
        // 负对照：把 b_qry 改一位（丁−1 或 +1）⇒ 判据必须为假；τ 必须与**这一个**查询配对
        final boolean[] otherQry = bQry.clone();
        int flip = -1;
        for (int i = 0; i < otherQry.length && flip < 0; i++) {
            if (otherQry[i]) {
                flip = i;
            }
        }
        for (int i = 0; i < otherQry.length && flip < 0; i++) {
            if (!otherQry[i]) {
                flip = i;
            }
        }
        otherQry[flip] = !otherQry[flip];
        check(stCape.tau() != BfGen.hammingWeight(otherQry),
            "N7-1（对照）把 b_qry 的第 %d 位翻转后 ‖·‖₁=%d ≠ τ=%d —— τ 确实与这一个查询配对",
            flip, BfGen.hammingWeight(otherQry), stCape.tau());
        // P7-2：τ 的域 = 打分信道的 t（本实现有两个 t，D11）
        check(stCape.tauModulus() == scoreT,
            "P7-2 τ 的域 == 打分信道 t = %d（A2 DECODE 9 的 s_j 在同一个域里）", scoreT);
        check(stCape.tauModulus() != t,
            "N7-3（对照）域换成 native 载荷域 t=%d 时 P7-2 必须判假（两个 t 确实被分开）", t);
        // P7-3：anchor 就是 A2 QUERY 1 的 st^anc_C（A2 DECODE 2 靠它）
        check(stCape.anchor() == stAnc && k1.equals(stCape.anchor().keyword()),
            "P7-3 st_C.anchor() == st^anc_C（A2 DECODE 1 的 Parse；DECODE 2 用它调 FusePIR.Decode）");
        // N7-2：b_qry 长度必须是 ℓ_BF（错用环维度 N 是典型误用）
        final boolean[] longQry = new boolean[ringDim];
        check(throwsRuntime(() -> FusePirClientState.Cape.fromQuery(stAnc, longQry, lBf, scoreT)),
            "N7-2 b_qry 长 %d ≠ ℓ_BF=%d ⇒ fromQuery 必须抛（%s）", ringDim, lBf, lastThrow);
        // P7-4：τ 必须在域内（域外 = 拿错了域）
        check(throwsRuntime(() -> new FusePirClientState.Cape(stAnc, scoreT, scoreT)),
            "N7-4a τ = 域本身 ⇒ 构造器必须抛（%s）", lastThrow);
        check(throwsRuntime(() -> new FusePirClientState.Cape(stAnc, -1, scoreT)),
            "N7-4b τ = −1 ⇒ 构造器必须抛（%s）", lastThrow);
        check(!throwsRuntime(() -> new FusePirClientState.Cape(stAnc, scoreT - 1, scoreT)),
            "N7-4c（对照）τ = 域−1 不抛 —— 上面两条不是'总是抛'");
        // P7-5：只有 τ 不同 ⇒ 不相等（τ 真的被存下来了）
        final FusePirClientState.Cape stCape2 =
            new FusePirClientState.Cape(stAnc, stCape.tau() + 1, scoreT);
        check(!stCape.equals(stCape2) && stCape.hashCode() != stCape2.hashCode(),
            "P7-5 只有 τ 不同的两个 st_C 不相等（τ=%d vs %d）", stCape.tau(), stCape2.tau());
        check(stCape.equals(FusePirClientState.Cape.fromQuery(
                new FusePirClientState(k1), bQry.clone(), lBf, scoreT)),
            "P7-5b 同样输入的两个 st_C 相等（等值语义健全）");
        // P7-6：A2 的 st_C 不打印关键词
        check(!leaks(stCape.toString(), k1) && leaks("anchor=" + k1, k1),
            "P7-6 st_C(A2) 的 toString() 不含关键词（对照串必须为真）");
        // P7-7：A2 的 st_C 与 A1 的 st_C 不是同一个类型（不许静默互换）
        check(!FusePirClientState.class.isAssignableFrom(FusePirClientState.Cape.class),
            "P7-7 st_C(A2) 与 st_C(A1) 是两个类型（A2 DECODE 1 显式 parse 出 st^anc_C）");
        // 负对照：同一个判据在**子类**设计上必须为真 —— 否则它只是个"永远为假"的判据
        check(FusePirParams.class.isAssignableFrom(FusePirParams.Cape.class),
            "N7-6（对照）同一个判据对 pp_C（真子类）必须为真：pp_C 可以直接当 pp_F 用");

        // ================================================================
        System.out.println("\n================ 汇总 ================");
        System.out.printf("  %d 项检查，%d 项失败%n", checks, fails);
        System.out.println(fails == 0
            ? "  === ALL CHECKS PASSED：pp/st_S/st_C 三个状态束按 A1 SETUP 17-18、A1 QUERY 7、"
                + "A2 SETUP 12-13、A2 QUERY 6 逐项成立 ===\n"
                + "      边界：本探针不含任何同态运算 / SEAL / native；三个类型在生产路径上目前无调用方\n"
                + "      （cape/ 本轮不许改动），所以'接上以后仍然对'这句话本探针证不了。"
            : "  === 有检查失败，见上面的 [FAIL] 行 ===");
        System.exit(fails == 0 ? 0 : 1);
    }

    // ==================================================================
    //  判据 / 工具（正反两边跑的是同一份代码，所以负对照有证明力）
    // ==================================================================

    /**
     * <b>A2 SETUP 13 的接线判据</b>：{@code st_S} 引用的是 {@code pp_F}（而不是加宽后的 {@code pp}）。
     *
     * <p>抽成一个函数是为了让正对照与负对照跑**同一段代码** ——
     * 否则负对照只能证明"我另写的一段判断能报错"。
     */
    private static boolean isPaperA2Wiring(FusePirServerState stS, FusePirParams ppF,
                                           FusePirParams.Cape ppCape) {
        return stS.params() == ppF && stS.params() != ppCape;
    }

    /** 数值项的摘要，覆盖 {@code pp} 的**每一个数据字段**（函数字段不参与，见类型注释）。 */
    private static String dataDigest(FusePirParams p) {
        return dataDigest(p.d(), p.t(), p.q(), p.layout(),
            p instanceof FusePirParams.Cape ? ((FusePirParams.Cape) p).lBf() : -1,
            p instanceof FusePirParams.Cape ? ((FusePirParams.Cape) p).m() : -1);
    }

    private static String dataDigest(int d, long t, BigInteger q, BffSetup.Layout layout,
                                     int lBf, int m) {
        return "d=" + d + ",t=" + t + ",q=" + q + ",R=" + layout.r + ",C=" + layout.c
            + ",N=" + layout.ringDim + ",lBf=" + lBf + ",m=" + m;
    }

    /** 全部落在 {@code [lo, hi)} 内。 */
    private static boolean inRange(int[] xs, int lo, int hi) {
        for (int x : xs) {
            if (x < lo || x >= hi) {
                return false;
            }
        }
        return true;
    }

    /** 字符串里是否出现关键词（泄露检测；子串判定）。 */
    private static boolean leaks(String s, String keyword) {
        return s != null && keyword != null && s.contains(keyword);
    }

    /** 直接声明字段的名字（过滤合成字段）。 */
    private static Set<String> declaredFields(Class<?> cls) {
        final Set<String> out = new TreeSet<>();
        for (Field f : cls.getDeclaredFields()) {
            if (!f.isSynthetic()) {
                out.add(f.getName());
            }
        }
        return out;
    }

    /** 是否有**数组**类型的字段（预展开的位置表就长这样）。 */
    private static boolean hasArrayField(Class<?> cls) {
        for (Field f : cls.getDeclaredFields()) {
            if (!f.isSynthetic() && f.getType().isArray()) {
                return true;
            }
        }
        return false;
    }

    /** 指定类型的字段名（用于"公开参数里不该有 String"这类检查）。 */
    private static List<String> fieldNamesOfType(Class<?> cls, Class<?> type) {
        final List<String> out = new ArrayList<>();
        for (Field f : cls.getDeclaredFields()) {
            if (!f.isSynthetic() && f.getType() == type) {
                out.add(f.getName());
            }
        }
        return out;
    }

    /** 跑一段代码，任何 {@code RuntimeException} 都算"抛了"，信息留在 {@link #lastThrow}。 */
    private static boolean throwsRuntime(Runnable r) {
        try {
            r.run();
            lastThrow = "（没有抛）";
            return false;
        } catch (RuntimeException e) {
            lastThrow = e.getClass().getSimpleName() + ": " + shorten(e.getMessage());
            return true;
        }
    }

    private static String shorten(String s) {
        if (s == null) {
            return "null";
        }
        return s.length() <= 90 ? s : s.substring(0, 90) + "…";
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    /** 负对照用：一个**故意**带位置表（{@code int[][]}）的类。 */
    private static final class PositionTableHolder {
        @SuppressWarnings("unused")
        private final int[][] pos = new int[2][3];
    }

    /**
     * ⚠️ 用 <b>varargs</b>（同 {@code probe/BffLayerTest} 的口径）。
     *
     * <p>项目里出现过固定两参版本被三占位符调用 ⇒ 抛
     * {@code MissingFormatArgumentException} ⇒ 把"检查失败"伪装成"探针崩溃"。
     * 这里同样兜底：格式化失败不许崩。
     */
    private static void check(boolean ok, String fmt, Object... args) {
        checks++;
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
