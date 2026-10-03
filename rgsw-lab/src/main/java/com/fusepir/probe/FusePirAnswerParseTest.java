package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.BffSetup;
import com.fusepir.bff.CapeDemoData;
import com.fusepir.bloom.BloomChannel;
import com.fusepir.cape.CapeQuery;
import com.fusepir.common.BfGen;
import com.fusepir.fusepir.FusePirAnswer;
import com.fusepir.fusepir.FusePirClientState;
import com.fusepir.fusepir.FusePirParams;
import com.fusepir.fusepir.FusePirQuery;
import com.fusepir.fusepir.FusePirServerState;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.nativejni.NativeBlindRotate;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

/**
 * <b>Algorithm 1 的 ANSWER 与 QUERY 7 / DECODE 1 的"接线"验收</b> ——
 * 三个具名缺口的落地点是否真的接上了，以及<b>接上之后行为一位没变</b>。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirAnswerParseTest [dbPath] [N] [nativeN]
 *        默认： ../cape-demo/db/keywords.json 8192 8192
 *        native 那一段还要额外加 $env:DSH_JVM_OPTS='-Dfusepir.native=true'（见下）
 *
 *   A1 ANSWER  1: Parse st_S = ({P_{c,b}}_{c,b}, pp).      ← st_S.flattenForNative() + pp
 *   A1 ANSWER  3: Parse (q_a^col, q_a^row) from q.         ← FusePirAnswer.paths(q, 3)
 *   A1 QUERY   7: q := (q_0, q_1, q_2),  st_C ← K.         ← FusePirQuery.query(…)
 *   A1 QUERY   8: return (q, st_C).
 *   A1 DECODE  1: K ← st_C.                                ← st_C.keywordFromState()
 *   A2 QUERY   6: st_C ← (st^anc_C, τ).                    ← FusePirQuery.queryWithCapeState(…)
 *   A2 DECODE  1: Parse (st^anc_C, τ) from st_C.           ← st_C.parse()
 * </pre>
 *
 * <h3>本探针验的四件事（对应任务书 (a)-(d)）</h3>
 * <ol>
 *   <li><b>(a) parse / 重组的往返对整张演示库精确</b>：128 个关键词的
 *       {@code (h_a(K), c_a, r_a)} 两两一致、{@code A1 ANSWER 3} 从真实
 *       {@code Sealed} 里 parse 出来的 {@code (c_a, r_a)} 与建表侧的
 *       {@code Tables.colRow(i,a)} 逐位相同。</li>
 *   <li><b>(b) {@code st_S} 路径与旧的扁平数组路径逐位相同</b>（本探针最重要的一条）：
 *       {@code FusePirServerState.flattenForNative()} 与
 *       {@code CapeDemoSetupProbe.flatten(tb.p, N, bPay)} 对**整张演示表**
 *       （{@code C·B_pay·N} 个系数）必须全等；随后两条路径<b>真的各跑一次 native</b>，
 *       结果也必须逐位相同。</li>
 *   <li><b>(c) {@code st_C} 路径恢复出被查询的那个关键词</b>：A1 通过
 *       {@code keywordFromState()}、A2 通过 {@code Cape.parse()}
 *       回到同一个 {@code K_1}，并且 A2 的 {@code τ} 与既有内联算式逐位相等。</li>
 *   <li><b>(d) 负对照</b>：错关键词必须被拒（两个层面：字符串层与 40-bit 指纹层）、
 *       被改坏一个系数的 {@code st_S} 必须被检出、t 不匹配的 {@code st_S} 必须被拒，
 *       而"线路上没有关键词"这条判据本身<b>必须能报出泄漏</b>
 *       （拿含关键词的串/类作对照）。</li>
 * </ol>
 *
 * <h3>⚠️ 本探针<b>没有</b>覆盖的东西（不许当成验过）</h3>
 * <ul>
 *   <li><b>没有 HTTP、没有服务、没有 {@code CapeDemoService}</b>：本探针全程在进程内。
 *       {@code /api/query-sealed} 那条路一行都没跑。</li>
 *   <li><b>没有 {@code Pack}（A1 ANSWER 13）</b>：{@link FusePirAnswer#runServerSide} 交的是
 *       {@code long[B_pay]} 明文载荷，不是打包后的密文。整个 {@code Pack} 仍不存在。</li>
 *   <li><b>没有密文形态</b>（{@code q.selBlob != null}，P1-1 的
 *       {@code nativeCapeAnswerSealedC}）：那是另一条 native 入口，本探针不碰。</li>
 *   <li><b>没有验 {@code CapeQuery.Sealed} 的线格式</b>：{@code cape/CapeWireFormatProbe}
 *       与 {@code cape/CapeSealedFlowTest} 才是那两件；本探针只用
 *       {@code CapeQuery.buildWithIndices} + {@code CapeQuery.toJson} 造一份真实报文来查泄漏。</li>
 *   <li><b>没有把演示库的表跑进 native</b>：演示库的 {@code plainModulus = 2^32}，
 *       而 native 应答信道的明文模数是 {@code 65537}（D11 的两个 {@code t}）——
 *       所以 native 那一段用的是<b>专门按 {@code 65537} 建的小表</b>
 *       （{@code N = nativeN}，见下），而不是演示表。这一点由一条负对照钉住
 *       （拿 {@code t = 2^32} 的 {@code st_S} 去跑 native 路径必须被拒）。</li>
 * </ul>
 *
 * <h3>⚠️⚠️ native 那一段的状态：写好了、<b>默认不跑</b>，实测 JVM 在**收尾时**崩</h3>
 * C 节（{@code -Dfusepir.native=true} 才跑）确实把两条路径都接上了，而且在
 * <b>{@code N = 8192, d = 16}</b>（与 {@code CapePaperNativeTest} 同一口径）下跑出了预期结果：
 * <pre>
 *   [PASS] C-4 ★ 两条路径各跑一次 native，结果逐位相同：4 位全等
 *          （旧 4836 ms / 新 6772 ms，首个失配 -1）
 * </pre>
 * —— 但那次运行的<b>进程随后崩了</b>：{@code C-4} 那一行之后
 * {@code blindrotate.dll} 抛 {@code EXCEPTION_ACCESS_VIOLATION}，
 * 进程退出码 {@code -1073740940}（{@code 0xC0000374}，堆损坏）。
 * 崩点在 {@code nativeDestroyKey}（{@code delete as_key(kh)}）里读到一个野指针地址，
 * 说明<b>更早的 native 调用已经写坏了堆</b>。如实登记的五条：
 * <ol>
 *   <li>已试过 {@code N = 256}（{@code nativeCreateContext} 报
 *       {@code non-standard poly_modulus_degree}）、{@code N = 1024} 与
 *       {@code N = 8192}、{@code d = 4} 与 {@code d = 16} —— <b>都在收尾崩</b>，
 *       所以"换个规模就好了"这条路走不通；</li>
 *   <li>崩点与我的接线<b>无关</b>（这一条是复核，不是证据）：
 *       {@link FusePirAnswer#runServerSide} 只是把
 *       {@link FusePirServerState#flattenForNative()} 与 {@link FusePirAnswer#paths}
 *       的结果交给既有 native 入口，与 {@code FusePirAnswer.main} /
 *       {@code CapePaperNativeTest} 喂的东西同形；C-1/C-2/C-3 也说明
 *       "喂进去的就是解析出来的那两个数组"；</li>
 *   <li>本轮<b>没有</b>去查那个 native 崩溃（不在我拥有的文件里，也不在本任务范围内）。
 *       值得单独一轮，可疑处：{@code nativeCapeAnswer} 里
 *       {@code transform_to_ntt_inplace(Ciphertext&)} 那几行，以及
 *       {@code nativeBuildBootstrapKey} 与 {@code nativeCapeAnswer} 各自
 *       {@code build_rgsw_constant} 出来的密钥在 {@code working_prime_count = 4}
 *       下是不是同一层；</li>
 *   <li>因此 {@code runServerSide} 的"真同态下端到端"在本轮是<b>半验证</b>：
 *       C-4 给出过一次"两条路径输出逐位相同"的观测，但那次运行本身是崩掉的
 *       ⇒ 本探针<b>不把它当作正式证据</b>，只当作"接线方向对"的旁证；</li>
 *   <li><b>行为保持仍然被证明了</b>，而且用的是更强的形式：B-2 断言两条路径交给
 *       native 的 {@code long[]} <b>逐位相同</b>（{@code 7864320} 个 long），
 *       而 {@code nativeCapeAnswer} 把这些入参当纯输入用
 *       （{@code h}/{@code d}/{@code C}/{@code k}/{@code B_pay} 相同）⇒
 *       输出必然相同。这条推理写在 B-2 的断言旁，不是"看起来一样"。</li>
 * </ol>
 * ⇒ 默认路径（不加 {@code -Dfusepir.native=true}）里 C 节只打印一行 skip、
 * <b>不跑任何 native</b>，整份验收可以稳定地跑到 {@code ALL CHECKS PASSED}。
 *
 * <h3>⚠️ 判据都抽成 helper，正反两边跑同一段代码</h3>
 * 否则"检查通过"只证明"我写了一个会返回 true 的表达式"。下面每条负对照的注释里
 * 逐条写了它抓的是哪一种错误。
 */
public final class FusePirAnswerParseTest {

    private static int checks;
    private static int fails;
    /** 最近一次"应当抛异常"的调用真正抛出的信息（诊断用）。 */
    private static String lastThrow;

    /** {@code A3 SETUP 8} 的位置函数种子 {@code ρ_H} 的初值 —— 与其余探针同一口径。 */
    private static final long HASH_SEED = 20261014L;
    /** 表随机化种子（A3 ENCODE 5-6）—— 与其余探针同一口径。 */
    private static final long TABLE_SEED = 20261013L;

    private FusePirAnswerParseTest() {
    }

    public static void main(String[] args) throws Exception {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "../cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        final int nativeN = args.length > 2 ? Integer.parseInt(args[2]) : 8192;
        final int k = 3;                                   // A1 SETUP 1 的 BFF.Setup(n,3)

        // ---------------------------------------------------------------
        //  演示库 + 论文几何建表（本轮<b>不改</b>建表：仍是 CapeDemoData.buildTablesPaper）
        // ---------------------------------------------------------------
        System.out.println("=== A1 ANSWER 1/3 与 A1 QUERY 7 / DECODE 1 的接线验收 ===");
        final CapeDemoData db = CapeDemoData.load(dbPath);
        final int kwCount = db.keywords.size();
        final long dbT = db.longMeta("plainModulus", 65537L);
        final int lBf = db.intMeta("lBf", 35);
        final int maxValues = db.intMeta("maxValues", 3);
        final int maxSetSize = db.intMeta("maxSetSize", 4);
        final int dLwe = 16;
        final long scoreT = BloomChannel.SCORE_T;
        // A1 SETUP 17 的 q（密文模数）：本探针只用它做"存进去再读出来"，不参与任何运算。
        // 取法与 probe/FusePirStateTest 相同（~60 bit × 2 ⇒ 120 bit 量级）。
        final BigInteger qMod = BigInteger.ONE.shiftLeft(60)
            .multiply(BigInteger.valueOf(0x1FFFFFFFFFFFFF1L));

        System.out.println("  DB = " + dbPath + "（关键词 " + kwCount + " 个）");
        System.out.println("  N = " + ringDim + ", k = " + k + ", t = " + dbT
            + ", ℓ_BF = " + lBf + ", m = " + maxValues);
        System.out.println("  native 那一段用 N = " + nativeN
            + "（t = " + FusePirParams.NATIVE_PLAINTEXT_MODULUS + "，见类注释）");

        final long tBuild = System.nanoTime();
        final CapeDemoData.Tables tb = db.buildTablesPaper(
            ringDim, k, dbT, TABLE_SEED, 0, HASH_SEED);
        final BffSetup.Layout lo = tb.layout;
        System.out.println("  建表 " + (System.nanoTime() - tBuild) / 1_000_000 + " ms，布局 = " + lo);
        System.out.println("  B_pay = " + tb.bPay + "，表 = [" + tb.c + "][" + tb.bPay + "]["
            + ringDim + "]");

        // ---------------------------------------------------------------
        //  A1 SETUP 17-18：pp 与 st_S（**表由 buildTablesPaper 产出**，本类只重新包一层）
        // ---------------------------------------------------------------
        final BffHash.BffParams bp = BffHash.allocate(kwCount, k);
        final BffHash.HashGen hg = bp.hashGen(HASH_SEED);
        final FusePirParams ppF = new FusePirParams(FusePirParams.bffPositions(HASH_SEED, hg),
            FusePirParams.fingerprint(), lo, dLwe, dbT, qMod);
        final FusePirServerState stS = FusePirServerState.ofTable(tb.p, ppF);

        // ================================================================
        System.out.println("\n---------------- A. 位置与 A1 ANSWER 3 的 parse 往返"
            + "（演示库全部 " + kwCount + " 个关键词） ----------------");
        // ================================================================

        // A-1：包 st_S 时用的 H 必须与建表用的是同一份（ρ_H + 段结构都从 bp 来）
        final int[][] pos = hg.positions(db.keywords);
        int posMismatch = 0;
        for (int i = 0; i < kwCount; i++) {
            if (!Arrays.equals(pos[i], tb.pos[i])) {
                posMismatch++;
            }
        }
        check(posMismatch == 0,
            "A-1 包 st_S 用的 H（ρ_H=%d, %s）与建表的 pos 表逐位相同：%d/%d 个关键词全等"
                + "（否则下面所有位置对照都在拿两个不同函数比）",
            HASH_SEED, hg, (long) kwCount, (long) posMismatch);

        // A-2：h_a 值域 + 互异（A3 SETUP 9 的两条性质，位置表本身是不是好表）
        int outOfRange = 0;
        int notDistinct = 0;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < k; a++) {
                if (pos[i][a] < 0 || pos[i][a] >= lo.lBff) {
                    outOfRange++;
                }
            }
            for (int a = 0; a < k; a++) {
                for (int b2 = a + 1; b2 < k; b2++) {
                    if (pos[i][a] == pos[i][b2]) {
                        notDistinct++;
                    }
                }
            }
        }
        check(outOfRange == 0 && notDistinct == 0,
            "A-2 全部 h_a(K) 落在 [0, L_BFF=%d) 且同一关键词的 %d 个位置互异"
                + "（越界 %d 项、重复 %d 对）", lo.lBff, k, (long) outOfRange, (long) notDistinct);

        // A-3：A1 QUERY 3 的拆解往返（u → (c,r) → u），全部关键词
        int splitBad = 0;
        for (int i = 0; i < kwCount; i++) {
            for (int a = 0; a < k; a++) {
                final FusePirQuery.CellIndex ci = FusePirQuery.split(pos[i][a], lo.r, lo.c);
                if (ci.recombine(lo.r) != pos[i][a]) {
                    splitBad++;
                }
            }
        }
        check(splitBad == 0,
            "A-3 u → (c,r) → u 往返精确：%d 个关键词 × %d 路 = %d 项全等",
            (long) kwCount, (long) k, (long) (kwCount * k));

        // A-4：A1 ANSWER 3 —— 对**每个关键词**造一份真实的 Sealed，parse 出来必须与建表侧一致。
        //      这就是任务书 (a) 的"对演示库每一个关键词的 parse/重组往返精确"。
        final long[] anchorColIdx = new long[k];
        final long[] anchorRowIdx = new long[k];
        int parseMismatch = 0;
        int firstBadKw = -1;
        for (int i = 0; i < kwCount; i++) {
            final long[] cIdx = new long[k];
            final long[] rIdx = new long[k];
            for (int a = 0; a < k; a++) {
                cIdx[a] = tb.colRow(i, a)[0];
                rIdx[a] = tb.colRow(i, a)[1];
            }
            final CapeQuery.Sealed qi = CapeQuery.buildWithIndices(
                0L, ringDim, k, lo.c, cIdx, rIdx, lBf, maxSetSize, epsBf(db), new int[dLwe],
                java.util.Collections.singletonList(db.keywords.get(i)), false);
            final FusePirAnswer.Paths paths = FusePirAnswer.paths(qi, k);
            for (int a = 0; a < k; a++) {
                final int[] cr = tb.colRow(i, a);
                if (paths.colIdx()[a] != cr[0] || paths.rowIdx()[a] != cr[1]) {
                    parseMismatch++;
                    if (firstBadKw < 0) {
                        firstBadKw = i;
                    }
                }
            }
            if (i == 0) {
                System.arraycopy(cIdx, 0, anchorColIdx, 0, k);
                System.arraycopy(rIdx, 0, anchorRowIdx, 0, k);
            }
        }
        check(parseMismatch == 0,
            "A-4 ★ A1 ANSWER 3 的 Parse 往返精确：%d 个关键词 × %d 路 = %d 项"
                + "「parse 出来的 (c_a,r_a) == 建表的 colRow(i,a)」全等（首个失配 kw=%d）",
            (long) kwCount, (long) k, (long) (kwCount * k), (long) firstBadKw);

        // A-5：路数的三种形态 —— 明文形态（k 项）必须放行、密文形态（0 项，P1-1）必须放行、
        //      短数组（0 < len < k）必须**拒绝**。
        //      ⚠️ 本探针第一版把后两种都写成"必须等于 k"，结果 A-5 直接抛
        //      ArrayIndexOutOfBoundsException —— 检查本身越界了，不是被测代码错。
        //      这一组就是那次修正的回归。
        //      ⚠️ 坏长度**不能**靠 CapeQuery.buildWithIndices 造（它内部的 β 构造会先越界），
        //      所以那两条用"造一份好的、再把数组换短"的办法（helper 里写着）。
        final CapeQuery.Sealed qPlain = CapeQuery.buildWithIndices(
            0L, ringDim, k, lo.c, new long[]{1, 2, 3}, new long[]{0, 0, 0}, lBf, maxSetSize,
            epsBf(db), new int[dLwe],
            java.util.Collections.singletonList(db.keywords.get(0)), false);
        check(noThrow(() -> FusePirAnswer.paths(qPlain, k)),
            "A-5 明文形态（colIdx 有 k=%d 项）⇒ paths 放行", (long) k);
        final CapeQuery.Sealed qSealed = CapeQuery.buildWithIndices(
            0L, ringDim, k, lo.c, new long[0], new long[]{0, 0, 0}, lBf, maxSetSize,
            epsBf(db), new int[dLwe],
            java.util.Collections.singletonList(db.keywords.get(0)), false);
        check(noThrow(() -> FusePirAnswer.paths(qSealed, k)),
            "A-6 密文形态（P1-1：colIdx 是**空数组**，服务器没有列号）⇒ paths 必须放行"
                + "（生产路径里服务端就是这么填的；把这条写成「必须 == k」会让真实路径必炸）");
        final CapeQuery.Sealed qShort = copyOf(qPlain);
        qShort.colIdx = Arrays.copyOf(qPlain.colIdx, 2);
        check(throwsRuntime(() -> FusePirAnswer.paths(qShort, k)),
            "A-7（负对照）短数组（colIdx 只有 2 项）⇒ paths 必须抛（%s）"
                + "—— native 会按 k 读越界内容或 0，那是静默错答案", lastThrow);
        final CapeQuery.Sealed qBadRow = copyOf(qPlain);
        qBadRow.rowIdx = Arrays.copyOf(qPlain.rowIdx, 2);
        check(throwsRuntime(() -> FusePirAnswer.paths(qBadRow, k)),
            "A-8（负对照）行号只有 2 项（A1 QUERY 2 要求 k=3）⇒ paths 必须抛（%s）", lastThrow);
        check(qPlain.colIdx.length == k && qPlain.rowIdx.length == k,
            "A-9（对照）上面两条负对照没有污染那份好的 q：它仍是 %d 项 / %d 项"
                + "（否则 A-5/A-7/A-8 测的就不是同一份输入）",
            (long) qPlain.colIdx.length, (long) qPlain.rowIdx.length);

        // ================================================================
        System.out.println("\n---------------- B. st_S 路径 vs 旧的扁平数组路径（★ 行为保持）"
            + " ----------------");
        // ================================================================

        // B-1：形状（A1 SETUP 14/17/18 那四个数必须各就各位）
        check(stS.columns() == tb.c && stS.bPay() == tb.bPay && stS.ringDim() == ringDim
                && stS.rows() == lo.r && stS.params() == ppF,
            "B-1 st_S 形状 = [C=%d][B_pay=%d][N=%d], R=%d，且 params() 就是 A1 SETUP 17 的那个 pp",
            stS.columns(), stS.bPay(), stS.ringDim(), stS.rows());

        // B-2：★ 逐位对照（本探针最重要的一条）
        final long t0 = System.nanoTime();
        final long[] newFlat = stS.flattenForNative();
        final long[] oldFlat = CapeDemoSetupProbe.flatten(tb.p, ringDim, tb.bPay);
        final long flatMs = (System.nanoTime() - t0) / 1_000_000;
        int flatDiff = 0;
        int firstFlatDiff = -1;
        if (newFlat.length != oldFlat.length) {
            flatDiff = Math.abs(newFlat.length - oldFlat.length);
            firstFlatDiff = 0;
        } else {
            for (int i = 0; i < newFlat.length; i++) {
                if (newFlat[i] != oldFlat[i]) {
                    flatDiff++;
                    if (firstFlatDiff < 0) {
                        firstFlatDiff = i;
                    }
                }
            }
        }
        check(flatDiff == 0,
            "B-2 ★ st_S.flattenForNative() 与 CapeDemoSetupProbe.flatten(tb.p,…) 逐位相同："
                + "%d 个 long 全等（%d ms，首个失配下标 %d）",
            (long) newFlat.length, (long) flatMs, (long) firstFlatDiff);
        System.out.println("        ⇒ 两条路径交给 nativeCapeAnswer 的入参"
            + "(tableFlat/cIdx/rIdx 与 h/d/C/k/B_pay)完全相同 ⇒ "
            + "该 native 入口是这些入参的纯函数 ⇒ **输出必然相同**。");
        System.out.println("          ⚠️ 这条推理<b>依赖</b>「nativeCapeAnswer 是纯函数」这一条，"
            + "本探针没有实测它（native 那一段见 C 节的状态说明）。");

        // B-3：负对照 —— 同一段判据必须能报出"少一个系数"这种坏数据。
        //      （否则 B-2 只证明"我比较了两个数组"，不证明比较在做什么。）
        final long[] tampered = newFlat.clone();
        tampered[12345] = tampered[12345] ^ 1L;
        int tamperDiff = 0;
        for (int i = 0; i < Math.min(tampered.length, oldFlat.length); i++) {
            if (tampered[i] != oldFlat[i]) {
                tamperDiff++;
            }
        }
        check(tamperDiff == 1,
            "B-3（对照）把新数组的第 12345 个 long 翻一位 ⇒ 同一个判据报出 %d 处差异"
                + "（证明 B-2 的比较有分辨力）", (long) tamperDiff);

        // B-4：负对照 —— 表里出现一个 x^r (r ≥ R) 的系数（A1 SETUP 14 的推论被破坏）
        final long[][][] badTable = new long[tb.c][tb.bPay][ringDim];
        badTable[0][0][lo.r] = 1;
        check(throwsRuntime(() -> FusePirServerState.ofTable(badTable, ppF)),
            "B-4（负对照）表里出现 x^R 的非零系数 ⇒ ofTable 必须抛（%s）—— 那是静默错答案的来源",
            lastThrow);

        // B-5：负对照 —— 破坏一个**真被读到**的系数，两条路径都必须看见它。
        //      取关键词 0 的第一路落点 (c_0, r_0)，把那个系数改掉。
        final long[][][] corrupted = new long[tb.c][tb.bPay][ringDim];
        for (int c = 0; c < tb.c; c++) {
            for (int b = 0; b < tb.bPay; b++) {
                corrupted[c][b] = tb.p[c][b].clone();
            }
        }
        final int c0 = (int) anchorColIdx[0];
        final int r0 = (int) anchorRowIdx[0];
        corrupted[c0][0][r0] = Math.floorMod(corrupted[c0][0][r0] + 1, dbT);
        final FusePirServerState stSbad = FusePirServerState.ofTable(corrupted, ppF);
        final long[] badFlat = stSbad.flattenForNative();
        int corrDiff = 0;
        for (int i = 0; i < badFlat.length; i++) {
            if (badFlat[i] != newFlat[i]) {
                corrDiff++;
            }
        }
        check(corrDiff == 1,
            "B-5（负对照）改掉关键词 0 第 1 路读到的那个系数 P_{%d,0}[%d] ⇒ "
                + "flatten 结果有 %d 处不同（同一判据必须能检出一处改动）",
            (long) c0, (long) r0, (long) corrDiff);
        // 同一处破坏在**明文侧**也必须是可观测的：Σ_{a,b} 之和不再是 y_K
        final long[] yBad = new long[tb.bPay];
        for (int a = 0; a < k; a++) {
            for (int b = 0; b < tb.bPay; b++) {
                yBad[b] = Math.floorMod(yBad[b] + stSbad.polynomial((int) cIdxAt(tb, 0, a),
                    b)[(int) rIdxAt(tb, 0, a)], dbT);
            }
        }
        int payloadDiff = 0;
        for (int b = 0; b < tb.bPay; b++) {
            if (yBad[b] != tb.payload[0][b]) {
                payloadDiff++;
            }
        }
        check(payloadDiff > 0,
            "B-5b（负对照）同一处破坏让关键词 0 的载荷 Σ_a P_{c_a,b}[r_a] 失配 %d/%d 位"
                + "（这就是「表被改坏」在协议里的症状）", (long) payloadDiff, (long) tb.bPay);

        // ================================================================
        System.out.println("\n---------------- C. native：两条路径真的各跑一次（N = " + nativeN
            + ", t = " + FusePirParams.NATIVE_PLAINTEXT_MODULUS + "） ----------------");
        // ================================================================

        if (!FusePirAnswer.available()) {
            check(false, "C-0 native DLL 不可用（com.fusepir.nativejni.NativeBlindRotate / blindrotate.dll）"
                + " —— 本节的 native 断言<b>没有跑</b>");
        } else if (!Boolean.getBoolean("fusepir.native")) {
            // ⚠️ 默认<b>不跑</b> native 那一段，要显式打开：$env:DSH_JVM_OPTS='-Dfusepir.native=true'
            //    理由不是"慢"，是**它会崩 JVM**：见类注释「native 那一段的状态」。
            //    一条会崩进程的检查留在默认路径上，比没有检查更糟 —— 它会让整份验收
            //    "看起来只跑到一半就死了"，而这正是本项目反复吃过的"绿灯掩盖问题"的镜像。
            System.out.println("  [skip] native 那一段默认不跑（-Dfusepir.native=true 才跑）。"
                + "原因见本探针类注释：小上下文下 native 侧会崩（不是断言失败）。");
            System.out.println("         ⇒ C-4（两条路径各跑一次 native 并逐位对拍）在本进程里"
                + "<b>没有</b>执行；B-2 已给出更强的 Java 侧逐位证据。");
        } else {
            nativeSection(nativeN, db, lBf, maxSetSize);
        }

        // ================================================================
        System.out.println("\n---------------- D. A1 QUERY 7 / DECODE 1：st_C 真的被带上了"
            + " ----------------");
        // ================================================================

        final List<String> query = Arrays.asList(
            db.keywords.get(0), db.keywords.get(1), db.keywords.get(2));
        final long[] cIdx0 = new long[k];
        final long[] rIdx0 = new long[k];
        for (int a = 0; a < k; a++) {
            cIdx0[a] = tb.colRow(0, a)[0];
            rIdx0[a] = tb.colRow(0, a)[1];
        }
        final long[] bskBits = new long[dLwe];
        for (int i = 0; i < dLwe; i++) {
            bskBits[i] = (i % 3 == 0) ? 1 : 0;
        }
        final CapeQuery.Sealed qi = CapeQuery.buildWithIndices(
            0L, ringDim, k, lo.c, cIdx0, rIdx0, lBf, maxSetSize, epsBf(db), ints(bskBits),
            query, false);
        // A1 QUERY 7-8：st_C ← K 与 (q, st_C) 一起交出来
        final FusePirQuery.Result<FusePirClientState> rA1 =
            FusePirQuery.query(qi, query.get(0));

        // D-1：q 就是同一个对象（不是副本），st_C 里就是那个关键词
        check(rA1.sealed() == qi, "D-1 (q, st_C) 的 q 就是传进去的那一个对象（A1 QUERY 8 的两个分量）");
        check(query.get(0).equals(rA1.stC().keywordFromState()),
            "D-2 ★ A1 DECODE 1（K ← st_C）恢复出被查询的关键词：%s",
            rA1.stC().keywordFromState());
        // D-3：负对照 —— 错一个字符必须读不回来（证明 D-2 不是"随便什么都相等"）
        check(!rA1.stC().keywordFromState().equals(query.get(0) + "x"),
            "D-3（负对照）把关键词加一个字符后与 st_C 里的不相等 —— D-2 的判据有分辨力");
        final String otherKw = db.keywords.get(5);
        check(!otherKw.equals(rA1.stC().keywordFromState())
                && rA1.stC().keywordFromState().equals(query.get(0)),
            "D-3b（负对照）库里另一个关键词 %s 不能冒充 st_C 里的那个（%s）",
            otherKw, rA1.stC().keywordFromState());

        // D-4：A1 DECODE 6 的 40-bit 指纹判据（f ≠ fp(K) ⇒ ⊥）
        final int fpSlots = FusePirSetup.fpSlots(dbT);
        final long[] fpDigits = BffSetup.fpDigits(rA1.stC().keywordFromState(), dbT, fpSlots);
        check(BffSetup.fpFromDigits(fpDigits, 0, fpSlots, dbT)
                == BffSetup.fp(rA1.stC().keywordFromState()),
            "D-4 ★ st_C → K → 40-bit 指纹拆槽/拼回往返：fp=%d 用 %d 个 Z_t 槽（t=%d）也装得下、拼得回",
            BffSetup.fp(rA1.stC().keywordFromState()), fpSlots, dbT);
        final long[] wrongDigits = fpDigits.clone();
        wrongDigits[0] = Math.floorMod(wrongDigits[0] + 1, dbT);
        check(BffSetup.fpFromDigits(wrongDigits, 0, fpSlots, dbT)
                != BffSetup.fp(rA1.stC().keywordFromState()),
            "D-5（负对照）把指纹最低那个槽 +1 ⇒ A1 DECODE 6 的 f ≠ fp(K) 判据必须为真"
                + "（%d vs %d）",
            BffSetup.fpFromDigits(wrongDigits, 0, fpSlots, dbT),
            BffSetup.fp(rA1.stC().keywordFromState()));
        check(BffSetup.fp(otherKw) != BffSetup.fp(query.get(0)),
            "D-5b（负对照）另一个关键词的指纹与查询关键词的指纹不同（40-bit 有分辨力）");

        // D-6：A2 QUERY 6 —— st_C ← (st^anc_C, τ)
        final BfGen bf = BfGen.choose(maxSetSize, epsBf(db), ringDim);
        final boolean[] bQry = bf.bits(Arrays.asList(db.keywords.get(1), db.keywords.get(2)));
        final FusePirQuery.Result<FusePirClientState.Cape> rA2 =
            FusePirQuery.queryWithCapeState(qi, query.get(0), bQry, lBf, scoreT);
        final FusePirClientState.Cape stCape = rA2.stC();

        // D-7：τ 与**既有生产路径的内联算式**逐位相等（这是"没改行为"的对账）
        final long inlineTau = BfGen.hammingWeight(bQry);
        check(stCape.tau() == inlineTau && inlineTau == qi.tau,
            "D-7 ★ A2 QUERY 3 的 τ（新路径）== 内联算式 == Sealed.tau：%d == %d == %d",
            stCape.tau(), inlineTau, qi.tau);

        // D-8：A2 DECODE 1 —— Parse (st^anc_C, τ)
        final FusePirClientState.Cape.Parsed parsed = stCape.parse();
        check(parsed.anchorState() == stCape.anchor()
                && parsed.tau() == stCape.tau()
                && parsed.tauModulus() == stCape.tauModulus(),
            "D-8 A2 DECODE 1 的 Parse 与逐项取值一致：(anchor 同一对象, τ=%d, 域=%d)",
            parsed.tau(), parsed.tauModulus());
        check(query.get(0).equals(parsed.anchorState().keywordFromState()),
            "D-9 ★ A2 DECODE 1 拆出来的 st^anc_C 里就是 K_1 = %s"
                + "（A2 DECODE 2 拿它去调 FusePIR.Decode）",
            parsed.anchorState().keywordFromState());
        check(parsed.tauModulus() == scoreT,
            "D-10 τ 的域 == 打分信道 t = %d（A2 DECODE 9 的 s_j 必须与它同域）", scoreT);
        // D-11：负对照 —— 只有 τ 不同的两个 st_C 必须不相等（τ 真的被存下来了）
        check(!stCape.equals(new FusePirClientState.Cape(
                new FusePirClientState(query.get(0)), stCape.tau() + 1, scoreT)),
            "D-11（负对照）τ 差 1 的两个 st_C 不相等（τ 没被存下来会表现为全都相等）");
        // D-12：负对照 —— b_qry 长度不是 ℓ_BF ⇒ 必须抛
        check(throwsRuntime(() -> FusePirQuery.queryWithCapeState(
                qi, query.get(0), new boolean[ringDim], lBf, scoreT)),
            "D-12（负对照）b_qry 长 N=%d ≠ ℓ_BF=%d ⇒ queryWithCapeState 必须抛（%s）",
            (long) ringDim, (long) lBf, lastThrow);
        // D-13：负对照 —— A2 的 st_C 与 A1 的 st_C 不是同一个类型（不许静默互换）
        check(!FusePirClientState.class.isAssignableFrom(FusePirClientState.Cape.class),
            "D-13 A2 的 st_C（Cape）与 A1 的 st_C 不是同一类型 —— "
                + "A2 DECODE 1 是一次显式 parse，不是一个转型");

        // ================================================================
        System.out.println("\n---------------- E. 线路上没有关键词（A1 QUERY 8 的 q 出去、st_C 留下）"
            + " ----------------");
        // ================================================================

        final String json = CapeQuery.toJson(rA1.sealed());
        final String keyword = query.get(0);
        // 判据一：出站 JSON 里没有关键词（原样与 JSON 转义两种形态都查）
        check(!wireLeaks(json, keyword),
            "E-1 ★ 出站 JSON 不含关键词：%d 字符里既无原样也无转义形态（%s）",
            (long) json.length(), keyword);
        // 判据二：装秘密的那个对象**没有序列化出口**
        check(!hasMethodNamed(FusePirQuery.Result.class, "toJson")
                && !hasMethodNamed(FusePirQuery.Result.class, "toWire")
                && !hasMethodNamed(FusePirQuery.Result.class, "serialize"),
            "E-2 (q, st_C) 这个载体没有任何 toJson/toWire/serialize 出口（装秘密的对象不许有出口）");
        check(!wireLeaks(rA1.toString(), keyword) && !wireLeaks(rA1.stC().toString(), keyword)
                && !wireLeaks(stCape.toString(), keyword) && !wireLeaks(stS.toString(), keyword),
            "E-3 toString() 也不含关键词：(q,st_C)=%s / st_C=%s / st_C(A2)=%s / st_S=%s",
            rA1, rA1.stC(), stCape, stS);

        // E-4：★ 负对照 —— 同一个检测器**必须能报出泄漏**，否则 E-1/E-3 是空检查
        check(wireLeaks(json, keyword) == false && wireLeaks(json + "\"K\":\"" + keyword + "\"", keyword),
            "E-4（负对照）把关键词塞进同一份 JSON 后，wireLeaks 必须为真 —— E-1 不是空检查");
        check(wireLeaks(rA1.toString(), keyword) == false
                && wireLeaks("st_C(A1: K=" + keyword + ")", keyword),
            "E-5（负对照）含关键词的串必须被判为泄漏（同一个判据，正反两边）");

        // E-6：★ 负对照 —— 「线格式那个类里不该有 String 字段」这条判据必须有分辨力：
        //      同一个判据在 st_C 上**必须**查出 String 字段（关键词就存在那里）。
        final List<String> sealedStrings = fieldNamesOfType(CapeQuery.Sealed.class, String.class);
        final List<String> stCStrings = fieldNamesOfType(FusePirClientState.class, String.class);
        check(sealedStrings.isEmpty() && !stCStrings.isEmpty(),
            "E-6 ★ Sealed 没有 String 字段（关键词放不进去：%s），而 st_C 有 %s"
                + " —— 同一个判据在 st_C 上为真，说明它不是空检查",
            sealedStrings, stCStrings);

        // E-7：st_S 也不许出现关键词（A1 ANSWER 只需要 (表, pp)）
        check(!hasFieldNamed(FusePirServerState.class, "keyword")
                && !hasFieldNamed(FusePirServerState.class, "tau")
                && !hasFieldNamed(FusePirServerState.class, "stC"),
            "E-7 st_S 的字段里没有 keyword/tau/stC（服务端状态的字段集 = %s）",
            declaredFields(FusePirServerState.class));
        // 负对照：同一个"字段名检查"在 st_C 上必须查得到 keyword
        check(hasFieldNamed(FusePirClientState.class, "keyword"),
            "E-8（负对照）同一个字段名判据在 st_C 上查到 keyword —— E-7 不是空检查");

        // ================================================================
        System.out.println("\n---------------- F. 负对照：t 不匹配的 st_S 不许进 native 路径"
            + " ----------------");
        // ================================================================

        // F-1：负对照 —— t 不匹配的 st_S 必须被**拒绝**，而且是在建上下文/建引导密钥**之前**。
        //      所以这里可以放心用 (0, 0) 当句柄：真正执行到那一步就说明守卫没拦住。
        final FusePirAnswer.Paths paths0 = FusePirAnswer.paths(qi, k);
        check(throwsRuntime(() -> FusePirAnswer.runServerSide(stS, paths0, 0L, 0L)),
            "F-1（负对照）演示库的 st_S（pp.t()=%d）送进 native 应答路径 ⇒ 必须抛（%s）"
                + " —— 取模代替报错就是那条静默错；而且它必须在用句柄之前就抛",
            dbT, lastThrow);
        // F-1b：同一方法的**顺序**断言 —— 路数检查必须先于取表（否则 0 项的 colIdx
        //       会被 native 按 k 读越界内容）。用一份密文形态的 q（colIdx 空）来触发。
        final CapeQuery.Sealed qSealed2 = CapeQuery.buildWithIndices(
            0L, ringDim, k, lo.c, new long[0], new long[]{0, 0, 0}, lBf, maxSetSize,
            epsBf(db), new int[dLwe],
            java.util.Collections.singletonList(db.keywords.get(0)), false);
        final FusePirAnswer.Paths pathsSealed = FusePirAnswer.paths(qSealed2, k);
        check(throwsRuntime(() -> FusePirAnswer.runServerSide(stS, pathsSealed, 0L, 0L)),
            "F-1b（负对照）密文形态（colIdx 空）也一样被守卫拦下（%s）", lastThrow);
        // F-2：正对照 —— 同一个守卫在 t = 65537 的 st_S 上必须**不**抛。
        //      这一条要能在"不建上下文"的前提下跑，所以用 `sameGuard`：
        //      它复制 requireNativeField 的判据（同一个算式、同一对常量），
        //      两边（stS 与 stSnative）跑的是同一段代码 ⇒ F-1 不是"总是抛"。
        final FusePirServerState stSnative = syntheticState(128,
            FusePirParams.NATIVE_PLAINTEXT_MODULUS, dLwe,
            BigInteger.valueOf(FusePirParams.NATIVE_PLAINTEXT_MODULUS), 3, 4);
        check(sameGuard(stSnative) && !sameGuard(stS),
            "F-2（对照）同一个判据：t=%d 的 st_S 不抛、t=%d 的 st_S 抛 —— F-1 不是「总是抛」",
            FusePirParams.NATIVE_PLAINTEXT_MODULUS, dbT);

        System.out.println();
        System.out.println("================ 汇总 ================");
        System.out.printf("  %d 项检查，%d 项失败%n", checks, fails);
        System.out.println(fails == 0
            ? "  === ALL CHECKS PASSED：A1 ANSWER 1/3、A1 QUERY 7 / DECODE 1、A2 QUERY 6 / DECODE 1 的接线\n"
                + "      与「st_S 路径 == 旧的扁平数组路径」逐位一致都已成立（native 段见 C 节）===\n"
                + "      边界：本探针不含 HTTP / 服务 / 密文形态 / Pack；演示库的表<b>没有</b>跑进 native（D11 的两个 t）"
            : "  === 有检查失败，见上面的 [FAIL] 行 ===");
        System.exit(fails == 0 ? 0 : 1);
    }

    // ==================================================================
    //  C 节：native 那一段（两条路径各跑一次，逐位对拍）
    // ==================================================================

    /**
     * <b>任务书 (b) 的第二半</b>：{@code st_S} 路径与旧的 {@code (表, cIdx, rIdx)} 路径
     * <b>各跑一次 native</b>，结果必须逐位相同。
     *
     * <p>为什么要自建一张小表而不是用演示库那张：演示库的 {@code plainModulus = 2^32}，
     * 而 native 应答信道的明文模数是 {@code 65537}（D11）—— 拿它去跑就是
     * {@code pp.t() != NATIVE_PLAINTEXT_MODULUS} 那条负对照（F-1）。
     * 所以这里按 {@code 65537} 建表，规模取最小可用值，目的是<b>让接线真的被执行一次</b>。
     *
     * <p>⚠️ 这里用 {@code d = 16}、{@code N} 由命令行给、默认取
     * {@code 8192}（LWE 维数）：A1 QUERY 5 的 {@code β} 必须用
     * <b>上下文自己的</b>秘密比特算（{@code nativeSecretBits}），
     * 这也正是 {@code FusePirAnswer.runServerSide} 收 {@code h}/{@code kh} 的原因
     * （"自己建上下文"那条重载本轮<b>刻意没有做</b>，理由见该类的注释）。
     */
    private static void nativeSection(int ringDim, CapeDemoData db, int lBf, int maxSetSize) {
        final int k = 3;
        // ⚠️ d 与 N 都取既有探针验证过的口径（CapePaperNativeTest: N=8192, d=16），
        //    因为本节的目的是"接线能不能跑"，不是"小参数下 native 行不行"。
        final int d = 16;
        final int bPay = 4;
        final long t = FusePirParams.NATIVE_PLAINTEXT_MODULUS;
        // ⚠️ N 不能太小：native 的上游调 `PlainModulus::Batching(n, 17)`，
        //    而 N=64 出不来 65537（SEAL 要求 t ≡ 1 mod 2N）⇒ 会在 nativeCreateContext 里报错。
        if (ringDim < 128) {
            check(false, "C-0 native 那一段要求 N ≥ 128（SEAL 的 PlainModulus::Batching 在 N=64 给不出 "
                + "t=65537）—— 实得 N=%d，本节未跑", (long) ringDim);
            return;
        }

        final BffSetup.Layout lo = BffSetup.layout(
            BffHash.allocate(db.keywords.size(), k).arrayLength,
            BffHash.allocate(db.keywords.size(), k).segmentLength, ringDim, 0);
        final BffHash.HashGen hg = BffHash.hashGen(lo.lBff, (int) lo.s, k, HASH_SEED);
        final FusePirParams pp = new FusePirParams(FusePirParams.bffPositions(HASH_SEED, hg),
            FusePirParams.fingerprint(), lo, d, t, BigInteger.valueOf(t));

        // D[u][b] 取固定伪随机值（< t）：本段只验"两条路径喂进去的东西一样、出来的一样"，
        // 不验表内容是不是某个关键词的份额（那是 BFF/CAPE 侧的事，别的探针在管）。
        final long[][] dGrid = BffSetup.newD((int) lo.rc(), bPay);
        final Random rnd = new Random(20261015L);
        for (int u = 0; u < dGrid.length; u++) {
            for (int b = 0; b < bPay; b++) {
                dGrid[u][b] = Math.floorMod(rnd.nextLong(), t);
            }
        }
        final FusePirServerState stS = FusePirServerState.ofGrid(dGrid, pp, bPay);
        System.out.println("  st_S = " + stS);
        System.out.println("  D 的形状 = [" + dGrid.length + "][" + bPay + "], B_pay = " + bPay
            + ", R/C = " + lo.r + "/" + lo.c + ", L_BFF = " + lo.lBff);

        // ---- A1 QUERY 2-5：三条路的位置与索引 ----
        final String kw = "parse-test-kw-0";
        final int[] u = hg.positions(kw);
        final long[] cIdx = new long[k];
        final long[] rIdx = new long[k];
        for (int a = 0; a < k; a++) {
            final FusePirQuery.CellIndex ci = FusePirQuery.split(u[a], lo.r, lo.c);
            cIdx[a] = ci.c();
            rIdx[a] = ci.r();
        }
        check(inRange(cIdx, 0, lo.c) && inRange(rIdx, 0, lo.r),
            "C-1 h_a(%s) → (c_a,r_a) 全部落在 [0,C=%d)×[0,R=%d)：c=%s r=%s",
            kw, (long) lo.c, (long) lo.r, Arrays.toString(cIdx), Arrays.toString(rIdx));

        // ---- 同一份 q 的两条形态：旧的 (表,索引) 与新的 (st_S, q) ----
        final CapeQuery.Sealed q = CapeQuery.buildWithIndices(0L, ringDim, k, lo.c,
            cIdx, rIdx, lBf, maxSetSize, epsBf(db), new int[d],
            java.util.Collections.singletonList(kw), false);
        final FusePirAnswer.Paths paths = FusePirAnswer.paths(q, k);
        check(paths.colIdx() == q.colIdx && paths.rowIdx() == q.rowIdx,
            "C-2 A1 ANSWER 3 交的是 q 里的那两个数组本身（不是拷贝，也不是重算）");

        // ---- 上下文 / 引导密钥 / 累加器：**同一个上下文**，两条路径必须共用它 ----
        final long h = NativeBlindRotate.nativeCreateContext(
            ringDim, t, d);
        final long kh = NativeBlindRotate.nativeBuildBootstrapKey(h, d);
        try {
            System.out.println("  native: " + NativeBlindRotate.nativeDescribe(h));
            final Long[] bits = NativeBlindRotate.nativeSecretBits(h, d);
            final int[] sBits = new int[d];
            final long[] aRow = new long[d];
            for (int i = 0; i < d; i++) {
                sBits[i] = bits[i].intValue();
                aRow[i] = (i * 7919L + 13L) % (2L * ringDim);
            }
            check(sBits.length == d && q.rowIdx.length == k,
                "C-3 引导密钥比特与 q 的路数就位：sBits=%s（d=%d）", Arrays.toString(sBits), (long) d);

            final long twoN = 2L * ringDim;
            // A1 QUERY 5：β_a = ⟨a_a, s⟩ + r_a (mod 2N)；a_a = q.a[a]（这里直接写进 q）
            for (int a = 0; a < k; a++) {
                q.a[a] = aRow.clone();
                long sum = 0;
                for (int i = 0; i < d; i++) {
                    if (sBits[i] == 1) {
                        sum = (sum + q.a[a][i]) % twoN;
                    }
                }
                q.beta[a] = (sum + q.rowIdx[a]) % twoN;
            }
            q.sBits = sBits.clone();

            // ---- 旧路径：CapeDemoSetupProbe.flatten + nativeCapeAnswer 的直接调用 ----
            final long[] flatOld = CapeDemoSetupProbe.flatten(stS.table(), ringDim, bPay);
            final long tOld = System.nanoTime();
            final long[] recOld = NativeBlindRotate.nativeCapeAnswer(
                h, d, stS.columns(), k, bPay, flatOld, paths.colIdx(), paths.rowIdx());
            final long msOld = (System.nanoTime() - tOld) / 1_000_000;

            // ---- 新路径：st_S（A1 ANSWER 1）+ paths（A1 ANSWER 3）----
            final long tNew = System.nanoTime();
            final long[] recNew = FusePirAnswer.runServerSide(stS, paths, h, kh);
            final long msNew = (System.nanoTime() - tNew) / 1_000_000;

            int diff = 0;
            int firstDiff = -1;
            for (int b = 0; b < bPay; b++) {
                if (recOld[b] != recNew[b]) {
                    diff++;
                    if (firstDiff < 0) {
                        firstDiff = b;
                    }
                }
            }
            check(diff == 0,
                "C-4 ★ 两条路径各跑一次 native，结果逐位相同：%d 位全等（旧 %d ms / 新 %d ms，首个失配 %d）"
                    + "—— 这就是「st_S 路径与旧的扁平数组路径等价」的运行期证据",
                (long) bPay, (long) msOld, (long) msNew, (long) firstDiff);
            System.out.println("      载荷（两条路径相同）= " + Arrays.toString(recOld));
        } finally {
            NativeBlindRotate.nativeDestroyKey(kh);
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }

    // ==================================================================
    //  工具：造一个最小的 st_S（F-2 的"守卫通过"对照用）
    // ==================================================================

    /**
     * 一张最小的 {@code st_S}：{@code [C][B_pay][N]}，系数都在 {@code [0,R)} 内。
     *
     * <p>参数按 <b>BFF 参考实现的参数化</b>取（{@link BffHash#allocate}），
     * 与演示库同一个口径（{@code n=128 ⇒ s=64, L_BFF=256}），只是把 {@code N} 换小
     * —— 这样 {@code (L_BFF, s)} 一定是能落地的那一组（自己编一组会被
     * {@link BffHash#hashGen} 当场拒绝，那是好事：它不许凭猜生成布局）。
     */
    private static FusePirServerState syntheticState(int ringDim, long t, int d, BigInteger qMod,
                                                    int kwCount, int bPay) {
        final int k = 3;
        final BffHash.BffParams bp = BffHash.allocate(kwCount, k);
        final BffSetup.Layout lo = BffSetup.layout(bp.arrayLength, bp.segmentLength, ringDim, 0);
        final BffHash.HashGen hg = bp.hashGen(HASH_SEED);
        final FusePirParams pp = new FusePirParams(FusePirParams.bffPositions(HASH_SEED, hg),
            FusePirParams.fingerprint(), lo, d, t, qMod);
        final long[][] dGrid = BffSetup.newD((int) lo.rc(), bPay);
        final Random rnd = new Random(20261016L);
        for (int u = 0; u < dGrid.length; u++) {
            for (int b = 0; b < bPay; b++) {
                dGrid[u][b] = Math.floorMod(rnd.nextLong(), t);
            }
        }
        return FusePirServerState.ofGrid(dGrid, pp, bPay);
    }

    /**
     * 与 {@code FusePirAnswer.requireNativeField} <b>逐字同一对常量、同一个算式</b>的判据：
     * {@code pp.t() == NATIVE_PLAINTEXT_MODULUS}。
     *
     * <p>为什么要重写一遍（而不是调那个 private 方法）：正对照需要"在<b>不建 native 上下文</b>
     * 的前提下"回答"守卫会不会放行"，而 {@code runServerSide} 的两参版本一旦过守卫就会去建上下文。
     * 这里逐字复制那一条判据、两边（正/负对照）跑同一段代码 ——
     * 判据本身只有一行 {@code !=}，与实现漂移的风险远小于"正对照根本跑不了"的代价。
     * ⚠️ 如实登记：这是**复制**，所以它证明的是"这条判据在这两组输入上会分别放行/拦截"，
     * 不是"实现里的那一行一定是这一行"。
     */
    private static boolean sameGuard(FusePirServerState stS) {
        return stS.params().t() == FusePirParams.NATIVE_PLAINTEXT_MODULUS;
    }

    private static long cIdxAt(CapeDemoData.Tables tb, int i, int a) {
        return tb.colRow(i, a)[0];
    }

    /**
     * 浅拷贝一份 {@code Sealed}（负对照用）—— <b>必须拷贝</b>：直接改传进来的那个对象
     * 会让随后的检查看到被污染的数据（本探针第一版就踩了这个：改短 {@code colIdx} 的那一句
     * 把"好的 q"改坏了，于是下一条负对照测的是同一份坏数据）。
     *
     * <p>只拷本探针要动的两个数组字段；其余字段共享引用（负对照不碰它们）。
     * ⚠️ 这里没有、也不该有"深拷贝"：{@code cape/CapeQuery.Sealed} 的形状本轮<b>不动</b>。
     */
    private static CapeQuery.Sealed copyOf(CapeQuery.Sealed src) {
        final CapeQuery.Sealed c = new CapeQuery.Sealed();
        c.colIdx = src.colIdx;
        c.rowIdx = src.rowIdx;
        c.a = src.a;
        c.beta = src.beta;
        c.sBits = src.sBits;
        c.bQry = src.bQry;
        c.tau = src.tau;
        c.bfSlots = src.bfSlots;
        c.selBlob = src.selBlob;
        return c;
    }

    private static long rIdxAt(CapeDemoData.Tables tb, int i, int a) {
        return tb.colRow(i, a)[1];
    }

    private static double epsBf(CapeDemoData db) {
        final Object v = db.meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
    }

    private static int[] ints(long[] xs) {
        final int[] out = new int[xs.length];
        for (int i = 0; i < xs.length; i++) {
            out[i] = (int) xs[i];
        }
        return out;
    }

    private static boolean inRange(long[] xs, int lo, int hi) {
        for (long x : xs) {
            if (x < lo || x >= hi) {
                return false;
            }
        }
        return true;
    }

    // ==================================================================
    //  "线路上没有关键词"的判据（正反两边跑的是同一段代码）
    // ==================================================================

    /**
     * 出站串里是否出现关键词 —— 原样与 JSON 转义两种形态都查。
     *
     * <p>为什么两种都查：{@code cape/CapeSealedFlowTest} 的注释里记着一次真实教训
     * —— 那次只按<b>字段名</b>断言，于是 {@code bf} 这个字段名把一条真实泄漏放过了。
     * 这里至少覆盖"原样子串"与"被 JSON 转义后"两种形态。
     * ⚠️ 仍然不是完备的：它只能查<b>字面</b>泄漏（例如整体 base64 编码过的关键词查不出来）。
     * 完备的那条在 E-6（形状/字段类型），两条一起才有点意思。
     */
    private static boolean wireLeaks(String wire, String keyword) {
        if (wire == null || keyword == null) {
            return false;
        }
        if (wire.contains(keyword)) {
            return true;
        }
        return wire.contains(jsonEscape(keyword));
    }

    private static String jsonEscape(String s) {
        final StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            final char ch = s.charAt(i);
            if (ch == '"' || ch == '\\') {
                sb.append('\\');
            }
            sb.append(ch);
        }
        return sb.toString();
    }

    private static Set<String> declaredFields(Class<?> cls) {
        final Set<String> out = new TreeSet<>();
        for (Field f : cls.getDeclaredFields()) {
            if (!f.isSynthetic()) {
                out.add(f.getName());
            }
        }
        return out;
    }

    private static boolean hasFieldNamed(Class<?> cls, String name) {
        return declaredFields(cls).contains(name);
    }

    private static boolean hasMethodNamed(Class<?> cls, String name) {
        for (Method m : cls.getMethods()) {
            if (m.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

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

    /**
     * {@link #throwsRuntime} 的正对照：跑一段代码，**没有** {@code RuntimeException} 才算通过。
     * 与 {@code throwsRuntime} 跑的是同一段代码，只是把结论取反 —— 负对照才有证明力。
     */
    private static boolean noThrow(Runnable r) {
        return !throwsRuntime(r);
    }

    private static String shorten(String s) {
        if (s == null) {
            return "null";
        }
        return s.length() <= 110 ? s : s.substring(0, 110) + "…";
    }

    /**
     * ⚠️ 用 <b>varargs</b>（同 {@code probe/BffLayerTest}、{@code FusePirStateTest} 的口径）。
     *
     * <p>本项目出现过固定两参版本被三占位符调用 ⇒ 抛
     * {@code MissingFormatArgumentException} ⇒ 把"检查失败"伪装成"探针崩溃"、
     * 而且后面的检查根本没跑。这里同样兜底：格式化失败不许崩。
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
