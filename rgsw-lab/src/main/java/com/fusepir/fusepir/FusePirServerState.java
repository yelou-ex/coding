package com.fusepir.fusepir;

import com.fusepir.bff.BffEncode;
import com.fusepir.bff.BffSetup;

/**
 * <b>{@code st_S} —— Algorithm 1 SETUP 18 的服务端状态（明文表 + {@code pp}）。</b>
 *
 * <pre>
 *   A1 SETUP 12-16: for c = 0 to C−1: for b = 1 to B_pay:
 *                       P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r.
 *   A1 SETUP 18:    st_S ← ({P_{c,b}}_{c,b}, pp).
 *   A1 ANSWER  1:   Parse st_S = ({P_{c,b}}_{c,b}, pp).
 *   A1 ANSWER  5:   Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X)).
 *   A2 SETUP  13:   st_S ← st^F_S.                     ← CAPE **不改** st_S
 *   A2 ANSWER  2:   resp_anc ← FusePIR.Answer(st_S, q_anc).
 * </pre>
 *
 * <h3>本类型之前不存在（审计 A1 SETUP 18 的缺口）</h3>
 * 表本身早就有（{@code bff/BffEncode.embed} 产出 {@code [C][B_pay][N]}），
 * 但它此前<b>只作为 {@code CapeDemoData.Tables} 的一个字段存在</b> ——
 * 于是"论文的 {@code st_S} 是<b>一对</b>（表 + {@code pp}）"这件事在类型层面看不见，
 * ANSWER 拿到的是一堆散装字段（{@code Tables.p}、{@code tb.c}、{@code tb.bPay}、系统属性里的 {@code t}…）。
 * 本类型就是那一对，<b>不多不少</b>：A1 SETUP 18 里没有载荷、没有位置表、没有 {@code u}/{@code r}/{@code c}。
 *
 * <h3>⚠️ 服务端状态里<b>不许</b>出现的东西（结构性断言，配负对照）</h3>
 * <ul>
 *   <li><b>关键词 {@code K}</b>：A1 QUERY 7 把 {@code st_C ← K} 留给客户端，
 *       A1 DECODE 1 才 {@code K ← st_C}。服务端在 ANSWER 里只需要 {@code st_S} 与 {@code q}。</li>
 *   <li><b>{@code τ}</b>：A2 QUERY 6 {@code st_C ← (st^anc_C, τ)}，τ 是客户端的接受阈值
 *       （{@code cape/CapeQuery} 的注释与 {@code CapeSealedFlowTest} 的断言都要求它不出工作站）。</li>
 * </ul>
 * 本类的字段只有 {@code table} 与 {@code params}，且 {@code toString()} 不含关键词。
 * {@code probe/FusePirStateTest} 用<b>反射</b>断言这两条（判据的负对照：同一个判据
 * 在 {@link FusePirClientState} 上必须**能**查出 {@code keyword} 字段 —— 否则就是"检查没在检查"）。
 *
 * <h3>⚠️ A2 SETUP 13：CAPE <b>不改</b> {@code st_S}，所以 {@link #params()} 在 A2 里是 {@code pp_F}</h3>
 * 这是一条容易"顺手改错"的论文细节：A2 SETUP 12 把 {@code pp} 加宽成
 * {@code (pp_F, ℓ_BF, G, m)}，紧接着 A2 SETUP 13 写的是 {@code st_S ← st^F_S}
 * —— 服务端状态引用的仍是 {@code pp_F}，加宽后的 {@code pp} 作为**协议公开参数**另行传递。
 * 本类型照抄这条：拿到什么就存什么，不替调用方决定。
 * 探针把两种接线都跑一遍并断言"哪一种才是论文的"
 * （{@code st_S.params() == pp_F} 且 {@code != 加宽后的 pp}），负对照是把加宽后的 pp 存进去。
 *
 * <h3>⚠️ 表的形状与不变式</h3>
 * {@code table[c][b][r]} 就是 {@code P_{c,b}} 在 {@code X^r} 上的系数，
 * 形状 {@code [C][B_pay][N]}（{@link BffEncode#embed} 的产物，全项目唯一一份 reshape）。
 * 由 A1 SETUP 14 的求和上界 {@code r < R} 可得一条**硬不变式**：
 * <b>系数 {@code [R, N)} 必须全为 0</b>。本类型在构造时用
 * {@link BffEncode#checkDataRadius}（不另写一份）做这条自检 ——
 * 越界非零意味着"表里有不属于任何关键词的数据"，那是静默错答案的来源。
 *
 * <h3>⚠️ {@link #polynomial} 返回**内部数组**，不做防御性拷贝（有意）</h3>
 * A1 ANSWER 5 要把 {@code P_{c,b}} 喂给 {@code CtPtMul}/native，
 * 而一份 {@code [C][B_pay][N]} 表在本组参数下是 {@code 16·B_pay·N} 个 {@code long}
 * —— 逐次拷贝是白付的带宽。所以本类**明确**把内部数组交出去：
 * 调用方不许改它（本类型也不做版本控制）。这是登记过的边界，不是"检查过了"。
 *
 * <h3>⚠️ 未验证 / 调用方现状</h3>
 * <ul>
 *   <li><b>接入（2026-10-15 "接线"轮）：A1 ANSWER 1 现在有落地点了。</b>
 *       {@link #flattenForNative()} 把 {@code {P_{c,b}}} 压成 {@code nativeCapeAnswer} 要的
 *       一维数组，{@link FusePirAnswer#runServerSide} 用它一次跑完 A1 ANSWER 4-11。
 *       所以本类型<b>不再是"只有探针在用"</b>；但 ⚠️ <b>生产路径仍未切换</b>：
 *       {@code cape/CapeDemoService}（{@code :118} 与 {@code :936}）依旧自己调
 *       {@code CapeDemoSetupProbe.flatten(tb.p, …)}，本轮<b>不许动 {@code cape/}</b>。</li>
 *   <li>{@code FusePirAnswer.runServerSide} 会用 {@code pp.t()} 与
 *       {@link FusePirParams#NATIVE_PLAINTEXT_MODULUS}（{@code 65537}）对账，
 *       不一致时抛异常 —— 因为 {@code {P_{c,b}}} 是被当成那个上下文的明文乘进去的。
 *       探针把这条做成了负对照。</li>
 *   <li>探针验的是"映射/形状/不变式/展平逐位一致/返回值"，<b>没有</b>跑任何同态运算本身：
 *       {@code CtPtMul}、{@code BlindRotate}、{@code SampleExtract_0} 的实际消费
 *       仍由 native（{@code rgsw_blindrotate.cpp} 的 {@code cape_answer_core}）完成，
 *       本类型只回答"表长什么样、怎么交给它"。</li>
 * </ul>
 */
public final class FusePirServerState {

    /** {@code {P_{c,b}}_{c,b}}：形状 {@code [C][B_pay][N]}。 */
    private final long[][][] table;
    /** {@code pp}（A1 SETUP 18 的第二项）。在 A2 里按 SETUP 13 就是 {@code pp_F}。 */
    private final FusePirParams params;

    private FusePirServerState(long[][][] table, FusePirParams params) {
        this.table = table;
        this.params = params;
    }

    /**
     * <b>A1 SETUP 12-18（前半）</b>：由 {@code D} 折出 {@code {P_{c,b}}} 并包成 {@code st_S}。
     *
     * <pre>
     *   A1 SETUP 12-16: P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r
     *   A1 SETUP 18:    st_S ← ({P_{c,b}}, pp)
     * </pre>
     *
     * <p>折表**不在这里重写**：转发到 {@link BffEncode#embed}（全项目唯一一份 reshape，
     * A1 SETUP 14 的字面实现）。本函数只做入口与自检。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）与 {@code probe/FusePirAnswerParseTest}
     * （后者用它建"接入后的 {@code st_S}"，并与旧的扁平数组路径逐位对账）。
     * 生产侧的建表在
     * {@code bff/CapeDemoData.buildTablesPaper}（它直接调 {@code BffEncode.embed}）。
     *
     * @param d     {@code D}：形状 {@code [RC][B_pay]}（{@link BffSetup#newD} 的产物）
     * @param pp    {@code pp}（A1 SETUP 17）
     * @param bPay  {@code B_pay}（{@code D} 每条的宽度）
     * @throws IllegalArgumentException 形状对不上：{@code d} 比 {@code RC} 短，
     *         或传入的 {@code bPay} 与 {@code d[u].length} 不一致
     * @throws IllegalStateException 见 {@link #ofTable}
     */
    public static FusePirServerState ofGrid(long[][] d, FusePirParams pp, int bPay) {
        if (d == null) {
            throw new IllegalArgumentException("D 不能为 null");
        }
        requireParams(pp);
        final int rc = (int) pp.layout().rc();
        if (d.length < rc) {
            throw new IllegalArgumentException("D 长 " + d.length + " < RC=" + rc
                + "：A1 SETUP 12-16 要读 D[r + cR] 到 r=C−1,R−1，短了会读到别的关键词的份额");
        }
        if (bPay < 1 || d[0].length != bPay) {
            throw new IllegalArgumentException("B_pay=" + bPay + " 与 D[0].length="
                + (d.length == 0 ? -1 : d[0].length) + " 不一致");
        }
        return ofTable(BffEncode.embed(d, pp.layout(), bPay), pp);
    }

    /**
     * <b>A1 SETUP 18</b>：把一张**已经建好的** {@code {P_{c,b}}} 表包成 {@code st_S}。
     *
     * <p>给"表由别处产出"的场合用（{@code CapeDemoData.Tables.p} 就是这个形状，
     * 将来接线只要一行）。本函数做三条自检，全部直接复用已有实现或读 {@code pp} 的字段：
     * <ol>
     *   <li>形状 = {@code [C][B_pay][N]}（{@code C}、{@code N} 取自 {@code pp.layout()}）；</li>
     *   <li>每个 {@code P_{c,b}} 的系数 {@code [R, N)} 全为 0（A1 SETUP 14 的推论），
     *       走 {@link BffEncode#checkDataRadius}；</li>
     *   <li>{@code R ≤ N}（A1 SETUP 4，{@code pp} 构造时已查，这里再查是因为表可能来自别处）。</li>
     * </ol>
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
     */
    public static FusePirServerState ofTable(long[][][] table, FusePirParams pp) {
        requireParams(pp);
        if (table == null) {
            throw new IllegalArgumentException("表不能为 null");
        }
        final int c = pp.c();
        final int n = pp.n();
        final int r = pp.r();
        if (table.length != c) {
            throw new IllegalArgumentException("表有 " + table.length + " 列，pp 的 C=" + c
                + "：A1 SETUP 14 的列数与 A1 SETUP 17 的 C 必须是同一个数");
        }
        if (r > n) {
            throw new IllegalArgumentException("R=" + r + " > N=" + n + "（A1 SETUP 4 要求 R ≤ N）");
        }
        final int bPay = table[0] == null ? 0 : table[0].length;
        if (bPay < 1) {
            throw new IllegalArgumentException("B_pay 必须 ≥ 1");
        }
        for (int cc = 0; cc < c; cc++) {
            if (table[cc] == null || table[cc].length != bPay) {
                throw new IllegalArgumentException("第 " + cc + " 列的宽度与第 0 列不一致（应为 " + bPay + "）");
            }
            for (int b = 0; b < bPay; b++) {
                if (table[cc][b] == null || table[cc][b].length != n) {
                    throw new IllegalArgumentException("P_{" + cc + "," + b + "} 的系数个数不是 N=" + n);
                }
            }
        }
        // A1 SETUP 14 的推论：P_{c,b} 只用到 X^0..X^{R−1} ⇒ 系数 [R, N) 必须为 0。
        // 直接复用 BffEncode.checkDataRadius（建表侧 cape 路径也在用同一份），不另写扫描。
        BffEncode.checkDataRadius(table, c, bPay, n, r);
        return new FusePirServerState(table, pp);
    }

    private static void requireParams(FusePirParams pp) {
        if (pp == null) {
            throw new IllegalArgumentException("pp 不能为 null（A1 SETUP 18 的第二项）");
        }
    }

    // ==================================================================
    //  取值函数 —— 当前调用方只有 probe/FusePirStateTest
    // ==================================================================

    /** {@code pp}（A1 SETUP 18 的第二项）。调用方：探针（含 A2 SETUP 13 的接线断言）。 */
    public FusePirParams params() {
        return params;
    }

    /**
     * {@code {P_{c,b}}_{c,b}} 本体（**内部数组**，见类注释）。
     *
     * <p>调用方：{@code probe/FusePirStateTest}。
     * ⚠️ native 侧要的是**一维** {@code flat} 数组
     * （{@code CapeDemoSetupProbe.flatten(p, ringDim, bPay)}）——
     * <b>2026-10-15 起那个展平也在本类型里</b>：见 {@link #flattenForNative()}
     * （它在 {@code fusepir/} 一侧，{@code cape/} 侧的形状仍未切换）。
     */
    public long[][][] table() {
        return table;
    }

    /**
     * {@code P_{c,b}} 的多项式系数（长度 {@code N}，只有 {@code [0, R)} 非零）。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（逐 ({@code c},{@code b}) 与
     * {@code D[r + cR][b]} 对照）。返回内部数组，理由见类注释。
     */
    public long[] polynomial(int c, int b) {
        if (c < 0 || c >= table.length) {
            throw new IndexOutOfBoundsException("c=" + c + " 越界（C=" + table.length + "）");
        }
        if (b < 0 || b >= table[c].length) {
            throw new IndexOutOfBoundsException("b=" + b + " 越界（B_pay=" + table[c].length + "）");
        }
        return table[c][b];
    }

    /** {@code C}（= {@code pp.c()}，A1 ANSWER 5 的求和上界）。调用方：探针。 */
    public int columns() {
        return table.length;
    }

    /** {@code B_pay}（= 表的第二维，A1 ANSWER 4 的循环上界）。调用方：探针（与 {@code Cape.bPay()} 对账）。 */
    public int bPay() {
        return table[0].length;
    }

    /** {@code N}（环维度 = 每条多项式的系数个数）。调用方：探针。 */
    public int ringDim() {
        return table[0][0].length;
    }

    /** {@code R}（= {@code pp.r()}，A1 SETUP 4；也是系数非零区间的上界）。调用方：探针。 */
    public int rows() {
        return params.r();
    }

    // ==================================================================
    //  A1 ANSWER 1 的落地点：把 {P_{c,b}} 交给应答代码
    // ==================================================================

    /**
     * <b>{@code A1 ANSWER 1: Parse st_S = (&lbrace;P_{c,b}&rbrace;_{c,b}, pp)} 的<b>表那一半</b>
     * —— 压成应答代码要的一维 {@code flat} 数组。</b>
     *
     * <pre>
     *   A1 ANSWER  1: Parse st_S = ({P_{c,b}}_{c,b}, pp).
     *   A1 ANSWER  5: Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X))   ← **native**
     *   A1 ANSWER  7: ct_{a,b} ← SampleExtract_0(Acc'_{a,b})                       ← **native**
     * </pre>
     *
     * <h3>为什么是"压平"而不是"换一种形状"</h3>
     * A1 ANSWER 4-11 在本项目里<b>整个在 native/C++</b>
     * （{@code rgsw_blindrotate.cpp:543} {@code cape_answer_core}，入口 {@code nativeCapeAnswer}），
     * 它接的是**一维** {@code long[C·B_pay·N]}：第 {@code (c,b)} 条的 {@code N} 个系数
     * 连续摆放，顺序 {@code c} 优先。
     * 这个展平此前<b>只以一个探针里的静态方法存在</b>
     * （{@code probe/CapeDemoSetupProbe.flatten}），生产侧要自己手写同一段循环
     * （{@code cape/CapeDemoService:118} 与 {@code :936}）。
     * 本方法把"从 {@code st_S} 到应答入口"这一步收到 {@code st_S} 自己身上
     * —— 形状由 {@code pp} 决定，不再由调用点手抄。
     *
     * <p>⚠️ <b>算式与 {@code CapeDemoSetupProbe.flatten} 逐字等价</b>
     * （同一套 {@code c} → {@code b} → {@code System.arraycopy(…, n)} 循环），
     * 这一点由 {@code probe/FusePirAnswerParseTest} 对整张演示表做<b>逐位对照</b>断言
     * —— 不看代码、不比"看起来一样"。那条断言（a）就是本轮的"行为保持"证据。
     *
     * <p>⚠️ <b>不是防御性拷贝的反面：这一份是<b>新数组</b></b>。{@link #table()} 交的是内部数组
     * （有意，见类注释），而本方法必然分配 {@code C·B_pay·N} 个 {@code long}
     * —— 本组参数下 {@code 16·60·8192 = 7.9M} 个 {@code long}（约 63 MB）。
     * 所以它<b>不该被放进循环里调用</b>：跨边界的那一份数组应当复用。
     *
     * <p><b>调用方</b>：
     * <ol>
     *   <li>{@link FusePirAnswer#runServerSide}（A1 ANSWER 的服务端路径 —— 本类的唯一"生产"调用方）；</li>
     *   <li>{@code probe/FusePirAnswerParseTest}（与 {@code CapeDemoSetupProbe.flatten} 逐位对账）。</li>
     * </ol>
     *
     * @return {@code long[C · B_pay · N]}，第 {@code (c·B_pay + b)} 段是 {@code P_{c,b}} 的 {@code N} 个系数
     */
    public long[] flattenForNative() {
        final int c = columns();
        final int bPay = bPay();
        final int n = ringDim();
        final long[] flat = new long[c * bPay * n];
        int ptr = 0;
        for (int cc = 0; cc < c; cc++) {
            for (int b = 0; b < bPay; b++) {
                System.arraycopy(table[cc][b], 0, flat, ptr, n);
                ptr += n;
            }
        }
        return flat;
    }

    /**
     * {@code st_S} 的可读形式。
     *
     * <p>⚠️ 只打印形状与 {@code pp} 的一行摘要，<b>不打印任何关键词</b>
     * （服务端不该持有它，见类注释）。调用方：探针（负对照：串里不许出现关键词）。
     */
    @Override
    public String toString() {
        return "st_S({P_{c,b}}[" + columns() + "][" + bPay() + "][" + ringDim() + "], "
            + params + ")";
    }
}
