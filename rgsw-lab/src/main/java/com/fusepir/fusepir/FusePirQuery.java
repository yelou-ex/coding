package com.fusepir.fusepir;

import com.fusepir.cape.CapeQuery.Sealed;

/**
 * <b>Algorithm 1 · QUERY</b> —— 位置拆解、列选择子、以及 {@code (q, st_C)} 这一对（FusePIR 那一半）。
 *
 * <pre>
 *   Alg 1 QUERY 2: for a = 0 to 2 do
 *   Alg 1 QUERY 3:     u_a ← h_a(K),  r_a ← u_a mod R,  c_a ← ⌊u_a/R⌋.
 *   Alg 1 QUERY 4:     e_{c_a} ← (0,…,0,1,0,…,0) ∈ {0,1}^C, with the 1 at index c_a.
 *   Alg 1 QUERY 5:     q_a = (q_a^col, q_a^row) = (RLWE.Enc_{s_R}(e_{c_a}), LWE.Enc_{s_L}(r_a)).
 *   Alg 1 QUERY 7:     q := (q_0, q_1, q_2),  st_C ← K.
 *   Alg 1 QUERY 8:     return (q, st_C).        ← {@link #query} / {@link Result}
 * </pre>
 *
 * <h3>本类存在的理由（审计结论）</h3>
 * QUERY 3 与 QUERY 4 在本项目里此前**只有内联表达式、没有具名函数**：
 * <ul>
 *   <li>QUERY 3 的拆解内联在 {@code cape/CapeQuery.buildPaper} 里
 *       （{@code colIdx[a] = u / lo.r;} / {@code rowIdx[a] = u % lo.r;}）；</li>
 *   <li>QUERY 4 的 one-hot 内联在 {@code cape/CapeQuery.encryptColumnSelectors} 里
 *       （{@code e[a*c + cc] = (cc == colIdx[a]) ? 1L : 0L;}）。</li>
 * </ul>
 * 内联表达式的代价在 {@code FusePirSetup} 的类注释里已经吃过一次：
 * 「两边各自手抄就是标准的漂移源 —— 改一处忘一处，症状是载荷被切错位，而且不会报错」。
 * 这里把这两步收成**一份**具名实现，并各带一条**边界断言**。
 *
 * <p>MAP §1（L51/L57）与本文件对应：{@code FusePirQuery} 此前「还没有独立文件」。
 * <b>⚠️ 本类只是 QUERY 的最小落地 —— 不是那次「把 Sealed 拆开」的完整重构。</b>
 * 那次重构要把 {@code q^col}/{@code q^row} 的**密文构造**也搬过来，会动
 * {@code CapeQuery.Sealed} 的形状（约 10 个调用点直接读它的字段），风险更高，**本轮刻意不做**。
 * 见本文件末尾「没做的事」那段。
 *
 * <h3>没做的事（如实登记，不是遗漏）</h3>
 * <ul>
 *   <li>QUERY 5 的 {@code q_a^row = LWE.Enc_{s_L}(r_a)}（带噪声）仍在 {@code CapeQuery}；
 *       本类的 {@link #split} 只产出 {@code (c_a, r_a)} 这两个**明文位置**。</li>
 *   <li>QUERY 5 的 {@code q_a^col = RLWE.Enc_{s_R}(e_{c_a})} 仍由
 *       {@code CapeQuery.encryptColumnSelectors} 广播到 native 层；
 *       本类的 {@link #oneHot} 只造**明文** {@code e_{c_a}}。</li>
 *   <li>{@code QUERY 3} 的 {@code h_a} 本身在 {@code bff/BffHash.positions}（A3 SETUP 9），
 *       不在本类 —— 本类<b>只做拆解</b>，不产生位置。</li>
 * </ul>
 *
 * <h3>2026-10-15 补的第三样：{@code A1 QUERY 7-8} 的 {@code (q, st_C)}（见 {@link Result}）</h3>
 * 本轮补的是"<b>客户端留着什么</b>"这一条：{@code st_C ← K} 此前只活在
 * {@code cape/CapeQuery} 一次调用的局部变量里，类型层面看不见。
 * {@link #query} / {@link #queryWithCapeState} 把它接上，并<b>刻意不动
 * {@code CapeQuery.Sealed} 的形状</b>（理由写在那两个函数的注释里，是<b>安全</b>理由，
 * 不是工作量理由）。⇒ 上一段说的"Sealed 拆开"这件事<b>仍然没做</b>，
 * 本轮的接线<b>不需要</b>它。
 */
public final class FusePirQuery {

    private FusePirQuery() {
    }

    /**
     * <b>{@code A1 QUERY 8: return (q, st_C)} 的载体</b> —— 出站的查询 {@code q}
     * 与<b>留下的</b>客户端状态 {@code st_C} 成对交出。
     *
     * <pre>
     *   A1 QUERY 7: q := (q_0, q_1, q_2),  st_C ← K.
     *   A1 QUERY 8: return (q, st_C).
     *   A1 DECODE 1: K ← st_C.
     *   A2 QUERY 6: st_C ← (st^anc_C, τ).
     *   A2 QUERY 7: return (q, st_C).
     *   A2 DECODE 1: Parse (st^anc_C, τ) from st_C …
     * </pre>
     *
     * <h3>为什么单独立一个类型，而不是把 {@code st_C} 塞进 {@code CapeQuery.Sealed}</h3>
     * <b>这是本轮唯一一处"与直觉相反"的设计决定，理由必须写清楚。</b>
     * 直觉的做法是给 {@code CapeQuery.Sealed} 加一个
     * {@code public FusePirClientState stC} 字段（那也确实是"自然的地方"）。
     * 那样做有两条硬伤，<b>都不是风格问题</b>：
     * <ol>
     *   <li><b>{@code Sealed} 是线格式的载体。</b>{@code CapeQuery.toJson(Sealed)} 就是按它的
     *       字段拼出站 JSON 的（{@code colIdx}/{@code rowIdx}/{@code aFlat}/{@code beta}/{@code sBits}）。
     *       把一个**装有关键词**的字段放进那个对象，等于让"关键词在不在线路上"这件事
     *       只由"谁记得不要去读它"来保证 —— 而 {@code probe/CapeSealedFlowTest}
     *       已经吃过一次同形的亏：{@code toJson} 曾无条件发 {@code bf}，
     *       而断言只查<b>字段名</b>，于是真实泄漏被绿灯放过（那份注释里写得很清楚）。</li>
     *   <li><b>服务端会持有同一个类的实例。</b>{@code cape/CapeDemoService.parseSealed(String)}
     *       在**服务进程里** {@code new CapeQuery.Sealed()} 并填字段，然后一路用到 ANSWER。
     *       状态字段一旦在线格式对象上，"服务端那份"与"客户端那份"就是同一个类型，
     *       而服务端那份按论文根本不该有关键词（A1 ANSWER 只需要 {@code st_S} 与 {@code q}）。
     *       ⇒ 本轮的选择是：{@code Sealed} <b>一个字段都不加</b>，
     *       客户端状态走 {@code (q, st_C)} 这条**参数通道**，
     *       服务端那条路上物理上不存在它。</li>
     * </ol>
     * <p>这与 MAP §7 的告警是同一件事的正面做法：那一节说"动 {@code Sealed} 的形状风险高"。
     * 本类不但没动它，还把"A2 的 {@code st_C} 是二元组"这一层用类型表示出来了。
     *
     * <h3>⚠️ 为什么 {@link Result} 带一个类型参数 {@code S}</h3>
     * A1 QUERY 8 的 {@code st_C} 是 {@code K}（{@link FusePirClientState}），
     * A2 QUERY 6 的 {@code st_C} 是 {@code (st^anc_C, τ)}（{@link FusePirClientState.Cape}），
     * 而 {@code Cape} <b>不是</b> {@code FusePirClientState} 的子类
     * （那是刻意的，理由见 {@code FusePirClientState} 的类注释：A2 DECODE 1 是显式 parse）。
     * 于是 {@code Result} 只能有一个类型参数来承载"两种形态各是哪个类型"：
     * <ul>
     *   <li>A1 的工厂给 {@code Result<FusePirClientState>}，A2 的给 {@code Result<Cape>}；</li>
     *   <li>想要 A2 那一半的 {@code τ} 就直接 {@code r.stC().tau()} —— <b>不需要强转</b>，
     *       也就不会出现"A2 的 st_C 被当成 A1 的 st_C 用"这种静默错
     *       （{@code probe/FusePirStateTest} 的 P7-7 专门验这条）。</li>
     * </ul>
     * ⚠️ <b>如实登记的边界</b>：{@code S} 是<b>无界</b>的，不是
     * {@code S extends FusePirClientState} —— 两个形态<b>没有</b>公共父类型
     * （给它们加一个公共接口就等于把"两者不许静默互换"这条性质削掉一半）。
     * 所以"它一定是两种 {@code st_C} 之一"这件事<b>由代码保证、编译器不保证</b>：
     * 唯一的构造器是 {@code private}，唯一的入口是 {@link #query} 与
     * {@link #queryWithCapeState}（两者都只传那两种形态）。
     */
    public static final class Result<S> {

        /** 出站的 {@code q}（A1 QUERY 8 的第一个分量）。 */
        private final Sealed query;
        /** 留下的 {@code st_C}（A1 QUERY 8 的第二个分量；A2 在它之上再包 {@code τ}）。 */
        private final S clientState;

        private Result(Sealed query, S clientState) {
            this.query = query;
            this.clientState = clientState;
        }

        /**
         * 出站的查询 {@code q} —— 交给 {@code CapeQuery.toJson} / 服务器。
         *
         * <p>⚠️ {@code q} 与 {@code st_C} 是 A1 QUERY 8 的<b>两个分量</b>：
         * 前者出去、后者留下。本方法给的是"出去"的那个。
         */
        public Sealed sealed() {
            return query;
        }

        /**
         * 留下的客户端状态 {@code st_C}（A1 QUERY 7 的 {@code st_C ← K}；
         * A2 QUERY 6 的 {@code st_C ← (st^anc_C, τ)}）。
         *
         * <p>调用方：探针（A1 DECODE 1 的 {@code K ← st_C} 与 A2 QUERY 6 的组装）。
         * ⚠️ <b>不出站</b>，见类注释。
         */
        public S stC() {
            return clientState;
        }

        /** ⚠️ 不打印关键词（{@code st_C} 自己会隐去）。调用方：探针。 */
        @Override
        public String toString() {
            return "(q, st_C=" + clientState + ")";
        }
    }

    /**
     * <b>A1 QUERY 7-8</b>：把已经建好的查询 {@code q} 与关键词 {@code K} 组成
     * {@code (q, st_C ← K)}。
     *
     * <pre>
     *   A1 QUERY 7: q := (q_0, q_1, q_2),  st_C ← K.
     *   A1 QUERY 8: return (q, st_C).
     * </pre>
     *
     * <p>算式一行都没有：{@code st_C ← K} <b>就是</b>
     * {@link FusePirClientState#FusePirClientState(String)} 构造器。
     * 本工厂做两件"把缝堵上"的事：
     * <ol>
     *   <li>{@code query} 与 {@code keyword} 都不许为 {@code null}；</li>
     *   <li>当 {@code query} 是 {@link FusePirQuery#split} 那条链路产出的
     *       {@code Sealed}（{@code colIdx} 非空）时，断言
     *       {@code query.colIdx.length == h_a(K) 的位置个数} ——
     *       也就是"这一份 {@code q} 确实是**这个** {@code K} 造出来的"。
     *       ⚠️ 这只是<b>形状</b>对账（个数），不是密码学绑定：
     *       {@code Sealed} 里没有关键词，两边都算不出"是不是同一个 K"。如实登记。</li>
     * </ol>
     *
     * <h3>⚠️ 为什么 {@code K} 要作为入参传进来，而不是从 {@code Sealed} 里读</h3>
     * 因为 {@code Sealed} 里<b>不该有</b>关键词（见 {@link Result} 的两条硬伤）。
     * 调用点因此必然写成 {@code query(q, query.get(0))} —— 两个参数都来自同一次
     * {@code CapeQuery.build*} 调用，这一点由探针断言
     * （{@code result.stC().keywordFromState().equals(query.get(0))}）。
     *
     * <p><b>调用方</b>：{@link #query(Sealed, String, boolean[], int, long)}（转发）与
     * {@code probe/FusePirAnswerParseTest}。
     *
     * @param query   出站的 {@code q}（{@code cape/CapeQuery.build*} 的产物）
     * @param keyword {@code K}（A1 QUERY 7；调用点通常就是 {@code query.get(0)}）
     */
    public static Result<FusePirClientState> query(Sealed query, String keyword) {
        if (query == null) {
            throw new IllegalArgumentException("q 不能为 null（A1 QUERY 8 的第一个分量）");
        }
        if (keyword == null) {
            throw new IllegalArgumentException("K 不能为 null（A1 QUERY 7：st_C ← K）");
        }
        if (query.colIdx != null && query.rowIdx != null
            && query.colIdx.length != query.rowIdx.length) {
            throw new IllegalArgumentException("q 的两条路数不一致：colIdx=" + query.colIdx.length
                + ", rowIdx=" + query.rowIdx.length + "（A1 QUERY 5 的 q_a 是成对的）");
        }
        return new Result<>(query, new FusePirClientState(keyword));
    }

    /**
     * <b>A2 QUERY 6-7</b>：在 A1 的 {@code st_C} 之上再包一层，给出
     * {@code st_C ← (st^anc_C, τ)}。
     *
     * <pre>
     *   A2 QUERY 2: b_qry ← BF.Gen(0, {K_2, …, K_Q}).
     *   A2 QUERY 3: τ ← ‖b_qry‖₁.
     *   A2 QUERY 6: st_C ← (st^anc_C, τ).
     *   A2 QUERY 7: return (q, st_C).
     * </pre>
     *
     * <p>返回的 {@link Result#stC()} 是那个<b>二元组</b>
     * （{@link FusePirClientState.Cape}）—— A2 DECODE 1 的
     * {@code Parse (st^anc_C, τ)} 由 {@link FusePirClientState.Cape#parse()} 给出。
     *
     * <p>{@code τ} 的算式<b>一行都没有重写</b>：转发到
     * {@link FusePirClientState.Cape#fromQuery}（它自己再转发到
     * {@link com.fusepir.common.BfGen#hammingWeight(boolean[])}，全项目唯一那一份）。
     * 本重载里那条 {@code bQry.length == lBf} 检查是为了**不把 {@code ℓ_BF} 猜错**：
     * 猜错的后果是一个"看起来正常但错"的 {@code τ}（见 {@code Cape.fromQuery} 的注释）。
     *
     * <p><b>调用方</b>：{@code probe/FusePirAnswerParseTest}。
     * ⚠️ 生产路径（{@code cape/CapeQuery.buildWithIndices}）**仍在内联**
     * {@code q.tau = BfGen.hammingWeight(q.bQry)}，本轮不许动 {@code cape/}；
     * 两边的 {@code τ} 由探针断言逐位相等。
     *
     * @param query       出站的 {@code q}
     * @param keyword     {@code K_1}（A2 QUERY 1 的 anchor 关键词 = A1 QUERY 7 的 {@code K}）
     * @param bQry        {@code b_qry}（A2 QUERY 2）
     * @param lBf         {@code ℓ_BF}（A2 SETUP 1；{@code b_qry} 的长度就是它）
     * @param scoreModulus {@code τ} 的域 = 打分信道的 {@code t}
     */
    public static Result<FusePirClientState.Cape> queryWithCapeState(
            Sealed query, String keyword, boolean[] bQry, int lBf, long scoreModulus) {
        final Result<FusePirClientState> base = query(query, keyword);
        if (bQry == null) {
            throw new IllegalArgumentException("b_qry 不能为 null（A2 QUERY 2）");
        }
        if (bQry.length != lBf) {
            throw new IllegalArgumentException("b_qry 长 " + bQry.length + " ≠ ℓ_BF=" + lBf
                + "：τ = ‖b_qry‖₁ 是**这个 Bloom 向量**的汉明重量（A2 QUERY 3），"
                + "长度不对算出来的是另一个量");
        }
        return new Result<>(query, FusePirClientState.Cape.fromQuery(
            base.stC(), bQry, lBf, scoreModulus));
    }

    /**
     * {@code A1 QUERY 3} 拆解的产物：{@code (列 c_a, 行 r_a)}。
     *
     * <p>做成一个小值类型而不是回传两个 {@code long}，是因为这两个数在调用点
     * <b>顺序极易写反</b>（{@code (c, r)} 与 {@code (r, c)} 都是 {@code [0,R)}/{@code [0,C)} 里的整数，
     * 编译器一个都不会拦）。具名字段把这条错误从「运行期查错槽」压到「编译期读不出来」。
     *
     * <p>不可变；{@link #toString} 是稳定格式，探针直接拿它做打印与比对。
     */
    public static final class CellIndex {
        /** {@code c_a = ⌊u/R⌋} —— 落到第几条多项式（第几列）。 */
        private final long c;
        /** {@code r_a = u mod R} —— 落在该多项式里的第几个系数（第几行）。 */
        private final long r;

        CellIndex(long c, long r) {
            this.c = c;
            this.r = r;
        }

        /** 列号 {@code c_a}（{@code A1 QUERY 5} 里 {@code e_{c_a}} 的下标）。 */
        public long c() {
            return c;
        }

        /** 行号 {@code r_a}（{@code A1 QUERY 5} 里被加密进 {@code q_a^row} 的那个数）。 */
        public long r() {
            return r;
        }

        /**
         * {@code A1 SETUP 14} 的还原：{@code u = c·R + r}。
         *
         * <p>这个方法把「拆解到底对不对」变成一条<b>可执行</b>的性质：
         * 对任何合法的 {@code u}，{@code split(u,R).recombine(R) == u}。
         * 探针用它对全部关键词做往返校验。
         *
         * <p>⚠️ 传进来的 {@code r} 必须与拆解时用的是同一个 {@code R}，本类**不校验**这一点
         * （{@code CellIndex} 不记 {@code R}，只有 {@code (c, r)} 两个数）。
         * 传别的 {@code R} 会得到一个**不报错但错**的数 —— 这正是 {@code R} 必须
         * 客户端与服务端同源的那个老问题，这里只做算术，不做同源保证。
         */
        public long recombine(int r) {
            if (r <= 0) {
                throw new IllegalArgumentException("R 必须 > 0，实得 " + r);
            }
            return c * r + this.r;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CellIndex)) {
                return false;
            }
            final CellIndex other = (CellIndex) o;
            return c == other.c && r == other.r;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(c) * 31 + Long.hashCode(r);
        }

        @Override
        public String toString() {
            return "(c=" + c + ", r=" + r + ")";
        }
    }

    /**
     * <b>{@code A1 QUERY 3}</b>：{@code u_a ← h_a(K)} 之后那一步
     * —— {@code c_a ← ⌊u_a/R⌋, r_a ← u_a mod R}。
     *
     * <pre>
     *   Alg 1 QUERY 3: u_a ← h_a(K),  r_a ← u_a mod R,  c_a ← ⌊u_a/R⌋.
     *   Alg 1 SETUP 14: P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r
     * </pre>
     *
     * <h3>为什么是 {@code (u/R, u mod R)}，而**不是**反过来</h3>
     * 判据只有一条：<b>拆解必须与建表时的下标算式互为逆运算</b>。
     * A1 SETUP 14 把 {@code D} 的第 {@code u} 项摆进第 {@code c} 条多项式的第 {@code r} 个系数，
     * 摆的位置是
     * <pre>
     *   u = c·R + r,   r ∈ [0, R)
     * </pre>
     * ⇒ 对 {@code u} 反解（{@code u mod R} 把高位商与低位余数分开）得到
     * {@code c = ⌊u/R⌋}、{@code r = u mod R}。查表侧再用 {@code P_{c_a,b}[r_a]}
     * 取回**同一个** {@code u}。
     *
     * <p><b>反过来写会怎样（这就是本项目最怕的假阴性）</b>：若取
     * {@code c = u mod C}、{@code r = ⌊u/C⌋}，那么还原出来的位置是
     * {@code c'·R + r' = (u mod C)·R + ⌊u/C⌋}，它**一般 ≠ u** ——
     * 于是 ANSWER 会选错列、旋错行，**两边都不报错**，只是载荷恒为 0 或假阴性。
     * 注意 {@code R = C} 时（我们的默认几何，{@code R = C = 16}）两条公式
     * <b>仍然不等价</b>，所以「反正 R = C」不是理由。
     * 反向读法的负对照见 {@code probe/FusePirQueryOpsTest}（128 个关键词全部对不上）。
     *
     * <h3>边界（这一步是**唯一**能拦住越界 {@code u} 的地方）</h3>
     * 断言 {@code 0 ≤ u < R·C}，越界抛 {@link IllegalArgumentException}，
     * 而不是用 {@code u >= R} 之类的「看起来够用」的宽松条件去算。
     * 理由：{@code u} 越界时拆出来的 {@code (c, r)} 是**另一个关键词的槽**
     * （A1 SETUP 4 只保证 {@code R·C ≥ L_BFF}，尾部那几个槽对应 `D[u] ← 0`），
     * 静默读下去就是假阴性，而不是崩溃。
     *
     * <p>⚠️ <b>诚实边界</b>：{@code R·C} 是 {@code u} 的<b>几何</b>上界；
     * 位置函数 {@code h_a} 的<b>值域</b>上界是 {@code L_BFF}（BFF 的 {@code arrayLength}）。
     * 当 {@code R·C > L_BFF}（存在尾部补零，A1 SETUP 9-11）时，
     * {@code [L_BFF, R·C)} 里的 {@code u} 能通过本方法而**不可能**是任何 {@code h_a} 的输出
     * ⇒ 调用方若要判「查询与建表同源」，必须**另做**那条 {@code u < L_BFF} 的检查。
     * {@code CapeQuery.buildPaper} 就是这么做的（两条检查并存，见那里的注释）。
     *
     * @param u 位置 {@code h_a(K)}（来自 {@code bff/BffHash.positions}）
     * @param r 行数 {@code R}（A1 SETUP 4；在 FusePIR-C 里它就是盲旋转的系数个数）
     * @param c 列数 {@code C}（A1 SETUP 4）
     * @throws IllegalArgumentException {@code u} 越界，或 {@code R}/{@code C} 非正
     */
    public static CellIndex split(long u, int r, int c) {
        if (r <= 0) {
            throw new IllegalArgumentException("R 必须 > 0，实得 " + r);
        }
        if (c <= 0) {
            throw new IllegalArgumentException("C 必须 > 0，实得 " + c);
        }
        // (long) 提升：R·C 在 int 上可能溢出（R ≤ N = 8192 时 C 只要 > 262143 就溢出），
        // 一旦溢出成负数，"越界"会被算成"在范围内"—— 又一条静默错。
        final long rc = (long) r * (long) c;
        if (u < 0 || u >= rc) {
            throw new IllegalArgumentException("位置 u=" + u + " 越界：A1 QUERY 3 要求 0 ≤ u < R·C = "
                + r + "·" + c + " = " + rc
                + "（越界会静默读到另一个关键词的槽 ⇒ 假阴性）");
        }
        return new CellIndex(u / r, u % r);
    }

    /**
     * <b>{@code A1 QUERY 4}</b>：{@code e_{c_a} ← (0,…,0,1,0,…,0) ∈ {0,1}^C}，
     * 1 落在下标 {@code c_a}。
     *
     * <pre>
     *   Alg 1 QUERY 4: e_{c_a} ← (0,…,0,1,0,…,0) ∈ {0,1}^C, with the 1 at index c_a.
     *   Alg 1 QUERY 5: q_a^col = RLWE.Enc_{s_R}(e_{c_a})
     * </pre>
     *
     * <p>返回值是**明文**向量（长度 {@code C}，元素只可能是 0 或 1）。
     * 加密不在本方法里：本项目的读法是「{@code C} 条独立标量密文」
     * （D3 已登记这条读法，它正是 {@code CtPtMul(ct,pt)} 能逐个相乘的原因），
     * 所以 {@code k} 路的 {@code k} 个 one-hot 会被**拼接**成 {@code k·C} 长的一维向量
     * 再交给 native 层，拼接顺序为路优先 {@code a·C + cc}
     * （{@code CapeQuery.encryptColumnSelectors} 负责，与
     * {@code nativeCapeAnswerSealedC} 的解析顺序一致）。
     *
     * <p>⚠️ <b>为什么必须断言 {@code 0 ≤ c_a < C}</b>：one-hot 越界时会得到一个**全零**向量，
     * 而全零向量是一条**合法**的输入 —— 加密照样成功、服务器照样算，只是
     * {@code Acc_{a,b} = 0}，最终载荷全 0。也就是说「列号写错」在这里的表现
     * 是**静默的假阴性**，不是异常。所以边界必须在构造 one-hot 这一步就拦住。
     *
     * @param c 列数 {@code C}（{@code e} 的长度）
     * @param cIdx 列号 {@code c_a}（来自 {@link #split}）
     * @throws IllegalArgumentException {@code C ≤ 0}，或 {@code c_a} 不在 {@code [0, C)}
     * @return 长度 {@code C} 的 {@code long[]}，只有下标 {@code cIdx} 处是 1
     */
    public static long[] oneHot(int c, long cIdx) {
        if (c <= 0) {
            throw new IllegalArgumentException("C 必须 > 0，实得 " + c);
        }
        if (cIdx < 0 || cIdx >= c) {
            throw new IllegalArgumentException("列号 c_a=" + cIdx + " 越界：A1 QUERY 4 要求 "
                + "0 ≤ c_a < C = " + c + "（越界会给出全零选择子 ⇒ 载荷静默全 0）");
        }
        final long[] e = new long[c];
        e[(int) cIdx] = 1L;
        return e;
    }
}
