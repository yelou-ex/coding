package com.fusepir.fusepir;

import com.fusepir.common.BfGen;

import java.util.Objects;

/**
 * <b>{@code st_C} —— 客户端的<b>两个</b>形态：Algorithm 1 的 {@code K} 与 Algorithm 2 的 {@code (st^anc_C, τ)}。</b>
 *
 * <pre>
 *   A1 QUERY  7: q := (q_0, q_1, q_2),  st_C ← K.
 *   A1 QUERY  8: return (q, st_C).
 *   A1 DECODE 1: K ← st_C.
 *   A1 DECODE 6: if f ≠ fp(K) then return ⊥.
 *   A2 QUERY  1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1).
 *   A2 QUERY  2: b_qry ← BF.Gen(0, {K_2, …, K_Q}).
 *   A2 QUERY  3: τ ← ‖b_qry‖₁.
 *   A2 QUERY  6: st_C ← (st^anc_C, τ).
 *   A2 QUERY  7: return (q, st_C).
 *   A2 DECODE 1: Parse (st^anc_C, τ) from st_C …
 *   A2 DECODE 2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc).
 *   A2 DECODE 9: if s_j = τ then R ← R ∪ {v_j}.
 * </pre>
 *
 * <h3>本类型之前不存在（审计 A1 QUERY 7 与 A2 QUERY 6 两条的缺口）</h3>
 * 关键词此前只活在 {@code cape/CapeQuery} 的一次调用的局部变量里，
 * 而 {@code τ} 是 {@code CapeQuery.Sealed.tau} 的一个 {@code public long} 字段
 * （{@code cape/CapeQuery.java}），两者**没有共同的类型**。后果是：
 * "客户端手里到底留着什么"只能靠读调用点的注释，DECODE 的两条输入
 * （{@code K} 与 {@code τ}）在签名上各写一遍。
 *
 * <h3>⚠️ 两个形态<b>刻意不是继承关系</b>（与 {@link FusePirParams.Cape} 的选择相反，理由见下）</h3>
 * A2 QUERY 6 的字面是"<b>二元组</b> {@code (st^anc_C, τ)}"，而 A2 DECODE 1 又明确
 * <b>把它 parse 开</b>：{@code Parse (st^anc_C, τ) from st_C}，
 * 随后 A2 DECODE 2 拿 {@code st^anc_C} 单独去调 {@code FusePIR.Decode}。
 * ⇒ 这里用<b>组合</b>（{@link Cape#anchor()}）而不是让 {@code Cape} 继承
 * {@link FusePirClientState}：
 * <ul>
 *   <li>继承会让"**A2 的** {@code st_C}"静默通过任何需要"A1 的 {@code st_C}"的地方，
 *       而论文那一步是显式的 parse（一个 {@code anchor()} 调用），不是同一件东西；</li>
 *   <li>继承还会让 {@code τ} 跟着 anchor 状态一起流到 FusePIR 那一层 —— 那一层
 *       按论文根本不该看见 {@code τ}。</li>
 * </ul>
 * 对照：{@link FusePirParams.Cape} 用的是子类，因为 A2 SETUP 12 是"**加宽**同一个 {@code pp}"
 * （算法 2 全程把 {@code pp_F} 当 {@code pp} 用），两条行的语义本来就不同。
 *
 * <h3>⚠️ {@code K} 与 {@code τ} 都是客户端私有 —— 本类型不提供任何出站形态</h3>
 * A1 QUERY 8 / A2 QUERY 7 返回的是 {@code (q, st_C)}：{@code q} 出去，{@code st_C} <b>留下</b>。
 * {@code cape/CapeSealedFlowTest} 与 {@code CapeQuery.toJson} 的注释都写着
 * "出站 JSON 不含关键词 / τ / b_qry"。所以本类型：
 * <ul>
 *   <li><b>没有</b> {@code toJson} / {@code toWire} / {@code serialize} 之类的出口；</li>
 *   <li>{@link #toString()} <b>不打印关键词</b>（打日志就等于泄露）；
 *       {@link Cape#toString()} 打印 {@code τ}（本地诊断用，与
 *       {@code CapeQuery} 的 {@code main} 打印 τ 的口径一致），但同样不打印关键词。</li>
 * </ul>
 * {@code probe/FusePirStateTest} 对"打印串里不含关键词"有断言，且用含关键词的串作负对照
 * 证明该判据有分辨力。
 *
 * <h3>⚠️ {@code τ} 必须带上它的<b>域</b>（{@link Cape#tauModulus()}）</h3>
 * A2 DECODE 9 的判定是 {@code s_j = τ}，其中 {@code s_j = Dec_{s_R}(ct_score,j)} ——
 * 也就是 <b>{@code τ} 与分数必须属于同一个明文域</b>。本实现有<b>两个</b> {@code t}
 * （缺陷总表 D11 / MAP §13.1）：
 * <table border="1">
 *   <tr><th>信道</th><th>明文模数</th><th>谁在用</th></tr>
 *   <tr><td>打分信道（Bloom）</td><td>{@code BloomChannel.SCORE_T = 65537}</td>
 *       <td>{@code ct_score} 所在的域 ⇒ <b>τ 属于这里</b></td></tr>
 *   <tr><td>native 载荷信道</td><td>{@code 2^32}（{@code -Dcape.t}）</td>
 *       <td>{@code P_{c,b}}、载荷、盲旋转</td></tr>
 * </table>
 * 所以 {@link Cape} 把 {@code τ} 与它的模数**一起**存，并在构造时要求
 * {@code 0 ≤ τ < tauModulus}：{@code τ} 是一个<b>计数</b>（{@code ‖b_qry‖₁ ≤ ℓ_BF}），
 * 落在域外只可能是"拿错了域"（例如把 native 域的量当成 {@code τ}）。
 * 探针的负对照：{@code τ = tauModulus} 必须抛；正对照：{@code τ = tauModulus−1} 不抛。
 * 另一条负对照把**另一个 {@code t}** 当域传进来，断言"域的检查有分辨力"。
 * <p>⚠️ 域这一项是<b>本实现为了闭合 D11 加的</b>，论文的 {@code st_C} 只有
 * {@code (st^anc_C, τ)} 两项 —— 如实登记，不假装是论文写的。
 *
 * <h3>⚠️ 未验证 / 调用方现状（2026-10-15 "接线"轮更新）</h3>
 * <ul>
 *   <li><b>接入</b>：{@link com.fusepir.fusepir.FusePirQuery.Result} 现在<b>真的持有</b>一个
 *       {@link FusePirClientState}（{@code fusepir/FusePirQuery.java} 的
 *       {@code query(…)} 工厂，对应 A1 QUERY 7-8 的 {@code st_C ← K} 与
 *       {@code return (q, st_C)}）。也就是说"客户端留着什么"第一次有了载体，
 *       而不只是一个类型。
 *       ⚠️ <b>它仍然不在 {@code CapeQuery.Sealed} 上</b>：{@code Sealed} 是**线格式**的载体
 *       （{@code CapeQuery.toJson} 就是按它的字段发 JSON 的），把 {@code K} 放进去
 *       等于把关键词交给"可能被发出去"的那个对象；而 {@code CapeDemoService.parseSealed}
 *       在服务进程里会**新建一个** {@code Sealed} 并持有它。
 *       ⇒ 本状态<b>故意与 wire 对象分离</b>，理由与判据在
 *       {@code FusePirQuery.Result} 的注释里。</li>
 *   <li>{@code cape/CapeDecode}（吃 {@code long tau} 参数）**仍在走原来的散装参数**
 *       —— 本轮不许动 {@code cape/}。所以本类型目前是"把论文的两行写成类型 + 接进
 *       {@code Result}"，<b>没有</b>让服务端/解密路径改成用它。</li>
 *   <li>探针<b>没有</b>验 {@code τ} 与真实 {@code ct_score} 解密值的相等性
 *       （那要起 SEAL/native）。{@code τ} 的"取值正确性"在本轮只到
 *       "等于 {@code BfGen.hammingWeight(b_qry)}"这一步；端到端判定仍由
 *       {@code CapeBloomScore} / {@code CapeDecode} 的既有断言覆盖。</li>
 * </ul>
 */
public final class FusePirClientState {

    /** {@code st_C ← K}（A1 QUERY 7）：客户端留下的关键词。 */
    private final String keyword;

    /**
     * <b>A1 QUERY 7</b>：{@code st_C ← K}。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一），以及 {@link Cape}（它按
     * A2 QUERY 6 把 anchor 的 {@code st^anc_C} 原样包起来）。
     *
     * @param keyword 关键词 {@code K}（不可为 {@code null}；空串是合法字符串但一定是 bug 之外的输入，
     *                这里只拒绝 {@code null}，不替调用方判空串）
     */
    public FusePirClientState(String keyword) {
        if (keyword == null) {
            throw new IllegalArgumentException("K 不能为 null（A1 QUERY 7：st_C ← K）");
        }
        this.keyword = keyword;
    }

    /**
     * {@code K}（A1 DECODE 1：{@code K ← st_C}；A1 DECODE 6 用它算 {@code fp(K)}）。
     *
     * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
     * ⚠️ <b>这是客户端私有的</b>：不许放进任何请求/响应字段
     * （{@code CapeSealedFlowTest} 有出站 JSON 断言），也不要在日志里打（见类注释）。
     */
    public String keyword() {
        return keyword;
    }

    /**
     * 按 {@code K} 判等（两个 {@code st_C} 相同 ⟺ 关键词相同）。
     *
     * <p>调用方：{@code probe/FusePirStateTest} 的"状态忘了存 K 就必须能看出来"那条负对照。
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FusePirClientState)) {
            return false;
        }
        return keyword.equals(((FusePirClientState) o).keyword);
    }

    /** 与 {@link #equals} 配套（{@code K} 的哈希）。调用方：探针。 */
    @Override
    public int hashCode() {
        return Objects.hash(keyword);
    }

    /** ⚠️ <b>不打印 {@code K}</b>（客户端私有）。调用方：探针的"打印串不许含关键词"断言。 */
    @Override
    public String toString() {
        return "st_C(A1: K=<已隐去>)";
    }

    /**
     * <b>{@code A1 DECODE 1: K ← st_C} 的落地点。</b>
     *
     * <pre>
     *   A1 DECODE 1: K ← st_C.
     *   A1 DECODE 6: if f ≠ fp(K) then return ⊥.
     * </pre>
     *
     * <p>本方法<b>就是</b> {@link #keyword()}（同一个引用，不是副本），之所以再给一个名字，
     * 是因为 DECODE 的那一行与 QUERY 的那一行是**两件事**：
     * QUERY 7 是"把 {@code K} <b>存进</b> {@code st_C}"（构造器），
     * DECODE 1 是"把 {@code K} 从 {@code st_C} <b>取出来</b>"。
     * 有了它，DECODE 的判据 {@code f ≠ fp(K)} 才能被写成
     * {@code BffSetup.fp(st_C.keywordFromState())} 而不再需要调用方自己知道
     * "关键词存在 st_C 的哪个字段里"。
     *
     * <p><b>调用方</b>：{@code probe/FusePirAnswerParseTest}（把
     * {@code fp(K)} 与 A1 DECODE 6 的 40-bit 指纹做正/负对照 —— 正确关键词必须过、
     * 错一个字符必须被拒）。
     *
     * <p>⚠️ <b>仍然不许出站</b>：本方法给的是客户端本地的关键词，服务端不该调它
     * （服务端只有 {@link FusePirServerState}，那里面没有关键词 —— 见该类注释）。
     */
    public String keywordFromState() {
        return keyword;
    }

    // ==================================================================
    //  A2 形态：st_C ← (st^anc_C, τ)
    // ==================================================================

    /**
     * <b>A2 QUERY 6</b> 的 {@code st_C}：{@code (st^anc_C, τ)}。
     *
     * <p>三项：anchor 的客户端状态（= A1 形态的 {@code K_1}）、接受阈值 {@code τ}、
     * 以及 {@code τ} 所属的明文域（{@link #tauModulus()}，为闭合 D11 的两个 {@code t} 而加，
     * 见类注释）。
     */
    public static final class Cape {
        /** {@code st^anc_C}（A2 QUERY 1 的产物）。 */
        private final FusePirClientState anchor;
        /** {@code τ = ‖b_qry‖₁}（A2 QUERY 3）。 */
        private final long tau;
        /** {@code τ} 所属的明文域（= 打分信道的 {@code t}）。 */
        private final long tauModulus;

        /**
         * <b>A2 QUERY 6</b>：{@code st_C ← (st^anc_C, τ)}。
         *
         * <p>调用方：{@code probe/FusePirStateTest}（唯一）与 {@link #fromQuery}。
         * 一般请用 {@link #fromQuery}（它按 A2 QUERY 2-3 自己算 τ 并校验 {@code ℓ_BF}）。
         *
         * @param anchor      {@code st^anc_C}（A2 QUERY 1 给的 A1 形态 state）
         * @param tau         {@code τ = ‖b_qry‖₁}（A2 QUERY 3）
         * @param tauModulus  {@code τ} 的明文域 = 打分信道的 {@code t}
         *                    （{@code bloom/BloomChannel.SCORE_T}，本实现 65537）
         */
        public Cape(FusePirClientState anchor, long tau, long tauModulus) {
            if (anchor == null) {
                throw new IllegalArgumentException("st^anc_C 不能为 null（A2 QUERY 6）");
            }
            if (tauModulus <= 1) {
                throw new IllegalArgumentException("τ 的域必须 > 1，实得 " + tauModulus);
            }
            if (tau < 0 || tau >= tauModulus) {
                throw new IllegalArgumentException("τ=" + tau + " 不在域 [0, " + tauModulus
                    + ") 内：τ 是计数（A2 QUERY 3 的 ‖b_qry‖₁ ≤ ℓ_BF），"
                    + "落在域外只能说明**拿错了域**（本实现有两个 t，见 D11）");
            }
            this.anchor = anchor;
            this.tau = tau;
            this.tauModulus = tauModulus;
        }

        /**
         * <b>A2 QUERY 2-6 的客户端那一段</b>：由 {@code b_qry} 定出 {@code τ} 并组装 {@code st_C}。
         *
         * <pre>
         *   A2 QUERY 2: b_qry ← BF.Gen(0, {K_2, …, K_Q}).
         *   A2 QUERY 3: τ ← ‖b_qry‖₁.
         *   A2 QUERY 6: st_C ← (st^anc_C, τ).
         * </pre>
         *
         * <p>{@code τ} 的算式**一行都没有重写**：调 {@link BfGen#hammingWeight(boolean[])}
         * （伪代码里有编号的一行，全项目唯一那一份 —— {@code cape/CapeQuery} 也是调它）。
         *
         * <p>⚠️ 两条自检，都是"域"这件事的直接后果：
         * <ol>
         *   <li>{@code bQry.length == lBf}：{@code b_qry} 的长度<b>必须</b>是 {@code ℓ_BF}
         *       （A2 SETUP 1 选的、A2 ANSWER 5 折 {@code log2 ℓ_BF} 轮的那个长度）。
         *       传环维度 {@code N} 或 anchor 载荷宽度进来会算出一个**看起来正常但错**的 τ
         *       —— 探针的负对照就用"长度 = N 的位向量"来触发它。</li>
         *   <li>构造器那条 {@code 0 ≤ τ < tauModulus}（见 {@link #Cape}）。</li>
         * </ol>
         *
         * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
         * ⚠️ 生产路径没有接线：{@code cape/CapeQuery} 目前在
         * {@code bQry} 上内联 {@code q.tau = BfGen.hammingWeight(q.bQry)}。
         *
         * @param anchor      {@code st^anc_C}（A2 QUERY 1）
         * @param bQry        {@code b_qry}（A2 QUERY 2）
         * @param lBf         {@code ℓ_BF}（A2 SETUP 1）
         * @param scoreModulus {@code τ} 的域 = 打分信道的 {@code t}
         */
        public static Cape fromQuery(FusePirClientState anchor, boolean[] bQry,
                                     int lBf, long scoreModulus) {
            if (bQry == null) {
                throw new IllegalArgumentException("b_qry 不能为 null（A2 QUERY 2）");
            }
            if (bQry.length != lBf) {
                throw new IllegalArgumentException("b_qry 长 " + bQry.length + " ≠ ℓ_BF=" + lBf
                    + "：τ 是**该 Bloom 向量**的汉明重量（A2 QUERY 3），长度不对算出来的是另一个量");
            }
            return new Cape(anchor, BfGen.hammingWeight(bQry), scoreModulus);
        }

        /**
         * {@code st^anc_C}（A2 DECODE 1 的 {@code Parse (st^anc_C, τ)}；
         * A2 DECODE 2 把它单独交给 {@code FusePIR.Decode}）。
         *
         * <p>调用方：{@code probe/FusePirStateTest}（唯一）。
         */
        public FusePirClientState anchor() {
            return anchor;
        }

        /** {@code τ}（A2 DECODE 9 的判据右端）。调用方：{@code probe/FusePirStateTest}（唯一）。 */
        public long tau() {
            return tau;
        }

        /**
         * {@code τ} 所属的明文域（= 打分信道的 {@code t}，本实现
         * {@code BloomChannel.SCORE_T = 65537}）。
         *
         * <p>调用方：{@code probe/FusePirStateTest}（唯一）。见类注释：
         * 这一项是本实现为闭合 D11 的两个 {@code t} 加的，论文的 {@code st_C} 没有它。
         */
        public long tauModulus() {
            return tauModulus;
        }

        /**
         * <b>{@code A2 DECODE 1: Parse (st^anc_C, τ) from st_C} 的落地点。</b>
         *
         * <pre>
         *   A2 DECODE 1: Parse (st^anc_C, τ) from st_C, (resp_anc, {ct_score,j}_{j=1}^m) from resp.
         *   A2 DECODE 2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc).
         *   A2 DECODE 9: if s_j = τ then R ← R ∪ {v_j}.
         * </pre>
         *
         * <p>论文把 A2 QUERY 6 的 {@code st_C} 定义成一个**二元组**（{@code anchor} 与 {@code τ}），
         * 而 DECODE 的两行分别要它的两半：DECODE 2 拿 {@code anchor} 去调 FusePIR，
         * DECODE 9 拿 {@code τ} 做判据。本方法把这两半<b>一次</b>拆出来，
         * 于是"parse 过"这件事在代码里有名字，而不是调用方随手 {@code .anchor()} + {@code .tau()}
         * 各取一次（那样漏取 {@code τ} 的后果是 DECODE 9 的判据退化成常量比较，
         * 与"忘了它"无法区分）。
         *
         * <p>⚠️ <b>返回的是本对象的两个字段引用，不是拷贝</b>：{@code tauModulus} 一并带上
         * （它是本实现为闭合 D11 的两个 {@code t} 加的，见类注释），
         * 因为 A2 DECODE 9 的 {@code s_j = τ} 只有在**同一个域**里才有意义。
         *
         * <p><b>调用方</b>：{@code probe/FusePirAnswerParseTest}
         * （它与 {@link #anchor()} / {@link #tau()} 逐项对账，并断言 {@code anchor} 里
         * 确实是 A1 QUERY 7 存下的那个关键词）。
         */
        public Parsed parse() {
            return new Parsed(anchor, tau, tauModulus);
        }

        /**
         * {@code A2 DECODE 1} 拆出来的那个二元组（{@code st^anc_C}, {@code τ}）＋ {@code τ} 的域。
         *
         * <p>字段与 {@link Cape} 一一对应、只是换了个"已经被 parse 出来"的名字，
         * 为的是让 DECODE 那两行的调用点读起来是 parse 的结果，而不是又一次字段读取。
         */
        public static final class Parsed {
            /** {@code st^anc_C}（{@code A2 DECODE 2} 的入参）。 */
            private final FusePirClientState anchorState;
            /** {@code τ}（{@code A2 DECODE 9} 的判据右端）。 */
            private final long tau;
            /** {@code τ} 所属的明文域。 */
            private final long tauModulus;

            Parsed(FusePirClientState anchorState, long tau, long tauModulus) {
                this.anchorState = anchorState;
                this.tau = tau;
                this.tauModulus = tauModulus;
            }

            /** {@code st^anc_C}（{@code A2 DECODE 2} 把它单独交给 {@code FusePIR.Decode}）。 */
            public FusePirClientState anchorState() {
                return anchorState;
            }

            /** {@code τ}（{@code A2 DECODE 9}）。 */
            public long tau() {
                return tau;
            }

            /** {@code τ} 的域（{@code s_j} 必须与 {@code τ} 同域才能比，见类注释）。 */
            public long tauModulus() {
                return tauModulus;
            }

            /** ⚠️ 不打印关键词（它在 {@code anchorState} 里，那个自己也不打印）。调用方：探针。 */
            @Override
            public String toString() {
                return "st_C(A2) parsed: (st^anc_C=" + anchorState + ", τ=" + tau
                    + " ∈ Z_" + tauModulus + ")";
            }
        }

        /**
         * 按 {@code (st^anc_C, τ, 域)} 判等。
         *
         * <p>调用方：{@code probe/FusePirStateTest}（负对照：只有 {@code τ} 不同的两个
         * {@code st_C} 必须**不**相等 —— 否则说明 {@code τ} 没被真正存下来）。
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Cape)) {
                return false;
            }
            final Cape other = (Cape) o;
            return tau == other.tau && tauModulus == other.tauModulus
                && anchor.equals(other.anchor);
        }

        /** 与 {@link #equals} 配套。调用方：探针。 */
        @Override
        public int hashCode() {
            return Objects.hash(anchor, tau, tauModulus);
        }

        /**
         * ⚠️ 打印 {@code τ} 与域，但<b>不打印关键词</b>（关键词在 anchor 里，它自己也不打印）。
         *
         * <p>打印 {@code τ} 是本地诊断（与 {@code CapeQuery} 的 {@code main} 口径一致，
         * 那一行注释写着"τ（**不进 JSON**）"）；本类型不提供任何序列化出口。
         * 调用方：{@code probe/FusePirStateTest}。
         */
        @Override
        public String toString() {
            return "st_C(A2: st^anc_C=" + anchor + ", τ=" + tau + " ∈ Z_" + tauModulus + ")";
        }
    }
}
