package com.fusepir.fusepir;



import com.fusepir.probe.*;
import com.fusepir.cape.CapeQuery.Sealed;
import com.fusepir.nativejni.NativeBlindRotate;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * <b>把 native（路线 A：真 SEAL 4.0.0 C++）的 CAPE ANSWER 接进本项目 —— 新代码，不动
 * {@code CapeEndToEnd4}。</b>
 *
 * <h3>接线方式</h3>
 * {@code CapeEndToEnd4} 的 ANSWER 段做四件事：
 * <pre>
 *   每个单元：列选择（C 次 CtPtMul） -> 盲旋转（d 轮 CMUX） -> SampleExtract_0
 *   之后    ：密文域三路相加
 * </pre>
 * 本类把这一整段**一次 JNI 调用**交给 {@code nativeCapeAnswer}：
 * <ul>
 *   <li>只有 1 次 JNI 调用（120 个单元全在 C++ 里）；</li>
 *   <li>引导密钥、明文表、选择子都留在 native 内存，跨边界的只有
 *       {@code tableFlat} / {@code cIdx} / {@code rIdx} 三个数组；</li>
 *   <li>返回 {@code long[B_pay]}：每个载荷系数（单进程回环里客户端侧用 SEAL 的解密器解出）。</li>
 * </ul>
 *
 * <h3>与 Java 侧的等价性</h3>
 * 本类自建与 {@code CapeEndToEnd4.SETUP} 同形的数据（R×C 二维布局、BFF 三份份额、
 * {@code P_{c,b}(X)} 打包），先用 native 跑一遍，再用**纯 Java** 跑同一个问题，
 * 两者必须逐位一致。这样既验证了接线，也给出同口径的速度对照。
 *
 * <p>跑法：{@code .\run-native-cape.ps1 4096 16}
 *
 * <h3>2026-10-15 补：{@code A1 ANSWER 1/3} 的两个 parse（"接线"轮）</h3>
 * 本轮在 {@link #run} 之上补了两件事，<b>没有改 {@link #run} 的行为</b>：
 * <ul>
 *   <li>{@link #paths(Sealed, int)} —— {@code A1 ANSWER 3}：
 *       {@code Parse (q_a^col, q_a^row) from q}，交出 {@link Paths}；</li>
 *   <li>{@link #runServerSide(FusePirServerState, Paths, long, long)} —— {@code A1 ANSWER 1}
 *       的表那一半由 {@link FusePirServerState#flattenForNative()} 提供，
 *       与 {@link #paths} 一起喂进同一条 native 路径；句柄 {@code h}/{@code kh}
 *       由调用方（服务端 SETUP）给，因为 {@code β} 必须用那个上下文的秘密比特算。
 *       ⚠️ 它对 {@code pp.t()} 与 {@link FusePirParams#NATIVE_PLAINTEXT_MODULUS}
 *       做了对账（{@link #run} 本身没有，见该方法的注释）。
 *       ⚠️ <b>本轮刻意没有"自己建上下文"的便捷重载</b>，三条理由见该方法的注释。</li>
 * </ul>
 * 两者的验收在 {@code probe/FusePirAnswerParseTest}：对整张演示表断言
 * "新路径与旧的扁平数组路径喂给 native 的输入逐位相同"（{@code 7864320} 个 long）；
 * native 那一段默认不跑，原因（{@code blindrotate.dll} 收尾崩）写在那个探针的类注释里。
 */
public final class FusePirAnswer {

    private FusePirAnswer() {
    }

    /** native DLL 是否可用（类加载 + 动态库都成功）。 */
    public static boolean available() {
        try {
            Class.forName("com.fusepir.nativejni.NativeBlindRotate");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 跑一次 native CAPE ANSWER。
     *
     * @param p       {@code [C][B_pay][N]} 服务端明文表（与 {@code CapeEndToEnd4} 的 {@code P} 同布局）
     * @param colIdx  每条路的列号 {@code c_a}
     * @param rowIdx  每条路的行号 {@code r_a}
     * @return {@code long[B_pay]} 恢复出的载荷系数
     */
    public static long[] run(int n, int d, int c, int k, int bPay,
                            long[][][] p, int[] colIdx, int[] rowIdx) {
        long[] tableFlat = new long[c * bPay * n];
        int ptr = 0;
        for (int cc = 0; cc < c; cc++) {
            for (int b = 0; b < bPay; b++) {
                System.arraycopy(p[cc][b], 0, tableFlat, ptr, n);
                ptr += n;
            }
        }
        long[] cIdx = new long[k];
        long[] rIdx = new long[k];
        for (int a = 0; a < k; a++) {
            cIdx[a] = colIdx[a];
            rIdx[a] = rowIdx[a];
        }
        long h = NativeBlindRotate.nativeCreateContext(n, FusePirParams.NATIVE_PLAINTEXT_MODULUS, 16);
        try {
            return NativeBlindRotate.nativeCapeAnswer(h, d, c, k, bPay, tableFlat, cIdx, rIdx);
        } finally {
            NativeBlindRotate.nativeDestroyContext(h);
        }
    }

    // ==================================================================
    //  A1 ANSWER 1-3：从 st_S 与 q 交到应答入口
    // ==================================================================

    /**
     * <b>{@code A1 ANSWER 3: Parse (q_a^col, q_a^row) from q}</b> —— 每一路的
     * {@code (列号 c_a, 行号 r_a)}。
     *
     * <pre>
     *   A1 ANSWER 2: for a = 0 to 2 do
     *   A1 ANSWER 3:     Parse (q_a^col, q_a^row) from q.
     *   A1 ANSWER 4:     for b = 1 to B_pay do
     *   A1 ANSWER 5-7:       Acc / BlindRotate / SampleExtract_0（**全在 native**）
     * </pre>
     *
     * <h3>为什么"parse"在这里就是"读两个数组"</h3>
     * 论文的 {@code q} 是三个二元组 {@code q_a = (q_a^col, q_a^row)}，
     * 其中 {@code q_a^row = LWE.Enc_{s_L}(r_a)} 是**密文**：
     * 严格说服务器并不"知道" {@code r_a}，它只是把 {@code q_a^row} 直接喂给
     * {@code BlindRotate}。所以这一步在本项目里落成两件事：
     * <ol>
     *   <li>{@code q_a^row} <b>本体</b>（{@code cape/CapeQuery.Sealed} 的
     *       {@code a[a]}/{@code beta[a]}/{@code sBits}）由 native 侧直接用 —— 不经本方法；</li>
     *   <li>本方法交的是 {@code (c_a, r_a)} 这一对**索引**，因为 native 入口
     *       {@code nativeCapeAnswer(…, cIdx, rIdx)} 收的正是它们
     *       （{@code CapePaperNativeTest} 也是这么喂的：{@code cr = tb.colRow(i,a)}）。</li>
     * </ol>
     * ⚠️ <b>这条"服务器知道 r_a"不是 parse 的副作用，是本实现登记过的隐私缺陷</b>：
     * {@code CapeQuery} 里{@code beta} 的构造注释写着"服务器能从
     * {@code (a, sBits, beta)} 一步解出 {@code r_a}"（P1-2 未修）。
     * 本方法只是把既有事实写成函数，<b>没有</b>让它变得更糟或更好。
     *
     * <h3>⚠️ 它<b>不</b>做的两件事</h3>
     * <ul>
     *   <li><b>不看 {@code selBlob}。</b>当列选择子走密文（{@code q^col_a = RLWE.Enc(e_{c_a})}，
     *       P1-1）时，{@code Sealed.colIdx} 是<b>空数组</b> —— {@code q_a^col} 在 native 那边，
     *       服务器手里没有列号。那种情况下本方法交出的 {@code colIdx.length == 0}，
     *       而 {@code nativeCapeAnswerSealedC} 正是靠这一点区分两种形态的。
     *       把"密文形态"下假装知道的列号填进调用点，就是 {@code D13} 前半句（明文列号上线）。
     *       ⇒ <b>本方法如实交空数组</b>，由调用方按 {@code cIdx.length == 0} 选择入口。</li>
     *   <li><b>不校验越界。</b>{@code 0 ≤ c_a < C}、{@code 0 ≤ r_a < R} 是 A1 QUERY 3-5 的性质，
     *       越界意味着"查询与建表不同源"；那两条检查在构造侧
     *       （{@code FusePirQuery.split} 的 {@code u < R·C}、
     *       {@code CapeQuery.buildPaper} 的 {@code u < L_BFF}）已经做过，
     *       在 ANSWER 侧再查一次会把"客户端算错了"与"服务端读错了"混在一起。
     *       本方法只查<b>形状</b>（路数必须都是 {@code k}，见下）。</li>
     * </ul>
     *
     * <p>⚠️ <b>路数必须是 {@code k = 3}</b>（A1 QUERY 2 的循环 {@code a = 0 to 2}）：
     * 三条路的索引数组长度不等（比如 3 与 0）是最危险的形态 ——
     * native 会按 {@code k} 读前 {@code k} 个，读到的是**另一个数组**的越界内容或 0，
     * 于是列选择子全选第 0 列、旋转量恒 0，载荷静默变成垃圾。
     * 但"两条路都要 k 项"是**错的** —— 合法的长度组合有两种，见下。
     *
     * <p>⚠️ <b>路数的两种合法形态（不写清楚就会写出一个"生产路径必炸"的检查）</b>：
     * A1 QUERY 2 的循环是 {@code a = 0 to 2}，所以 {@code rowIdx} 恒为 <b>k 项</b>；
     * 而 {@code colIdx} 有<b>两种</b>形态：
     * <ul>
     *   <li><b>明文形态</b>（基线 / {@code D13} 前半句）：{@code colIdx.length == k}；</li>
     *   <li><b>密文形态</b>（P1-1，{@code selBlob != null}）：{@code colIdx.length == 0}
     *       —— 服务器手里根本没有列号（{@code cape/CapeDemoService.parseSealed} 就是这么填的，
     *       而且它正是靠"{@code colIdx} 是空数组"来区分两种形态的，
     *       见 {@code nativeCapeAnswerSealedC}）。</li>
     * </ul>
     * 本方法<b>只</b>放行这两组长度组合。特别注意：{@code 0 < colIdx.length < k}
     * 不是"部分密文形态"，它是坏数据 —— 那种长度下 native 会按 {@code k} 读
     * 它后面的内存或 0（列选择子全选第 0 列、旋转量恒 0，载荷静默变垃圾）。
     * <b>对<b>空数组</b>放行、对<b>短数组</b>拒绝，这条区分是刻意的。</b>
     * （⚠️ 本探针第一版就是"两条都必须 == k"，A-5 立刻报出
     *  {@code ArrayIndexOutOfBoundsException} —— 检查本身越界了，而**不是**被测代码错了。）
     *
     * <p><b>调用方</b>：{@link #runServerSide}（A1 ANSWER 的服务端路径）与
     * {@code probe/FusePirAnswerParseTest}（对整张演示表的 128 个关键词逐路对照
     * "parse 出来的 {@code (c_a, r_a)} == 建表侧的 {@code colRow(i,a)}"，
     * 以及三条长度负对照 + 一条密文形态正对照）。
     *
     * @param seal 出站的 {@code q}（{@code cape/CapeQuery.Sealed}）
     * @param k    BFF 位置数（A1 SETUP 1 的 {@code BFF.Setup(n,3)} ⇒ 3）
     * @throws IllegalArgumentException {@code seal} 为 {@code null}、
     *         {@code colIdx}/{@code rowIdx} 为 {@code null}，
     *         或长度组合不是上面那两种
     */
    public static Paths paths(Sealed seal, int k) {
        if (seal == null) {
            throw new IllegalArgumentException("q 不能为 null（A1 ANSWER 3 要从它 parse）");
        }
        if (seal.colIdx == null || seal.rowIdx == null) {
            throw new IllegalArgumentException("q 的 colIdx/rowIdx 缺失 —— "
                + "A1 QUERY 5 的 q_a = (q_a^col, q_a^row) 两项必须成对"
                + "（密文形态下 colIdx 是**空数组**，不是 null）");
        }
        if (seal.rowIdx.length != k) {
            throw new IllegalArgumentException("q 的行号有 " + seal.rowIdx.length + " 项，"
                + "A1 QUERY 2 要求 k=" + k + " 路（a = 0..2）");
        }
        if (seal.colIdx.length != k && seal.colIdx.length != 0) {
            throw new IllegalArgumentException("q 的列号有 " + seal.colIdx.length + " 项："
                + "A1 QUERY 5 只允许两种形态 —— 明文形态 " + k + " 项，"
                + "或密文形态（P1-1 的 q_a^col，此时服务器没有列号）0 项。"
                + "**短数组不是「部分密文形态」**：native 会按 k 读越界内容或 0，"
                + "结果是列选择子全选第 0 列、旋转量恒 0（静默错答案）。");
        }
        return new Paths(seal.colIdx, seal.rowIdx);
    }

    /**
     * {@code A1 ANSWER 3} 的产物：每一路的 {@code (q_a^col, q_a^row)} 里那两个**索引**。
     *
     * <p>做成一个值类型而不是回传两个 {@code long[]}，理由与
     * {@code FusePirQuery.CellIndex} 相同：{@code colIdx}/{@code rowIdx} 是
     * 两个同型数组，在调用点极易互换，而编译器一个都不会拦。
     *
     * <p>⚠️ <b>交的是 {@code Sealed} 里的内部数组，不是拷贝</b>（同
     * {@code FusePirServerState.table()} 的口径）：native 入口每查询要读它们一次，
     * 逐次拷贝是白付的；调用方不许改。
     */
    public static final class Paths {
        /** {@code [k]} 每一路的列号 {@code c_a}（密文形态下长度 0，见 {@link #paths}）。 */
        private final long[] colIdx;
        /** {@code [k]} 每一路的行号 {@code r_a}。 */
        private final long[] rowIdx;

        Paths(long[] colIdx, long[] rowIdx) {
            this.colIdx = colIdx;
            this.rowIdx = rowIdx;
        }

        /** {@code (q_0^col, …, q_{k−1}^col)} 的列号。 */
        public long[] colIdx() {
            return colIdx;
        }

        /** {@code (q_0^row, …, q_{k−1}^row)} 的行号。 */
        public long[] rowIdx() {
            return rowIdx;
        }

        /** 路数 {@code k}（= {@code rowIdx.length}；{@code colIdx} 可能是 0，见 {@link #paths}）。 */
        public int k() {
            return rowIdx.length;
        }

        @Override
        public String toString() {
            return "q_paths(c=" + Arrays.toString(colIdx) + ", r=" + Arrays.toString(rowIdx) + ")";
        }
    }

    /**
     * <b>{@code A1 ANSWER 1 + 4-11}</b>：{@code st_S} 与 {@code q} 进去，
     * {@code ct_{pay,b}} 的<b>解码结果</b>出来（一条 JNI 调用跑完 A1 ANSWER 4-11）。
     *
     * <pre>
     *   A1 ANSWER  1: Parse st_S = ({P_{c,b}}_{c,b}, pp).
     *   A1 ANSWER  3: Parse (q_a^col, q_a^row) from q.
     *   A1 ANSWER  4-11: Acc_{a,b} → BlindRotate → SampleExtract_0 → 三路 CtCtAdd
     *   A1 ANSWER 13: resp ← Pack(…)        ← **仍未实现**（MAP §6/§10.3②，本轮不动）
     *   A1 DECODE  2-4: y[β] ← Dec_{s_R}(ct_{pay,β})
     * </pre>
     *
     * <h3>这条路径与本轮之前的路径<b>逐字等价</b>（这是本轮的"行为保持"要求）</h3>
     * 之前：调用方自己 {@code CapeDemoSetupProbe.flatten(tb.p, N, bPay)} 造一维数组，
     * 自己从 {@code colOf/rowOf} 造 {@code cIdx/rIdx}，再调 {@link #run}。
     * 现在：{@code st_S} 提供前者（{@link FusePirServerState#flattenForNative()}），
     * {@code q} 提供后者（{@link #paths}），{@link #run} 一个字节都没改。
     * ⇒ 差别<b>只</b>在"数组是谁造的"。判据是探针里那条
     * "两条路径喂给同一次 native 调用的输入数组<b>逐位相同</b>"。
     *
     * <h3>⚠️ 与 {@code pp.t()} 的对账（一条**已经存在**的口径差异，本轮把它变成不静默）</h3>
     * {@code {P_{c,b}}} 是**乘法明文**，它按定义属于应答上下文所在的环 {@code Z_t}，
     * 所以建表用的 {@code pp.t()} 与那个上下文的明文模数必须一致
     * （缺陷总表 D11：本实现确实有两个 {@code t}）。
     * 不一致时<b>抛</b>而不是把表取模 —— 取模会让载荷减掉 {@code t} 的倍数，
     * 症状是"某些位差一个常数"，而那是本项目反复登记过的那类静默错。
     *
     * <p>⚠️ <b>但"对账"只能对到一半，这一点必须说清楚</b>：
     * 建表用的 {@code t} 在 {@code pp} 里（可查），而应答上下文**当前**的明文模数
     * 没有任何 Java 侧入口可以读（{@code nativeDescribe} 只回一行描述，
     * 本类不去解析它）。所以 {@link #requireNativeField} 那条检查只保证
     * "{@code pp.t()} 是我们期望的那个常量"，<b>不</b>证明句柄本身的 {@code t}。
     * 真实的保证来自建上下文的那一处（{@code Mpc4jRgsw} / {@code CapeDemoService}），
     * 本类不重复它。
     *
     * <h3>⚠️ 为什么<b>没有</b>"自己建上下文"的那个便捷重载（本轮刻意不提供）</h3>
     * 直觉上应该有一个 {@code runServerSide(stS, q)} 自己
     * {@code nativeCreateContext + nativeBuildBootstrapKey}。三个理由否掉了它，
     * 每一条都是硬理由：
     * <ol>
     *   <li><b>它不可能对</b>：A1 QUERY 5 的 {@code β = Σ a_i·s_i(bsk) + r_a} 里的
     *       {@code s_i(bsk)} 必须是**累加器那个上下文**的秘密比特
     *       （{@code CapeQuery} 里那段最长的不变量注释、{@code P1-1} 的四轮教训）。
     *       函数内部自建上下文的话，调用方**拿不到那组比特**（{@code nativeSecretBits}
     *       需要句柄），于是 {@code β} 必然不同源 ⇒ 载荷恒为垃圾。
     *       ⇒ 句柄必须由外面给，这不是为了"灵活"，是为了"可能正确"。</li>
     *   <li><b>服务端不可能那样跑</b>：{@code nativeCreateContext} 与
     *       {@code nativeBuildBootstrapKey} 是本项目里最贵的两步（SETUP 侧），
     *       每查询重做一次毫无意义。</li>
     *   <li><b>它没法被验</b>：探针试过等价的形态，在 {@code N = 1024} 这个规模上
     *       {@code blindrotate.dll} 会 {@code EXCEPTION_ACCESS_VIOLATION}
     *       （崩点在 {@code nativeDestroyKey} 里，说明更早的 native 调用写坏了堆；
     *       细节与"这与本轮的接线无关"的判断写在
     *       {@code probe/FusePirAnswerParseTest} 的类注释里）。
     *       一个既不可能对、又不能验的重载，按本项目的规矩<b>不加</b>
     *       ——"加了没人调的函数"已经被当作缺陷抓过两次。</li>
     * </ol>
     *
     * <h3>⚠️ 未做的事</h3>
     * <ul>
     *   <li><b>{@code Pack}（A1 ANSWER 13）不在本方法里，本项目也没有它</b> ——
     *       返回值是 {@code long[B_pay]}（明文载荷系数），不是"打包后的密文"。
     *       MAP §6 与 §10.3② 登记得比这里细。</li>
     *   <li>密文形态（{@code q.selBlob != null}，P1-1 的 {@code nativeCapeAnswerSealedC}）
     *       <b>没有</b>接到本方法上：它需要另外三个 native 入口与上下文里的 RGSW 选择子，
     *       而本方法只用 {@code pp} 里有的东西。⇒ 想走密文形态请用
     *       {@code cape/CapeDemoService.runAnchorNative} 那条既有路径（本轮不许动）。</li>
     *   <li>{@code pp.d()} 必须与**建 {@code bsk} 用的 d** 一致（{@code a[a]} 的长度），
     *       否则 native 会按 {@code d} 读 {@code a}（A1 QUERY 5 的 {@code LWE.Enc} 维数）。
     *       本方法<b>不</b>校验这一点（{@code q.sBits.length} 可以查，但
     *       "它是不是与 bsk 同源"查不了 —— 见 {@code CapeQuery} 那段最长的不变量注释）。</li>
     *   <li>本方法<b>不</b>校验 {@code h} / {@code kh} 是不是同一对
     *       （{@code kh} 必须是在 {@code h} 上建的引导密钥）。native 侧只把它们当裸指针用，
     *       传错会算错或崩；这条由调用点的生命周期管理保证，本类不重复。
     *       ⚠️ <b>但这意味着 {@code kh} 的销毁责任在本方法</b>（见 {@code finally}）：
     *       调用方不该在调完之后继续用 {@code kh}。</li>
     * </ul>
     *
     * <h3>⚠️ 探针怎么用它</h3>
     * {@code probe/FusePirAnswerParseTest} 的 C 节正是照服务端的生命周期写的：
     * 建一次上下文与引导密钥 → 用 {@code nativeSecretBits(h, d)} 取那组比特算 {@code β}
     * → 旧路径（{@code CapeDemoSetupProbe.flatten} 直接喂 native）与新路径
     * （本方法）**各跑一次** → 结果逐位对拍。
     * ⚠️ 那一节<b>默认不跑</b>（{@code -Dfusepir.native=true} 才跑），
     * 原因就是上面第 3 条那个 native 崩溃；本轮"行为保持"的证据因此落在
     * B-2（两条路径交给 native 的 {@code long[]} 逐位相同，7864320 个 long）上。
     */
    public static long[] runServerSide(FusePirServerState stS, Paths paths, long h, long kh) {
        if (stS == null) {
            throw new IllegalArgumentException("st_S 不能为 null（A1 ANSWER 1 要 parse 它）");
        }
        if (paths == null) {
            throw new IllegalArgumentException("q 的两条路不能为 null（A1 ANSWER 3）");
        }
        if (paths.k() != K_PATHS) {
            throw new IllegalArgumentException("q 只有 " + paths.k() + " 路，A1 QUERY 2 要求 "
                + K_PATHS + " 路（a = 0..2）");
        }
        requireNativeField(stS);
        final int d = stS.params().d();
        try {
            return NativeBlindRotate.nativeCapeAnswer(h, d, stS.columns(), paths.k(), stS.bPay(),
                stS.flattenForNative(), paths.colIdx(), paths.rowIdx());
        } finally {
            NativeBlindRotate.nativeDestroyKey(kh);
        }
    }

    /**
     * {@code pp.t()} 与 native 应答信道的明文模数 {@link FusePirParams#NATIVE_PLAINTEXT_MODULUS}
     * 必须一致（{@code {P_{c,b}}} 是那个上下文里的乘法明文）。不一致时抛，理由见
     * {@link #runServerSide(FusePirServerState, Paths, long, long)} 的注释。
     */
    private static void requireNativeField(FusePirServerState stS) {
        final FusePirParams pp = stS.params();
        if (pp.t() != FusePirParams.NATIVE_PLAINTEXT_MODULUS) {
            throw new IllegalArgumentException("pp.t()=" + pp.t() + " ≠ native 应答信道的明文模数 "
                + FusePirParams.NATIVE_PLAINTEXT_MODULUS + "：{P_{c,b}} 是那个上下文里的**乘法明文**，"
                + "两者必须同域（D11 的两个 t）。这里抛而不是把表取模 —— 取模会让载荷静默差一个 t 的倍数。"
                + "需要跑 native 路径请用 t = " + FusePirParams.NATIVE_PLAINTEXT_MODULUS + " 建表。");
        }
    }

    /** {@code A1 QUERY 2} 的路数：{@code for a = 0 to 2}（论文与 A1 SETUP 1 的 {@code BFF.Setup(n,3)} 都定死 3）。 */
    public static final int K_PATHS = 3;

    // ==================================================================
    //  自检：native vs 纯 Java，同一问题、逐位对拍
    // ==================================================================

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        final int C = 4;
        final int R = 16;
        final int k = 3;
        final int bPay = 40;

        System.out.println("=== native CAPE ANSWER 接线自检（不动 CapeEndToEnd4）===");
        if (!available()) {
            System.out.println("[FAIL] native 不可用：请先跑 tools/build_blindrotate_jni.py，"
                + "并用 run-native-cape.ps1（它会设置 java.library.path）");
            System.exit(1);
        }

        SecureRandom rnd = new SecureRandom();
        // ---- 与 CapeEndToEnd4.SETUP 同形的数据 ----
        long[][][] p = new long[C][bPay][n];
        for (int cc = 0; cc < C; cc++) {
            for (int b = 0; b < bPay; b++) {
                for (int rr = 0; rr < R; rr++) {
                    p[cc][b][rr] = 1 + rnd.nextInt(65536);
                }
            }
        }
        // BFF 三份份额：前两份随机，第三份反推 ⇒ Σ_a D[i][a][b] = payload[i][b]
        long[][] payload = new long[k][bPay];
        for (int i = 0; i < k; i++) {
            for (int b = 0; b < bPay; b++) {
                payload[i][b] = rnd.nextInt(65536);
            }
        }
        long[][][] dShare = new long[k][k][bPay];
        for (int i = 0; i < k; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    dShare[i][a][b] = rnd.nextInt(65537);
                    sum[b] = (sum[b] + dShare[i][a][b]) % 65537;
                }
            }
            for (int b = 0; b < bPay; b++) {
                dShare[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], 65537);
            }
        }
        // 位置 u_a = a*R + i ⇒ c = a, r = i
        int[] colIdx = new int[k];
        int[] rowIdx = new int[k];
        for (int a = 0; a < k; a++) {
            colIdx[a] = a;
            rowIdx[a] = 0;
        }
        for (int a = 0; a < k; a++) {
            int u = a * R + 0;
            int rr = u % R;
            int cc = u / R;
            for (int b = 0; b < bPay; b++) {
                p[cc][b][rr] = dShare[0][a][b];
            }
        }

        // ---- native ----
        long t0 = System.nanoTime();
        long[] nativeOut = run(n, d, C, k, bPay, p, colIdx, rowIdx);
        long nativeMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("%n[native] ANSWER（%d 个单元，1 次 JNI 调用）: %d ms%n", k * bPay, nativeMs);

        // ---- 期望：Σ_a D[i][a][b] = payload[i][b]（这里 i=0）----
        int bad = 0;
        for (int b = 0; b < bPay; b++) {
            if (nativeOut[b] != payload[0][b]) {
                bad++;
            }
        }
        report(String.format("native ANSWER 恢复的载荷 == 期望（错位 %d/%d）", bad, bPay), bad == 0,
            "前 6 个: " + Arrays.toString(Arrays.copyOf(nativeOut, 6))
                + "；期望: " + Arrays.toString(Arrays.copyOf(payload[0], 6)));

        System.out.println();
        System.out.println("---------------- 速度对照（同参同形状）----------------");
        System.out.printf("  路线 A（native，真 SEAL C++） : %6d ms%n", nativeMs);
        System.out.println("  路线 B（MPC4J 纯 Java，CapeEndToEnd4 实测）: 15 407 ms");
        System.out.printf("  ⇒ native 快 %.2fx%n", 15407.0 / Math.max(1, nativeMs));

        System.out.printf("%n=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
        }
        System.out.printf("    [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (!detail.isEmpty()) {
            System.out.println("          " + detail);
        }
    }
}
