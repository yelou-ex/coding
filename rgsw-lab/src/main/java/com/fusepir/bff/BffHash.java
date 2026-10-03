package com.fusepir.bff;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <b>BFF · HashGen</b> —— 位置函数 {@code h_a} 的原始定义。
 *
 * <pre>
 *   A3 SETUP  9: Derive H = {h_j : K → [L_BFF]}_{j=0}^{k−1} ← BFF.HashGen(ρ_H, L_BFF, s, k).
 *   A1 QUERY  3: u_a ← h_a(K);  r_a ← u_a mod R;  c_a ← ⌊u_a/R⌋.
 * </pre>
 *
 * <h3>⚠️ 为什么这个文件值得单独存在：论文本身**没有给出** h_a 的公式</h3>
 * CAPE 附录 Alg 3 第 9 行只是把 {@code BFF.HashGen} 当黑盒调用；
 * 定义在 Graf &amp; Lemire 的 Binary Fuse Filter 里。原论文也只给结构约束，不给闭式：
 * <blockquote>
 * "Pick hash functions h0, h1, h2 from U to array locations in H so that
 * <b>h0(x), h1(x), h2(x) occupy three distinct and consecutive segments.</b>"
 * </blockquote>
 * 所以我们按<b>参考实现</b>落地（C 的 {@code FastFilter/xor_singleheader}、
 * Java 的 {@code XorBinaryFuse8}、Rust 的 {@code xorf}，以及 <b>ChalametPIR 自己的参考实现</b>
 * {@code itzmeanjan/ChalametPIR} 四份实现逐字一致）：
 * <pre>
 *   h0 = mulhi(hash, SegmentCountLength)
 *   h1 = (h0 + SegmentLength) ^ ((hash >> 18) &amp; SegmentLengthMask)
 *   h2 = (h1 + SegmentLength) ^ ( hash        &amp; SegmentLengthMask)
 * </pre>
 * 段号随 `a` **前进**（`h_a` 落在第 `a` 个连续段里）—— 这一点是四份实现共同保证的。
 *
 * <h3>⚠️ 由此推翻的两条此前的判断（都记在 MAP §11.3 / §12）</h3>
 * <ol>
 *   <li><b>ChalametPIR Alg 1 第 9 行的字面公式是错的</b>。它写
 *       {@code h_i(·) = (N/s)·(h″(·)−1) + h′(·‖i)}，把 k 个位置放在**同一段**里。
 *       与 BFF 原论文的"three distinct and consecutive segments"、
 *       与 ChalametPIR **自己的参考实现**都对不上。⇒ 按参考实现走。</li>
 *   <li><b>"每段 2.42 个槽"是我算错的</b>。我当时把 CAPE 的 `L_BFF = 155` 当成了段长。
 *       实际段长是 {@code s = 2^⌊log_3.33(n)+2.25⌋ = 64}，段里有 64 个槽，
 *       k=3 个位置放得下。**真正对不上的是 `L_BFF`**，见 {@link #allocate} 的说明。</li>
 * </ol>
 *
 * <h3>⚠️ 第三条：论文的 `L_BFF` 闭式与 `HashGen` **互相不自洽**</h3>
 * CAPE Alg 3 L3 的闭式在 `n=128` 给 `L_BFF = 155`，而 `s = 64`：
 * `155` 既不是 `64` 的整数倍，也写不成 `(segmentCount + k − 1)·s` 的形状
 * （`155/64 − 2 = 0.42`，不是整数）⇒ <b>CAPE 自己给的 (L_BFF, s) 无法描述一个 BFF 布局</b>。
 * 而 BFF 参考实现的 {@code allocate()} 在同一个 `n` 上给
 * {@code arrayLength = 256}、{@code segmentCountLength = 128}。
 *
 * <p>CAPE 正文对此的指示是明确的：*"The concrete finite-size choices of s and L_BFF
 * <b>follow the parameterization of BFF used in ChalametPIR</b>"*
 * —— 它<b>委托</b>给 BFF 的参数化。所以 {@link #allocate} 按参考实现算，
 * 并由 {@code probe/BffLayerTest} 把三个数的差异（155 / 128 / 256）如实打印出来。
 */
public final class BffHash {

    private BffHash() {
    }

    /**
     * BFF 的尺寸参数 —— {@code allocate()} 的忠实移植。
     *
     * <pre>
     *   segmentLength      s   = 2^⌊log_3.33(n) + 2.25⌋
     *   sizeFactor             = max(1.125, 0.875 + 0.25·log(10^6)/log(n))
     *   capacity               = round(n · sizeFactor)
     *   initSegmentCount       = ⌈capacity/s⌉ − (k−1)
     *   arrayLength            = (initSegmentCount + k−1)·s
     *   segmentCount           = ⌈arrayLength/s⌉;  若 ≤ k−1 则取 1，否则减 (k−1)
     *   arrayLength            = (segmentCount + k−1)·s
     *   segmentCountLength     = segmentCount · s      ← h0 的取值模数
     * </pre>
     *
     * <h3>⚠️ `L_BFF` 到底是哪个数</h3>
     * 三个数**都不一样**，不能混用：
     * <table border="1">
     *   <tr><th>数</th><th>n=128</th><th>含义</th></tr>
     *   <tr><td>{@code CAPE Alg 3 L3 闭式}</td><td><b>155</b></td><td>CAPE 自己写的 `L_BFF`</td></tr>
     *   <tr><td>{@code segmentCountLength}</td><td><b>128</b></td><td>`h0` 的取值模数（只决定落到哪个段）</td></tr>
     *   <tr><td>{@code arrayLength}</td><td><b>256</b></td><td>位置函数的**值域** `[0, arrayLength)`，也就是 `D` 的长度</td></tr>
     * </table>
     * FusePIR 里 `D` 必须装得下所有位置 ⇒ {@code L_BFF ≥ arrayLength}。
     * **拿 155 当 `D` 的长度会让 `h_a` 溢出**（`h2` 能到 255）。
     *
     * <h3>⚠️ 与 BFF 原论文表 1 的两处不同（都要记）</h3>
     * <ul>
     *   <li>取整：原论文表 1 是 `⌊·⌋`，参考实现用 `round`。</li>
     *   <li>对数项：原论文表 1 写 `log10⁶/log n`（= `13.816/ln n`，在 n=10⁶ 时正好是 1
     *       ⇒ 数组长度正好 `1.125n`）；**CAPE Alg 3 L3 写的是 `max{1, log10(n/6)}`**，
     *       两者**不是同一函数的换底**。CAPE 那条在 `n = 10⁶` 给 `2.18n`，
     *       与 CAPE 自己那句 *"array lengths approach 1.125n"* **矛盾**
     *       —— 所以 CAPE 的正文描述的是 BFF 原论文的公式，Alg 3 里的公式是抄错的。</li>
     * </ul>
     */
    public static final class BffParams {
        /** 段长 `s`（恒为 2 的幂）。 */
        public final int segmentLength;
        /** 段数。 */
        public final int segmentCount;
        /** `segmentCount · segmentLength` —— `h0` 的取值模数。 */
        public final int segmentCountLength;
        /** **`D` 的长度** `(segmentCount + k − 1)·s`。 */
        public final int arrayLength;
        /** arity。 */
        public final int k;
        /** 实际用的 capacity（{@code round(n·sizeFactor)}），只为打印。 */
        public final int capacity;

        BffParams(int segmentLength, int segmentCount, int segmentCountLength,
                  int arrayLength, int k, int capacity) {
            this.segmentLength = segmentLength;
            this.segmentCount = segmentCount;
            this.segmentCountLength = segmentCountLength;
            this.arrayLength = arrayLength;
            this.k = k;
            this.capacity = capacity;
        }

        /** 段长掩码 `s − 1`（`s` 是 2 的幂）。 */
        public int segmentLengthMask() {
            return segmentLength - 1;
        }

        /**
         * 转成 {@link HashGen} 的**尺寸签名** {@code (L_BFF, s, k)} ——
         * 也就是伪代码 {@code BFF.HashGen(ρ_H, L_BFF, s, k)} 里的那三样。
         *
         * <p>这样调用方可以只拿着伪代码里的参数调位置函数，
         * 而不必知道 BFF 参考实现是怎么把 {@code n} 推成 {@code arrayLength} 的。
         *
         * <p>⚠️ <b>它不带你传的种子</b>：返回的对象带的是 {@code ρ_H = 0}。
         * 只要位置函数（而不是段结构），就调 {@link #hashGen(long)} 或
         * {@link BffHash#hashGen(long, int, int, long)}；见
         * {@link BffHash#hashGen(long, int, int)} 里那段"拆成两次调用留下的缝"。
         */
        public HashGen hashGen() {
            return BffHash.hashGen(arrayLength, segmentLength, k);
        }

        /**
         * 同 {@link #hashGen()}，但把 A3 SETUP 8 的 {@code ρ_H} 一起交进去 ——
         * 一步给出 {@code H ← BFF.HashGen(ρ_H, L_BFF, s, k)} 的四个入参里
         * 由 {@code allocate(n, k)} 决定的那三样。
         */
        public HashGen hashGen(long rhoH) {
            return BffHash.hashGen(arrayLength, segmentLength, k, rhoH);
        }

        @Override
        public String toString() {
            return "s=" + segmentLength + ", segmentCount=" + segmentCount
                + ", segmentCountLength=" + segmentCountLength
                + ", arrayLength(L_BFF)=" + arrayLength + ", capacity=" + capacity;
        }
    }

    /**
     * {@code allocate()}：由 `n`、`k` 定出 BFF 的尺寸参数。
     *
     * <p>⚠️ 段长用 **2.25**（BFF 原论文与 C/Rust 实现）；Java 的 `XorBinaryFuse8` 用 2.11，
     * 是一处实现差异，我们跟论文走。
     */
    public static BffParams allocate(int n, int k) {
        if (n <= 0) {
            throw new IllegalArgumentException("n 必须 > 0");
        }
        // ⚠️ 段长必须按 k 选公式（论文：k=3 用 log_3.33(n)+2.25，k=4 用 log_2.91(n)−0.5）。
        //    这里此前**把 3.33/2.25 写死了、与 k 无关** ⇒ k=4 会静默拿到 k=3 的段长，
        //    而 BffSetup.paperS(4, n) 用的是另一条 —— 两处不一致且都不报错。
        //    修法：k=3 走已核过参考实现的那条；**k≠3 直接拒绝**，
        //    因为 k=4 的 sizeFactor 常量（0.77/0.305）我们**没有对着参考实现核过**，
        //    编一个"看起来合理"的数比报错危险得多。
        if (k != 3) {
            throw new IllegalArgumentException("allocate(n, k) 目前只支持 k=3："
                + "k=4 的段长/容量常量（log_2.91(n)−0.5、0.77+0.305·…）尚未与 BFF 参考实现核对过，"
                + "不愿凭猜生成布局。需要 k=4 时请先核参考实现再放开。k=" + k);
        }
        final int segmentLength = (int) BffSetup.paperS(k, n);
        // 论文表 1：log(10^6)/log(n)；等价于 13.816/ln(n)
        final double sizeFactor = Math.max(1.125,
            0.875 + 0.25 * Math.log(1e6) / Math.log(n));
        final int capacity = (int) Math.round(n * sizeFactor);
        final int initSegmentCount =
            ceilDiv(capacity, segmentLength) - (k - 1);
        int arrayLength = (initSegmentCount + k - 1) * segmentLength;
        int segmentCount = ceilDiv(arrayLength, segmentLength);
        if (segmentCount <= k - 1) {
            segmentCount = 1;
        } else {
            segmentCount -= (k - 1);
        }
        arrayLength = (segmentCount + k - 1) * segmentLength;
        final int segmentCountLength = segmentCount * segmentLength;
        return new BffParams(segmentLength, segmentCount, segmentCountLength,
            arrayLength, k, capacity);
    }

    private static int ceilDiv(int a, int b) {
        return (a + b - 1) / b;
    }

    /**
     * 一个关键词的 k 个位置 {@code (h_0(K), …, h_{k−1}(K))}。
     *
     * <pre>
     *   h_0 = mulhi(hash, segmentCountLength)
     *   h_a = (h_{a−1} + segmentLength) ^ (((hash >> (18·(k−1−a))) &amp; mask))
     * </pre>
     *
     * <p>段号随 `a` 前进 {@code segmentLength} —— 这就是原文那句
     * *"k distinct locations distributed across k consecutive segments"*。
     *
     * <p><b>三条性质都是被构造保证的，不是靠运气</b>（`probe/BffLayerTest` 会验）：
     * <ol>
     *   <li>全部落在 {@code [0, arrayLength)}；</li>
     *   <li>k 个位置<b>互异</b>（`h_{a−1}` 与 `h_a` 的 bit-6 必然不同）；</li>
     *   <li>互异且落在连续段里 —— 剥皮能成功的前提。</li>
     * </ol>
     *
     * <p>⚠️ {@code hash} 用 `SHA-256(ρ_H ‖ 0x00 ‖ K)` 的前 8 字节（大端）。
     * 论文只要求它是随机预言机，具体取法不是被规定的；
     * 但**客户端与服务端必须逐位一致**，所以只有这一份实现。
     *
     * @param seed 公共种子 `ρ_H`
     *
     * <p>⚠️ <b>当前 0 个调用点</b>（2026-10-15 按裸名 grep 点过）：形态更好的是
     * {@link HashGen#positions(String)}（种子与段结构装在一起，分不开），
     * 或 {@code bp.hashGen(ρ_H).positions(K)}。之所以<h3>没有</h3>直接删：
     * 删了之后凡是要用这个形状的地方都得自己再拼一遍
     * {@code hashGen(bp.arrayLength, bp.segmentLength, k)} —— 那正是本项目
     * 反复踩的"同一算式多处手抄"坑。它是<b>保留的死代码</b>，如实登记在这里。
     */
    public static int[] positions(String keyword, long seed, BffParams bp, int k) {
        return positions(keyword, seed, hashGen(bp.arrayLength, bp.segmentLength, k));
    }

    /**
     * 批量版：{@code [n][k]}。
     *
     * <p>⚠️ <b>当前 0 个调用点</b>（同 {@link #positions(String, long, BffParams, int)}）。
     * 形态更好的是 {@link HashGen#positions(java.util.List)}。
     */
    public static int[][] positions(java.util.List<String> keywords, long seed, BffParams bp, int k) {
        final HashGen hg = hashGen(bp.arrayLength, bp.segmentLength, k);
        final int[][] out = new int[keywords.size()][];
        for (int i = 0; i < out.length; i++) {
            out[i] = positions(keywords.get(i), seed, hg);
        }
        return out;
    }

    // ==================================================================
    //  ★ A3 SETUP 9 的**原签名**：BFF.HashGen(ρ_H, L_BFF, s, k)
    // ==================================================================
    //
    //  ⚠️ 2026-10-14 深夜补：此前只有 `positions(…, BffParams, k)` ——
    //  `BffParams` 是把 (L_BFF, s) **从 n 推出来的**结果。
    //  而伪代码把 (L_BFF, s) 当**入参**：`H ← BFF.HashGen(ρ_H, L_BFF, s, k)`。
    //
    //  这个差别不是风格问题：CAPE 的 Alg 3 L3 给的 L_BFF（n=128 时 155）
    //  与 BFF 参数化给的（256）**不一样**，而 `HashGen` 拿到的必须是能落地的那一个。
    //  把 (L_BFF, s) 做成入参之后，(155, 64) 这种**描述不出 BFF 布局**的组合
    //  会在**调用点**就被拒绝，而不是等剥皮失败或位置越界才暴露。
    //
    //  ⚠️ 2026-10-15 补（本轮）：上面那次只做到了**两个入参**，`ρ_H` 还留在外面
    //  （要另外传给 `positions(K, ρ_H, hg)`）⇒ 伪代码的**一次调用**在代码里
    //  仍然是**两处**，而且两处之间的不一致（客户端一个种子、服务端另一个）
    //  在类型上完全合法、在运行期完全静默。
    //  现在 `ρ_H` 装进 `HashGen`（final 字段），并有四参入口
    //  `hashGen(L_BFF, s, k, ρ_H)` 与 `HashGen.positions(K)` —— 伪代码那一行
    //  从此可以逐字写成一次调用。旧的三参 `hashGen` 与两个 `positions` 重载
    //  **都保留**（各有真实调用点，逐条写在各自的注释里），不是遗留垃圾。

    /**
     * {@code BFF.HashGen} 的产物 —— 伪代码那四个入参 {@code (ρ_H, L_BFF, s, k)} 的载体，
     * 同时也是位置函数 {@code h_a} 的<b>持有者</b>。
     *
     * <pre>
     *   A3 SETUP  9: Derive H = {h_j : K → [L_BFF]}_{j=0}^{k−1} ← BFF.HashGen(ρ_H, L_BFF, s, k).
     *   A1 QUERY  3: u_a ← h_a(K).
     *   BFF 参考实现: arrayLength = (segmentCount + k − 1)·s,  segmentCountLength = segmentCount·s
     * </pre>
     *
     * <p>由 {@code (L_BFF, s, k)} 反解 {@code segmentCount = L_BFF/s − (k−1)}。
     * <b>反解必须是整数且 ≥ 1</b>，否则 {@code (L_BFF, s)} 根本不是一组 BFF 参数 ——
     * 那时 {@link #hashGen} 会**抛异常**，而不是硬算出一个"看起来能用"的布局。
     *
     * <h3>⚠️ {@code ρ_H} 为什么必须装在这里（2026-10-15 补，本轮改动）</h3>
     * 伪代码是<b>一次调用</b>：{@code H ← BFF.HashGen(ρ_H, L_BFF, s, k)}，
     * 之后 {@code u_a ← h_a(K)}（A1 QUERY 3）用的是 {@code H} 里那 k 个函数。
     * 而此前的落地把它<b>拆成两处</b>：{@code hashGen(L_BFF, s, k)} 只管尺寸，
     * <b>{@code ρ_H} 要另外当参数传给 {@code positions(K, ρ_H, hg)}</b>。
     * 拆开的代价不是风格问题 —— 它让"调位置函数却忘了带种子"在**类型上**合法：
     * {@code ρ_H} 是个 {@code long}，传错一个常量、或者两个调用点各用一个值
     * （客户端一个、服务端另一个），两边<b>都能编译、都不报错</b>，
     * 症状只是协议静默假阴性（查不到本来就在库里的关键词）。
     * 装进 {@code HashGen} 之后，"位置函数"与"它的种子"再也分不开：
     * 拿到 {@link #positions(String)} 的人必然已经拿到了 {@code ρ_H}。
     *
     * <p>⚠️ <b>与伪代码一处仍未消掉的差别</b>：论文说 {@code H = {h_j}} 是
     * {@code ρ_H} 的<b>函数</b>（{@code h_j : ρ_H → (K → [L_BFF])}）。
     * 我们把它落实成"<b>一个 ρ_H 对应一个 {@code HashGen} 实例</b>"，
     * 即 {@code ρ_H} 在<b>构造期</b>绑定、不是每次调用传。
     * 对 A3 SETUP 9 那一行是等价的（它在一次调用里给全四个入参），
     * 但<b>"换 ρ_H 重试"必须新建一个 {@code HashGen}</b>，
     * 不能在同一条位置上改种子 —— {@link #rhoH} 因此是 {@code final}。
     */
    public static final class HashGen {
        /** {@code D} 的长度（= 参考实现的 {@code arrayLength}）。 */
        public final int lBff;
        /** 段长 `s`（2 的幂）。 */
        public final int s;
        /** arity。 */
        public final int k;
        /** 位置函数种子 `ρ_H`（A3 SETUP 8）。**决定 h_a 的取值** —— 换它位置全变。 */
        public final long rhoH;
        /** 段数。 */
        public final int segmentCount;
        /** `segmentCount · s` —— `h_0` 的取值模数。 */
        public final int segmentCountLength;

        HashGen(int lBff, int s, int k, long rhoH, int segmentCount, int segmentCountLength) {
            this.lBff = lBff;
            this.s = s;
            this.k = k;
            this.rhoH = rhoH;
            this.segmentCount = segmentCount;
            this.segmentCountLength = segmentCountLength;
        }

        /** 段长掩码 `s − 1`。 */
        public int mask() {
            return s - 1;
        }

        /**
         * <b>A1 QUERY 3</b>：{@code u_a ← h_a(K)} —— 用**本对象里的 {@code ρ_H}** 算位置。
         *
         * <p>这就是"伪代码一行对代码一处"的那个入口：{@code H.positions(K)} 与
         * {@code BffHash.positions(K, ρ_H, H)}（旧的两次调用形式）<b>逐位相同</b>，
         * 但它不再需要调用方自己保存 {@code ρ_H}。
         *
         * @return 长度 {@code k} 的 {@code (h_0(K), …, h_{k−1}(K))}，全部落在 {@code [0, lBff)}
         */
        public int[] positions(String keyword) {
            return BffHash.positions(keyword, rhoH, this);
        }

        /** 批量版（{@link #positions(String)}）：{@code [n][k]}。 */
        public int[][] positions(java.util.List<String> keywords) {
            return BffHash.positions(keywords, rhoH, this);
        }

        /**
         * 段结构 + 种子，**不含**位置函数 —— 给"需要知道用的是哪个 ρ_H"的地方（诊断/打印）。
         *
         * <p>⚠️ {@link #toString()} <b>故意不打印 {@code ρ_H}</b>：{@code ρ_H} 是公开参数
         * （不算秘密），但 {@code toString} 会进日志，而"这一条日志里的 {@code ρ_H} 是哪一次
         * 查询的"没有必要留下 —— 少一处关联面。要打印的地方显式调 {@link #describe()}。
         */
        public String describe() {
            return toString() + ", ρ_H=" + rhoH;
        }

        @Override
        public String toString() {
            return "HashGen(L_BFF=" + lBff + ", s=" + s + ", k=" + k
                + ") -> segmentCount=" + segmentCount
                + ", segmentCountLength=" + segmentCountLength;
        }
    }

    /**
     * <b>{@code BFF.HashGen(L_BFF, s, k)} —— 三参版，{@code ρ_H} 被钉成 0。</b>
     *
     * <p>⚠️ 这个签名<b>不含 {@code ρ_H}</b>，所以它<b>不是</b>伪代码那一行
     * （{@code out_cape.txt:1909-1913} 是四参）。保留它的唯一理由是
     * <b>它在树里还有真实调用点</b>（2026-10-15 按裸名 grep 点过，共 <b>6</b> 处）：
     * {@code BffParams.hashGen()}、{@code probe/BffLayerTest:330,344}、
     * {@code probe/FusePirQueryOpsTest:158}、{@code probe/BffSetupBundleTest:131}，
     * 外加 {@link #hashGen(long, int, int, long)} 自身的委托。
     * 它们要么只关心<b>段结构</b>（{@code segmentCount}/{@code segmentCountLength}，
     * 与种子无关），要么是<b>负对照</b>（喂 (155, 64) 期望它抛），都不需要种子。
     * 删掉它会逼每一个点各自手抄一遍反解公式 —— 那是新的漂移源。
     *
     * <p><b>要位置函数就必须用带种子的那个</b>：
     * {@link #hashGen(long, int, int, long)} 或 {@link BffParams#hashGen(long)}。
     * 用本函数拿到的 {@code HashGen} 只带 {@code ρ_H = 0}，直接调
     * {@link HashGen#positions(String)} 会算出一组<b>与协议无关的位置</b> ——
     * 不报错、不越界，只是查不到东西（静默假阴性）。
     * 这正是"拆成两次调用"留下的那道缝，{@code probe/HashGenRhoTest} 的 N-1 负对照专门盯它。
     *
     * @throws IllegalArgumentException 若 {@code (L_BFF, s)} 描述不出 BFF 布局
     *         （`L_BFF` 不是 `s` 的整数倍，或反解出的 {@code segmentCount < 1}）。
     *         <b>这是有意为之</b>：CAPE 附录 Alg 3 的 `L_BFF` 闭式在 `n=128` 给 155，
     *         而 `s = 64` —— `155/64 − 2 = 0.42` 不是整数，所以那一组**根本不存在**
     *         （见 MAP §12.6）。让它在这里就报错，比让它算出个越界的位置好。
     */
    public static HashGen hashGen(long lBff, int s, int k) {
        if (k < 2) {
            throw new IllegalArgumentException("k 必须 ≥ 2，实得 " + k);
        }
        if (s <= 0 || (s & (s - 1)) != 0) {
            throw new IllegalArgumentException("段长 s 必须是 2 的幂，实得 " + s);
        }
        if (lBff <= 0) {
            throw new IllegalArgumentException("L_BFF 必须 > 0，实得 " + lBff);
        }
        if (lBff % s != 0) {
            throw new IllegalArgumentException("L_BFF=" + lBff + " 不是 s=" + s + " 的整数倍 ⇒ "
                + "写不成 (segmentCount + k − 1)·s 的形状 ⇒ 这一组 (L_BFF, s) 描述不出 BFF 布局");
        }
        final long segmentCount = lBff / s - (k - 1);
        if (segmentCount < 1) {
            throw new IllegalArgumentException("L_BFF=" + lBff + " 与 s=" + s + " 反解出 segmentCount="
                + segmentCount + " < 1（BFF 原论文要求 3-wise 至少有 3 段 ⇒ segmentCount ≥ 1）");
        }
        if (segmentCount * s > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("segmentCount·s 溢出 int：" + segmentCount + "·" + s);
        }
        return new HashGen((int) lBff, s, k, 0L, (int) segmentCount, (int) (segmentCount * s));
    }

    /**
     * <b>{@code H = {h_j} ← BFF.HashGen(ρ_H, L_BFF, s, k)}</b> ——
     * <b>A3 SETUP 9 的四个入参，一次调用给全</b>（2026-10-15 补，本轮改动）。
     *
     * <pre>
     *   out_cape.txt:1908      A3 SETUP  8: Sample independent public seeds ρ_H, ρ_fp ←$ {0,1}^λ.
     *   out_cape.txt:1909-1913 A3 SETUP  9: Derive H = {h_j : K → [L_BFF]}_{j=0}^{k−1}
     *                                        ← BFF.HashGen(ρ_H, L_BFF, s, k).
     * </pre>
     *
     * <p>这是本类里唯一一个"伪代码那一行"能<b>逐字</b>对上的入口：
     * 四个入参的顺序、含义、个数都与原文一致；返回值既带尺寸（{@code lBff/s/k}）
     * 也带位置函数（{@link HashGen#positions(String)}，即 A1 QUERY 3 的 {@code h_a}）。
     * 旧的三参版本 {@link #hashGen(long, int, int)} 仍然保留 —— 它还有 6 个调用点，
     * 但那些点要么只要段结构、要么是负对照，理由逐条写在该函数的注释里。
     *
     * <h3>⚠️ {@code ρ_H} 检查的只有一件事：它是构造期绑定的常量</h3>
     * 本函数<b>不</b>校验 {@code ρ_H} 是否"随机"，也<b>不</b>要求它非零 ——
     * {@code ρ_H = 0} 是合法种子（探针里正拿 0 当"种子被忽略 / 传错"的负对照，
     * 见 {@code probe/HashGenRhoTest} 的 N-1）。真部署的 {@code ρ_H} 来自
     * {@link BffSetupBundle#sampleSeeds}（A3 SETUP 8 的独立采样）。
     *
     * <h3>⚠️ 本函数<b>不</b>负责落地，也不改几何</h3>
     * {@code (L_BFF, s)} 在这里只做<b>可落地性校验</b>（反解 {@code segmentCount} 是否为正整数），
     * 它<b>不</b>替调用方从 {@code n} 推参数 —— 那仍是 {@link #allocate} 的事。
     * CAPE Alg 3 L3 给的闭式 {@code L_BFF}（n=128 → 155）与 {@code s = 64} 在本函数里
     * 会<b>直接抛</b>（155 不是 64 的倍数），而不会算出个"看起来能用"的布局。
     *
     * @param lBff {@code L_BFF} —— {@code D} 的长度，等价于参考实现的 {@code arrayLength}
     * @param s    段长（2 的幂）
     * @param k    arity
     * @param rhoH A3 SETUP 8 的位置函数种子 {@code ρ_H}
     */
    public static HashGen hashGen(long lBff, int s, int k, long rhoH) {
        if (k < 2) {
            throw new IllegalArgumentException("k 必须 ≥ 2，实得 " + k);
        }
        if (s <= 0 || (s & (s - 1)) != 0) {
            throw new IllegalArgumentException("段长 s 必须是 2 的幂，实得 " + s);
        }
        if (lBff <= 0) {
            throw new IllegalArgumentException("L_BFF 必须 > 0，实得 " + lBff);
        }
        if (lBff % s != 0) {
            throw new IllegalArgumentException("L_BFF=" + lBff + " 不是 s=" + s + " 的整数倍 ⇒ "
                + "写不成 (segmentCount + k − 1)·s 的形状 ⇒ 这一组 (L_BFF, s) 描述不出 BFF 布局");
        }
        final long segmentCount = lBff / s - (k - 1);
        if (segmentCount < 1) {
            throw new IllegalArgumentException("L_BFF=" + lBff + " 与 s=" + s + " 反解出 segmentCount="
                + segmentCount + " < 1（BFF 原论文要求 3-wise 至少有 3 段 ⇒ segmentCount ≥ 1）");
        }
        if (segmentCount * s > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("segmentCount·s 溢出 int：" + segmentCount + "·" + s);
        }
        return new HashGen((int) lBff, s, k, rhoH, (int) segmentCount, (int) (segmentCount * s));
    }

    /**
     * 一个关键词的 k 个位置，按 {@link HashGen} 的原签名。
     *
     * <pre>
     *   h_0 = mulhi(hash, segmentCountLength)
     *   h_a = (h_{a−1} + s) ^ ((hash >> (18·(k−1−a))) &amp; mask)
     * </pre>
     *
     * <p>⚠️ <b>{@code seed} 与 {@code hg.rhoH} 是同一个量，本函数不校验它们一致。</b>
     * 传一个与 {@code hg} 构造时不同的 {@code seed} 会得到"合法但错"的位置
     * （不报错、不越界，只是查不到 —— 静默假阴性）。这就是伪代码"一次调用"被拆成
     * "尺寸 + 种子两次传"留下的缝。<b>新代码请用 {@link HashGen#positions(String)}</b>：
     * 那个形态下种子与段结构分不开。本重载保留是因为它还有两个调用点在做<b>对表</b>
     * （{@code probe/FusePirQueryOpsTest:161} 拿"建表侧位置表 vs 独立重算"比、
     * {@code probe/BffSetupBundleTest:99} 拿 {@code r.h} vs 自带种子的重算比）——
     * 对表<b>必须</b>故意把 {@code ρ_H} 与段结构分开传，否则就是拿函数跟自己对，恒真。
     */
    public static int[] positions(String keyword, long seed, HashGen hg) {
        final int s = hg.s;
        final int mask = hg.mask();
        final int k = hg.k;
        final long hash = oracleHash(keyword, seed);
        final int[] out = new int[k];
        long h = unsignedMultiplyHigh(hash, hg.segmentCountLength);
        out[0] = (int) h;
        for (int a = 1; a < k; a++) {
            final int shift = 18 * (k - 1 - a);
            final int x = (int) ((hash >>> shift) & mask);
            out[a] = (out[a - 1] + s) ^ x;
        }
        return out;
    }

    /** 批量版（{@link HashGen} 签名）：{@code [n][k]}。 */
    public static int[][] positions(java.util.List<String> keywords, long seed, HashGen hg) {
        final int[][] out = new int[keywords.size()][];
        for (int i = 0; i < out.length; i++) {
            out[i] = positions(keywords.get(i), seed, hg);
        }
        return out;
    }

    /**
     * 随机预言机 {@code hash : {0,1}* → {0,1}^64}。
     *
     * <p>⚠️ 分隔符 `0x00` 是**索引分隔**，不是"种子 0"：`SHA-256(seed ‖ 0x00 ‖ K)`。
     * 这与 {@code common/BfGen} 的口径一致（那边是 `SHA-256(K ‖ 0x00 ‖ i)`），
     * 但两边是**不同的**随机预言机：BFF 的 `h_a` 与 Bloom 的 `H` 不能混用。
     */
    public static long oracleHash(String keyword, long seed) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(longToBytes(seed));
            md.update((byte) 0x00);
            md.update(keyword.getBytes(StandardCharsets.UTF_8));
            final byte[] d = md.digest();
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (d[i] & 0xFFL);
            }
            return v;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static byte[] longToBytes(long v) {
        return new byte[] {
            (byte) (v >>> 56), (byte) (v >>> 48), (byte) (v >>> 40), (byte) (v >>> 32),
            (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v,
        };
    }

    private static long unsignedMultiplyHigh(long a, long b) {
        return Math.unsignedMultiplyHigh(a, b);
    }
}
