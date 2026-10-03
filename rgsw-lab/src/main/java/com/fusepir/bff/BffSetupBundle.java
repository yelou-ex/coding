package com.fusepir.bff;

import java.util.Random;
import java.util.function.ToLongFunction;

/**
 * <b>{@code (D, H, fp) ← BFF.Setup(n, 3)}</b> —— A1 SETUP 1 的**单一入口**，
 * 也就是 A3 SETUP 1-14 那 14 行的产物。
 *
 * <h3>为什么要有这个类（2026-10-14 深夜补）</h3>
 * 审计把"没有单一的 {@code BFF.Setup} 入口"列为**卡住调用方**的一条：
 * 论文 A1 SETUP 1 是一行
 * <pre>
 *   A1 SETUP 1: (D, H, fp) ← BFF.Setup(n, 3).
 * </pre>
 * 而我们的这"一行"此前散在 **6 个地方**：
 * {@code BffSetup.setup}（只给 s/L_BFF）、{@code BffHash.allocate}（给段结构）、
 * {@code BffSetup.fp}（给指纹）、{@code BffSetup.newD}（给 D 的形状）、
 * {@code BffSetup.layout}（A1 SETUP 4 的 (R,C)）、{@code BffSetup.paperLBff}（闭式对照）。
 * ⇒ <b>伪代码的一行对不上代码的一处</b>，读的人得自己拼。
 *
 * <h3>⚠️ 这个类**不重算**任何东西</h3>
 * 它只是把上面那 6 处的结果**按伪代码的顺序装在一个对象里**，
 * 每个字段的来源都写在字段注释上。数值一律由原函数产出 ——
 * 这里再抄一遍算式就是新的漂移源（项目已经因为同一算式多处手抄踩过好几次）。
 *
 * <h3>⚠️ {@code H} 与 {@code fp} 是**函数**，不是数据</h3>
 * 论文里两者都是"函数"：{@code H = {h_j : K → [L_BFF]}}、{@code fp : K → {0,1}^μ}。
 * 所以这里用 {@link BffHash.HashGen}（段结构 + 位置函数）与
 * {@link ToLongFunction}（关键词 → 40-bit 指纹）表示，**不预先展开成表** ——
 * 展开成 K×k 的表既浪费，又会让"客户端与服务端各自算一遍"这条性质看不见。
 */
public final class BffSetupBundle {

    private BffSetupBundle() {
    }

    /**
     * A3 SETUP 14 的 5 元组 {@code (D, H, fp_{ρ_fp}, L_BFF, s)}，
     * 外加 A1 SETUP 4 选出的 {@code (R, C)} 与 A3 SETUP 3 的闭式对照值。
     */
    public static final class SetupResult {
        /** A3 SETUP 11-12 的 {@code D}：形状 {@code [RC][B_pay]}（**不是** {@code [L_BFF]}）。 */
        public final long[][] d;
        /** A3 SETUP 9 的 {@code H}（段结构 + 位置函数 + 它自己的 {@code ρ_H}）。 */
        public final BffHash.HashGen h;
        /**
         * A3 SETUP 8 交给 {@code HashGen} 的那个位置函数种子 {@code ρ_H}
         * —— 就是 {@code h.rhoH} 的副本，供调用方直接读（不必知道 {@code H} 的内部字段）。
         *
         * <p>⚠️ <b>它<b>不</b>等于"建表最终用的那个种子"</b>，这一点必须说清楚：
         * {@code H} 与它的 {@code ρ_H} 是<b>构造期绑定、不可变</b>的（{@code HashGen.rhoH} 是 final），
         * 而 A3 ENCODE 2-3 允许"MappingStep 失败 ⇒ 换新种子重来"。
         * 我们这边那条重试在 {@code CapeDemoData.buildTablesPaper} 的
         * {@code posFn = s -> hashGen(L_BFF, s, k, s).positions(...)} 里 ——
         * 每次重试用的是 {@code ρ_H + i}，<b>不是</b>本字段。
         * 所以：<b>本字段是 Setup 的入口种子，不是"表用的是哪个种子"</b>；
         * 后者要问 {@code BffEncode.Table.seed}。
         */
        public final long rhoH;
        /** A3 SETUP 10 的 {@code fp_{ρ_fp}}：关键词 → 40-bit 指纹。 */
        public final ToLongFunction<String> fp;
        /** A3 SETUP 2 的 {@code L_BFF}（= {@code H.lBff}，同一个数）。 */
        public final long lBff;
        /** A3 SETUP 2 的段长 {@code s}（= {@code H.s}）。 */
        public final long s;
        /** A1 SETUP 4 选出的 {@code (R, C)}。 */
        public final BffSetup.Layout layout;
        /** A3 SETUP 2-3 的**闭式值**（`s`、`L_BFF`）—— 只作对照，默认路径不用它。 */
        public final BffSetup.Params closedForm;
        /** {@code B_pay}（{@code D} 每个条目的宽度）。 */
        public final int bPay;

        SetupResult(long[][] d, BffHash.HashGen h, long rhoH, ToLongFunction<String> fp,
                    long lBff, long s, BffSetup.Layout layout,
                    BffSetup.Params closedForm, int bPay) {
            this.d = d;
            this.h = h;
            this.rhoH = rhoH;
            this.fp = fp;
            this.lBff = lBff;
            this.s = s;
            this.layout = layout;
            this.closedForm = closedForm;
            this.bPay = bPay;
        }

        @Override
        public String toString() {
            return "BFF.Setup -> " + h + ", ρ_H=" + rhoH + ", " + layout + ", B_pay=" + bPay
                + "（闭式对照：s=" + closedForm.s + ", L_BFF=" + closedForm.lBff + "）";
        }
    }

    /**
     * <b>A1 SETUP 1 + A1 SETUP 4 + A3 SETUP 1-14 一次做完</b>。
     *
     * <pre>
     *   out_cape.txt:1908      A3 SETUP  8: Sample independent public seeds ρ_H, ρ_fp ←$ {0,1}^λ.
     *   out_cape.txt:1909-1913 A3 SETUP  9: H = {h_j : K → [L_BFF]} ← BFF.HashGen(ρ_H, L_BFF, s, k).
     *   A1 SETUP 1: (D, H, fp) ← BFF.Setup(n, 3)
     *   A1 SETUP 2: L_BFF ← |D|
     *   A1 SETUP 4: Select R, C such that RC ≥ L_BFF, R ≤ N
     * </pre>
     *
     * <h3>⚠️ 为什么 {@code ρ_H} 是入参，而且<b>没有</b>"不带种子"的那个重载（2026-10-15 本轮）</h3>
     * 此前这里是 6 参（无 {@code ρ_H}），内部走 {@code bp.hashGen()} —— 那个 {@code HashGen}
     * 带的是 {@code ρ_H = 0}，调用方要拿位置函数就得<b>自己再传一次种子</b>
     * （{@code BffHash.positions(K, ρ_H, r.h)}）。伪代码的<b>一次调用</b>因此在代码里是两处，
     * 而且"两处用了不同种子"在类型上完全合法、在运行期完全静默。
     * 本轮把 {@code ρ_H} 提成入参（四参 {@link BffHash#hashGen(long, int, int, long)}）、
     * 种子的唯一真源变成 {@link SetupResult#h}{@code .rhoH}，
     * <b>原来那个 6 参重载已删除</b> —— 它正是"A3 SETUP 9 缺一个入参"的那一版，
     * 留着就等于留着一条可以静默绕过种子的路。
     *
     * <p>⚠️ 真部署的 {@code ρ_H} 来自 A3 SETUP 8 的 {@link #sampleSeeds}；
     * 本函数<b>不</b>替你采样 —— demo 为了可复现性把种子钉死（见 {@link #sampleSeeds} 的注释），
     * 那是刻意偏离，不是"采样被忘了"。
     *
     * @param n       关键词个数
     * @param k       arity（论文定死 3）
     * @param bPay    {@code D} 每个条目的宽度（由 A1 SETUP 5-7 的载荷布局决定）
     * @param ringDim 环维度 {@code N}
     * @param forceR  强制 {@code R}（{@code 0} = 方格策略，见 MAP §12.7）
     * @param useCeil {@code L_BFF} 闭式的取整方向（只影响 {@code closedForm} 那个对照字段）
     * @param rhoH    A3 SETUP 8 的位置函数种子 {@code ρ_H}
     */
    public static SetupResult setup(int n, int k, int bPay, int ringDim,
                                    int forceR, boolean useCeil, long rhoH) {
        // A3 SETUP 2/3：s 与 L_BFF —— 用 BFF 参考实现的参数化（见 BffHash 类注释）
        final BffHash.BffParams bp = BffHash.allocate(n, k);
        // A3 SETUP 9：H = {h_j} ← BFF.HashGen(ρ_H, L_BFF, s, k) —— 伪代码那四个入参一次给全
        final BffHash.HashGen h = bp.hashGen(rhoH);
        // A1 SETUP 4：(R, C)
        final BffSetup.Layout layout = BffSetup.layout(h.lBff, h.s, ringDim, forceR);
        // A3 SETUP 11-12 / A1 SETUP 1 的 D（形状 [RC][B_pay]）
        final long[][] d = BffSetup.newD((int) layout.rc(), bPay);
        // A3 SETUP 10：fp_{ρ_fp}
        final ToLongFunction<String> fp = BffSetup::fp;
        // A1 SETUP 2：L_BFF ← |D| —— 注意是 **h.lBff**，不是 d.length（d 是 RC 长的网格）
        return new SetupResult(d, h, h.rhoH, fp, h.lBff, h.s, layout,
            BffSetup.setup(n, k, useCeil), bPay);
    }

    // ==================================================================
    //  A3 SETUP 8: Sample independent public seeds ρ_H, ρ_fp ←$ {0,1}^λ
    // ==================================================================

    /**
     * <b>A3 SETUP 8</b>：两个**独立采样**的公开种子 {@code ρ_H} 与 {@code ρ_fp}。
     *
     * <pre>
     *   A3 SETUP  8: Sample independent public seeds ρ_H, ρ_fp ←$ {0,1}^λ.
     *   A3 SETUP  9: … ← BFF.HashGen(ρ_H, L_BFF, s, k)      （ρ_H 决定位置）
     *   A3 SETUP 10: Derive a fingerprint function fp_{ρ_fp}（ρ_fp 决定指纹）
     * </pre>
     *
     * <p>正文对这两个种子有一句明确要求：
     * <i>"The seeds ρ_H and ρ_fp are sampled <b>independently</b>. The former determines
     * the BFF locations, whereas the latter is used to detect queries for keywords
     * that were not encoded."</i> —— 所以它们**必须来自两次独立的采样**。
     *
     * <p>⚠️ <b>本函数目前只有探针调用</b>，这是**有意**的：demo 为了让"同种子 ⇒ 同表"
     * （{@code CapeDemoData} 的固定种子）成立，把两个种子都**钉死**了 ——
     * {@code ρ_H} 由调用方传 {@code seed0}，{@code ρ_fp} 是常量 {@link BffSetup#FP_SEED}。
     * 那是**为了可复现性的一处刻意偏离**，不是"忘了采样"。
     * 真部署应当调本函数。<b>这一点必须一起说，别把偏离说成实现。</b>
     */
    public static Seeds sampleSeeds(Random rnd) {
        if (rnd == null) {
            throw new IllegalArgumentException("采样需要随机源；demo 的可复现性请显式传固定种子");
        }
        final long rhoH = rnd.nextLong();
        long rhoFp = rnd.nextLong();
        // 两次独立采样的结果理论上可以相等（概率 2^-64）。相等时**换一个**而不是静默接受：
        // 论文要求"independent"，而 ρ_H == ρ_fp 会让位置函数与指纹同源 —— 那是可关联的。
        while (rhoFp == rhoH) {
            rhoFp = rnd.nextLong();
        }
        return new Seeds(rhoH, rhoFp);
    }

    /** A3 SETUP 8 的两个种子。 */
    public static final class Seeds {
        /** 位置函数种子 {@code ρ_H}。 */
        public final long rhoH;
        /** 指纹种子 {@code ρ_fp}。 */
        public final long rhoFp;

        Seeds(long rhoH, long rhoFp) {
            this.rhoH = rhoH;
            this.rhoFp = rhoFp;
        }

        /** 两者必须不同（论文要求 independent）。 */
        public boolean independent() {
            return rhoH != rhoFp;
        }

        @Override
        public String toString() {
            return "Seeds(ρ_H=" + rhoH + ", ρ_fp=" + rhoFp + ")";
        }
    }
}
