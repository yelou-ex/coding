package com.fusepir.prim;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>伪代码点名的同态运算</b> —— 论文里写作 {@code CtCtAdd} / {@code CtCtMul} /
 * {@code CtRotate} / {@code CtPtMul} / {@code SampleExtract_0} 的那几个。
 *
 * <h3>为什么要有这个类（2026-10-14 深夜补）</h3>
 * 审计算出来一件事：**论文里这些运算都有名字，而我们的 Java 树里没有一个是函数** ——
 * 全是内联展开，或者只在 C++ 的 {@code cape_answer_core} 里。后果不是"跑不动"，
 * 而是<b>没法把伪代码的一行对上代码的一处</b>：
 * <ul>
 *   <li>读代码的人看到 {@code ev.multiply(q, c, prod); ev.relinearizeInplace(prod, m.relinKeys());}
 *       得自己认出这就是 ANSWER 4 的 {@code CtCtMul}；</li>
 *   <li>更糟的是 <b>relinearize 忘记写不会有任何报错</b> —— 密文维度涨上去，
 *       后面某一步才炸，或者结果悄悄错。</li>
 * </ul>
 * 所以把它们收成函数，强制"乘法之后必然 relinearize"。
 *
 * <h3>⚠️ 本类只收**已经被调用**的运算，不建空壳 —— 两处例外见下</h3>
 * 论文里另外两个点名运算**故意没有**放进来，因为它们在 Java 侧没有调用点，
 * 放进来就是新的死代码：
 * <ul>
 *   <li>{@code CtPtMul}（A1 ANSWER 5 {@code Σ_c CtPtMul(q^col[c], P_{c,b})}）——
 *       我们这条路径整个在 native/C++ 的 {@code cape_answer_core} 里
 *       （{@code Evaluator.multiplyPlain} 只有 {@code ExpandOps} 的私有包装在用）。</li>
 *   <li>{@code SampleExtract_0}（A1 ANSWER 7）—— 同上，native 侧做掉了；
 *       Java 侧最接近的是 {@code LweRlweBridge.sampleExtract(m, ct, 0)}，
 *       但它返回的是 **LWE 样本 {@code long[][]}**，不是密文，签名对不上，
 *       硬包一层只会误导。</li>
 * </ul>
 * （⚠️ 上一条是 2026-10-14 的判断；2026-10-15 <b>已按"伪代码点名的运算要有名字"
 * 的口径放进本类</b>：{@link #ctPtMul} / {@link #sampleExtract0}，
 * 两者都<b>如实标注 0 个生产调用方</b>。判断改变了，理由不变 ——
 * 让伪代码的每一行在 Java 里都有一个可调用的入口。）
 *
 * <h3>与本类配套的那两个名字（A1 ANSWER 6 / A2 ANSWER 6）</h3>
 * <ul>
 *   <li><b>A1 ANSWER 6</b> {@code Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b})} →
 *       {@code BlindRotateOps.blindRotateRow(m, bk, acc, qRowA, qRowB)}
 *       （**同样 0 个生产调用方**：{@code rgsw_blindrotate.cpp:494-512} 的 C++ {@code blind_rotate}
 *       才是生产路径，它在 {@code cape_answer_core:680} 被调用）。</li>
 *   <li><b>A2 ANSWER 6</b> 的折叠与 {@code Galois} 旋转 → {@link #ctRotateRows}（**活的**）。</li>
 * </ul>
 * 需要它们的时候（比如实现 Java 版 ANSWER 5-7，或 {@code Pack}）再接线，
 * 那时它们会立刻有调用方。
 *
 * <h3>⚠️ 原地版与值版：热循环里必须用原地版</h3>
 * {@link #ctCtAddInplace} 是给折叠循环用的 —— 折叠要跑 {@code ⌈log2 ℓ_BF⌉} 轮，
 * 每轮如果都新建一条密文，分配开销会变成本的一部分。
 * 值版 {@link #ctCtAdd} 给"读起来像伪代码"的地方用。
 */
public final class CtOps {

    private CtOps() {
    }

    /**
     * <b>{@code CtCtAdd(ct, x)}</b> —— A1 ANSWER 11
     * {@code ct_{pay,b} ← CtCtAdd(CtCtAdd(ct_{0,b},ct_{1,b}),ct_{2,b})}，
     * 也是 A2 ANSWER 5 折叠里的那一加。{@code acc ← acc + x}（原地）。
     *
     * <p>用法是 {@code CtOps.ctCtAddInplace(m, acc, shifted)}。
     *
     * <p>⚠️ <b>只提供原地形态，没有值形态</b>：唯一的调用方是折叠循环
     * （{@code BloomScoring.foldSlots}/{@code foldAllSlots}），它每轮跑一次、
     * 共 {@code ⌈log2 ℓ_BF⌉} 轮，值形态会引入每轮一次密文分配。
     * 值形态版本我加过又删了 —— 因为<b>当时没有任何调用方</b>，
     * 留着就是死代码（本项目已经因为"加了没人调的 函数"被审计抓过两次）。
     */
    public static void ctCtAddInplace(Mpc4jRgsw m, Ciphertext acc, Ciphertext x) {
        m.addInplace(acc, x);
    }

    /**
     * <b>{@code CtCtMul(ct, ct')}</b> —— A2 ANSWER 4
     * {@code ct_{score,j} ← CtCtMul(q^BF, ct^BF_j)}。
     *
     * <p>⚠️ <b>乘法之后必须 relinearize</b>，否则密文从 2 个多项式涨成 3 个，
     * 下一次乘法就废掉。这一步<b>忘了不会报错</b>，所以收进函数、不给漏的机会。
     * 与 {@code BloomScoring} 里原来的写法逐字等价。
     */
    public static Ciphertext ctCtMul(Mpc4jRgsw m, Ciphertext a, Ciphertext b) {
        final Ciphertext out = new Ciphertext();
        m.evaluator.multiply(a, b, out);
        m.evaluator.relinearizeInplace(out, m.relinKeys());
        return out;
    }

    /**
     * <b>{@code CtRotate(ct, 2^r)}</b> —— A2 ANSWER 5 折叠里的行内旋转。
     *
     * <p>用的是 {@code rotateRowsInplace}（同一行内平移），不是跨行旋转 ——
     * SEAL 的两行布局下，行内平移的步长上限是 {@code N/2 − 1}，
     * 所以折叠只折到 {@code N/4}，跨行那一次由一次列旋转补
     * （见 {@code BloomScoring.foldAllSlots} 的注释）。
     *
     * @param step {@code 2^r}，必须 {@code < N/2}
     */
    public static Ciphertext ctRotateRows(Mpc4jRgsw m, Ciphertext ct, int step, GaloisKeys galoisKeys) {
        final Ciphertext out = new Ciphertext();
        out.copyFrom(ct);
        m.evaluator.rotateRowsInplace(out, step, galoisKeys);
        return out;
    }

    /**
     * <b>{@code CtPtMul(ct, pt)}</b> —— <b>A1 ANSWER 5</b>
     * （也用于 FusePIR-C Alg 4 的同一行）：
     * {@code Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X))}。
     *
     * <p>⚠️ <b>目前没有 Java 调用方</b>：我们这条路径的 ANSWER 4-8 整个在
     * native/C++ 的 {@code cape_answer_core} 里（{@code rgsw_blindrotate.cpp:543}）。
     * 留着它的理由是<b>伪代码点名要求这个函数</b>，而且一旦要在 Java 侧写 ANSWER 5，
     * 这是唯一正确的入口（{@code Evaluator.multiplyPlain} 现在只有
     * {@code ExpandOps} 的私有包装在用）。
     *
     * <p>⚠️ 明文必须是 {@code new Plaintext(N)} 造的（长度不对乘上去会**静默出错**）。
     * ⚠️ 这里<b>没有</b>做长度自检：本库的 {@code Plaintext} 没有公开的长度读取方法
     * （只有 {@code reserve/resize/set} 与构造器），所以挡不住 ——
     * <b>这是本类已知的一个边界，不是"检查过了"</b>。要挡就得在构造侧统一走一个工厂。
     */
    public static Ciphertext ctPtMul(Mpc4jRgsw m, Ciphertext ct, Plaintext pt) {
        if (pt == null) {
            throw new IllegalArgumentException("CtPtMul：明文为 null");
        }
        final Ciphertext out = new Ciphertext();
        m.evaluator.multiplyPlain(ct, pt, out);
        return out;
    }

    /**
     * <b>{@code SampleExtract_0(Acc)}</b> —— <b>A1 ANSWER 7</b>：取常数项那个系数。
     *
     * <p>⚠️ <b>类型映射要说清楚</b>：论文里 {@code SampleExtract_0} 交出的是
     * 一条 **LWE 密文**；我们这边 {@link LweRlweBridge#sampleExtract} 返回的是
     * LWE 样本本身（{@code long[][]}，即 {@code (b, a)} 分量），不是密文对象。
     * 本函数如实转发那个类型 —— 硬包成一个 {@code Ciphertext} 只会骗人。
     *
     * <p>⚠️ 与 {@link #ctPtMul} 一样：<b>目前没有 Java 调用方</b>（ANSWER 在 C++ 里）。
     */
    public static long[][] sampleExtract0(Mpc4jRgsw m, Ciphertext acc) {
        return LweRlweBridge.sampleExtract(m, acc, 0);
    }
}
