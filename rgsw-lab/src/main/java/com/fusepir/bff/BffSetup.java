package com.fusepir.bff;

/**
 * <b>BFF · SETUP</b> —— 参数这一半。
 *
 * <pre>
 *   Alg 1 SETUP 1: (D, H, fp) ← BFF.Setup(n, 3).
 *   Alg 1 SETUP 2: L_BFF ← |D|
 *   Alg 3 SETUP 1-3: if k=3 then s ← 2^floor(log_3.33(n) + 2.25)
 *                    L_BFF ← max(⌈(0.875 + 0.25·max(1, log10(n/6)))·n⌉, ⌈1.125n⌉)
 *   Alg 3 SETUP 5-7: k=4 的同形闭式（2^floor(log_2.91(n) − 0.5)、1.075n）
 * </pre>
 *
 * <h3>⚠️ 我们的实现与这两条闭式的关系（必须一起说）</h3>
 * <ol>
 *   <li>这两个函数是**论文的闭式**，本类把它们从
 *       {@code probe.CapeBffParamDiag} 搬进来 —— 它们是**协议层的定义**，
 *       不是验收代码，所以应该在 {@code bff/} 里。</li>
 *   <li>但**我们的实现并不用它们推参数**：我们的 {@code L_BFF = cellsPerCol·C}
 *       是**网格几何的副产品**（先按 n 定列数 `C`，再乘出 `L_BFF`），
 *       而不是像论文那样「先 `BFF.Setup(n,3)` 得到 `L_BFF`，再选 `(R,C)`」。
 *       **⇒ 推导顺序是反的**，这是 P1-4 如实记录的一条形态差。</li>
 *   <li>{@code h_i}（位置函数）**没有实现** —— 我们用的是
 *       {@link BffEncode#keywordHash} 的线性探测，见该类注释。</li>
 * </ol>
 *
 * <p>在 n=128、k=3 上：论文闭式给 {@code L_BFF = 155}，渐近界是 144，
 * 而我们的 130 反而**更小**（比值 1.0156）—— 因为它是几何副产品，不是按余量留的。
 */
public final class BffSetup {

    private BffSetup() {
    }

    /**
     * 段大小 {@code s}（CAPE Alg.3 第 2/5 行 = ChalametPIR Alg.1 第 2 行）。
     *
     * <pre>
     *   k = 3:  s = 2^floor( log_3.33(n) + 2.25 )
     *   k = 4:  s = 2^floor( log_2.91(n) - 0.5  )
     * </pre>
     * 注意它恒是 <b>2 的幂</b>（两个出处都这么写）。
     */
    public static long paperS(int k, long n) {
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
     * （{@code N = ⌊c·m⌋}，且第二项是 {@code ⌊1.125m⌋}）。<b>两篇这一处确实不一致</b>，
     * 不假装它们一模一样。
     *
     * <p>⚠️ 还有一条更要紧的观察：<b>CAPE 自己的闭式并不收敛到它自己声明的 1.125n</b>
     * —— 它随 n 单调升到 ~2.18n ⇒ 「照抄论文的闭式」不足以复现论文的量。
     *
     * @param useCeil true = CAPE 的形状（ceil）；false = ChalametPIR 的形状（floor）
     */
    public static long paperLBff(int k, long n, boolean useCeil) {
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
}
