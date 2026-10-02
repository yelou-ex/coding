package com.fusepir.fusepir;

import com.fusepir.bff.*;

/**
 * <b>Algorithm 1 · SETUP</b> —— 网格参数这一半（{@code R, C, cellsPerCol, L_BFF}）。
 *
 * <pre>
 *   Alg 1 SETUP 4:  Select R, C such that RC ≥ L_BFF, R ≤ N.
 *   Alg 1 SETUP 14: P_{c,b}(X) ← Σ_{r=0}^{R-1} D[r + cR][b]·X^r
 * </pre>
 *
 * <h3>本类消掉的重复</h3>
 * {@code cellsPerCol} 与 {@code C}（列数）这两条算式此前在
 * <b>三个地方各写了一遍</b>（{@code CapeDemoData}、{@code CapeQuery.build}、
 * {@code CapeQuery.buildIndicesOnly}），靠注释写着"必须与 … 逐位一致"。
 * 客户端与服务端**必须**算出同一组网格，否则会静默查错列 —— 那种安排迟早会漂。
 * 现在只有一份。
 *
 * <h3>⚠️ 与论文的形态差（P1-4 已记）</h3>
 * <ol>
 *   <li><b>推导顺序是反的</b>。论文是
 *       {@code BFF.Setup(n,3) → L_BFF ← |D| → 才选 (R,C)}；
 *       我们是**先按 n 定列数** {@code C = ⌈n/cellsPerCol⌉}，
 *       再把 {@code L_BFF = cellsPerCol · C} 当成副产品。
 *       ⇒ {@link BffSetup#paperLBff} 那两条闭式**我们不使用**。</li>
 *   <li><b>一个位置占 {@code maxValues} 行，不是一行</b>。
 *       论文的 {@code r_a = u_a mod R} 直接是列内行号；
 *       我们是 {@code (u mod cellsPerCol) · maxValues + a}，
 *       把 k 路分享塞进同一个 cell 的连续 k 行。</li>
 *   <li>因此论文的 {@code RC ≥ L_BFF} 在我们这里退化成
 *       {@code cellsPerCol · C ≥ n}（本组参数：{@code 5·26 = 130 ≥ 128}）。</li>
 * </ol>
 */
public final class FusePirSetup {

    private FusePirSetup() {
    }

    /**
     * 一列里有多少个 cell：{@code ⌊R / maxValues⌋}。
     *
     * <p>每个关键词要占 {@code maxValues} 行（cell），所以一列能放
     * {@code ⌊R/maxValues⌋} 个关键词 —— 这也是"为什么 {@code R} 不能太小"的原因。
     */
    public static int cellsPerCol(int r, int maxValues) {
        return FusePirSetup.cellsPerCol(r, maxValues);
    }

    /**
     * 需要多少列：{@code ⌈n / cellsPerCol⌉}。
     *
     * <p>⚠️ 论文给了 {@code RC ≥ L_BFF} 这个**约束**，但没给怎么把 {@code C} 定下来。
     * 我们取"刚好装下 n 个关键词"的最小列数 —— 于是 {@code L_BFF} 变成几何副产品。
     */
    public static int columns(int kwCount, int cellsPerCol) {
        return FusePirSetup.columns(kwCount, cellsPerCol);
    }

    /**
     * 我们的 {@code L_BFF} = {@code cellsPerCol · C}（{@code Span}）。
     *
     * <p>它不是按 {@code BFF.Setup(n,3)} 算出来的，见类注释第 1 条。
     */
    public static int span(int cellsPerCol, int c) {
        return cellsPerCol * c;
    }
}
