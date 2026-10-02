package com.fusepir.cape;

import com.fusepir.bff.*;
import com.fusepir.bloom.*;
import com.fusepir.prim.*;
import com.fusepir.fusepir.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;

/**
 * <b>Algorithm 2 · SETUP</b> —— CAPE 在 FusePIR 之上新增的那一层。
 *
 * <pre>
 *   A2 SETUP 1:  Select public Bloom-filter parameters ℓ_BF and G = {g_1, ..., g_h}
 *   A2 SETUP 2:  m ← max_i |V_{K_i}|
 *   A2 SETUP 3-6: for each v: S_v ← {K_i : v ∈ V_{K_i}} ; b_v ← BF.Gen(0, S_v)
 *   A2 SETUP 7-10: V^CAPE_{K_i} ← {(v_{i,j}, b_{v_{i,j}})} ; DB^CAPE ← ...
 *   A2 SETUP 11: (pp_F, st_C^F, sk) ← FusePIR.Setup(1^λ, DB^CAPE)
 *   A2 SETUP 12-13: pp ← (pp_F, ℓ_BF, G, m) ; st_S ← st_S^F
 * </pre>
 *
 * <h3>这一步的实现落在哪（本类只做入口与口径说明）</h3>
 * <table border="1">
 *   <tr><th>论文行</th><th>实现位置</th></tr>
 *   <tr><td>1 {@code ℓ_BF, G}</td><td>数据集 meta（{@code ℓ_BF=18}）+ {@code com.fusepir.common.BfGen}（{@code h=5}）</td></tr>
 *   <tr><td>2 {@code m}</td><td>{@code CapeDemoData} 的 {@code meta.maxValues}</td></tr>
 *   <tr><td>3-6 {@code b_v ← BF.Gen(0, S_v)}</td><td>{@code CapeDemoData} 建载荷时逐值算（{@code bfGen.bits(...)}）</td></tr>
 *   <tr><td>7-10 {@code DB^CAPE}</td><td>{@code CapeDemoData} 的 {@code payload}（值 = {@code (v, b_v)}，占 {@code 1+ℓ_BF} 项）</td></tr>
 *   <tr><td>11 {@code FusePIR.Setup}</td><td>{@code CapeDemoData.load}（BFF.Encode + 表 {@code P_{c,b}}）</td></tr>
 * </table>
 *
 * <p><b>本类不复制那些运算</b> —— 读它就是读"这一步有哪几件事、各自在哪"。
 * 打分信道（{@code ct_score} 所在的域）由 {@link CapeBloomScore#setup} 建，
 * 论文里没有对应的一步：<b>那是本实现的口径差</b>（两个 {@code t}、两把 sk，见 D11）。
 *
 * <h3>⚠️ 一条必须一起说的推断</h3>
 * 论文 Alg 1 SETUP 6 把载荷定义成 {@code y ← fp(K_i) ‖ m_i ‖ v_{i,1} ‖ … ‖ v_{i,m} ∈ Z_t^{B_pay}}，
 * 于是 {@code B_pay = 2 + m}。CAPE 把每个值换成 {@code (v, b_v)}，
 * 每个值就占 {@code 1 + ℓ_BF} 项 —— 但 <b>Alg 2 从头到尾没有再提 {@code B_pay}</b>。
 * ⇒ {@code B_pay = 2 + m(1 + ℓ_BF)} 是**我们的推断**（本组参数 {@code 59 = 2 + 3×19}），
 * 不是原文。它同时解释了为什么 {@code Pack} 在 CAPE 里比在 FusePIR 里重要得多。
 */
public final class CapeSetup {

    private CapeSetup() {
    }

    /**
     * CAPE 的载荷宽度 {@code B_pay = 2 + m(1 + ℓ_BF)}。
     *
     * <p>⚠️ <b>这是推断，不是原文</b> —— 见类注释。论文只给了 FusePIR 的
     * {@code B_pay = 2 + m}，CAPE 的值类型变宽之后没有重述。
     */
    public static int bPay(int maxValues, int lBf) {
        return 2 + maxValues * (1 + lBf);
    }
}
