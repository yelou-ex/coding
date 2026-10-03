package com.fusepir.fusepir;

import com.fusepir.prim.BlindRotateOps;
import com.fusepir.prim.CtOps;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Arrays;

/**
 * <b>A1 ANSWER 1-13 逐步所需的接口</b>（2026-10-15 新建）。
 *
 * <h2>为什么放在 {@code fusepir/} 而不是 {@code prim/}</h2>
 * 本类要编排 {@link FusePirServerState}（ANSWER 1 的 {@code st_S}）与
 * {@link FusePirPackSlot}（ANSWER 13 的 {@code Pack}），而分层图是
 * {@code prim ← bloom ← bff ← fusepir ← cape} —— <b>{@code prim} 不能反过来依赖 {@code fusepir}</b>。
 * 所以这一层属于 FusePIR 自己。
 *
 * <h2>为什么要有这一层</h2>
 * 论文 ANSWER 每一步本来都有名字（{@code CtPtMul} / {@code BlindRotate} /
 * {@code SampleExtract_0} / {@code CtCtAdd} / {@code Pack}），而
 * <b>真正让实现出错的是它们之间那几件没人管的"形态"与"契约"事</b>：
 *
 * <table border="1">
 *   <tr><th>论文行</th><th>接口</th><th>它替调用方管掉的那件事</th></tr>
 *   <tr><td>ANSWER 1</td><td>{@link FusePirServerState}</td>
 *       <td>{@code Parse st_S = ({P_{c,b}}, pp)} —— {@link FusePirServerState#polynomial(int,int)}</td></tr>
 *   <tr><td>ANSWER 3</td><td>{@code FusePirAnswer.paths}（已存在）</td>
 *       <td>{@code Parse (q_a^col, q_a^row) from q}</td></tr>
 *   <tr><td>ANSWER 5</td><td>{@link #polynomialNtt} + {@link #constantSelectorNtt} + {@link #columnSelect}</td>
 *       <td>{@code multiplyPlain} 要求<b>两侧同为 NTT 形态</b>；且<b>零要用 {@code encryptZero()}</b></td></tr>
 *   <tr><td>ANSWER 6</td><td>{@link #blindRotateStep}</td>
 *       <td>盲旋转要<b>系数形态</b>累加器，而 5 的输出是 NTT 形态</td></tr>
 *   <tr><td>ANSWER 7</td><td>{@link #sampleExtract0Rns} + {@link #toTruncatedZLwe}</td>
 *       <td>⚠️ {@code sampleExtract} <b>维数盲</b>，机械返回 {@code N+1} 项；
 *           必须显式截到秘密支撑 {@code d}，否则 Pack 索要 {@code nLwe=N} 行密钥</td></tr>
 *   <tr><td>ANSWER 11</td><td>{@link #addPaths}</td>
 *       <td>三路相加是<b>RNS 分量逐素数求和</b>，且在缩放<b>之前</b></td></tr>
 *   <tr><td>ANSWER 13</td><td>{@link FusePirPackSlot#pack}（§23 已实现）</td>
 *       <td>槽位布局 + gadget 覆盖 + 折叠轮数契约</td></tr>
 * </table>
 *
 * <h2>⚠️ 本类里唯一不属于论文的一行</h2>
 * {@link #phaseOf} 是<b>诊断接口</b>。它不参与协议；存在的理由是 ANSWER 出错时，
 * 没有它就只能靠"打包件解出来不对"这种末端症状去猜哪一步错了（MAP §27.3 记着这个过程）。
 *
 * <h2>形态约定（实测得出，不是猜的）</h2>
 * <ul>
 *   <li>{@code Encryptor.encryptSymmetric} 产出<b>系数形态</b>密文；</li>
 *   <li>{@code Evaluator.multiplyPlain} 只在<b>两侧都是 NTT 形态</b>时做<b>环乘</b>
 *       （NTT 是环 {@code Z_q[X]/(X^N+1)} 的变换，不是批处理槽位）。一方是系数形态就抛
 *       {@code "NTT form mismatch"}；</li>
 *   <li>⚠️ {@code Plaintext.isNttForm()} 在本移植里<b>默认就是 true</b>（{@code new Plaintext(n)} 也是），
 *       所以它<b>不能</b>用来判断"我准备的是不是系数形态"—— 判据恒真。
 *       要 NTT 明文就显式 {@code transformToNttInplace}（见 {@link #polynomialNtt}）。</li>
 * </ul>
 */
public final class AnswerOps {

    private AnswerOps() {
    }

    // ==================================================================
    //  A1 ANSWER 5 的两侧接口
    // ==================================================================

    /**
     * <b>{@code P_{c,b}(X)} → NTT 形态明文</b>（{@link #columnSelect} 的右操作数）。
     *
     * <p>{@code P_{c,b}} 是<b>系数编码</b>（A1 SETUP 14：{@code Σ_r D[r+cR][b]·X^r}），
     * 而 {@code multiplyPlain} 要 NTT 形态，所以这里显式转一次。
     * <b>调用方不要再自己判断形态</b> —— {@code isNttForm()} 在本移植里不可靠。
     */
    public static Plaintext polynomialNtt(Mpc4jRgsw m, long[] coeffs) {
        if (coeffs == null) {
            throw new IllegalArgumentException("P_{c,b} 的系数不能为 null");
        }
        if (coeffs.length != m.n) {
            throw new IllegalArgumentException("P_{c,b} 的系数个数是 " + coeffs.length
                + "，应为 N = " + m.n + "（长度不对乘上去会静默出错）");
        }
        final Plaintext pt = new Plaintext(coeffs);
        m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        return pt;
    }

    /**
     * <b>{@code e_c} → NTT 形态密文</b>（{@link #columnSelect} 的左操作数）。
     *
     * <p>A1 ANSWER 5 的 {@code q_a^col[c]} 是一个<b>标量</b>的加密
     * （D3 读法：{@code C} 条标量密文，不是一个整体选择器）。
     *
     * <p>⚠️ <b>零要用 {@link Mpc4jRgsw#encryptZero()}</b>，不能用 {@code encrypt(全零数组)}：
     * 后者是"加密一个全零消息"，与"零密文"不是同一件事。规范 §3.2 也专门警告过零分量
     * （*"e_a[c] = 0 的项不要真的去做乘 0"*）。
     */
    public static Ciphertext constantSelectorNtt(Mpc4jRgsw m, long value) {
        final Ciphertext ct;
        if (Math.floorMod(value, m.t) == 0) {
            ct = m.encryptZero();
        } else {
            final long[] constant = new long[m.n];
            constant[0] = Math.floorMod(value, m.t);
            ct = m.encrypt(constant);
        }
        if (!ct.isNttForm()) {
            m.evaluator.transformToNttInplace(ct);
        }
        return ct;
    }

    /**
     * <b>{@code A1 ANSWER 5}</b>：
     * {@code Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_a^col[c], P_{c,b}(X))}。
     *
     * <p>返回<b>系数形态</b>（因为 ANSWER 6 的盲旋转要系数形态）—— 形态转换收在这里。
     *
     * <p>⚠️ <b>不跳过零分量</b>：D3 读法要求服务端对全部 {@code C} 列都算，
     * 否则它就得知道 {@code c_a}，那正是 D13 的明文列号泄露。
     * 零那几项由 {@link #constantSelectorNtt} 保证是<b>合法的零密文</b>，相加自然不贡献。
     */
    public static Ciphertext columnSelect(Mpc4jRgsw m, Ciphertext[] qColRow,
                                          FusePirServerState stS, int b) {
        if (qColRow == null || qColRow.length == 0) {
            throw new IllegalArgumentException("q^col 的那一路不能为空");
        }
        if (b < 0 || b >= stS.bPay()) {
            throw new IllegalArgumentException("字段下标 " + b + " 不在 [0, B_pay="
                + stS.bPay() + ") 内");
        }
        if (qColRow.length != stS.columns()) {
            throw new IllegalArgumentException("q^col 有 " + qColRow.length + " 条，"
                + "但 st_S 的列数是 C = " + stS.columns()
                + "（A1 ANSWER 5 的 Σ 上界必须与建表一致）");
        }
        Ciphertext acc = null;
        for (int c = 0; c < qColRow.length; c++) {
            final Plaintext p = polynomialNtt(m, stS.polynomial(c, b));
            final Ciphertext term = CtOps.ctPtMul(m, qColRow[c], p);
            if (acc == null) {
                acc = term;
            } else {
                CtOps.ctCtAddInplace(m, acc, term);
            }
        }
        if (acc.isNttForm()) {
            m.evaluator.transformFromNttInplace(acc);
        }
        return acc;
    }

    // ==================================================================
    //  A1 ANSWER 6 / 7
    // ==================================================================

    /** <b>{@code A1 ANSWER 6}</b>：{@code Acc' ← BlindRotate(q^row, Acc)}（收口形态）。 */
    public static Ciphertext blindRotateStep(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, Ciphertext acc,
                                             long[] qRowA, long qRowB) {
        if (acc.isNttForm()) {
            m.evaluator.transformFromNttInplace(acc);
        }
        return BlindRotateOps.blindRotateRow(m, bk, acc, qRowA, qRowB);
    }

    /** <b>{@code A1 ANSWER 7}</b>：{@code ct_{a,b} ← SampleExtract_0(Acc')}，<b>RNS 原样</b>。 */
    public static long[][] sampleExtract0Rns(Mpc4jRgsw m, Ciphertext accPrime) {
        return CtOps.sampleExtract0(m, accPrime);
    }

    /**
     * <b>{@code SampleExtract_0} 的契约：RNS 样本 → 截到秘密支撑 {@code d} 的 {@code Z_t} 样本。</b>
     *
     * <pre>
     *   返回 [β, a_0, …, a_{d−1}]（长度 d+1），全部在 Z_t
     * </pre>
     *
     * <p>⚠️ <b>为什么必须显式截断</b>：{@link LweRlweBridge#sampleExtract} 是<b>维数盲</b>的 ——
     * 它机械地把 {@code N} 个系数全抽出来（返回 {@code [L][N+1]}），<b>不管秘密的支撑在哪</b>。
     * 而铺开后的 {@code s_R} 只在 {@code [0,d)} 上非零（规范 §0.5）⇒ {@code a_k (k ≥ d)}
     * 根本不参与相位。不截断，Pack 会看到"样本维数 = N"并索要 {@code nLwe = N} 行的交换密钥
     * （{@code N = 8192} 时就是 <b>12.0 GB</b>）—— 这就是 MAP §18.4 那个数字的来处。
     *
     * <p>截断的<b>正确性</b>与"不截断会错"两侧都实测过（MAP §26 的 P4.1 / P4.2）。
     */
    public static long[] toTruncatedZLwe(Mpc4jRgsw m, long[][] rnsSample, int d) {
        if (d <= 0 || d > m.n) {
            throw new IllegalArgumentException("d 必须在 [1, N] 内（C9），实得 " + d);
        }
        final long[] zt = FusePirPackSlot.rnsToT(m, rnsSample);
        return Arrays.copyOf(zt, d + 1);
    }

    // ==================================================================
    //  A1 ANSWER 11
    // ==================================================================

    /**
     * <b>{@code A1 ANSWER 11}</b> 的<u>前半</u>：{@code ct_{a,b} ← Σ_a}（<b>只相加，不缩放</b>）。
     *
     * <p>⚠️ 与缩放到 {@code Z_t} **必须分开**：三路相加要在 <b>RNS 分量上逐素数</b>做完，
     * 然后才缩放并截到 {@code d}。顺序反了（先各自缩放再相加）会多引入两轮舍入。
     * 分开还有一个用处：{@link #phaseOfRns} 要吃的正是"相加后、缩放前"的 RNS 样本。
     *
     * <p>实现就是 {@link FusePirPackSlot#sumRns}（"mod 该素数"那一步漏了不报错、只会让 CRT 还原出别的数）。
     */
    public static long[][] sumPaths(Mpc4jRgsw m, long[][][] pathSamples) {
        if (pathSamples == null || pathSamples.length == 0) {
            throw new IllegalArgumentException("至少要有一路的样本");
        }
        return FusePirPackSlot.sumRns(m, Arrays.copyOf(pathSamples, pathSamples.length));
    }

    /**
     * <b>{@code A1 ANSWER 11 + 12}</b> 的便捷入口：{@code Σ_a} 之后缩放到 {@code Z_t} 并截到 {@code d}。
     *
     * <p><b>它就是上面两步的复合</b>（{@link #sumPaths} 然后 {@link #toTruncatedZLwe}），
     * 不额外做任何算术 —— 所以不存在"同一算式两处实现"的问题。
     * 注意：{@code FusePirFourStep.answerSamples} 现在<b>显式分两步调用</b>
     * （因为它要把中间的 RNS 形态交给诊断用），本入口留给只需要最终样本的调用方。
     */
    public static long[] addPaths(Mpc4jRgsw m, int d, long[][][] pathSamples) {
        return toTruncatedZLwe(m, sumPaths(m, pathSamples), d);
    }

    /**
     * <b>【诊断】ANSWER 5-11 的<b>算术层</b>相位：在 {@code Z_{q_R}} 上把相位算完，只做<u>一次</u>舍入。</b>
     *
     * <pre>
     *   phase_{q_R} = β − Σ_k a_k·s_L[k]   (mod q_R)      ← SEAL 的相位是 c0 + c1·s，而 a = −c1
     *   返回 round(phase_{q_R} · t / q_R) mod t
     * </pre>
     *
     * <h3>为什么必须与 {@link #phaseOf} 并存（两个判据测的不是同一层）</h3>
     * <table border="1">
     *   <tr><th>判据</th><th>经过什么</th><th>能不能要求"精确相等"</th></tr>
     *   <tr><td>{@link #phaseOf} + {@code FusePirPackSlot.rnsToT}</td>
     *       <td>把 {@code β} 与 {@code N} 个 {@code a_k} <b>各自</b>从 {@code q_R} 舍入到 {@code Z_t}，
     *           再在 {@code Z_t} 里做内积</td>
     *       <td>❌ <b>不能</b>。每次舍入都带 {@code δ_k ∈ (−½,½]}，
     *           相位里因此多出 {@code Σ_k δ_k·s_k}，上界 {@code #ones/2}。
     *           这是 {@code q_R→Z_t} <b>桥的固有残差</b>，已登记（MAP §24.4 / §26.3），
     *           与 ANSWER 的算术无关</td></tr>
     *   <tr><td><b>本方法</b></td>
     *       <td>先在 {@code Z_{q_R}} 里把相位算成<b>一个大整数</b>，再舍入一次</td>
     *       <td>✅ <b>可以</b>。舍入误差只有一次（{@code ≤ ½} 个 {@code Z_t} 单位），
     *           所以"相位 == 真值"这条判据在这一层是<b>精确</b>的</td></tr>
     * </table>
     *
     * <p>⚠️ <b>本方法测的是"ANSWER 的算术对不对"，<u>不是</u>"交付出去的载荷对不对"。</b>
     * 真实协议把 {@code a} 逐分量缩放后喂 {@code Pack}，所以残差**确实**在交付路径上；
     * 要判交付正确性得用 {@link #phaseOf} 那条（并如实带上残差上界）。
     * <b>把这两条混着说就会把"桥的残差"误报成"盲旋转错"——本轮之前正是这么错的。</b>
     *
     * @param rnsSample {@code SampleExtract_0}（或三路相加后）的 RNS 样本：
     *                  {@code [workingPrimeCount][N+1]}，{@code [pi][0] = β}、{@code [pi][1+k] = a_k}
     * @param sL        LWE 私钥（二进制），长度 {@code d}；只取前 {@code d} 项参与相位
     */
    public static long phaseOfRns(Mpc4jRgsw m, long[][] rnsSample, int[] sL) {
        if (rnsSample == null || sL == null) {
            throw new IllegalArgumentException("RNS 样本与私钥都不能为 null");
        }
        final int L = m.workingPrimeCount;
        if (rnsSample.length != L) {
            throw new IllegalArgumentException("RNS 样本有 " + rnsSample.length
                + " 个素数分量，但上下文的工作素数个数是 " + L);
        }
        final int n = m.n;
        for (int pi = 0; pi < L; pi++) {
            if (rnsSample[pi] == null || rnsSample[pi].length != n + 1) {
                throw new IllegalArgumentException("第 " + pi + " 个分量长度不是 N+1 = " + (n + 1));
            }
        }
        final java.math.BigInteger qR = m.q;
        final long[] residues = new long[L];
        for (int pi = 0; pi < L; pi++) {
            residues[pi] = rnsSample[pi][0];
        }
        java.math.BigInteger phase = LweRlweBridge.crtCentered(m, residues);
        for (int k = 0; k < sL.length; k++) {
            if (sL[k] == 0) {
                continue;                       // 秘密为 0 的位根本不参与相位（s_R 铺开后的支撑）
            }
            for (int pi = 0; pi < L; pi++) {
                residues[pi] = rnsSample[pi][1 + k];
            }
            // ⚠️⚠️ 必须**取反** —— 与 {@code FusePirPackSlot.rnsToT:368} 的 `.negate()` 逐字同一符号约定：
            //   RLWE（SEAL）相位是 `c0 + c1·s`，而 RingPack/本项目的约定是 `b ≡ ⟨a,s⟩ + m`，
            //   所以样本里的 `a` 是 `−c1`。漏掉这一次取反 ⇒ 相位变成 `β − Σ c1_k s_k`，
            //   与真值差 `2·Σ c1_k s_k` ⇒ 现象是"每个字段都像随机数"。
            //   （本条是**实测**出来的：第一次跑 P4.0a 就是 0/61，而交付层同时是 61/61。）
            final java.math.BigInteger ak = LweRlweBridge.crtCentered(m, residues).negate();
            phase = phase.subtract(ak.multiply(java.math.BigInteger.valueOf(sL[k])));
        }
        // ⚠️ 只在这里舍入一次，且复用桥自己的口径（不许再手抄一遍 scaleToT 的公式）
        return FusePirPackSlot.scaleToT(phase.mod(qR), qR, m.t);
    }

    // ==================================================================
    //  诊断（不属于论文）
    // ==================================================================

    /**
     * <b>【诊断】从 {@code Z_t} 上的 LWE 样本读出相位</b>：{@code β − Σ_k a_k·s_L[k] mod t}。
     *
     * <p>这是 A1 ANSWER 5-11 的<b>唯一一条与 Pack 无关的判据</b>：它错就说明前面那几步错，
     * 它对而打包件解出来错就说明 Pack 那层错（MAP §27.2 就是靠它把 bug 定位到 ANSWER 5-11 的）。
     *
     * @param ztLwe {@link #toTruncatedZLwe} 的产物：{@code [β, a_0 … a_{d−1}]}
     * @param sL    LWE 私钥（二进制），长度必须等于 {@code ztLwe.length − 1}
     */
    public static long phaseOf(long[] ztLwe, int[] sL, long t) {
        if (ztLwe == null || sL == null) {
            throw new IllegalArgumentException("样本与私钥都不能为 null");
        }
        if (ztLwe.length != sL.length + 1) {
            throw new IllegalArgumentException("样本长度 " + ztLwe.length + " 与私钥长度 "
                + sL.length + " 不匹配（应为 d+1 对 d）");
        }
        long acc = 0;
        for (int k = 0; k < sL.length; k++) {
            acc += ztLwe[1 + k] * sL[k];
        }
        return Math.floorMod(ztLwe[0] - Math.floorMod(acc, t), t);
    }
}
