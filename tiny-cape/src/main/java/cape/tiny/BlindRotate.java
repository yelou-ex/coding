package cape.tiny;

import java.util.Random;

/**
 * 盲旋转（规范第 5、6 节）。
 *
 * <h3>要解决的问题</h3>
 * 客户端送来的是 <b>LWE 加密的行索引</b> {@code r*}（密钥 {@code s_L}），
 * 服务器手里是<b>明文多项式</b> {@code P(X)}（数据库的一列）。目标：
 * <pre>
 *   P(X) · X^{−r*}   →   常数项正好是 P[r*]
 * </pre>
 * 但 {@code r*} 是密文，服务器算不出 {@code X^{−r*}}。
 *
 * <h3>做法：逐位 CMUX</h3>
 * {@code r* = Σ_j r*_j·2^j}，于是 {@code X^{−r*} = Π_j X^{−r*_j·2^j}}。
 * 每一位要么"乘 {@code X^{−2^j}}"、要么"不动"，这是一次<b>保密二选一</b>：
 * <pre>
 *   cur = P(X)
 *   for j = 0 .. d−1:
 *       rotated = cur · X^{−2^j}              ← 公开单项式乘法
 *       cur     = CMUX(BK[j], cur, rotated)   ← BK[j] = RGSW(r*_j)
 *   cur 的常数项 = P[r*]（按负循环下标）
 * </pre>
 *
 * <h3>密钥变化（规范第 5 节）</h3>
 * 客户端用 {@code s_L} 加密索引比特；{@code BK[j] = KSK[j] = RGSW_{s_R}(r*_j)}。
 * CMUX 之后累加器变成 {@code s_R} 下的 RLWE —— <b>密钥从 s_L 切到 s_R</b>。
 * SampleExtract 再把它变回 {@code s_L}。全程只有一套秘密。
 *
 * <h3>谁做什么</h3>
 * <ul>
 *   <li><b>客户端</b>：持有 {@code r*}，用 {@link #clientSelectors} 生成 BK；</li>
 *   <li><b>服务端</b>：只拿 BK 和明文 {@code P(X)}，用 {@link #blindRotate} 旋转。
 *       它<b>看不到 r*</b> —— 这正是隐私所在。</li>
 * </ul>
 */
public final class BlindRotate {

    private BlindRotate() {
    }

    /**
     * <b>客户端</b>：把行索引 {@code r*} 的每一位做成 RGSW 选择子。
     *
     * <p>注意每一位是<b>独立的 RGSW 密文</b>（{@code RGSW(r*_j)} 的相位是常数 0 或 1）。
     * 服务端拿到它也只能做 CMUX，无法反推 {@code r*}。
     *
     * @param key  客户端密钥
     * @param rStar 行索引（本极小版要求 {@code r* < 2^d} 且 {@code r* < 2N} 以免环绕）
     * @param d    比特数（= LWE 维数）
     */
    public static RGSW[] clientSelectors(TinyKey key, int rStar, int d, Random rnd) {
        RGSW[] out = new RGSW[d];
        int[] mu = new int[key.p.n];
        for (int j = 0; j < d; j++) {
            mu[0] = (rStar >> j) & 1;
            out[j] = RGSW.encrypt(key, mu.clone(), rnd);
        }
        return out;
    }

    /**
     * <b>服务端</b>：对累加器做盲旋转。只需要 BK 和明文数据库。
     *
     * @param acc 初始累加器（RLWE 密文，相位 = Δ·P(X)）
     * @param bk  客户端送来的逐位 RGSW 选择子
     */
    public static RLWECipher blindRotate(RLWECipher acc, RGSW[] bk) {
        RLWECipher cur = acc;
        for (int j = 0; j < bk.length; j++) {
            RLWECipher rotated = cur.mulMonomial(-(1L << j));   // × X^{−2^j}
            cur = RGSW.cmux(bk[j], cur, rotated);
        }
        return cur;
    }

    /**
     * <b>明文参照</b>：{@code P(X)·X^{−r*} mod (X^N+1)} 的整数系数。
     *
     * <p>直接按定义算，不用任何"公式记忆"：
     * <pre>
     *   X^{−r*}·P(X) = Σ_k P[k]·X^{k−r*}
     * </pre>
     * 指数 {@code e = k − r*} 可能落在 {@code [−N+1, N−1]} 之外，用
     * {@code X^e = X^{e mod 2N}} 且 {@code X^{e+N} = −X^e} 归一。
     *
     * <p>以 {@code long} 返回，因为负循环环里会出现 {@code −P[j]}，
     * 而 {@code Z_t} 无法表达 {@code −1}（见 {@link Poly#centralize}）。
     */
    public static long[] referenceRotateExact(int[] P, int rStar, TinyParams p) {
        int n = p.n;
        long[] out = new long[n];
        for (int k = 0; k < n; k++) {
            long e = (long) k - rStar;                 // 真实指数
            long reduced = Math.floorMod(e, 2L * n);   // 归一到 [0,2N)
            int target = (int) (reduced % n);
            long sign = (reduced >= n) ? -1 : 1;       // X^{e+N} = −X^e
            out[target] += sign * P[k];
        }
        return out;
    }

    /**
     * 明文参照（中心化后的 {@code Z_t} 形式），可直接与解密结果比较。
     */
    public static int[] referenceRotate(int[] P, int rStar, TinyParams p) {
        long[] exact = referenceRotateExact(P, rStar, p);
        int[] out = new int[p.n];
        for (int i = 0; i < p.n; i++) out[i] = Poly.centralize((int) exact[i], p.t);
        return out;
    }

    /**
     * {@code P(X)·X^{−r*}} 的<b>常数项</b>（中心代表元）。
     *
     * <h3>正确公式</h3>
     * 只有 {@code k = r*} 这一项能贡献常数项，且它来自
     * <pre>
     *   X^{r*}·X^{−r*} = X^0          （r* ≥ 1 时需要借道 X^N = −1 一次）
     * </pre>
     * 具体地：{@code e = r* − r* = 0}，但 {@code X^{r*}·X^{−r*}} 在负循环环里
     * 写作 {@code X^{r*}·X^{N−r*} = X^N = −1}，所以
     * <pre>
     *   P(X)·X^{−r*} 的常数项 = +P[(−r*) mod N]     若 (−r*) mod N ≠ 0 且未借位
     * </pre>
     * 直接用 {@link #referenceRotateExact} 取第 0 项最稳妥，避免记错。
     */
    public static int coefficientAt(int[] P, int rStar, TinyParams p) {
        long[] exact = referenceRotateExact(P, rStar, p);
        return Poly.centralize((int) exact[0], p.t);
    }
}
