package cape.tiny;

import java.util.Arrays;

/**
 * 环 {@code Z_m[X]/(X^N+1)} 上的多项式运算。
 *
 * <p>两种"域"在这里都实现了，文档第 2/3 节反复用到：
 * <ul>
 *   <li><b>系数域</b>：多项式系数就是数据（数据库 {@code P_{c,b}(X)} 用这个）。</li>
 *   <li><b>槽位域</b>：多项式在 {@code X^N+1} 的 N 个根上求值，
 *       <b>逐槽位相乘 = 逐点相乘</b>（Pack / Bloom 内积用这个）。</li>
 * </ul>
 *
 * <h3>为什么槽位域能做内积而系数域不能</h3>
 * 槽位域下乘积是逐点相乘：{@code (a·b)(ζ_i) = a(ζ_i)·b(ζ_i)} ✔
 * 系数域下乘积是负循环卷积，把所有系数加起来得到的是
 * {@code Σ_k (a⊛b)_k = (Σa_i)(Σb_j) = |a|·|b|} —— 与逐位逻辑无关。
 *
 * <p>槽位求值点 = {@code X^N+1} 在 {@code F_t} 上的根（本参数下恰好 N 个，已由
 * {@link TinyParams} 构造时校验）。
 */
public final class Poly {

    private Poly() {
    }

    // ==================== 基本 ====================

    public static int[] zero(int n) {
        return new int[n];
    }

    public static int[] add(int[] a, int[] b, int mod) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = Math.floorMod(a[i] + b[i], mod);
        return r;
    }

    public static int[] sub(int[] a, int[] b, int mod) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = Math.floorMod(a[i] - b[i], mod);
        return r;
    }

    public static int[] neg(int[] a, int mod) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[i] == 0 ? 0 : mod - a[i];
        return r;
    }

    public static int[] scalar(int[] a, int k, int mod) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (int) ((long) a[i] * k % mod);
        return r;
    }

    public static int[] copy(int[] a) {
        return Arrays.copyOf(a, a.length);
    }

    public static boolean equals(int[] a, int[] b) {
        return Arrays.equals(a, b);
    }

    // ==================== 环乘法（负循环卷积） ====================

    /**
     * 环乘法 {@code f·g mod (X^N+1)}，模 {@code mod}。
     *
     * <p>直接按定义算负循环卷积：{@code h[k] = Σ_{i+j=k} f_i g_j − Σ_{i+j=k+N} f_i g_j}。
     * N=8 时只有 64 次乘法，不需要 NTT，而且**更容易逐位核对**。
     */
    public static int[] mul(int[] f, int[] g, int mod) {
        int n = f.length;
        long[] acc = new long[n];
        for (int i = 0; i < n; i++) {
            if (f[i] == 0) continue;
            for (int j = 0; j < n; j++) {
                if (g[j] == 0) continue;
                int k = i + j;
                long prod = (long) f[i] * g[j];
                if (k < n) {
                    acc[k] += prod;              // X^k
                } else {
                    acc[k - n] -= prod;          // X^{N+j} = −X^j
                }
            }
        }
        int[] h = new int[n];
        for (int i = 0; i < n; i++) h[i] = (int) Math.floorMod(acc[i], mod);
        return h;
    }

    /** 逐系数乘法（不是环乘法！用于槽位域的逐点相乘） */
    public static int[] pointwise(int[] a, int[] b, int mod) {
        int[] r = new int[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (int) ((long) a[i] * b[i] % mod);
        return r;
    }

    // ==================== 槽位编解码 ====================

    /**
     * 系数域 → 槽位域：把多项式在各槽位点上求值（Horner）。
     *
     * @param f     系数（长度 N）
     * @param mod   求值所用的模（槽位编码时用 t）
     * @param points 槽位求值点（{@code X^N+1} 在 F_mod 上的 N 个根）
     */
    public static int[] toSlots(int[] f, int mod, int[] points) {
        int n = f.length;
        int[] out = new int[n];
        for (int s = 0; s < n; s++) {
            int x = points[s];
            long acc = 0;
            for (int i = n - 1; i >= 0; i--) {
                acc = (acc * x + f[i]) % mod;      // Horner
            }
            out[s] = (int) acc;
        }
        return out;
    }

    /**
     * 槽位域 → 系数域：拉格朗日插值。
     *
     * <p>{@code f(X) = Σ_s y_s · L_s(X)}，其中
     * {@code L_s(X) = Π_{r≠s} (X − ζ_r)/(ζ_s − ζ_r)}。
     */
    public static int[] fromSlots(int[] y, int mod, int[] points) {
        int n = y.length;
        int[] acc = new int[n];
        for (int s = 0; s < n; s++) {
            if (y[s] == 0) continue;
            int[] basis = lagrangeBasis(s, mod, points);
            int ys = y[s];
            for (int i = 0; i < n; i++) {
                acc[i] = (int) ((acc[i] + (long) basis[i] * ys) % mod);
            }
        }
        return acc;
    }

    /** 第 s 个拉格朗日基多项式 L_s(X)（模 mod） */
    public static int[] lagrangeBasis(int s, int mod, int[] points) {
        int n = points.length;
        int[] basis = {1};                                 // 从常数 1 开始
        int denom = 1;
        for (int r = 0; r < n; r++) {
            if (r == s) continue;
            // basis *= (X − points[r])
            basis = polyMulLinear(basis, Math.floorMod(-points[r], mod), mod);
            denom = (int) ((long) denom * Math.floorMod(points[s] - points[r], mod) % mod);
        }
        int inv = TinyParams.modInverse(denom, mod);
        return scalar(padTo(basis, n), inv, mod);
    }

    private static int[] polyMulLinear(int[] f, int constantTerm, int mod) {
        int[] r = new int[f.length + 1];
        for (int i = 0; i < f.length; i++) {
            r[i + 1] = (int) ((r[i + 1] + f[i]) % mod);            // ×X
            r[i] = (int) ((r[i] + (long) f[i] * constantTerm) % mod); // ×(c)
        }
        return r;
    }

    private static int[] padTo(int[] f, int n) {
        return f.length == n ? f : Arrays.copyOf(f, n);
    }

    /** 逐槽位掩码：{@code out[i] = a[i]·mask[i]}（槽位域） */
    public static int[] slotMask(int[] a, int[] mask, int mod) {
        return pointwise(a, mask, mod);
    }

    // ==================== 中心代表元 ====================

    /**
     * 把 {@code Z_t} 上的系数换成<b>中心代表元</b>（落在 {@code (−t/2, t/2]}）。
     *
     * <h3>为什么必须有这一步</h3>
     * 本组参数 {@code Δ=5, q=97} 下，明文相位必须落在 {@code (−q/2, q/2]} 内才能被
     * 正确解码，即<b>明文值（含符号）必须 ≤ maxPlaintext() = 9</b>。
     *
     * <p>而 {@code Z_t}（t=17）里 {@code −1} 的代表元是 {@code 16}，{@code Δ·16 = 80 > 48}
     * —— <b>无法表达</b>。必须换成中心代表元 {@code −1}，相位才是 {@code Δ·(−1) = 92 ≡ −5}，
     * 落在窗口内。
     *
     * <p>这在盲旋转里必然出现：{@code X^{−r*}} 会把 {@code X^N = −1} 用上，
     * 常数项常常是"某个系数的相反数"。
     */
    public static int[] centralize(int[] f, int t) {
        int[] r = new int[f.length];
        for (int i = 0; i < f.length; i++) r[i] = centralize(f[i], t);
        return r;
    }

    /** 单个值的中心化：{@code > t/2} 的映射到负半轴 */
    public static int centralize(int v, int t) {
        int x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    // ==================== 单项式旋转 ====================

    /**
     * 乘上公开单项式 {@code X^k}（负循环环，{@code X^N = −1}）。
     *
     * <p>规则：{@code k' = k mod 2N}；{@code k' ≥ N} 等价于整体取负再平移 {@code k'−N}；
     * 平移过程中 {@code i + shift ≥ N} 的项因跨过 {@code X^N} 也要变号。
     * 两条件异或决定最终符号。
     */
    public static int[] mulMonomial(int[] f, long k, int mod) {
        int n = f.length;
        long twoN = 2L * n;
        long kk = ((k % twoN) + twoN) % twoN;
        boolean negate = kk >= n;
        int shift = (int) (kk % n);
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            int target = i + shift;
            boolean wrap = target >= n;
            if (wrap) target -= n;
            int v = f[i];
            if (negate ^ wrap) v = v == 0 ? 0 : mod - v;
            out[target] = v;
        }
        return out;
    }

    /** 打印（便于手工核对） */
    public static String show(int[] f) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < f.length; i++) {
            sb.append(f[i]).append(i + 1 < f.length ? " " : "");
        }
        return sb.append("]").toString();
    }

    /** 打印 long（切段还原用） */
    public static String show(long[] f) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < f.length; i++) {
            sb.append(f[i]).append(i + 1 < f.length ? " " : "");
        }
        return sb.append("]").toString();
    }
}
