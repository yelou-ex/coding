package cape.tiny;

/**
 * RGSW 密文与外部积（规范第 5/6 节）。
 *
 * <h3>结构</h3>
 * 两组、每组 {@code l} 个 RLWE 密文：
 * <pre>
 *   group0[i] 的相位 = B^i · μ(X)
 *   group1[i] 的相位 = B^i · μ(X)·s_R
 * </pre>
 * 所以 {@code group0} 是"把 μ 按 gadget 倍数加密"，{@code group1} 是"再乘上 s_R"。
 *
 * <h3>外部积为什么成立</h3>
 * 把源密文的相位按 B 进制切成 {@code l} 段：{@code phase = Σ d_i·B^i}。则
 * <pre>
 *   ⟨d, group0⟩ + ⟨d', group1⟩
 *     = Σ d_i·B^i·μ + Σ d'_i·B^i·μ·s_R
 *     = μ·(Σ d_i B^i + s_R·Σ d'_i B^i)
 *     = μ·(c0' + s_R·c1')        ← 正好是 μ 乘以源密文的相位
 * </pre>
 * 全程不需要知道 μ，也不改动 μ —— 这正是"保密地选择"所需的性质。
 */
public final class RGSW {

    /** group0[i]：相位 = B^i·μ */
    public final RLWECipher[] group0;
    /** group1[i]：相位 = B^i·μ·s_R */
    public final RLWECipher[] group1;
    /** 参数 */
    public final TinyParams p;

    public RGSW(RLWECipher[] group0, RLWECipher[] group1, TinyParams p) {
        this.group0 = group0;
        this.group1 = group1;
        this.p = p;
    }

    /** RGSW 加密（μ 是 Z_t 上的明文多项式；盲旋转里 μ 是常数 s_L[j] ∈ {0,1}） */
    public static RGSW encrypt(TinyKey key, int[] mu, java.util.Random rnd) {
        TinyParams p = key.p;
        RLWECipher[] g0 = new RLWECipher[p.levels];
        RLWECipher[] g1 = new RLWECipher[p.levels];
        long power = 1;
        for (int i = 0; i < p.levels; i++) {
            // group0：原始级加密 B^i·μ
            int[] m0 = new int[p.n];
            for (int k = 0; k < p.n; k++) m0[k] = (int) (mu[k] * power % p.q);
            g0[i] = key.encryptRaw(m0, rnd);

            // group1：相位 = B^i·μ·s_R —— 用"原始加密后相位再乘 s_R"实现：
            // 先加密 B^i·μ，再构造一个相位为 (B^i·μ)·s_R 的密文。
            // 做法：c0' = (B^i·μ)·s_R − a·s_R，c1' = a  →  相位 = (B^i·μ)·s_R
            int[] a = new int[p.n];
            for (int k = 0; k < p.n; k++) a[k] = rnd.nextInt(p.q);
            int[] muS = Poly.mul(m0, key.sR, p.q);
            int[] as = Poly.mul(a, key.sR, p.q);
            g1[i] = new RLWECipher(Poly.sub(muS, as, p.q), a, p.q);

            power = power * p.base % p.q;
        }
        return new RGSW(g0, g1, p);
    }

    /**
     * 外部积：{@code RGSW ⊗ RLWE → RLWE}，结果相位 = μ · 源相位。
     *
     * <p>切段用<b>平衡位</b>（balanced digits）：每段落在 {@code (−B/2, B/2]}，
     * 这样数值小、且是"精确展开"（只要 {@code B^l ≥ q}）。
     */
    public RLWECipher externalProduct(RLWECipher src) {
        int[] d0 = decompose(src.c0);
        int[] d1 = decompose(src.c1);

        int[] acc0 = Poly.zero(p.n);
        int[] acc1 = Poly.zero(p.n);
        for (int i = 0; i < p.levels; i++) {
            int[] digit0 = digitLayer(d0, i);
            int[] digit1 = digitLayer(d1, i);
            acc0 = Poly.add(acc0, Poly.mul(digit0, group0[i].c0, p.q), p.q);
            acc1 = Poly.add(acc1, Poly.mul(digit0, group0[i].c1, p.q), p.q);
            acc0 = Poly.add(acc0, Poly.mul(digit1, group1[i].c0, p.q), p.q);
            acc1 = Poly.add(acc1, Poly.mul(digit1, group1[i].c1, p.q), p.q);
        }
        return new RLWECipher(acc0, acc1, p.q);
    }

    // ==================== 切段 ====================

    /**
     * 把一个多项式按 B 进制切成 {@code l} 段，用<b>平衡位</b>（每段 ∈ (−B/2, B/2]）。
     *
     * <p>返回的数组按"逐系数"存：{@code out[i*n + k]} = 第 k 个系数的第 i 段，
     * 已归一到 {@code [0,q)}（负段存成 {@code q+r}）。
     *
     * <p>平衡位是精确展开：只要 {@code B^l ≥ q}，就有
     * {@code x = Σ r_i·B^i}（在整数上，不取模）。因为每段都是 B 进制的一位，
     * 且 |r_i| ≤ B/2。
     */
    public int[] decompose(int[] f) {
        int[] out = new int[p.levels * p.n];
        int half = p.base / 2;
        for (int k = 0; k < p.n; k++) {
            long x = Math.floorMod(f[k], p.q);          // 归一到 [0,q)
            for (int i = 0; i < p.levels; i++) {
                long r = x % p.base;                    // [0,B)
                if (r > half) r -= p.base;              // 平移到 (−B/2, B/2]
                out[i * p.n + k] = (int) Math.floorMod(r, p.q);
                x = (x - r) / p.base;                   // 用真实的 r（可能为负）继续
            }
        }
        return out;
    }

    /** 取第 i 段作为一个多项式 */
    private int[] digitLayer(int[] decomposed, int i) {
        int[] layer = new int[p.n];
        System.arraycopy(decomposed, i * p.n, layer, 0, p.n);
        return layer;
    }

    /**
     * 切段的逆运算（自检用）：{@code Σ r_i·B^i} 应等于原值（在整数上，不取模）。
     * 段以有符号形式解读（>{@code q/2} 视为负）。
     */
    public long[] recompose(int[] decomposed) {
        long[] out = new long[p.n];
        for (int k = 0; k < p.n; k++) {
            long acc = 0, power = 1;
            for (int i = 0; i < p.levels; i++) {
                long d = decomposed[i * p.n + k];
                if (d > p.q / 2) d -= p.q;
                acc += d * power;
                power *= p.base;
            }
            out[k] = acc;
        }
        return out;
    }

    // ==================== CMUX ====================

    /**
     * 保密二选一：{@code CMUX(RGSW(c), A, B)}。
     *
     * <pre>
     *   结果 = A + RGSW(c) ⊗ (B − A)
     *   c = 0 → 得 A      c = 1 → 得 B
     * </pre>
     *
     * <p>关键：<b>选择发生在槽位域</b>。{@code c} 的每个槽位是 0 或 1，
     * 于是"选 A 还是 B"是逐槽位决定的 —— 这正是盲旋转每轮需要的能力。
     */
    public static RLWECipher cmux(RGSW selector, RLWECipher a, RLWECipher b) {
        RLWECipher diff = b.sub(a);
        RLWECipher prod = selector.externalProduct(diff);
        return a.add(prod);
    }

    @Override
    public String toString() {
        return "RGSW{l=" + group0.length + ", base=" + p.base + "}";
    }
}
