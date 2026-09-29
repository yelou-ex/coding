package cape.tiny;

/**
 * 极小验证版的参数（对应《CAPE 实现步骤（极简验证版）》第 0 节）。
 *
 * <h3>为什么这一层要自成一套</h3>
 * 仓库里已有的 HE 代码走的是 <b>MPC4J / SEAL 的 BFV</b> 路线，它<b>接受不了</b>这里的极小参数：
 * 系数模数必须是若干 NTT 友好素数的乘积、N 有最小规模要求。
 * 而本规范要的是「参数极小、噪声为 0、可手工逐位验算」，
 * 所以这里用<b>零依赖</b>的自实现，专门服务正确性验证。
 *
 * <h3>参数（规范给定）</h3>
 * <pre>
 *   N       = 8      多项式次数
 *   t       = 17     明文模数，t ≡ 1 (mod 2N = 16) ✓
 *   q       = 97     密文模数
 *   B       = 2      gadget 基
 *   l       = ceil(log_2 q) = 7
 *   ell_BF  = 2      Bloom 长度
 *   k_BFF   = 3      BFF 位置数
 *   R, C    = 2, 2   L_BFF = R*C = 4
 *   B_pay   = 2 + m*(1 + ell_BF) = 5
 *   噪声    = 0      全部噪声为 0，解密即精确明文
 * </pre>
 *
 * <h3>数学可行性（已实测确认）</h3>
 * <ul>
 *   <li><b>槽位分解</b>：{@code X^8+1} 在 {@code F_17} 上<b>完全分裂</b>成 8 个一次因式
 *       （根为 3,5,6,7,10,11,12,14），所以<b>恰好有 8 个槽位</b> —— 槽位编码可用。</li>
 *   <li><b>NTT</b>：{@code q=97}，{@code 16 | q-1}（96/16=6），16 阶单位根 ω=8（5^6 = 8）。
 *       本实现为了可读性用直接卷积（N=8 时只有 64 次乘），NTT 只在需要时另加。</li>
 *   <li><b>缩放</b>：Δ = floor(q/t) = 5；噪声为 0 时 {@code phase = Δ·m} 精确，
 *       解码 {@code round(phase/Δ) = m}。</li>
 * </ul>
 */
public final class TinyParams {

    /** 多项式次数 N（环是 Z_q[X]/(X^N+1)） */
    public final int n;
    /** 明文模数 t */
    public final int t;
    /** 密文模数 q（素数，16 | q-1 以支持 16 阶单位根） */
    public final int q;
    /** gadget 基 B */
    public final int base;
    /** gadget 层数 l（须满足 B^l ≥ q） */
    public final int levels;
    /** 缩放因子 Δ = floor(q/t) */
    public final int delta;
    /** Bloom 长度 ℓ_BF */
    public final int bloomLength;
    /** BFF 位置数 k */
    public final int bffK;

    /** 16 阶单位根 ω（用于槽位编解码），满足 ω^8 = −1 mod q */
    public final int omega;
    /** X^8+1 在 F_t 上的根（即 8 个槽位对应的求值点） */
    public final int[] slotPoints;
    /** 槽位数 = N */
    public final int slots;

    public TinyParams(int n, int t, int q, int base, int levels, int bloomLength, int bffK) {
        if (Integer.bitCount(n) != 1) throw new IllegalArgumentException("N 必须是 2 的幂: " + n);
        this.n = n;
        this.t = t;
        this.q = q;
        this.base = base;
        this.levels = levels;
        this.bloomLength = bloomLength;
        this.bffK = bffK;
        this.delta = q / t;
        this.slots = n;
        if (delta == 0) throw new IllegalArgumentException("q/t == 0，噪声预算为零");

        // ---- 自动求 16 阶单位根（对 q 求）----
        this.omega = findRootOfUnity(n, q);
        if (modPow(omega, n, q) != q - 1) {
            throw new IllegalArgumentException("ω^N 应等于 −1，实际 " + modPow(omega, n, q));
        }

        // ---- 求 X^N+1 在 F_t 上的全部根 = 槽位求值点 ----
        int[] roots = new int[n];
        int found = 0;
        for (int x = 0; x < t && found < n; x++) {
            if (modPow(x, n, t) == t - 1) roots[found++] = x;
        }
        if (found != n) {
            throw new IllegalArgumentException(
                "X^N+1 在 F_t 上不完全分裂（只找到 " + found + " 个根 / 需要 " + n
                    + "）→ 无法做槽位编码。请换 t 或 N。");
        }
        this.slotPoints = roots;
    }

    /** 规范的默认极小参数：N=8, t=17, q=97, B=2, l=7, ℓ_BF=2, k=3 */
    public static TinyParams spec() {
        return new TinyParams(8, 17, 97, 2, 7, 2, 3);
    }

    // ==================== 通用模算术 ====================

    /** 模幂（用 long 防溢出） */
    public static int modPow(long base, long exp, int mod) {
        long result = 1, b = ((base % mod) + mod) % mod;
        while (exp > 0) {
            if ((exp & 1) == 1) result = result * b % mod;
            b = b * b % mod;
            exp >>= 1;
        }
        return (int) result;
    }

    /** 模逆（扩展欧几里得） */
    public static int modInverse(int a, int mod) {
        int g = mod, x = 0, x1 = 1, a1 = ((a % mod) + mod) % mod;
        while (a1 != 0) {
            int q = g / a1;
            int nx = x - q * x1;
            x = x1; x1 = nx;
            int na = g - q * a1;
            g = a1; a1 = na;
        }
        if (g != 1) throw new ArithmeticException(a + " 在模 " + mod + " 下不可逆");
        return ((x % mod) + mod) % mod;
    }

    /** 求 2N 阶单位根（先找原根，再取 2N 次方） */
    public static int findRootOfUnity(int n, int q) {
        int twoN = 2 * n;
        if ((q - 1) % twoN != 0) {
            throw new IllegalArgumentException("2N=" + twoN + " 不整除 q-1=" + (q - 1));
        }
        int g = primitiveRoot(q);
        return modPow(g, (q - 1) / twoN, q);
    }

    /** 求模 q 的最小原根 */
    public static int primitiveRoot(int q) {
        for (int g = 2; g < q; g++) {
            boolean ok = true;
            for (int factor : primeFactors(q - 1)) {
                if (modPow(g, (q - 1) / factor, q) == 1) { ok = false; break; }
            }
            if (ok) return g;
        }
        throw new IllegalStateException("找不到原根: q=" + q);
    }

    /** 试除求素因子 */
    public static java.util.List<Integer> primeFactors(int x) {
        java.util.List<Integer> out = new java.util.ArrayList<>();
        for (int d = 2; (long) d * d <= x; d++) {
            if (x % d == 0) {
                out.add(d);
                while (x % d == 0) x /= d;
            }
        }
        if (x > 1) out.add(x);
        return out;
    }

    // ==================== 参数派生量 ====================

    /** 每个关键词的 payload 字段数 B_pay = 2 + m·(1+ℓ_BF) */
    public int payloadFields(int maxValues) {
        return 2 + maxValues * (1 + bloomLength);
    }

    /** 第 j（从 1 起）个值在 payload 里的字段号 */
    public int valueField(int j) {
        return 2 + (j - 1) * (1 + bloomLength);
    }

    /** 第 j 个值、第 i（从 0 起）个 Bloom 位的字段号 */
    public int bloomField(int j, int i) {
        return valueField(j) + 1 + i;
    }

    /** 把 v ∈ [0,t) 编码成 Z_q 元素：Δ·v */
    public int encode(int v) {
        return ((v % t) + t) % t * delta % q;
    }

    /**
     * <b>可表达的最大明文值</b>：{@code ⌊(q/2)/Δ⌋}。
     *
     * <p>这是本组极小参数最紧的约束，也是调试时最容易踩的坑：
     * <b>噪声为 0 并不等于"什么值都能表达"</b> —— 相位必须落在
     * {@code (−q/2, q/2]} 内才能被 {@link #decode} 正确还原。
     *
     * <p>本参数（Δ=5, q=97）下 {@code maxPlaintext() = 9}。
     * 于是：
     * <ul>
     *   <li>单个明文：必须 ≤ 9；</li>
     *   <li>明文<b>乘积</b>（CtCtMul 等）：{@code m·m' ≤ 9}；</li>
     *   <li>Bloom 得分是若干 0/1 之和，最多 m 项，故 {@code m ≤ 9} 即可。</li>
     * </ul>
     */
    public int maxPlaintext() {
        return (q / 2) / delta;
    }

    /** 明文乘积是否可表达（乘积也要 ≤ maxPlaintext） */
    public boolean productFits(int... factors) {
        long prod = 1;
        for (int f : factors) prod *= f;
        return prod <= maxPlaintext();
    }

    /** 解码相位相位 → Z_t 元素（四舍五入到最近的 Δ 倍数） */
    public int decode(int phase) {
        int p = ((phase % q) + q) % q;
        // 中心化到 (−q/2, q/2]
        if (p > q / 2) p -= q;
        long rounded = Math.round((double) p / delta);
        return (int) ((rounded % t) + t) % t;
    }

    /**
     * 解码成 <b>中心代表元</b>（落在 {@code (−t/2, t/2]}）。
     *
     * <p>需要它的原因：盲旋转用到 {@code X^N = −1}，明文中会自然出现负数
     * （如 {@code −P[j]}）。用 {@link #decode} 得到的是 {@code [0,t)} 代表元（{@code −1 → 16}），
     * 用本方法得到 {@code −1}。两者是同一个元素，但<b>对拍时必须统一</b>，
     * 否则会把"表示不同"误判成"算错了"。
     */
    public int decodeCentered(int phase) {
        int p = ((phase % q) + q) % q;
        if (p > q / 2) p -= q;
        long rounded = Math.round((double) p / delta);
        return Poly.centralize((int) rounded, t);
    }

    /** 解密整个多项式（中心代表元） */
    public int[] decodePolynomialCentered(int[] phase) {
        int[] out = new int[phase.length];
        for (int i = 0; i < phase.length; i++) out[i] = decodeCentered(phase[i]);
        return out;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(String.format(
            "N=%d, t=%d, q=%d, Δ=%d, B=%d, l=%d, ℓ_BF=%d, k=%d, 槽位=%d, ω=%d",
            n, t, q, delta, base, levels, bloomLength, bffK, slots, omega));
        sb.append(", 槽位求值点={");
        for (int i = 0; i < slotPoints.length; i++) {
            sb.append(slotPoints[i]).append(i + 1 < slotPoints.length ? "," : "");
        }
        return sb.append("}").toString();
    }
}
