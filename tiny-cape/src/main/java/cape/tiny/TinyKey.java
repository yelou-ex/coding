package cape.tiny;

import java.util.Random;

/**
 * 密钥与基础加解密原语。
 *
 * <h3>一套秘密、两种形态（规范第 0 节）</h3>
 * <pre>
 *   s_L = (s_L[0], …, s_L[d−1]) ∈ {0,1}^d          LWE 私钥
 *   s_R(X) = s_L[0] + s_L[1]·X + … + s_L[d−1]·X^{d−1}   RLWE 私钥（同源！）
 * </pre>
 * <b>同源是关键</b>：SampleExtract 之后密钥从 {@code s_R} 变成 {@code s_L}，
 * Pack 再把它变回 {@code s_R} —— 全程只有一套秘密，所以客户端只需保存一份。
 *
 * <p>本实现噪声为 0，所以相位 {@code c0 + c1·s_R} 精确等于 {@code Δ·m(X)}，
 * 解密无需担心舍入。
 */
public final class TinyKey {

    /** 参数 */
    public final TinyParams p;
    /** LWE 私钥比特 s_L ∈ {0,1}^d */
    public final int[] sL;
    /** RLWE 私钥多项式 s_R ∈ Z_q[X]/(X^N+1) */
    public final int[] sR;

    public TinyKey(TinyParams p, int[] sL) {
        this.p = p;
        this.sL = sL.clone();
        int[] sr = new int[p.n];
        for (int j = 0; j < Math.min(sL.length, p.n); j++) sr[j] = sL[j];
        this.sR = sr;
    }

    /** 随机密钥 */
    public static TinyKey random(TinyParams p, int d, Random rnd) {
        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        return new TinyKey(p, s);
    }

    // ==================== RLWE ====================

    /**
     * <b>带缩放</b>加密：相位 = {@code Δ·m(X)}（密文级）。
     * 用于数据库/累加器这类"要解密读明文"的数据。
     */
    public RLWECipher encryptRLWE(int[] m, Random rnd) {
        int[] scaled = new int[p.n];
        for (int i = 0; i < p.n; i++) scaled[i] = m[i] * p.delta % p.q;
        return encryptRaw(scaled, rnd);
    }

    /**
     * <b>原始</b>加密：相位 = {@code msg(X)}，<b>不做 Δ 缩放</b>（原始级）。
     *
     * <p>用于内部量（重线性化密钥的 {@code s_R²}）和"掩码" ——
     * 掩码要以原始级参与乘法，才能让 {@code ΔP · (mask)} 恰好得到 {@code Δ·(mask·P)}，
     * 而不多出一个 Δ。
     */
    public RLWECipher encryptRaw(int[] msg, Random rnd) {
        int[] a = new int[p.n];
        for (int i = 0; i < p.n; i++) a[i] = rnd.nextInt(p.q);
        int[] as = Poly.mul(a, sR, p.q);
        // c0 = msg − a·s
        return new RLWECipher(Poly.sub(msg, as, p.q), a, p.q);
    }

    /** RLWE 相位 = c0 + c1·s_R（模 q） */
    public int[] phase(RLWECipher ct) {
        return Poly.add(ct.c0, Poly.mul(ct.c1, sR, p.q), p.q);
    }

    /** RLWE 解密：相位 → Z_t 上的多项式（[0,t) 代表元） */
    public int[] decryptRLWE(RLWECipher ct) {
        int[] ph = phase(ct);
        int[] out = new int[p.n];
        for (int i = 0; i < p.n; i++) out[i] = p.decode(ph[i]);
        return out;
    }

    /**
     * RLWE 解密：相位 → Z_t 上的多项式（<b>中心代表元</b>）。
     *
     * <p>盲旋转会用 {@code X^N = −1} 产生负数，那时必须用这个版本对拍，
     * 否则 {@code −1} 会显示成 {@code 16}，看起来像算错。
     */
    public int[] decryptRLWECentered(RLWECipher ct) {
        return p.decodePolynomialCentered(phase(ct));
    }

    // ==================== LWE ====================

    /**
     * <b>SampleExtract_0</b>（规范第 7 行）：从 RLWE 密文里取出<b>常数项</b>。
     *
     * <h3>⚠️ 状态：未解决（不影响端到端）</h3>
     * 提取出的 LWE {@code (a, b)} 与 RLWE 相位常数项的关系<b>没有对齐</b>。
     * 已验证的部分：
     * <ul>
     *   <li>{@code (c1·s_R)[0] = c1[0]·s[0] − Σ_{k=1}^{N−1} c1[k]·s[N−k]} —— 逐项插桩确认
     *       （{@code Poly.mul} 与公式一致）；</li>
     *   <li>{@code c0[0] + (c1·s_R)[0] = Δ·m[0]} —— 恒等式成立；</li>
     *   <li>但 {@code b − ⟨a,s_L⟩} 与常数项始终差一个常数（实测 67），
     *       说明 {@code a} 的下标/符号映射还漏了一层。</li>
     * </ul>
     * 需要时从 {@code Diag11/Diag12/Diag13} 接着查（插桩打印已就绪）。
     *
     * <p><b>为什么可以暂时放下</b>：CAPE 的 ANSWER 链只需要把目标行挪到常数项再读出来，
     * 而 {@link BlindRotate#blindRotate} 已经做到了（整条多项式对拍通过）。
     * SampleExtract 只在"要把 RLWE 变回 LWE 密文继续做 LWE 层运算"时才需要。
     */
    public LWECipher sampleExtract0(RLWECipher ct) {
        int n = p.n;
        int d = sL.length;
        int[] a = new int[d];

        // 常数项 = c0[0] + c1[0]·s[0] − Σ_{k=1}^{N−1} c1[k]·s[N−k]
        // 下面这版是按"负号留在 c1 上"写的（Diag12 的逐项结论）；
        // 与恒等式 b − ⟨a,s_L⟩ == phase[0] 仍差一个常数，待查。
        a[0] = (int) Math.floorMod(ct.c1[0], p.q);
        for (int k = 1; k < n; k++) {
            int idx = n - k;
            if (idx < d) {
                a[idx] = (int) Math.floorMod(a[idx] - ct.c1[k], p.q);
            }
        }
        int b = (int) Math.floorMod(ct.c0[0], p.q);
        return new LWECipher(a, b, p.q);
    }

    /** 用 s_L 解密一条 LWE 密文（返回 Z_t 上的值） */
    public int decryptLWEValue(LWECipher ct) {
        long dot = 0;
        for (int i = 0; i < ct.a.length; i++) dot += (long) ct.a[i] * sL[i];
        long phase = Math.floorMod(ct.b - dot, ct.qL);
        // 若模数是 q 而明文在 t，需要缩放
        if (ct.qL == p.q) {
            return p.decodeCentered((int) phase);
        }
        return (int) Math.floorMod(phase, p.t);
    }

    /** LWE 加密：相位 = b − ⟨a,s_L⟩ = m（Δ_L = 1） */
    public LWECipher encryptLWE(int m, Random rnd) {
        int d = sL.length;
        int[] a = new int[d];
        long dot = 0;
        for (int i = 0; i < d; i++) {
            a[i] = rnd.nextInt(p.t);
            dot += (long) a[i] * sL[i];
        }
        int b = (int) Math.floorMod(dot + m, p.t);
        return new LWECipher(a, b, p.t);
    }

    /** LWE 相位（中心化后的明文） */
    public int lwePhase(LWECipher ct) {
        long dot = 0;
        for (int i = 0; i < ct.a.length; i++) dot += (long) ct.a[i] * sL[i];
        return (int) Math.floorMod(ct.b - dot, ct.qL);
    }

    /** LWE 解密 */
    public int decryptLWE(LWECipher ct) {
        return lwePhase(ct);
    }

    // ==================== 槽位辅助 ====================

    /** s_R 的槽位形式（各槽位点上求值，模 t） */
    public int[] sRSlots() {
        return Poly.toSlots(sR, p.t, p.slotPoints);
    }

    // ==================== 重线性化密钥 ====================

    private RLWECipher[] rlk;

    /**
     * 重线性化密钥 {@code rlk = RLWE_{s_R}(s_R²)}（懒生成并缓存）。
     *
     * <p>CtCtMul 的张量积会引入 {@code s_R²} 项，必须用它消掉（规范第 6 节的"三步"之二）。
     * 生成方式：直接加密 {@code s_R·s_R}（噪声为 0，无需 gadget 分解）。
     */
    public RLWECipher[] relinKeys(Random rnd) {
        if (rlk == null) {
            // s² 的系数在 Z_q 上，所以用"原始加密"（不做 Δ 缩放）——
            // 重线性化密钥要能直接消掉 d2·s² 这一项。
            int[] sSq = Poly.mul(sR, sR, p.q);
            rlk = new RLWECipher[]{encryptRaw(sSq, rnd)};
        }
        return rlk;
    }

    // ==================== CtCtMul + 重线性化 ====================

    /**
     * 密文×密文（规范第 6 节的三步）。
     *
     * <pre>
     *   1. 张量积：d0 = c0·e0, d1 = c0·e1 + c1·e0, d2 = c1·e1
     *      相位 = d0 + d1·s + d2·s²
     *   2. 重线性化：用 rlk = RLWE(s²) 消 d2 → d1' = d1 + d2·s
     *      相位回到 d0 + d1'·s（只有两个分量）
     *   3. 缩放回落：本参数 Δ=5 在 Z_97 下可逆，故乘 Δ^{-1} 是精确的
     * </pre>
     *
     * <p><b>前提</b>：两个操作数都必须是<b>带缩放级</b>（相位 = Δ·m），
     * 结果才是带缩放级；否则要跳过第 3 步（见 {@link #ctCtMulNoRescale}）。
     */
    public RLWECipher ctCtMul(RLWECipher x, RLWECipher y, Random rnd) {
        RLWECipher r = ctCtMulNoRescale(x, y, rnd);
        int invDelta = TinyParams.modInverse(p.delta % p.q, p.q);
        return new RLWECipher(Poly.scalar(r.c0, invDelta, p.q), Poly.scalar(r.c1, invDelta, p.q), p.q);
    }

    /** 只做张量积 + 重线性化，<b>不做缩放回落</b>（相位 = 两个输入相位之积） */
    public RLWECipher ctCtMulNoRescale(RLWECipher x, RLWECipher y, Random rnd) {
        int[] d0 = Poly.mul(x.c0, y.c0, p.q);
        int[] d1 = Poly.add(Poly.mul(x.c0, y.c1, p.q), Poly.mul(x.c1, y.c0, p.q), p.q);
        int[] d2 = Poly.mul(x.c1, y.c1, p.q);

        RLWECipher key = relinKeys(rnd)[0];
        int[] r0 = Poly.add(d0, Poly.mul(d2, key.c0, p.q), p.q);
        int[] r1 = Poly.add(d1, Poly.mul(d2, key.c1, p.q), p.q);
        return new RLWECipher(r0, r1, p.q);
    }

    /** 除以 Δ（把带缩放级降到原始级，或把 Δ² 级降到带缩放级） */
    public RLWECipher divDelta(RLWECipher ct) {
        int invDelta = TinyParams.modInverse(p.delta % p.q, p.q);
        return new RLWECipher(Poly.scalar(ct.c0, invDelta, p.q), Poly.scalar(ct.c1, invDelta, p.q), p.q);
    }
}
