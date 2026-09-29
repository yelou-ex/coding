package cape.tiny;

import java.util.Arrays;
import java.util.Random;

/**
 * 第 0–2 层自检：参数 / 环运算 / 槽位转换 / RLWE 加减乘。
 *
 * <p>这几层是所有后续步骤的地基，所以先把它们钉死，再往上叠。
 */
public final class TinySelfTest {

    private static int failed = 0;

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        System.out.println("=== tiny-cape 自检（第 0–2 层）===");
        System.out.println("[params] " + p);
        System.out.println();

        testParams(p);
        testPolyRing(p);
        testSlotRoundTrip(p);
        testRLWE(p);
        testCtCtMul(p);
        System.out.println();
        System.out.println(failed == 0 ? "=== 全过 ===" : "=== " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 第 0 层：参数自洽 */
    private static void testParams(TinyParams p) {
        System.out.println("--- 0. 参数 ---");
        check("Δ = floor(q/t) = 5", p.delta == 5, "实际 " + p.delta);
        check("ω^N ≡ −1 (mod q)", TinyParams.modPow(p.omega, p.n, p.q) == p.q - 1,
            "ω=" + p.omega + ", ω^8=" + TinyParams.modPow(p.omega, p.n, p.q));
        check("X^N+1 在 F_t 完全分裂 → N 个槽位点", p.slotPoints.length == p.n,
            Arrays.toString(p.slotPoints));
        boolean allRoots = true;
        for (int x : p.slotPoints) if (TinyParams.modPow(x, p.n, p.t) != p.t - 1) allRoots = false;
        check("所有槽位点都满足 ζ^N = −1", allRoots, "");
        check("B^l ≥ q", Math.pow(p.base, p.levels) >= p.q,
            p.base + "^" + p.levels + "=" + (long) Math.pow(p.base, p.levels));
        check("Δ 在 Z_q 可逆", TinyParams.modInverse(p.delta, p.q) * p.delta % p.q == 1, "");
        check("可表达明文上界 maxPlaintext() = floor((q/2)/Δ)", p.maxPlaintext() == (p.q / 2) / p.delta,
            "= " + p.maxPlaintext());
        System.out.printf("      说明：Δ=%d, q=%d → 明文（含乘积）必须 ≤ %d，否则相位翻到负半轴%n",
            p.delta, p.q, p.maxPlaintext());
        System.out.println();
    }

    /** 第 1 层：环运算 */
    private static void testPolyRing(TinyParams p) {
        System.out.println("--- 1. 环 Z_q[X]/(X^N+1) ---");
        int[] x = {0, 1, 0, 0, 0, 0, 0, 0};              // X
        int[] xN1 = new int[p.n];
        xN1[p.n - 1] = 1;                                 // X^{N−1}
        int[] xN = Poly.mul(x, xN1, p.q);                 // X · X^{N−1} = X^N
        int[] minusOne = new int[p.n];
        minusOne[0] = p.q - 1;
        check("X^N = −1（负循环）", Poly.equals(xN, minusOne),
            "X·X^{N−1}=" + Poly.show(xN) + " 期望 " + Poly.show(minusOne));

        // 交换律 / 结合律抽检
        Random rnd = new Random(1);
        int[] a = randPoly(p, rnd), b = randPoly(p, rnd), c = randPoly(p, rnd);
        check("乘法交换律", Poly.equals(Poly.mul(a, b, p.q), Poly.mul(b, a, p.q)), "");
        check("乘法结合律",
            Poly.equals(Poly.mul(Poly.mul(a, b, p.q), c, p.q), Poly.mul(a, Poly.mul(b, c, p.q), p.q)), "");
        check("分配律",
            Poly.equals(Poly.mul(a, Poly.add(b, c, p.q), p.q),
                Poly.add(Poly.mul(a, b, p.q), Poly.mul(a, c, p.q), p.q)), "");

        // 单项式旋转与环乘法一致
        boolean monOk = true;
        for (int k = 0; k < 2 * p.n; k++) {
            int[] byMul = Poly.mul(a, monomial(k, p), p.q);
            if (!Poly.equals(byMul, Poly.mulMonomial(a, k, p.q))) monOk = false;
        }
        check("mulMonomial(k) 与乘 X^k 一致（全部 2N 个 k）", monOk, "");
        System.out.println();
    }

    /** 第 2 层：槽位编解码 */
    private static void testSlotRoundTrip(TinyParams p) {
        System.out.println("--- 2. 系数域 ↔ 槽位域 ---");
        Random rnd = new Random(2);
        boolean roundTrip = true, mulOk = true, addOk = true;
        for (int trial = 0; trial < 20; trial++) {
            int[] f = randPolyMod(p, p.t, rnd), g = randPolyMod(p, p.t, rnd);
            int[] fs = Poly.toSlots(f, p.t, p.slotPoints);
            int[] gs = Poly.toSlots(g, p.t, p.slotPoints);
            if (!Poly.equals(Poly.fromSlots(fs, p.t, p.slotPoints), f)) roundTrip = false;

            // 逐点相乘 == 环乘法再转槽位
            int[] pointwise = Poly.pointwise(fs, gs, p.t);
            int[] ringThenSlots = Poly.toSlots(Poly.mul(f, g, p.t), p.t, p.slotPoints);
            if (!Poly.equals(pointwise, ringThenSlots)) mulOk = false;

            // 槽位域加法
            if (!Poly.equals(Poly.add(fs, gs, p.t), Poly.toSlots(Poly.add(f, g, p.t), p.t, p.slotPoints)))
                addOk = false;
        }
        check("槽位编解码往返（20 组）", roundTrip, "");
        check("逐槽相乘 == 环乘法后转槽位（20 组）", mulOk, "");
        check("槽位域加法同态（20 组）", addOk, "");

        // 明确演示：系数域求和会退化成 |a|·|b|，与内积无关
        int[] fa = {1, 1, 0, 0, 0, 0, 0, 0};   // 汉明重量 2
        int[] fb = {1, 0, 1, 0, 0, 0, 0, 0};   // 汉明重量 2，与 fa 交集 1
        int[] conv = Poly.mul(fa, fb, p.t);
        int sumConv = 0;
        for (int v : conv) sumConv = (sumConv + v) % p.t;
        int dot = 0;
        for (int i = 0; i < p.n; i++) dot = (dot + fa[i] * fb[i]) % p.t;
        System.out.printf("      演示：系数域 Σ(a⊛b) = %d，而内积 ⟨a,b⟩ = %d（|a|·|b| = %d mod t = %d）%n",
            sumConv, dot, 2 * 2, (2 * 2) % p.t);
        check("系数域求和 ≠ 内积（证明必须走槽位域）", sumConv != dot, "");
        System.out.println();
    }

    /** RLWE 加解密与同态加 */
    private static void testRLWE(TinyParams p) {
        System.out.println("--- 3. RLWE 加解密 / 同态加 ---");
        Random rnd = new Random(3);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int cap = p.maxPlaintext();

        // 明文必须 ≤ maxPlaintext：同态加之后是 2·m，所以 m ≤ cap/2
        int mCap = cap / 2;
        int[] m = randPolyMod(p, mCap + 1, rnd);
        RLWECipher ct = key.encryptRLWE(m, rnd);
        check("解密往返", Arrays.equals(key.decryptRLWE(ct), m), "");

        int[] m2 = randPolyMod(p, mCap + 1, rnd);
        RLWECipher ct2 = key.encryptRLWE(m2, rnd);
        int[] sum = new int[p.n];
        for (int i = 0; i < p.n; i++) sum[i] = (m[i] + m2[i]) % p.t;
        check("同态加（和 ≤ " + cap + "）", Arrays.equals(key.decryptRLWE(ct.add(ct2)), sum), "");
        check("同态减", Arrays.equals(key.decryptRLWE(ct.sub(ct2)), Poly.sub(m, m2, p.t)), "");

        // 原始级加密：相位不缩放
        int[] raw = new int[p.n];
        for (int i = 0; i < p.n; i++) raw[i] = rnd.nextInt(p.q);
        RLWECipher rawCt = key.encryptRaw(raw, rnd);
        check("原始级加密（相位 = msg，不缩放）", Arrays.equals(key.phase(rawCt), raw), "");

        // 明确演示：超出容量会翻到负半轴
        int[] over = new int[p.n];
        over[0] = cap + 1;
        int got = key.decryptRLWE(key.encryptRLWE(over, rnd))[0];
        System.out.printf("      演示：明文 %d 超出上界 %d → 解密得到 %d（相位翻到负半轴）%n",
            cap + 1, cap, got);
        System.out.println();
    }

    /** 第 3 层：CtCtMul（张量积 + 重线性化 + 缩放回落） */
    private static void testCtCtMul(TinyParams p) {
        System.out.println("--- 4. CtCtMul（密文×密文）---");
        Random rnd = new Random(4);
        TinyKey key = TinyKey.random(p, p.n, rnd);

        // 容量约束的正确理解：
        //   环乘法是【卷积】，结果的每个系数是"N 个乘积项之和"（本环里带符号）。
        //   所以要保证的是【卷积后每个系数】≤ maxPlaintext()，不是逐点乘积。
        //   取 0/1 数据时，卷积系数 ∈ [−N, N]，本参数 N=8 ≤ 9 ✓
        //   而 0/1 本来就是 CAPE 的真实数据（Bloom 位、指纹位）。
        boolean ok = true;
        StringBuilder detail = new StringBuilder();
        for (int trial = 0; trial < 8; trial++) {
            int[] m = bits(p, rnd), m2 = bits(p, rnd);
            RLWECipher prod = key.ctCtMul(key.encryptRLWE(m, rnd), key.encryptRLWE(m2, rnd), rnd);
            int[] want = Poly.mul(m, m2, p.t);
            int[] got = key.decryptRLWE(prod);
            if (!Arrays.equals(got, want)) {
                ok = false;
                if (detail.length() < 100) {
                    detail.append("m=").append(Poly.show(m)).append(" m2=").append(Poly.show(m2))
                          .append(" got=").append(Poly.show(got)).append("; ");
                }
            }
        }
        check("8 组密文×密文都正确（0/1 数据）", ok, detail.toString());
        System.out.printf("      容量：卷积系数 ∈ [−N,N] = [−%d,%d]，上界 %d ✓%n",
            p.n, p.n, p.maxPlaintext());

        // 槽位掩码：掩码 0/1、数据 0/1 → 卷积系数同样有界
        int[] P = bits(p, rnd);
        int[] maskSlots = {1, 0, 1, 1, 0, 0, 1, 0};
        int[] maskCoeff = Poly.fromSlots(maskSlots, p.t, p.slotPoints);
        RLWECipher masked = key.ctCtMulNoRescale(
            key.encryptRLWE(P, rnd), key.encryptRaw(maskCoeff, rnd), rnd);
        int[] got = key.decryptRLWE(masked);
        int[] want = Poly.mul(maskCoeff, P, p.t);
        check("槽位掩码：解密 == maskCoeff·P（环乘积）", Arrays.equals(got, want),
            "got=" + Poly.show(got) + " want=" + Poly.show(want));

        int[] gotSlots = Poly.toSlots(got, p.t, p.slotPoints);
        int[] wantSlots = Poly.pointwise(maskSlots, Poly.toSlots(P, p.t, p.slotPoints), p.t);
        check("槽位掩码：槽位域 == 逐槽相乘", Arrays.equals(gotSlots, wantSlots),
            "got=" + Poly.show(gotSlots) + " want=" + Poly.show(wantSlots));
        System.out.println();
    }

    /** 0/1 随机多项式（CAPE 的真实数据形态） */
    private static int[] bits(TinyParams p, Random rnd) {
        int[] f = new int[p.n];
        for (int i = 0; i < p.n; i++) f[i] = rnd.nextInt(2);
        return f;
    }

    // ==================== 工具 ====================

    private static int[] monomial(int k, TinyParams p) {
        int[] f = new int[p.n];
        f[0] = 1;
        return Poly.mulMonomial(f, k, p.q);
    }

    private static int[] powerOfX(int k, int mod) {
        int[] f = new int[8];
        f[k % 8] = 1;
        return f;
    }

    private static int[] randPoly(TinyParams p, Random rnd) {
        int[] f = new int[p.n];
        for (int i = 0; i < p.n; i++) f[i] = rnd.nextInt(p.q);
        return f;
    }

    private static int[] randPolyMod(TinyParams p, int mod, Random rnd) {
        int[] f = new int[p.n];
        for (int i = 0; i < p.n; i++) f[i] = rnd.nextInt(mod);
        return f;
    }

    private static void check(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "  [PASS] " : "  [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
    }
}
