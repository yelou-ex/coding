package com.fusepir.rgsw;

import java.util.Random;

/**
 * <b>确认 LWE 域列选择的数学</b>（用户澄清的形态）。
 *
 * <h3>要点</h3>
 * LWE 密文 {@code (a, b)} 只加密一个<b>标量</b>：相位 {@code b − ⟨a,s⟩ = m ∈ Z_t}。
 *
 * <p>要让它表达一个<b>多项式</b> {@code P(X)}（把 {@code P} 的系数放进去），
 * 必须把 LWE 维度从 {@code d} 扩到 {@code d·R}，并让秘密扩成
 * <pre>
 *   s ⊗ (1, X, X^2, …, X^{R−1})        （R 个旋转副本）
 * </pre>
 * 于是相位变成
 * <pre>
 *   b − Σ_{i<d} Σ_{k<R} a_{i,k}·s_i·X^k
 *   = b − Σ_i s_i·(Σ_k a_{i,k}·X^k) = b − ⟨a(X), s⟩
 * </pre>
 * —— 一个<b>多项式相位</b>，也就是 RLWE 的形态（密钥是 {@code s(X) = Σs_i X^i}）。
 *
 * <p><b>结论</b>：把 LWE 的 {@code a} 按 R 个旋转副本铺开，
 * 就得到 RLWE 形态的累加器 —— 这与"客户端直接发 RLWE 选择子"是同一件事，
 * 只是 {@code a} 的编排不同（正如用户所说）。
 *
 * <p>所以 {@code q^col[c] · P_{c,b}(X)} 在 LWE 域的正确含义是：
 * <b>把 {@code a} 铺开后，各分量乘上 P 的对应系数</b>；乘完的累加器就是 RLWE 形态。
 */
public final class LweColumnMath {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== LWE 域列选择：a 的旋转铺开 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261008L);

        // ---- 秘密：s_R = Σ s_i X^i（与 RLWE 私钥同源）----
        int[] s = new int[n];
        for (int i = 0; i < n; i++) s[i] = rnd.nextInt(2);
        System.out.println("[key] s_R 已生成（n=" + n + " 个系数）");

        // ---- 客户端：把 one-hot 的第 c 位用 LWE 加密（标量）----
        // 铺开形态：a(X) = Σ_k a_k X^k（R = n 个旋转副本），b 是标量
        // 相位应为 e[c] · X^c  —— 即"one-hot 编进系数"的那个多项式
        int cStar = 2;
        long[] aPoly = new long[n];
        long dot = 0;
        for (int k = 0; k < n; k++) {
            aPoly[k] = Math.floorMod(rnd.nextLong(), m.t);
            dot = (dot + aPoly[k] * s[k]) % m.t;
        }
        long[] targetPoly = new long[n];
        targetPoly[cStar] = 1;                       // e(X) = X^{c*}
        // b = ⟨a, s⟩ + e(X) 的"常数项"？—— 多项式相位不能只靠一个标量 b 表达。
        // 关键：b 也是一个多项式！ 把 b 铺成 X^k 系数，就得到完整的多项式相位。
        long[] bPoly = new long[n];
        for (int k = 0; k < n; k++) {
            bPoly[k] = Math.floorMod(dotOfShift(aPoly, s, k, m.t) + targetPoly[k], m.t);
        }
        System.out.println("[query] a(X)、b(X) 都是多项式（长度 n），相位 = b(X) − a(X)·s(X)");
        System.out.println("        期望 = e(X) = X^" + cStar);
        System.out.println();

        // ---- 验证相位 ----
        long[] phase = new long[n];
        for (int k = 0; k < n; k++) phase[k] = bPoly[k];
        // 减去 a(X)·s(X)（负循环环 mod t）
        for (int i = 0; i < n; i++) {
            if (aPoly[i] == 0) continue;
            for (int j = 0; j < n; j++) {
                if (s[j] == 0) continue;
                int k = i + j;
                long prod = aPoly[i] * s[j] % m.t;
                if (k < n) phase[k] = Math.floorMod(phase[k] - prod, m.t);
                else phase[k - n] = Math.floorMod(phase[k - n] + prod, m.t);   // X^N = −1
            }
        }
        System.out.print("[check] 相位前 5 = ");
        for (int i = 0; i < 5; i++) System.out.print(phase[i] + " ");
        System.out.println();
        System.out.print("        期望前 5 = ");
        for (int i = 0; i < 5; i++) System.out.print(targetPoly[i] + " ");
        System.out.println();

        boolean ok = true;
        for (int i = 0; i < n; i++) if (phase[i] != targetPoly[i]) ok = false;
        failed += report("相位 == e(X)（多项式相位成立）", ok, "");

        // ---- 列选择：乘 P_{c,b}(X) ----
        System.out.println();
        long[] P = new long[n];
        for (int i = 0; i < 8; i++) P[i] = 100 + i;
        P[0] = 40;
        // P(X) 乘到相位上（两个都是多项式）→ 负循环卷积
        long[] want = ringMul(targetPoly, P, m.t);
        // LWE 域怎么做：a ← a·P, b ← b·P（都是多项式乘）
        long[] aScaled = ringMul(aPoly, P, m.t);
        long[] bScaled = ringMul(bPoly, P, m.t);
        long[] phaseScaled = new long[n];
        System.arraycopy(bScaled, 0, phaseScaled, 0, n);
        for (int i = 0; i < n; i++) {
            if (aScaled[i] == 0) continue;
            for (int j = 0; j < n; j++) {
                if (s[j] == 0) continue;
                int k = i + j;
                long prod = aScaled[i] * s[j] % m.t;
                if (k < n) phaseScaled[k] = Math.floorMod(phaseScaled[k] - prod, m.t);
                else phaseScaled[k - n] = Math.floorMod(phaseScaled[k - n] + prod, m.t);
            }
        }
        boolean ok2 = true;
        for (int i = 0; i < n; i++) if (phaseScaled[i] != want[i]) ok2 = false;
        failed += report("乘 P(X) 后相位 == e(X)·P(X)（列选择成立）", ok2, "");
        System.out.print("        e·P 前 5 = ");
        for (int i = 0; i < 5; i++) System.out.print(phaseScaled[i] + " ");
        System.out.println("   （期望 = P 右移 c*=2 位）");

        System.out.println();
        System.out.println(failed == 0
            ? "=== LWE 域列选择数学成立（关键是 a、b 都要铺成多项式）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** ⟨a·X^k, s⟩（用于造 b 的系数） */
    private static long dotOfShift(long[] a, int[] s, int k, long mod) {
        long sum = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] == 0) continue;
            int j = (i - k + s.length) % s.length;
            sum = (sum + a[i] * s[j]) % mod;
        }
        return sum;
    }

    /** 负循环环乘法 mod t */
    private static long[] ringMul(long[] f, long[] g, long mod) {
        int n = f.length;
        long[] h = new long[n];
        for (int i = 0; i < n; i++) {
            if (f[i] == 0) continue;
            for (int j = 0; j < n; j++) {
                if (g[j] == 0) continue;
                int k = i + j;
                long prod = f[i] * g[j] % mod;
                if (k < n) h[k] = Math.floorMod(h[k] + prod, mod);
                else h[k - n] = Math.floorMod(h[k - n] - prod, mod);
            }
        }
        return h;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
