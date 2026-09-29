package cape.tiny;

import java.util.Random;

/**
 * SampleExtract 自检（规范第 7 行）。
 *
 * <p>它是一个<b>代数恒等式</b>，所以可以直接对拍：
 * <pre>
 *   SampleExtract_0(ct) 的相位  ==  ct 相位的常数项
 * </pre>
 * 左边 = {@code b − ⟨a, s_L⟩}，右边 = {@code phase(ct)[0]}（当作 Z_q 上的数）。
 * 两者必须逐比特相同 —— 这就同时验证了下标方向和负号。
 */
public final class SampleExtractSelfTest {

    private static int failed = 0;

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(555);
        TinyKey key = TinyKey.random(p, p.n, rnd);

        System.out.println("=== SampleExtract 自检 ===");
        System.out.println("[params] " + p);
        System.out.println("[s_L] " + Poly.show(key.sL));
        System.out.println();

        System.out.println("--- 1. 恒等式：LWE 相位 == RLWE 相位的常数项 ---");
        boolean ok = true;
        StringBuilder bad = new StringBuilder();
        for (int trial = 0; trial < 10; trial++) {
            int[] m = new int[p.n];
            for (int i = 0; i < p.n; i++) m[i] = rnd.nextInt(2);
            RLWECipher ct = key.encryptRLWE(m, rnd);
            LWECipher lwe = key.sampleExtract0(ct);

            int[] ph = key.phase(ct);
            int constTerm = ph[0];                       // Z_q 上
            // a、b 本身就在 Z_q 域（SampleExtract 不改变模数），所以直接用，
            // 不能再乘 Δ —— 它们已经是 q 尺度的数。
            long dot = 0;
            for (int i = 0; i < lwe.a.length; i++) dot += (long) lwe.a[i] * key.sL[i];
            long lhs = Math.floorMod((long) lwe.b - dot, p.q);

            if (lhs != constTerm) {
                ok = false;
                if (bad.length() < 120) {
                    bad.append("trial").append(trial).append(" lhs=").append(lhs)
                       .append(" rhs=").append(constTerm).append("; ");
                }
            }
        }
        check("10 组：⟨a,s_L⟩ 关系成立", ok, bad.toString());
        System.out.println();

        System.out.println("--- 2. 提取出的正是那个明文系数 ---");
        int[] P = {3, 1, 4, 1, 5, 9, 2, 6};
        RLWECipher ct2 = key.encryptRLWE(P, rnd);
        LWECipher lwe2 = key.sampleExtract0(ct2);
        int got = key.decryptLWEValue(lwe2);
        System.out.println("  明文多项式 = " + Poly.show(P));
        System.out.println("  提取出的常数项 = " + got + "（期望 " + P[0] + "）");
        check("SampleExtract_0 取到常数项", got == P[0], "got=" + got);
        System.out.println();
        System.out.println("  说明：本参数 t=17 下 P 的元素必须 ≤ maxPlaintext()=" + p.maxPlaintext()
            + " 才能被正确还原。");

        System.out.println();
        System.out.println(failed == 0 ? "=== SampleExtract 全过 ===" : "=== " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 把 t 域的值还原回 q 域的尺度（Δ 倍） */
    private static int scaleUp(int v, TinyParams p) {
        return (int) ((long) v * p.delta % p.q);
    }

    private static void check(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
    }
}
