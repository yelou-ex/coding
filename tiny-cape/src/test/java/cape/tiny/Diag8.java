package cape.tiny;

import java.util.Random;

/** 把 c1·s_R 的常数项用三种方式算出来，逐项对照。 */
public final class Diag8 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(31337);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("s_L = " + Poly.show(key.sL));
        System.out.println("s_R = " + Poly.show(key.sR));
        System.out.println();

        int[] m = new int[n];
        for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);

        RLWECipher ct = key.encryptRLWE(m, rnd);
        System.out.println("m   = " + Poly.show(m));
        System.out.println("c0  = " + Poly.show(ct.c0));
        System.out.println("c1  = " + Poly.show(ct.c1));
        System.out.println();

        // ---- 方式 A：Poly.mul（可信）----
        int[] c1s = Poly.mul(ct.c1, key.sR, p.q);
        int A = c1s[0];

        // ---- 方式 B：按 derived 规则 Σ（用 s_L 下标）----
        long B = ct.c1[0] * key.sL[0];
        for (int j = 1; j < n; j++) {
            B -= (long) ct.c1[n - j] * key.sL[j];
        }
        B = Math.floorMod(B, p.q);

        // ---- 方式 C：逐项展开，把 Poly.mul 的贡献列出来 ----
        System.out.println("--- Poly.mul(c1, s_R) 逐项贡献（i + j ≥ n 时进 acc[i+j−n] 且取负）---");
        long manual = 0;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                if (ct.c1[i] == 0 || key.sR[j] == 0) continue;
                int k = i + j;
                long prod = (long) ct.c1[i] * key.sR[j];
                if (k == 0) {
                    manual += prod;
                    System.out.printf("  c1[%d]·s[%d] → X^0  +%d%n", i, j, prod);
                } else if (k == n) {
                    manual -= prod;
                    System.out.printf("  c1[%d]·s[%d] → X^%d=−1  −%d%n", i, j, k, prod);
                }
            }
        }
        manual = Math.floorMod(manual, p.q);

        System.out.println();
        System.out.println("方式 A（Poly.mul 常数项）      = " + A);
        System.out.println("方式 B（Σ ±c1·s_L，derived）   = " + B);
        System.out.println("方式 C（逐项手算）             = " + manual);
        System.out.println();
        System.out.println("phase[0] = " + key.phase(ct)[0] + "   (应 = Δ·m[0] + A)");
        System.out.printf("  Δ·m[0] = %d, Δ·m[0]+A = %d%n",
            m[0] * p.delta, Math.floorMod((long) m[0] * p.delta + A, p.q));
        System.out.println();
        System.out.println("SampleExtract 的 b = c0[0] = " + ct.c0[0]);
        System.out.println("  b − B = " + Math.floorMod((long) ct.c0[0] - B, p.q));
        System.out.println("  期望  = " + Math.floorMod((long) ct.c0[0] + A, p.q) + "  (= phase[0])");
        System.out.println();
        System.out.println("→ 差异 = " + Math.floorMod((B - A), p.q) + "  (B − A mod q)");
        System.out.println("  c1[0]·s[0] = " + ct.c1[0] * key.sL[0]);
        System.out.println("  s_R[0]     = " + key.sR[0] + ",  s_L[0] = " + key.sL[0]);
    }
}
