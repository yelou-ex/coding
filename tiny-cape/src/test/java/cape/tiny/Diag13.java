package cape.tiny;

import java.util.Random;

/** 插桩：打印 Poly.mul 落到常数项(索引 0)的每一次累加。 */
public final class Diag13 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(555);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;
        System.out.println("s_R = " + Poly.show(key.sR));

        int[] m = new int[n];
        for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
        RLWECipher ct = key.encryptRLWE(m, rnd);
        int[] f = ct.c1, g = key.sR;
        System.out.println("f = c1 = " + Poly.show(f));
        System.out.println("g = sR = " + Poly.show(g));
        System.out.println();

        // 手工复刻 Poly.mul 的累加，并打印所有落到索引 0 的项
        long[] acc = new long[n];
        System.out.println("落到 acc[0] 的项：");
        for (int i = 0; i < n; i++) {
            if (f[i] == 0) continue;
            for (int j = 0; j < n; j++) {
                if (g[j] == 0) continue;
                int k = i + j;
                long prod = (long) f[i] * g[j];
                if (k < n) {
                    if (k == 0) System.out.printf("  +f[%d]·g[%d] = +%d%n", i, j, prod);
                    acc[k] += prod;
                } else {
                    if (k - n == 0) System.out.printf("  -f[%d]·g[%d] = -%d%n", i, j, prod);
                    acc[k - n] -= prod;
                }
            }
        }
        System.out.println("  acc[0] 原始和 = " + acc[0]);
        System.out.println("  acc[0] mod 97 = " + Math.floorMod(acc[0], p.q));
        System.out.println("  Poly.mul(f,g)[0] = " + Poly.mul(f, g, p.q)[0]);
        System.out.println();

        // 逐项按公式算
        long formula = (long) f[0] * g[0];
        for (int k = 1; k < n; k++) formula -= (long) f[k] * g[n - k];
        System.out.println("公式 c1[0]·s[0] − Σ c1[k]·s[n−k] = " + formula
            + "  mod 97 = " + Math.floorMod(formula, p.q));
    }
}
