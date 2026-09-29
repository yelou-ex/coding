package cape.tiny;

import java.util.Random;

/** 打印全部关键数字，找出 phase = Δ·m 恒等式为何不成立。 */
public final class Diag9 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(31337);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("s_L      = " + Poly.show(key.sL));
        System.out.println("s_R      = " + Poly.show(key.sR));
        System.out.println("key.sR == key.sL ? " + java.util.Arrays.equals(key.sR, key.sL));
        System.out.println();

        int[] m = new int[n];
        for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
        System.out.println("m        = " + Poly.show(m));

        RLWECipher ct = key.encryptRLWE(m, rnd);
        System.out.println("c0       = " + Poly.show(ct.c0));
        System.out.println("c1       = " + Poly.show(ct.c1));
        System.out.println();

        int[] as = Poly.mul(ct.c1, key.sR, p.q);
        int[] scaled = new int[n];
        for (int i = 0; i < n; i++) scaled[i] = m[i] * p.delta % p.q;

        System.out.println("c1·s_R   = " + Poly.show(as));
        System.out.println("Δ·m      = " + Poly.show(scaled));
        System.out.println("c0 + c1·s_R = " + Poly.show(Poly.add(ct.c0, as, p.q)));
        System.out.println("phase()  = " + Poly.show(key.phase(ct)));
        System.out.println();

        // 逐系数核对恒等式
        int[] sum = Poly.add(ct.c0, as, p.q);
        boolean ident = java.util.Arrays.equals(sum, scaled);
        System.out.println("恒等式 c0 + c1·s_R == Δ·m ? " + ident);
        if (!ident) {
            System.out.println("  逐系数差异：");
            for (int i = 0; i < n; i++) {
                if (sum[i] != scaled[i]) {
                    System.out.printf("    [%d] c0+c1s=%d  Δm=%d  差=%d%n",
                        i, sum[i], scaled[i], Math.floorMod(sum[i] - scaled[i], p.q));
                }
            }
        }
        System.out.println();

        // 直接验算 c0[0] + (c1·s_R)[0]
        System.out.println("c0[0]        = " + ct.c0[0]);
        System.out.println("(c1·s_R)[0]  = " + as[0]);
        System.out.println("和           = " + Math.floorMod(ct.c0[0] + as[0], p.q));
        System.out.println("Δ·m[0]       = " + scaled[0]);
        System.out.println();

        // 手工用下标公式重算 (c1·s_R)[0]
        long manual = (long) ct.c1[0] * key.sR[0];
        for (int j = 1; j < n; j++) manual -= (long) ct.c1[n - j] * key.sR[j];
        System.out.println("手工下标公式 (c1·s_R)[0] = " + Math.floorMod(manual, p.q));
        System.out.println();
        System.out.println("各 s[j]=1 的项：");
        for (int j = 0; j < n; j++) {
            if (key.sR[j] != 0) {
                int k = j == 0 ? 0 : n - j;
                System.out.printf("  s[%d]=%d  ↔  c1[%d]=%d%n", j, key.sR[j], k, ct.c1[k]);
            }
        }
    }
}
