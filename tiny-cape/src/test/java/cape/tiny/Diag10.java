package cape.tiny;

import java.util.Random;

/** 修正后再次逐项核对 sampleExtract0。 */
public final class Diag10 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(31337);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("s_L = " + Poly.show(key.sL));

        int[] m = new int[n];
        for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);

        RLWECipher ct = key.encryptRLWE(m, rnd);
        System.out.println("m   = " + Poly.show(m));
        System.out.println("c0  = " + Poly.show(ct.c0));
        System.out.println("c1  = " + Poly.show(ct.c1));

        int[] c1s = Poly.mul(ct.c1, key.sR, p.q);
        int phase0 = key.phase(ct)[0];
        System.out.println("(c1·s_R)[0] = " + c1s[0]);
        System.out.println("phase[0]    = " + phase0);
        System.out.println();

        LWECipher lwe = key.sampleExtract0(ct);
        System.out.println("从 sampleExtract0 得到：");
        System.out.println("  a = " + Poly.show(lwe.a));
        System.out.println("  b = " + lwe.b + "   (c0[0] = " + ct.c0[0] + ")");
        System.out.println("  qL = " + lwe.qL);

        long dot = 0;
        for (int i = 0; i < lwe.a.length; i++) dot += (long) lwe.a[i] * key.sL[i];
        System.out.println("  ⟨a,s_L⟩ = " + dot + "  (= " + Math.floorMod(dot, p.q) + " mod q)");
        System.out.println("  b − ⟨a,s_L⟩ = " + Math.floorMod((long) lwe.b - dot, p.q));
        System.out.println("  期望 phase[0] = " + phase0);
        System.out.println();

        System.out.println("逐项：");
        System.out.print("  a[0]=" + lwe.a[0] + " (应 c1[0]=" + ct.c1[0] + ")");
        System.out.println();
        for (int j = 1; j < n; j++) {
            int k = n - j;
            System.out.printf("  a[%d]=%d  c1[%d]=%d  s[%d]=%d  %s%n",
                j, lwe.a[j], k, ct.c1[k], j, key.sL[j],
                lwe.a[j] == ct.c1[k] ? "✓" : "✗");
        }
    }
}
