package cape.tiny;

import java.util.Random;

/** 用 SampleExtractSelfTest 的同一个密钥做诊断。 */
public final class Diag11 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(555);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("s_L = " + Poly.show(key.sL));
        System.out.println("s_R = " + Poly.show(key.sR));
        System.out.println("s_L==s_R ? " + java.util.Arrays.equals(key.sL, key.sR));
        System.out.println();

        for (int trial = 0; trial < 3; trial++) {
            int[] m = new int[n];
            for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
            RLWECipher ct = key.encryptRLWE(m, rnd);
            LWECipher lwe = key.sampleExtract0(ct);

            int[] ph = key.phase(ct);
            long dot = 0;
            for (int i = 0; i < lwe.a.length; i++) dot += (long) lwe.a[i] * key.sL[i];
            long lhs = Math.floorMod((long) lwe.b - dot, p.q);

            System.out.printf("试验 %d: lhs=%d phase[0]=%d  %s%n",
                trial, lhs, ph[0], lhs == ph[0] ? "✓" : "✗");
            if (lhs != ph[0]) {
                System.out.println("  c0 = " + Poly.show(ct.c0));
                System.out.println("  c1 = " + Poly.show(ct.c1));
                System.out.println("  a  = " + Poly.show(lwe.a) + "  b=" + lwe.b);
                int[] c1s = Poly.mul(ct.c1, key.sR, p.q);
                System.out.println("  (c1·s_R)[0] = " + c1s[0] + ", c0[0]=" + ct.c0[0]
                    + ", 和 = " + Math.floorMod(ct.c0[0] + c1s[0], p.q));
                System.out.println("  dot = " + dot);
                System.out.println("  逐项对照 a[j] vs c1[n-j]:");
                for (int j = 0; j < n; j++) {
                    int k = j == 0 ? 0 : n - j;
                    System.out.printf("    a[%d]=%d c1[%d]=%d %s%n", j, lwe.a[j], k, ct.c1[k],
                        lwe.a[j] == ct.c1[k] ? "✓" : "✗");
                }
                break;
            }
        }
    }
}
