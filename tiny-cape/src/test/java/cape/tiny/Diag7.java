package cape.tiny;

import java.util.Random;

/** 用单系数密钥逐项验证 SampleExtract 的实现是否与反推出的规则一致。 */
public final class Diag7 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(31337);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("=== 用真实密钥验证：b - <a,s> 是否 == phase[0] ===");
        System.out.println("s = " + Poly.show(key.sL));
        System.out.println();

        for (int t = 0; t < 6; t++) {
            int[] m = new int[n];
            for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
            RLWECipher ct = key.encryptRLWE(m, rnd);
            LWECipher lwe = key.sampleExtract0(ct);

            int[] ph = key.phase(ct);
            long dot = 0;
            for (int i = 0; i < lwe.a.length; i++) dot += (long) lwe.a[i] * key.sL[i];
            long lhs = Math.floorMod((long) lwe.b - dot, p.q);

            System.out.printf("试验 %d: b=%d, a=%s%n", t, lwe.b, Poly.show(lwe.a));
            System.out.printf("         dot=%d, b-dot=%d, phase[0]=%d  %s%n",
                dot, lhs, ph[0], lhs == ph[0] ? "✓" : "✗");

            if (lhs != ph[0]) {
                // 逐项打开：看每个 s[j]=1 的位置贡献了多少
                System.out.print("         分解: ");
                for (int j = 0; j < n; j++) {
                    if (key.sL[j] == 1) System.out.print("s[" + j + "]·a[" + j + "]=" + lwe.a[j] + "  ");
                }
                System.out.println();
                System.out.println("         期望各项（按反推规则）:");
                System.out.print("           c1[0]=" + ct.c1[0] + "  ");
                for (int j = 1; j < n; j++) {
                    System.out.print("-c1[" + (n - j) + "]=" + Math.floorMod(-(long) ct.c1[n - j], p.q) + "  ");
                }
                System.out.println();
                System.out.println("         c1 = " + Poly.show(ct.c1));
                break;
            }
        }
    }
}
