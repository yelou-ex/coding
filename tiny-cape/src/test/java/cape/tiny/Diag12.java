package cape.tiny;

import java.util.Random;

/** 列出 c1·s_R 的常数项【全部】贡献项，看漏了哪一类。 */
public final class Diag12 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(555);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;
        System.out.println("s = " + Poly.show(key.sL));

        int[] m = new int[n];
        for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
        RLWECipher ct = key.encryptRLWE(m, rnd);
        System.out.println("c1 = " + Poly.show(ct.c1));
        System.out.println();

        System.out.println("所有 i+j ≡ 0 (mod n) 的项（i+j=0 或 i+j=n 且后者取负）：");
        long total = 0;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                int k = i + j;
                if (k == 0) {
                    long v = (long) ct.c1[i] * key.sR[j];
                    total += v;
                    System.out.printf("  i=%d j=%d  c1[%d]·s[%d] = %d·%d = +%d%n",
                        i, j, i, j, ct.c1[i], key.sR[j], v);
                } else if (k == n) {
                    long v = (long) ct.c1[i] * key.sR[j];
                    total -= v;
                    System.out.printf("  i=%d j=%d  c1[%d]·s[%d] = %d·%d = -%d%n",
                        i, j, i, j, ct.c1[i], key.sR[j], v);
                }
            }
        }
        System.out.println("  合计 = " + Math.floorMod(total, p.q));
        System.out.println("  实际 (c1·s_R)[0] = " + Poly.mul(ct.c1, key.sR, p.q)[0]);
        System.out.println();

        System.out.println("按【s 的下标 j】归并：");
        for (int j = 0; j < n; j++) {
            int iA = Math.floorMod(-j, n);          // i + j = 0 mod n，i = -j mod n
            long vA = iA == 0 ? (long) ct.c1[0] * key.sR[j] : 0;
            // i + j = n → i = n - j
            int iB = n - j;
            long contrib = 0;
            String desc;
            if (j == 0) {
                contrib = (long) ct.c1[0] * key.sR[0];
                desc = "c1[0]·s[0]  (+)" ;
            } else {
                // i + j = n → i = n-j，取负
                contrib = -(long) ct.c1[n - j] * key.sR[j];
                desc = "-c1[" + (n - j) + "]·s[" + j + "]";
            }
            System.out.printf("  s[%d]=%d → %s = %d%n", j, key.sR[j], desc, Math.floorMod(contrib, p.q));
        }
    }
}
