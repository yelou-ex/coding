package cape.tiny;

import java.util.Random;

/** 用直接卷积核对 SampleExtract 的下标与符号。 */
public final class Diag5 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(555);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        System.out.println("s_R = " + Poly.show(key.sR));
        System.out.println();

        RLWECipher ct = key.encryptRLWE(new int[]{1, 0, 0, 0, 0, 0, 0, 0}, rnd);
        int n = p.n;

        // 直接卷积：phase = c0 + c1·s_R，用 Poly.mul（这是可信的，已单独验证）
        int[] phase = key.phase(ct);
        System.out.println("phase (经 Poly.mul) = " + Poly.show(phase));

        // 手算常数项，逐项列出
        System.out.println();
        System.out.println("展开 c1·s_R 的常数项：");
        System.out.println("  c1[0]·s_R[0] = " + ct.c1[0] + "·" + key.sR[0]
            + " = " + (long) ct.c1[0] * key.sR[0] % p.q);
        long manual = (long) ct.c1[0] * key.sR[0] % p.q;
        for (int k = 1; k < n; k++) {
            // X^k · X^{j} 贡献常数项当 k+j = n（得到 X^n = -1）
            int j = n - k;
            long term = -(long) ct.c1[k] * key.sR[j];
            System.out.println("  c1[" + k + "]·s_R[" + j + "] 带负号 = -" + ct.c1[k] + "·" + key.sR[j]
                + " = " + Math.floorMod(term, p.q));
            manual = Math.floorMod(manual + term, p.q);
        }
        System.out.println("  手算常数项 = " + manual);
        System.out.println("  卷积常数项 = " + phase[0]);
        System.out.println("  c0[0] = " + ct.c0[0]);
        System.out.println("  手算 + c0[0] = " + Math.floorMod(manual + ct.c0[0], p.q));
        System.out.println();

        System.out.println("SampleExtract 给出的 a、b：");
        LWECipher lwe = key.sampleExtract0(ct);
        System.out.println("  a = " + Poly.show(lwe.a));
        System.out.println("  b = " + lwe.b + "   (c0[0] = " + ct.c0[0] + ")");
        System.out.println();

        System.out.println("逐项对照 a[j] 与 -c1[n-j]：");
        System.out.println("  a[0]=" + lwe.a[0] + "  c1[0]=" + ct.c1[0]);
        for (int j = 1; j < n; j++) {
            int expect = Math.floorMod(-(long) ct.c1[n - j], p.q);
            System.out.println("  a[" + j + "]=" + lwe.a[j] + "  期望 -c1[" + (n - j) + "]=" + expect
                + (lwe.a[j] == expect ? "  ✓" : "  ✗"));
        }
    }
}
