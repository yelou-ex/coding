package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import java.util.Random;

/** 最小实测：盲旋转要取到 payload[r]，β 该用 +r 还是 −r？ */
public final class BlindRotateSignProbe {

    public static void main(String[] args) {
        int n = 2048, d = 32;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        Random rnd = new Random(7);

        long[] payload = new long[n];
        for (int i = 0; i < 8; i++) payload[i] = 100 + i;      // payload[r] = 100+r

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        System.out.println("payload[0..7] = 100 101 102 103 104 105 106 107");
        System.out.println();
        System.out.println("     r     β=sum+r 时常数位    β=sum−r 时常数位    a[i]乘旋转后 β=sum−r");
        for (int r = 0; r < 6; r++) {
            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), 2L * n);
                sum = (sum + a[i] * s[i]) % m.t;
            }
            // 情形 1：β = sum + r，用既有 blindRotate
            long b1 = Math.floorMod(sum + r, m.t);
            long g1 = Math.floorMod(m.decrypt(BlindRotateOps.blindRotate(m, bk, m.encrypt(payload), a, b1))[0], m.t);
            // 情形 2：β = sum − r，用既有 blindRotate
            long b2 = Math.floorMod(sum - r, m.t);
            long g2 = Math.floorMod(m.decrypt(BlindRotateOps.blindRotate(m, bk, m.encrypt(payload), a, b2))[0], m.t);
            // 情形 3：β = sum − r，但 a[i] 那轮改成乘 X^{−a[i]}
            long g3;
            {
                Ciphertext cur = m.encrypt(payload);
                for (int i = 0; i < d; i++) {
                    if (Math.floorMod(a[i], 2L * n) == 0) continue;
                    Ciphertext rot = m.multiplyPowerOfX(cur, -a[i]);
                    cur = m.cmux(bk[i], cur, rot);
                }
                cur = m.multiplyPowerOfX(cur, Math.floorMod(r, m.t));
                g3 = Math.floorMod(m.decrypt(cur)[0], m.t);
            }
            System.out.printf("    %d     %-20d %-20d %d%n", r, g1, g2, g3);
        }
    }
}
