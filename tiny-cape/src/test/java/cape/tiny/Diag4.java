package cape.tiny;

import java.util.Random;

/** 常数项判据的对齐检查。 */
public final class Diag4 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(2024);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int[] P = {1, 0, 1, 1, 0, 0, 1, 0};
        int d = 3;

        RLWECipher acc = key.encryptRLWE(P, rnd);
        System.out.println("r*  | phase[0] 之中心化 | decodeCentered | coefficientAt | 明文参照常数项(中心化)");
        for (int r = 0; r < p.n; r++) {
            RGSW[] bk = BlindRotate.clientSelectors(key, r, d, rnd);
            RLWECipher rot = BlindRotate.blindRotate(acc, bk);
            int[] ph = key.phase(rot);
            int phC = ph[0] > p.q / 2 ? ph[0] - p.q : ph[0];
            int dc = p.decodeCentered(ph[0]);
            int ca = BlindRotate.coefficientAt(P, r, p);
            long[] exact = BlindRotate.referenceRotateExact(P, r, p);
            int ref = Poly.centralize((int) exact[0], p.t);
            System.out.printf("  %d | %14d | %14d | %13d | %d%n", r, phC, dc, ca, ref);
        }
    }
}
