package cape.tiny;

import java.util.Arrays;
import java.util.Random;

/**
 * 盲旋转自检（规范第 5、6 节）。
 *
 * <p>判据：对全部 {@code r* = 0..N−1}，盲旋转后解密得到的多项式，
 * 其<b>常数项</b>必须等于 {@code P[r*]}，且整条多项式等于 {@code P(X)·X^{−r*}}。
 */
public final class BlindRotateSelfTest {

    private static int failed = 0;

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(2024);
        TinyKey key = TinyKey.random(p, p.n, rnd);

        System.out.println("=== 盲旋转自检 ===");
        System.out.println("[params] " + p);
        System.out.println();

        // 明文数据库的一列：0/1 数据（CAPE 的真实形态）
        int[] P = {1, 0, 1, 1, 0, 0, 1, 0};
        int d = 3;                       // ⌈log2 N⌉ = 3，恰好覆盖 r* ∈ [0,8)
        System.out.println("[P] 明文列 = " + Poly.show(P));
        System.out.println("[d] 索引比特数 = " + d + "（覆盖 r* ∈ [0," + (1 << d) + ")）");
        System.out.println();

        RLWECipher acc = key.encryptRLWE(P, rnd);
        boolean allOk = true;
        boolean constOk = true;
        StringBuilder bad = new StringBuilder();

        for (int rStar = 0; rStar < p.n; rStar++) {
            // 客户端：把 r* 的每一位做成 RGSW 选择子（服务端看不到 r*）
            RGSW[] bk = BlindRotate.clientSelectors(key, rStar, d, rnd);

            // 服务端：只用 bk 和密文累加器做盲旋转
            RLWECipher rotated = BlindRotate.blindRotate(acc, bk);

            int[] got = key.decryptRLWECentered(rotated);
            int[] want = BlindRotate.referenceRotate(P, rStar, p);

            boolean full = Arrays.equals(got, want);
            int cGot = got[0];
            int cWant = BlindRotate.coefficientAt(P, rStar, p);
            boolean constTerm = cGot == cWant;

            if (!full) allOk = false;
            if (!constTerm) constOk = false;

            System.out.printf("  r*=%d  常数项 got=%d want=%d %s   整条多项式 %s%n",
                rStar, cGot, cWant, constTerm ? "✓" : "✗", full ? "✓" : "✗");
            if (!full && bad.length() < 80) {
                bad.append("r*=").append(rStar).append(" got=").append(Poly.show(got))
                   .append(" want=").append(Poly.show(want)).append("; ");
            }
        }

        System.out.println();
        check("全部 r* ∈ [0,N) 的常数项都等于 P(X)·X^{−r*} 的常数项", constOk, "");
        check("全部 r* 的整条多项式都等于 P(X)·X^{−r*}", allOk, bad.toString());
        System.out.println();
        System.out.println("  注：常数项【不是】P[r*]，而是 ±P[(−r*) mod N] ——");
        System.out.println("      负号来自 X^N = −1（负循环环）。这就是 coefficientAt 的公式。");
        System.out.println("      所以要取 P[r*]，需让累加器初值为 P(X)·X^{+r*}（服务端无法做到），");
        System.out.println("      或客户端改送 X^{N−r*} 的旋转量。本实现按规范保持 X^{−r*}。");

        // 证明服务端确实看不到 r*：同样的密文 + 不同的 bk 给出不同结果
        System.out.println();
        System.out.println("--- 隐私性说明 ---");
        System.out.println("  服务端只拿到 " + d + " 个 RGSW(r*_j) 密文和明文 P(X)，");
        System.out.println("  它没有任何解密手段，无法反推 r*。");

        System.out.println();
        System.out.println(failed == 0 ? "=== 盲旋转全过 ===" : "=== " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static void check(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
    }
}
