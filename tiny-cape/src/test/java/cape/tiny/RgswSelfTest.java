package cape.tiny;

import java.util.Arrays;
import java.util.Random;

/**
 * RGSW 层自检：切段 / 外部积 / CMUX（规范第 5、6 节）。
 *
 * <p>这三样是盲旋转的零件，所以必须先独立验证。
 */
public final class RgswSelfTest {

    private static int failed = 0;

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(11);
        TinyKey key = TinyKey.random(p, p.n, rnd);

        System.out.println("=== RGSW / 外部积 / CMUX 自检 ===");
        System.out.println("[params] " + p);
        System.out.println();

        testDecompose(p, key, rnd);
        testExternalProduct(p, key, rnd);
        testCmux(p, key, rnd);

        System.out.println();
        System.out.println(failed == 0 ? "=== RGSW 层全过 ===" : "=== " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 切段可逆 */
    private static void testDecompose(TinyParams p, TinyKey key, Random rnd) {
        System.out.println("--- 1. gadget 切段（平衡位）---");
        boolean ok = true;
        StringBuilder detail = new StringBuilder();
        RGSW dummy = RGSW.encrypt(key, new int[p.n], rnd);
        for (int trial = 0; trial < 20; trial++) {
            int[] f = new int[p.n];
            for (int i = 0; i < p.n; i++) f[i] = rnd.nextInt(p.q);
            int[] dig = dummy.decompose(f);
            long[] back = dummy.recompose(dig);
            for (int i = 0; i < p.n; i++) {
                if (back[i] != Math.floorMod(f[i], p.q)) {
                    ok = false;
                    if (detail.length() < 90) {
                        detail.append("f[").append(i).append("]=").append(f[i])
                              .append(" -> ").append(back[i]).append("; ");
                    }
                }
            }
        }
        check("decompose/recompose 往返（20 组多项式）", ok, detail.toString());
        // 打印一例，便于手工核对
        int[] f = {96, 50, 5, 0, 97 - 1, 1, 2, 3};
        System.out.println("      示例 f        = " + Poly.show(f));
        System.out.println("           segments = " + Poly.show(dummy.decompose(f)));
        System.out.println("           recompose= " + Poly.show(dummy.recompose(dummy.decompose(f))));
        System.out.println();
    }

    /** 外部积：μ=0 → 0；μ=1 → 原密文 */
    private static void testExternalProduct(TinyParams p, TinyKey key, Random rnd) {
        System.out.println("--- 2. 外部积 RGSW(μ) ⊗ RLWE(m) = μ·m ---");
        // 容量约束：Δ·μ·m ≤ q/2 ⇒ μ·m ≤ maxPlaintext() = 9
        int[] m = {1, 2, 0, 1, 2, 1, 0, 1};           // 元素 ≤ 2
        RLWECipher ct = key.encryptRLWE(m, rnd);

        int[] muZero = new int[p.n];
        RLWECipher zero = RGSW.encrypt(key, muZero, rnd).externalProduct(ct);
        int[] gotZero = key.decryptRLWE(zero);
        boolean allZero = true;
        for (int v : gotZero) if (v != 0) allZero = false;
        check("μ=0 → 结果全 0", allZero, Poly.show(gotZero));

        int[] muOne = new int[p.n];
        muOne[0] = 1;
        RLWECipher one = RGSW.encrypt(key, muOne, rnd).externalProduct(ct);
        check("μ=1 → 结果 = 原密文", Arrays.equals(key.decryptRLWE(one), m),
            Poly.show(key.decryptRLWE(one)));

        // μ = 2（常数）：乘任何 ≤ 4 的数据都在容量内
        int[] muConst = new int[p.n];
        muConst[0] = 2;
        int[] mSmall = {1, 0, 2, 0, 1, 0, 0, 0};      // ≤ 2
        RLWECipher ctSmall = key.encryptRLWE(mSmall, rnd);
        RLWECipher prod = RGSW.encrypt(key, muConst, rnd).externalProduct(ctSmall);
        int[] want = Poly.mul(muConst, mSmall, p.t);
        check("μ=2（常数）⊗ m → 2m", Arrays.equals(key.decryptRLWE(prod), want),
            "got=" + Poly.show(key.decryptRLWE(prod)) + " want=" + Poly.show(want));
        System.out.println();
    }

    /** CMUX */
    private static void testCmux(TinyParams p, TinyKey key, Random rnd) {
        System.out.println("--- 3. CMUX（保密二选一）---");
        int[] ma = {1, 1, 0, 0, 0, 0, 0, 0};
        int[] mb = {0, 0, 2, 2, 0, 0, 0, 0};
        RLWECipher a = key.encryptRLWE(ma, rnd);
        RLWECipher b = key.encryptRLWE(mb, rnd);

        int[] c0 = new int[p.n];
        RLWECipher r0 = RGSW.cmux(RGSW.encrypt(key, c0, rnd), a, b);
        check("c=0 → 得 A", Arrays.equals(key.decryptRLWE(r0), ma), Poly.show(key.decryptRLWE(r0)));

        int[] c1 = new int[p.n];
        c1[0] = 1;
        RLWECipher r1 = RGSW.cmux(RGSW.encrypt(key, c1, rnd), a, b);
        check("c=1 → 得 B", Arrays.equals(key.decryptRLWE(r1), mb), Poly.show(key.decryptRLWE(r1)));

        // 槽位域逐槽选择：掩码 0/1 各槽 —— 这正是盲旋转每轮要做的事
        int[] maskSlots = {1, 0, 1, 0, 0, 1, 0, 0};
        int[] maskCoeff = Poly.fromSlots(maskSlots, p.t, p.slotPoints);
        RLWECipher slotMux = RGSW.cmux(RGSW.encrypt(key, maskCoeff, rnd), a, b);
        int[] gotSlots = Poly.toSlots(key.decryptRLWE(slotMux), p.t, p.slotPoints);
        int[] aSlots = Poly.toSlots(ma, p.t, p.slotPoints);
        int[] bSlots = Poly.toSlots(mb, p.t, p.slotPoints);
        int[] wantSlots = new int[p.n];
        for (int i = 0; i < p.n; i++) wantSlots[i] = maskSlots[i] == 1 ? bSlots[i] : aSlots[i];
        check("逐槽位 CMUX（掩码 0/1）", Arrays.equals(gotSlots, wantSlots),
            "got=" + Poly.show(gotSlots) + " want=" + Poly.show(wantSlots));
        System.out.println();
    }

    private static void check(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "  [PASS] " : "  [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
    }
}
