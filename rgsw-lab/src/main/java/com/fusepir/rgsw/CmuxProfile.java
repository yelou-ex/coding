package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

/**
 * <b>把一次 CMUX（= 盲旋转的一轮）拆开量：切段（{@code decompose}）与十次明文乘各占多少。</b>
 *
 * <p>为什么量这个：实测单轮 CMUX = <b>15.6 ms</b>，而 ANSWER 的 <b>98%</b> 都在这上面。
 * 读代码可知每轮 CMUX 由两部分组成（{@code Mpc4jRgsw:409-427}）：
 * <ol>
 *   <li>{@code decompose} ×2 —— 每个都要对 <b>n = 4096 个系数</b>做
 *       {@code crtAt}（<b>BigInteger</b> 的 CRT 重构）+ {@code levels = 5} 次取模；</li>
 *   <li>{@code 2 × levels = 10} 次 {@code multiplyPlainNtt} + 累加。</li>
 * </ol>
 *
 * <p>这个拆分决定一条重要的路线判断：
 * <ul>
 *   <li>若 <b>①（BigInteger 切段）占大头</b> ⇒ 可以用 {@code long} 重写切段拿到数倍提速，
 *       <b>不必先做 native</b>；</li>
 *   <li>若 <b>②（10 次明文乘）占大头</b> ⇒ 纯 Java 侧几乎没有余地，
 *       只能走 native 后端拿 2~3 个数量级。</li>
 * </ul>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CmuxProfile 4096}
 */
public final class CmuxProfile {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int reps = args.length > 1 ? Integer.parseInt(args[1]) : 40;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 单轮 CMUX 拆分 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[plan]   N=%d, 重复 %d 次（取中位数）%n%n", n, reps);

        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 7) + 1;
        }
        Ciphertext src = m.encrypt(msg);
        Mpc4jRgsw.Rgsw rgsw = m.encryptRgswConstant(1);

        long[] other = new long[n];
        for (int i = 0; i < n; i++) {
            other[i] = (i % 5) + 3;
        }
        Ciphertext b = m.encrypt(other);

        // 预热（JIT 对大方法很敏感，本类只量稳态）
        for (int w = 0; w < 6; w++) {
            m.decompose(src, 0);
            m.decompose(src, 1);
            m.externalProduct(rgsw, src);
            m.cmux(rgsw, src, b);
        }

        double[] tD0 = new double[reps];
        double[] tD1 = new double[reps];
        double[] tEP = new double[reps];
        double[] tCmux = new double[reps];
        for (int i = 0; i < reps; i++) {
            long t = System.nanoTime();
            m.decompose(src, 0);
            tD0[i] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            m.decompose(src, 1);
            tD1[i] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            m.externalProduct(rgsw, src);
            tEP[i] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            m.cmux(rgsw, src, b);
            tCmux[i] = (System.nanoTime() - t) / 1e6;
        }

        double d0 = med(tD0);
        double d1 = med(tD1);
        double dec = d0 + d1;
        double ep = med(tEP);
        double cx = med(tCmux);

        System.out.println("    分段（中位数，ms）：");
        System.out.printf("      ① decompose(ct, 0)            : %7.2f%n", d0);
        System.out.printf("      ① decompose(ct, 1)            : %7.2f%n", d1);
        System.out.printf("      ① 切段小计（2 个分量）        : %7.2f   ← %s%n", dec,
            m.fastDecompose ? "纯 long（128 位 Garner + Montgomery）" : "BigInteger CRT（回退路径）");
        System.out.printf("      ② externalProduct 总计         : %7.2f%n", ep);
        System.out.printf("      ② 其中 10 次 multiplyPlainNtt+加: %7.2f   ← = 总计 − 切段%n", ep - dec);
        System.out.printf("      一次完整 cmux（含加减）        : %7.2f%n%n", cx);

        System.out.println("    ⇒ 占比：");
        System.out.printf("      切段 ① 占 externalProduct 的 %.0f%%%n", 100 * dec / ep);
        System.out.printf("      明文乘 ② 占 %.0f%%%n%n", 100 * (ep - dec) / ep);

        System.out.println("    ★ 路线判断：");
        if (dec / ep > 0.4) {
            System.out.println("      ① 仍占大头 ⇒ 切段还没优化干净（应已启用纯 long 快路径，见 DecomposeEquiv）。");
        } else {
            System.out.println("      ② 占压倒性多数 ⇒ 下一步只有两条：");
            System.out.println("        (a) 用 RNS 层（NttTool/RnsIterator）替掉 Evaluator.multiplyPlain 的包装，");
            System.out.println("            见 docs/reports/MPC4J-SEAL可用加速点盘点-2026-09-30.md；");
            System.out.println("        (b) native 后端 —— 唯一能拿量级的路。");
        }
        System.out.printf("%n    参考：base=%d 的平衡位半宽 = %d，明文窗口 ±%d ⇒ base 已顶到窗口上限；%n",
            m.base, m.base / 2, (m.t - 1) / 2);
        System.out.printf("           levels=%d 由 B^levels/2 > q(≈2^%d) 决定。%n", m.levels, m.qBits);

        subProfile(m, n, src, reps);
    }

    /**
     * 把 {@code multiplyPlainNtt} 内部再拆三段：建明文 / fast plain lift + NTT / 点乘。
     *
     * <p>决定 ②（RNS 域替换）值不值得做，以及该替换掉哪一段。
     */
    private static void subProfile(Mpc4jRgsw m, int n, Ciphertext ct, int reps) {
        System.out.println("\n--- ③ multiplyPlainNtt 内部再拆（10 次/轮 CMUX）---");
        long[] digits = new long[n];
        for (int i = 0; i < n; i++) {
            digits[i] = (i % 9) - 4;                 // 小的平衡位，模拟真实 digit
            if (digits[i] < 0) {
                digits[i] += m.t;
            }
        }
        Ciphertext ctNtt = new Ciphertext();
        ctNtt.copyFrom(ct);
        if (!ctNtt.isNttForm()) {
            m.evaluator.transformToNttInplace(ctNtt);
        }
        Ciphertext dst = new Ciphertext();
        edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext pt = new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(n);
        edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext ptNtt =
            new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(n);

        for (int w = 0; w < 8; w++) {                // 预热
            edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext p =
                new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(digits);
            m.evaluator.transformToNttInplace(p, ct.parmsId());
            m.evaluator.multiplyPlain(ctNtt, p, dst);
        }

        double[] tBuild = new double[reps];
        double[] tLift = new double[reps];
        double[] tMul = new double[reps];
        double[] tWhole = new double[reps];
        for (int r = 0; r < reps; r++) {
            long t = System.nanoTime();
            edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext p =
                new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(digits);
            tBuild[r] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            m.evaluator.transformToNttInplace(p, ct.parmsId());
            tLift[r] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            m.evaluator.multiplyPlain(ctNtt, p, dst);
            tMul[r] = (System.nanoTime() - t) / 1e6;

            t = System.nanoTime();
            edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext q =
                new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(digits);
            m.evaluator.transformToNttInplace(q, ct.parmsId());
            m.evaluator.multiplyPlain(ctNtt, q, dst);
            tWhole[r] = (System.nanoTime() - t) / 1e6;
        }
        double build = med(tBuild);
        double lift = med(tLift);
        double mul = med(tMul);
        double whole = med(tWhole);
        System.out.printf("      建 Plaintext(long[])            : %6.3f ms%n", build);
        System.out.printf("      fast plain lift + NTT          : %6.3f ms   ← ② 里最可能的大头%n", lift);
        System.out.printf("      Evaluator.multiplyPlain 本体   : %6.3f ms%n", mul);
        System.out.printf("      ─────────────────────────────────────%n");
        System.out.printf("      合计（一次 multiplyPlainNtt）  : %6.3f ms%n", whole);
        System.out.printf("      ⇒ 每轮 CMUX 10 次 = %6.2f ms（与上面 ② 段对得上）%n",
            whole * 2 * m.levels);
        System.out.println("\n      ★ ② 的目标就是把「fast plain lift + NTT」这一段的包装换掉：");
        System.out.println("        直接用 context.firstContextData().smallNttTables() + NttTool.*LazyRns");
        System.out.println("        + RnsIterator 自己做，省掉 Plaintext 对象与 Evaluator 校验层。");
    }

    private static double med(double[] v) {
        double[] c = v.clone();
        java.util.Arrays.sort(c);
        return c[c.length / 2];
    }
}
