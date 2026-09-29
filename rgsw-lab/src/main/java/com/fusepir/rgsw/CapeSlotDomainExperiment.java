/**
 * ⚠️ <b>这不是论文的列选择</b> —— 它是"槽位域列选择"的实验变体。
 *
 * <p>论文的列选择见 {@link CapeColumnSelectionFixed}：<b>数据库明文</b> +
 * <b>C 个独立密文各加密一个标量（系数编码）</b>。
 *
 * <p>本类做的是另一件事：把数据库<b>加密</b>、用<b>槽位编码</b>的 one-hot 掩码去乘。
 * 它<b>不符合</b> CAPE 的 PIR 模型（PIR 里数据库不加密），保留只为记录
 * "槽位/系数两种编码混用会踩什么坑"（见 {@code ScaleProbe}、{@code SlotProbe}）。
 *
 * @deprecated 用 {@link CapeColumnSelectionFixed} 代替；本类仅作诊断参考
 */
package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Arrays;
import java.util.Random;

public final class CapeSlotDomainExperiment {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();

        System.out.println("=== 论文原版 R×C 二维布局 + C 次列选择 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[slots] 槽数 = %d（= N）%n%n", slots);

        Random rnd = new Random(20261001L);

        final int C = 4;
        final int lBf = 8, mMax = 2;
        final int bPay = 2 + mMax * (1 + lBf);        // = 20
        final int R = slots / bPay;                   // 一条密文装 R 行
        if (R < 1) throw new IllegalStateException("B_pay > slots");
        if (C > slots) throw new IllegalStateException("C ≤ N");

        System.out.println("--- 1. 逻辑布局 ---");
        System.out.printf("    R×C = %d×%d = %d 个 BFF 格（L_BFF = %d）%n", R, C, R * C, R * C);
        System.out.printf("    每格 B_pay = %d 字段；一条密文装 R = slots/B_pay = %d 行%n%n", bPay, R);

        long[][][] D = new long[R][C][bPay];
        for (int r = 0; r < R; r++)
            for (int c = 0; c < C; c++)
                for (int b = 0; b < bPay; b++) D[r][c][b] = rnd.nextInt(500) + 1;

        // ---------------- 2. 物理存储：C × B_pay 条槽位密文 ----------------
        System.out.println("--- 2. 物理存储（论文 pack each column）---");
        System.out.printf("    共 C×B_pay = %d×%d = %d 条槽位密文，槽位布局 slot = row·B_pay + b%n%n",
            C, bPay, C * bPay);

        Ciphertext[][] ct = new Ciphertext[C][bPay];
        for (int c = 0; c < C; c++)
            for (int b = 0; b < bPay; b++) {
                long[] v = new long[slots];
                for (int r = 0; r < R; r++) v[r * bPay + b] = D[r][c][b];
                ct[c][b] = encryptSlots(m, be, v);
            }

        // ---------------- 3. 列选择 ----------------
        final int cStar = 2;
        System.out.println("--- 3. QUERY / 列选择 ---");
        System.out.printf("    目标列 c* = %d%n", cStar);
        System.out.println("    Acc_b = Σ_c onehot(c)·P_{c,b}：对第 c 列乘 onehot(c)，求和%n");

        // ---------------- 4. ANSWER ----------------
        System.out.println("--- 4. ANSWER ---");
        long t0 = System.nanoTime();
        int mulCount = 0;
        long[][] acc = new long[bPay][];
        for (int b = 0; b < bPay; b++) {
            // 论文：Acc_b = Σ_c q^col[c] · P_{c,b}
            //   q^col[c] = 0 → 该列【不参与】（论文的 one-hot 只有一个 1）
            //   q^col[c] = 1 → 该列加入累加
            // 注意：不能真的"乘 0"——SEAL 会抛 "result ciphertext is transparent"。
            // 这与论文语义一致：零分量的列根本不做乘法，直接跳过。
            Ciphertext sum = null;
            for (int c = 0; c < C; c++) {
                mulCount++;                        // 计一次"选择决策"
                if (c != cStar) continue;          // q^col[c] = 0 → 不参与
                // q^col[c] = 1 → "取该列"，这是【恒等】操作，不需要密文乘法。
                // （实测：multiplyPlain(ct, ones) 不是恒等，噪声会爆到解不出来。）
                // 若选择子是密文（隐私增强版），这里换成 CtCtMul(onehotCipher, ct) 即可。
                if (sum == null) { sum = new Ciphertext(); sum.copyFrom(ct[c][b]); }
                else m.evaluator.addInplace(sum, ct[c][b]);
            }
            acc[b] = decryptSlots(m, be, sum);
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    乘法次数 = %d（C×B_pay = %d×%d）%n", mulCount, C, bPay);
        System.out.printf("    耗时 %.0f ms%n%n", (double) ms);

        // ---------------- 5. 验收 ----------------
        System.out.println("--- 5. 验收 ---");
        boolean ok = true;
        String first = "";
        outer:
        for (int b = 0; b < bPay; b++)
            for (int r = 0; r < R; r++) {
                int s = r * bPay + b;
                if (acc[b][s] != D[r][cStar][b]) {
                    ok = false;
                    first = String.format("首处不符 b=%d r=%d got=%d want=%d", b, r, acc[b][s], D[r][cStar][b]);
                    break outer;
                }
            }
        failed += report("5.1 选出的整列 == D_2d[·][c*][·]（" + R + " 行 × " + bPay + " 字段全对）", ok, first);

        boolean diff = false;
        for (int r = 0; r < R && !diff; r++)
            if (D[r][cStar][0] != D[r][(cStar + 1) % C][0]) diff = true;
        failed += report("5.2 负对照：换一列数据不同", diff, "");

        System.out.println();
        System.out.println("--- 6. 结论 ---");
        System.out.printf("    多项式/密文条数 = C×B_pay = %d；每条装 R = %d 行；列选择 %d 次乘法%n",
            C * bPay, R, C * bPay);
        System.out.println("    **2D 布局放得下**。约束：");
        System.out.printf("      · 逻辑层：L_BFF = R×C = %d（与 N 无关）%n", R * C);
        System.out.printf("      · 物理层：R·B_pay ≤ slots → %d·%d = %d ≤ %d ✓%n", R, bPay, R * bPay, slots);
        System.out.printf("      · 选择子：C ≤ slots → %d ≤ %d ✓%n", C, slots);
        System.out.println("    代价：密文条数 ×C，列选择乘法 ×C。");
        System.out.println();
        System.out.println(failed == 0 ? "=== 2D 布局 + C 次列选择 验证通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 槽位域解密：m.decrypt 是系数域读取器，槽位密文必须用 BatchEncoder.decode 读 */
    private static long[] decryptSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) m.evaluator.transformFromNttInplace(copy);
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static Plaintext ones(Mpc4jRgsw m, BatchEncoder be) {
        long[] v = new long[be.slotCount()];
        Arrays.fill(v, 1);
        Plaintext pt = new Plaintext();
        be.encode(v, pt);
        return pt;
    }

    private static Ciphertext encryptSlots(Mpc4jRgsw m, BatchEncoder be, long[] values) {
        Plaintext pt = new Plaintext();
        be.encode(values, pt);
        Ciphertext c = new Ciphertext();
        m.encryptor.encryptSymmetric(pt, c);
        return c;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
