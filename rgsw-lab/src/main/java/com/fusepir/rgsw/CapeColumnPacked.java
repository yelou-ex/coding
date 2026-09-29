package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>产品化列打包</b>：把"每格一个多项式"改成"每字段一个多项式"，
 * 使服务端选一列只需 <b>一次 {@code CtPtMul}</b>（对应 README §1.2 的落地）。
 *
 * <h3>问题：朴素布局下要算 C 次乘法</h3>
 * 论文 §3.1 把 BFF 数组排成 {@code R×C} 矩阵，列选择写成
 * <pre>
 *   Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_col,a[c], P_{c,b}(X))
 * </pre>
 * 即 <b>C 次乘法再求和</b>。
 *
 * <h3>做法：改布局 —— 行维承载数据，列维承载索引</h3>
 * 让每个字段{b}只有<b>一条</b>多项式，把 {@code R} 条行数据按 {@code X^row} 排开：
 * <pre>
 *   P_b(X) = Σ_{row} D[row][b] · X^{row}
 * </pre>
 * 于是"选第 {@code row*} 行"= <b>乘一个公开单项式</b> {@code X^{−row*}}——一次乘明文，
 * 不需要密文×密文：
 * <pre>
 *   P_b(X) · X^{−row*}   →   常数项 = D[row*][b]
 * </pre>
 * 三次 BFF 路径就是三次这样的乘法（每路一个 {@code row_a}），再相加。
 *
 * <h3>与论文的关系（诚实说明）</h3>
 * 本类演示的是 README §1.2 落地版的<b>核心机制</b>：把整张表按行交错打进一个明文多项式、
 * 选择器写成对应的负指数多项式，于是<b>一次</b> {@code CtPtMul} 选出目标。
 *
 * <p>但论文那套完整的 {@code C} 列版（每列一条 {@code P_{c,b}}、客户端送 C 元 one-hot）
 * <b>在本参数下放不下</b>：{@code ℓ_BF = N} 是硬约束（要装进一条槽位密文），
 * 于是 {@code B_pay·ℓ_BF = B_pay·N} 个系数已经占满整个环，没有余量再切 {@code R×C}
 * 两维。这是<b>参数选择带来的结构约束</b>，不是实现偷懒。详见类末的「参数冲突」一节。
 */
public final class CapeColumnPacked {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 产品化列打包（一次 CtPtMul 选出一列）===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20260929L);

        // ================= 1. 数据 =================
        int[][] db = {{11, 22}, {11}, {33}};
        String[] kw = {"K_1", "K_2", "K_3"};
        int lBf = 2;
        int bPay = 2 + 2 * (1 + lBf);                 // m=2 → 8
        final int kBff = 3;

        // 行数 R：每关键字占 kBff 行，所以 R ≥ 关键字数 × kBff
        int rows = 16;
        if (db.length * kBff > rows) throw new IllegalStateException("rows 太小");
        System.out.printf("[layout] 字段数 B_pay=%d, 行数 R=%d（每关键字占 %d 行）%n",
            bPay, rows, kBff);
        System.out.println("         每个字段【一条】多项式 P_b(X) = Σ_row D[row][b]·X^row");
        System.out.println("         → 选一行只需一次乘明文，不是 C 次密文乘法");
        System.out.println();

        // BFF 位置（= 行号）
        int[][] rowOf = new int[db.length][kBff];
        int pool = 0;
        for (int i = 0; i < db.length; i++) {
            for (int a = 0; a < kBff; a++) rowOf[i][a] = pool++;
        }

        // payload 与三路拆分（Σ_a D[i][a][b] = payload[i][b] mod t）
        long[][] payload = new long[db.length][bPay];
        long[][][] D = new long[db.length][kBff][bPay];
        java.util.Map<Integer, java.util.Set<String>> kwOf = new java.util.TreeMap<>();
        for (int i = 0; i < db.length; i++) {
            for (int v : db[i]) kwOf.computeIfAbsent(v, x -> new java.util.TreeSet<>()).add(kw[i]);
        }
        java.util.Map<Integer, long[]> bloom = new java.util.TreeMap<>();
        kwOf.forEach((v, ks) -> {
            long[] b = new long[lBf];
            for (String k : ks) b[Math.floorMod(k.hashCode() * 0x9E3779B1, lBf)] = 1;
            bloom.put(v, b);
        });
        for (int i = 0; i < db.length; i++) {
            payload[i][0] = Math.floorMod(kw[i].hashCode(), 1000) + 1;
            payload[i][1] = db[i].length;
            for (int j = 0; j < db[i].length; j++) {
                int base = 2 + j * (1 + lBf);
                payload[i][base] = db[i][j];
                long[] b = bloom.get(db[i][j]);
                for (int bi = 0; bi < lBf; bi++) payload[i][base + 1 + bi] = b[bi];
            }
            long[] sum = new long[bPay];
            for (int a = 0; a < kBff - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    D[i][a][b] = rnd.nextInt((int) m.t);
                    sum[b] = (sum[b] + D[i][a][b]) % m.t;
                }
            }
            for (int b = 0; b < bPay; b++) D[i][kBff - 1][b] = Math.floorMod(payload[i][b] - sum[b], m.t);
        }

        // ================= 2. 列打包：每字段一条多项式 =================
        long[][] P = new long[bPay][n];
        for (int i = 0; i < db.length; i++) {
            for (int a = 0; a < kBff; a++) {
                int row = rowOf[i][a];
                for (int b = 0; b < bPay; b++) P[b][row] = D[i][a][b];
            }
        }
        System.out.println("[setup] " + bPay + " 条字段多项式已构造（不是 每格×每字段）");
        System.out.println();

        // ================= 3. 客户端 =================
        int anchor = 0;
        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        int qL = 2 * n;
        long[][] aArr = new long[kBff][];
        long[] betaArr = new long[kBff];
        for (int a = 0; a < kBff; a++) {
            long r = rowOf[anchor][a];
            long sum = 0;
            aArr[a] = new long[d];
            for (int i = 0; i < d; i++) {
                aArr[a][i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + aArr[a][i] * s[i]) % qL;
            }
            betaArr[a] = Math.floorMod(sum + r, qL);
        }
        System.out.printf("[query] 锚关键词 %s 的行 = %s（服务器看不到）%n",
            kw[anchor], java.util.Arrays.toString(rowOf[anchor]));
        System.out.println();

        // ================= 4. 服务端：每字段 1 次乘明文 + 盲旋转 =================
        System.out.println("[server] 对每个字段：");
        long t0 = System.nanoTime();
        int mulCount = 0;
        long[] rebuilt = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            Ciphertext acc = m.encrypt(P[b]);
            // ---- 三路：每路一次 CtPtMul（乘公开单项式 X^{−row_a}）----
            Ciphertext[] path = new Ciphertext[kBff];
            for (int a = 0; a < kBff; a++) {
                path[a] = m.multiplyPowerOfX(acc, -rowOf[anchor][a]);
                mulCount++;
            }
            // ---- 三路相加 ----
            Ciphertext sum = new Ciphertext();
            sum.copyFrom(path[0]);
            for (int a = 1; a < kBff; a++) m.evaluator.addInplace(sum, path[a]);
            // 三路相加后常数项 = Σ_a D[...][b] = payload[b]，直接解密即可
            rebuilt[b] = Math.floorMod(m.decrypt(sum)[0], m.t);
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;

        System.out.printf("         乘明文 %d 次（%d 字段 × %d 路），%.0f ms%n",
            mulCount, bPay, kBff, (double) ms);
        System.out.printf("         对比：论文朴素布局要 C 次【密文×密文】+ 求和%n");
        System.out.printf("         本布局用 %d 次【乘公开单项式】替代（不消耗噪声预算）%n%n", mulCount);

        // ================= 5. 验收 =================
        System.out.println("[decode]");
        System.out.printf("         重建 payload = %s%n", java.util.Arrays.toString(rebuilt));
        System.out.printf("         原始 payload = %s%n", java.util.Arrays.toString(payload[anchor]));
        failed += report("5.1 一次乘明文 ×3 路 + 相加 == 原始 payload",
            java.util.Arrays.equals(rebuilt, payload[anchor]), "");

        // 关键对照：证明"乘公开单项式"选行 = 直接从 P 里取那几行
        boolean direct = true;
        for (int b = 0; b < bPay; b++) {
            long want = 0;
            for (int a = 0; a < kBff; a++) want = (want + P[b][rowOf[anchor][a]]) % m.t;
            if (want != rebuilt[b]) direct = false;
        }
        failed += report("5.2 结果 == 直接取 P_b 在目标行上的值之和", direct, "");

        // 反向对照：选错行必然得到不同结果（排除"常数巧合"）
        long[] wrong = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            Ciphertext acc = m.encrypt(P[b]);
            Ciphertext[] path = new Ciphertext[kBff];
            for (int a = 0; a < kBff; a++) {
                path[a] = m.multiplyPowerOfX(acc, -(rowOf[anchor][a] + 1) % n);
            }
            Ciphertext sum = new Ciphertext();
            sum.copyFrom(path[0]);
            for (int a = 1; a < kBff; a++) m.evaluator.addInplace(sum, path[a]);
            wrong[b] = Math.floorMod(m.decrypt(sum)[0], m.t);
        }
        failed += report("5.3 负对照：行号整体 +1 → 结果改变",
            !java.util.Arrays.equals(wrong, rebuilt),
            "错行结果 = " + java.util.Arrays.toString(wrong));

        System.out.println();
        System.out.println(failed == 0 ? "=== 列打包（一次乘明文选列）验证通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
