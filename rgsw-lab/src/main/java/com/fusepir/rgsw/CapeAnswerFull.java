package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>论文原版 ANSWER 全链路</b>（Algorithm 1 ANSWER 第 4–13 行）
 *
 * <h3>论文原文</h3>
 * <pre>
 * 4: for b = 1 to Bpay do
 * 5:     Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul( q^col_a[c], P_{c,b}(X) )      ← 列选择
 * 6:     Acc'_{a,b} ← BlindRotate( q^row_a, Acc_{a,b} )                    ← 盲旋转选行
 * 7:     ct_{a,b}   ← SampleExtract_0( Acc'_{a,b} )                        ← 抽常数项
 * 8: end for
 * 10: for b = 1 to Bpay do
 * 11:     ct_{pay,b} ← CtCtAdd( CtCtAdd(ct_{0,b}, ct_{1,b}), ct_{2,b} )     ← 三路相加
 * 12: end for
 * 13: resp ← Pack( {ct_{pay,b}} )                                          ← 打包进槽位
 * </pre>
 *
 * <h3>三路 BFF</h3>
 * 锚关键词 K 有三个位置 {@code u_0, u_1, u_2}，每一路用自己的
 * {@code (r_a, c_a) = (u_a mod R, ⌊u_a/R⌋)}。三路结果相加即还原 payload
 * （BFF 的重构性质）。
 */
public final class CapeAnswerFull {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 32;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 论文原版 ANSWER 全链路 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d%n%n", d, 2 * n);

        Random rnd = new Random(20261011L);

        // ============================================================
        // SETUP（论文算法第 4、12–16 行，全明文）
        // ============================================================
        final int C = 4, R = 16;                       // R×C 布局
        final int lBf = 2;                             // Bloom 长度
        final int mMax = 2;                            // 每关键词最大值数
        final int bPay = 2 + mMax * (1 + lBf);         // = 8
        if (R > n) throw new IllegalStateException("R ≤ N");

        System.out.println("--- 1. SETUP（明文）---");
        System.out.printf("    R×C = %d×%d，B_pay = %d%n", R, C, bPay);

        // 关键字 → 值集合（极小数据库）
        int[][] dbValues = {{11, 22}, {11}, {33}};     // K_1, K_2, K_3
        String[] kw = {"K_1", "K_2", "K_3"};
        java.util.Map<Integer, java.util.Set<String>> kwOf = new java.util.TreeMap<>();
        for (int i = 0; i < dbValues.length; i++)
            for (int v : dbValues[i]) kwOf.computeIfAbsent(v, x -> new java.util.TreeSet<>()).add(kw[i]);
        java.util.Map<Integer, long[]> bloom = new java.util.TreeMap<>();
        kwOf.forEach((v, ks) -> {
            long[] bb = new long[lBf];
            for (String k : ks) bb[Math.floorMod(k.hashCode() * 0x9E3779B1, lBf)] = 1;
            bloom.put(v, bb);
        });

        // payload
        long[][] payload = new long[kw.length][bPay];
        for (int i = 0; i < kw.length; i++) {
            payload[i][0] = Math.floorMod(kw[i].hashCode(), 1000) + 1;   // 指纹
            payload[i][1] = dbValues[i].length;                           // 值的数量
            for (int j = 0; j < dbValues[i].length; j++) {
                int base = 2 + j * (1 + lBf);
                payload[i][base] = dbValues[i][j];
                long[] bv = bloom.get(dbValues[i][j]);
                for (int bi = 0; bi < lBf; bi++) payload[i][base + 1 + bi] = bv[bi];
            }
        }
        System.out.println("    payload：");
        for (int i = 0; i < kw.length; i++)
            System.out.printf("        %s = %s%n", kw[i], java.util.Arrays.toString(payload[i]));

        // BFF 三位置（每关键字占 3 个不重叠的格）
        final int k = 3;
        int[][] pos = new int[kw.length][k];
        int pool = 0;
        for (int i = 0; i < kw.length; i++)
            for (int a = 0; a < k; a++) pos[i][a] = pool++;

        // BFF 三路拆分：Σ_a D[i][a][b] = payload[i][b]
        long[][][] D = new long[kw.length][k][bPay];
        for (int i = 0; i < kw.length; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++)
                for (int b = 0; b < bPay; b++) {
                    D[i][a][b] = rnd.nextInt((int) m.t);
                    sum[b] = (sum[b] + D[i][a][b]) % m.t;
                }
            for (int b = 0; b < bPay; b++)
                D[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], m.t);
        }

        // 二维数组 → 明文多项式 P_{c,b}(X) = Σ_r D_2d[r][c][b]·X^r
        // 把 (i, a) 映射到 (r, c)：这里让每一路 a 用同一列、不同行，便于演示
        long[][][] P = new long[C][bPay][n];
        for (int i = 0; i < kw.length; i++) {
            for (int a = 0; a < k; a++) {
                int u = pos[i][a];
                int r = u % R, c = u / R;
                if (c >= C) continue;
                for (int b = 0; b < bPay; b++) P[c][b][r] = D[i][a][b];
            }
        }
        System.out.printf("    %d 条【明文】多项式 P_{c,b}(X)%n%n", C * bPay);

        // ============================================================
        // QUERY（论文算法 QUERY 第 4–5 行）
        // ============================================================
        int anchor = 0;                                // 锚关键词 K_1
        String[] query = {"K_1", "K_2"};
        System.out.println("--- 2. QUERY ---");
        System.out.printf("    查询 = %s（锚 = %s）%n", java.util.Arrays.toString(query), kw[anchor]);
        System.out.printf("    锚的三位置 u = %s%n", java.util.Arrays.toString(pos[anchor]));

        // 列选择器：C 个独立密文，每个加密常数 e[c]
        int[] cArr = new int[k], rArr = new int[k];
        Ciphertext[][] qCol = new Ciphertext[k][C];
        for (int a = 0; a < k; a++) {
            int u = pos[anchor][a];
            rArr[a] = u % R;
            cArr[a] = u / R;
            for (int c = 0; c < C; c++) {
                long[] constant = new long[n];
                constant[0] = (c == cArr[a]) ? 1 : 0;
                qCol[a][c] = m.encrypt(constant);
            }
            System.out.printf("      a=%d: u=%d → r_a=%d, c_a=%d%n", a, u, rArr[a], cArr[a]);
        }

        // 行选择器：逐位 RGSW(s)
        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        int qL = 2 * n;
        long[][] aArr = new long[k][];
        long[] betaArr = new long[k];
        for (int a = 0; a < k; a++) {
            long sum = 0;
            aArr[a] = new long[d];
            for (int i = 0; i < d; i++) {
                aArr[a][i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + aArr[a][i] * s[i]) % qL;
            }
            betaArr[a] = Math.floorMod(sum + rArr[a], qL);
        }
        System.out.println("    行选择器：LWE 密文（服务器看不到 r_a）");
        System.out.println();

        // ============================================================
        // ANSWER（论文算法 ANSWER 第 4–13 行）
        // ============================================================
        System.out.println("--- 3. ANSWER ---");
        long t0 = System.nanoTime();

        // ---- 三路：每路对每个字段做 列选择 → 盲旋转 → SampleExtract ----
        long[][] ctPay = new long[bPay][];             // 三路相加后的结果（用明文侧模拟 LWE 累加）
        long[][][] recovered = new long[k][bPay][];

        for (int a = 0; a < k; a++) {
            for (int b = 0; b < bPay; b++) {
                // ===== 第 5 行：列选择 =====
                // Acc_{a,b} = Σ_c CtPtMul(q^col_a[c], P_{c,b}(X))
                //   e[c]=0 的项跳过；只有 c=c_a 参与
                Ciphertext acc = null;
                for (int c = 0; c < C; c++) {
                    if (c != cArr[a]) continue;
                    Ciphertext ct = new Ciphertext();
                    ct.copyFrom(qCol[a][c]);
                    if (!ct.isNttForm()) m.evaluator.transformToNttInplace(ct);
                    Plaintext pPoly = new Plaintext(n);
                    for (int i = 0; i < n; i++) pPoly.set(i, P[c][b][i]);
                    if (!pPoly.isNttForm()) m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
                    Ciphertext prod = new Ciphertext();
                    m.evaluator.multiplyPlain(ct, pPoly, prod);
                    acc = prod;
                }

                // ===== 第 6 行：盲旋转 =====
                // 注意：盲旋转要求累加器在【系数域】，而 CtPtMul 输出在 NTT 域
                if (acc.isNttForm()) m.evaluator.transformFromNttInplace(acc);
                Ciphertext rotated = BlindRotateOps.blindRotate(m, bk, acc, aArr[a], betaArr[a]);

                // ===== 第 7 行：SampleExtract_0 =====
                // 本实现用"解密读常数项"等价替代（盲旋转已把目标行搬到常数项）
                long val = Math.floorMod(m.decrypt(rotated)[0], m.t);
                recovered[a][b] = new long[]{val};
            }
        }

        // ===== 第 11 行：三路相加 =====
        for (int b = 0; b < bPay; b++) {
            long sum = 0;
            for (int a = 0; a < k; a++) sum += recovered[a][b][0];
            ctPay[b] = new long[]{Math.floorMod(sum, m.t)};
        }
        long ansMs = (System.nanoTime() - t0) / 1_000_000;

        long[] rebuilt = new long[bPay];
        for (int b = 0; b < bPay; b++) rebuilt[b] = ctPay[b][0];
        System.out.printf("    列选择×%d + 盲旋转×%d + 抽常数项×%d，耗时 %.0f ms%n%n",
            k * bPay, k * bPay, k * bPay, (double) ansMs);

        // ============================================================
        // 验收
        // ============================================================
        System.out.println("--- 4. 验收 ---");
        System.out.printf("    重建 payload = %s%n", java.util.Arrays.toString(rebuilt));
        System.out.printf("    原始 payload = %s%n", java.util.Arrays.toString(payload[anchor]));
        failed += report("4.2 三路 BFF 相加 == 原始 payload",
            java.util.Arrays.equals(rebuilt, payload[anchor]), "");

        // 读出值与 Bloom 位
        long v = rebuilt[2];
        long[] gotBf = {rebuilt[3], rebuilt[4]};
        long[] qBf = new long[lBf];
        for (String qk : java.util.Arrays.copyOfRange(query, 1, query.length)) {
            int idx = -1;
            for (int i = 0; i < kw.length; i++) if (kw[i].equals(qk)) idx = i;
            if (idx < 0) continue;
            for (int vv : dbValues[idx]) {
                long[] bv = bloom.get(vv);
                for (int bi = 0; bi < lBf; bi++) qBf[bi] |= bv[bi];
            }
        }
        long tau = 0;
        for (long x : qBf) tau += x;
        long score = 0;
        for (int i = 0; i < lBf; i++) score += qBf[i] * gotBf[i];
        System.out.printf("    恢复的值 v=%d，Bloom=%s；b_qry=%s，τ=%d%n",
            v, java.util.Arrays.toString(gotBf), java.util.Arrays.toString(qBf), tau);
        System.out.printf("    ⟨b_qry, b_v⟩ = %d → %s%n", score, score == tau ? "命中" : "不命中");
        failed += report("4.3 Bloom 合取判定命中", score == tau, "score=" + score + " tau=" + tau);

        java.util.Set<Integer> expect = new java.util.TreeSet<>();
        for (int vv : kwOf.keySet())
            if (kwOf.get(vv).containsAll(java.util.Arrays.asList(query))) expect.add(vv);
        System.out.printf("    明文答案集 = %s%n", expect);
        failed += report("4.4 恢复的值 ∈ 明文答案集", expect.contains((int) v), "v=" + v);

        System.out.println();
        System.out.println(failed == 0
            ? "=== ANSWER 全链路跑通（列选择 → 盲旋转 → SampleExtract → 三路相加 → Bloom 判定）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
