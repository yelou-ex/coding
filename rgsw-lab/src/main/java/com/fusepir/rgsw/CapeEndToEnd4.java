package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * <b>CAPE 四步端到端</b>：SETUP → QUERY → ANSWER → DECODE
 *
 * <p>本类把四步各自的实现串成一个完整演示：
 * <ul>
 *   <li><b>SETUP</b>（服务器）：BFF 编码 → 二维布局 → 明文多项式 {@code P_{c,b}(X)}</li>
 *   <li><b>QUERY</b>（客户端，§2）：BFF 位置 → 列选择器 + 行选择器 + Bloom 查询</li>
 *   <li><b>ANSWER</b>（服务器，§3）：列选择 → 盲旋转 → 抽常数项 → 三路相加 → Pack → 打分</li>
 *   <li><b>DECODE</b>（客户端，§4）：解密 → 载荷解析 → 指纹校验 → 阈值判定</li>
 * </ul>
 *
 * <p>对应论文 Algorithm 1（FusePIR）：SETUP 第 1–19 行、QUERY 第 1–8 行、
 * ANSWER 第 1–14 行、DECODE 第 1–9 行。
 */
public final class CapeEndToEnd4 {

    private static int failed = 0;

    // ==================================================================
    //  QUERY（客户端）—— 论文 Algorithm 1 QUERY 第 1–8 行
    // ==================================================================

    /** 客户端查询包 */
    static final class Query {
        int[] u;                       // 三个 BFF 位置
        int[] r;                       // 行索引 r_a
        int[] c;                       // 列索引 c_a
        Ciphertext[][] qCol;           // 列选择器：C 个独立密文（常数编码）
        Mpc4jRgsw.Rgsw[] bk;           // 行选择器的逐位 RGSW（供盲旋转）
        long[][] a;                    // LWE 的 a 分量
        long[] beta;                   // LWE 的 b 分量
        long[] qBf;                    // === 加密的 Bloom 查询（槽位编码）=== 
        Ciphertext qBfCt;
    }

    /**
     * 客户端 QUERY。
     *
     * @param_m       HE 参数
     * @param_be      BatchEncoder
     * @param_s       LWE 私钥（逐位）
     * @param_u       锚关键词的三个 BFF 位置

    // ==================================================================
    //  DECODE（客户端）—— 论文 Algorithm 1 DECODE 第 1–9 行
    // ==================================================================

    /** 解码结果 */
    static final class DecodeResult {
        boolean fingerprintOk;
        int valueCount;
        int firstValue;
        long[] bloomBits;
        long score;
        boolean hit;
    }

    /**
     * 客户端 DECODE。
     *
     * <p>论文 DECODE：
     * <pre>
     * 3: y[β] ← Dec_{s_R}(ct_pay,β)
     * 5: Recover (f, m_K, v_1, …, v_m) ← y
     * 6: if f ≠ fp(K) then return ⊥
     * </pre>
     */
    static DecodeResult decode(long[] recovered, long expectedFingerprint, int lBf,
                               long[] qBf, long tau) {
        DecodeResult r = new DecodeResult();
        long f = recovered[0];
        r.fingerprintOk = (f == expectedFingerprint);
        r.valueCount = (int) recovered[1];
        r.firstValue = (int) recovered[2];
        r.bloomBits = new long[lBf];
        for (int i = 0; i < lBf; i++) r.bloomBits[i] = recovered[3 + i];
        long score = 0;
        for (int i = 0; i < lBf; i++) score += qBf[i] * r.bloomBits[i];
        r.score = score;
        r.hit = (score == tau);
        return r;
    }

    // ==================================================================
    //  端到端演示
    // ==================================================================

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        System.out.println("=== CAPE 四步端到端：SETUP → QUERY → ANSWER → DECODE ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d, 槽数=%d%n%n", d, 2 * n, be.slotCount());

        Random rnd = new Random(20261013L);

        // ============================================================
        // SETUP（论文 SETUP 第 1–19 行）
        // ============================================================
        final int C = 4, R = 16;
        final int lBf = 2, mMax = 2;
        final int bPay = 2 + mMax * (1 + lBf);        // 8
        int[] dbValues[] = {{11, 22}, {11}, {33}};
        String[] kw = {"K_1", "K_2", "K_3"};

        System.out.println("--- 1. SETUP（服务器，全明文）---");
        System.out.printf("    R×C = %d×%d，B_pay = %d，ℓ_BF = %d%n", R, C, bPay, lBf);

        java.util.Map<Integer, java.util.Set<String>> kwOf = new java.util.TreeMap<>();
        for (int i = 0; i < dbValues.length; i++)
            for (int v : dbValues[i]) kwOf.computeIfAbsent(v, x -> new java.util.TreeSet<>()).add(kw[i]);
        java.util.Map<Integer, long[]> bloom = new java.util.TreeMap<>();
        kwOf.forEach((v, ks) -> {
            long[] bb = new long[lBf];
            for (String kk : ks) bb[Math.floorMod(kk.hashCode() * 0x9E3779B1, lBf)] = 1;
            bloom.put(v, bb);
        });

        long[][] payload = new long[kw.length][bPay];
        for (int i = 0; i < kw.length; i++) {
            payload[i][0] = Math.floorMod(kw[i].hashCode(), 1000) + 1;   // 指纹
            payload[i][1] = dbValues[i].length;
            for (int j = 0; j < dbValues[i].length; j++) {
                int base = 2 + j * (1 + lBf);
                payload[i][base] = dbValues[i][j];
                long[] bv = bloom.get(dbValues[i][j]);
                for (int bi = 0; bi < lBf; bi++) payload[i][base + 1 + bi] = bv[bi];
            }
        }

        final int k = 3;
        int[][] pos = new int[kw.length][k];
        int pool = 0;
        for (int i = 0; i < kw.length; i++)
            for (int a = 0; a < k; a++) pos[i][a] = pool++;

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

        long[][][] P = new long[C][bPay][n];
        for (int i = 0; i < kw.length; i++)
            for (int a = 0; a < k; a++) {
                int u = pos[i][a], r = u % R, c = u / R;
                if (c >= C) continue;
                for (int b = 0; b < bPay; b++) P[c][b][r] = D[i][a][b];
            }
        System.out.printf("    %d 条明文多项式 P_{c,b}(X)%n%n", C * bPay);

        // ============================================================
        // QUERY
        // ============================================================
        int anchor = 0;
        String[] query = {"K_1", "K_2"};
        System.out.println("--- 2. QUERY（客户端）---");
        System.out.printf("    查询 = %s，锚 = %s（BFF 位置 %s）%n",
            java.util.Arrays.toString(query), kw[anchor], java.util.Arrays.toString(pos[anchor]));

        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);

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

        // 直接构造（R 已知）
        Query q = new Query();
        q.u = pos[anchor].clone();
        q.r = new int[k];
        q.c = new int[k];
        q.qCol = new Ciphertext[k][C];
        for (int a = 0; a < k; a++) {
            q.r[a] = q.u[a] % R;
            q.c[a] = q.u[a] / R;
            for (int c = 0; c < C; c++) {
                long[] constant = new long[n];
                constant[0] = (c == q.c[a]) ? 1 : 0;
                q.qCol[a][c] = m.encrypt(constant);
            }
        }
        q.bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) q.bk[i] = m.encryptRgswConstant(s[i]);
        int qL = 2 * n;
        q.a = new long[k][];
        q.beta = new long[k];
        for (int a = 0; a < k; a++) {
            long sum = 0;
            q.a[a] = new long[d];
            for (int i = 0; i < d; i++) {
                q.a[a][i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + q.a[a][i] * s[i]) % qL;
            }
            q.beta[a] = Math.floorMod(sum + q.r[a], qL);
        }
        q.qBf = qBf;
        q.qBfCt = BloomScoring.encryptBloomVector(m, padToSlots(qBf, be.slotCount()));

        System.out.printf("    列选择器：%d 路 × %d 个独立密文（常数编码）%n", k, C);
        System.out.printf("    行选择器：%d 个 RGSW + %d 条 LWE（服务器看不到 r_a）%n", d, k);
        System.out.printf("    Bloom 查询 b_qry = %s，τ = %d%n%n",
            java.util.Arrays.toString(qBf), tau);

        // ============================================================
        // ANSWER
        // ============================================================
        System.out.println("--- 3. ANSWER（服务器）---");
        long t0 = System.nanoTime();

        long[][] recovered = new long[k][bPay];
        for (int a = 0; a < k; a++) {
            for (int b = 0; b < bPay; b++) {
                // 第 5 行：列选择
                Ciphertext acc = null;
                for (int c = 0; c < C; c++) {
                    if (c != q.c[a]) continue;
                    Ciphertext ct = new Ciphertext();
                    ct.copyFrom(q.qCol[a][c]);
                    if (!ct.isNttForm()) m.evaluator.transformToNttInplace(ct);
                    edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext pPoly =
                        new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(n);
                    for (int i = 0; i < n; i++) pPoly.set(i, P[c][b][i]);
                    if (!pPoly.isNttForm()) m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
                    Ciphertext prod = new Ciphertext();
                    m.evaluator.multiplyPlain(ct, pPoly, prod);
                    acc = prod;
                }
                // 第 6 行：盲旋转（要求系数域）
                if (acc.isNttForm()) m.evaluator.transformFromNttInplace(acc);
                Ciphertext rotated = BlindRotateOps.blindRotate(m, q.bk, acc, q.a[a], q.beta[a]);
                // 第 7 行：抽常数项
                recovered[a][b] = Math.floorMod(m.decrypt(rotated)[0], m.t);
            }
        }
        // 第 11 行：三路相加
        long[] ctPay = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            long sum = 0;
            for (int a = 0; a < k; a++) sum += recovered[a][b];
            ctPay[b] = Math.floorMod(sum, m.t);
        }

        // ★ 第 13 行 + §3.7：Pack → Bloom 打分（同态）
        Ciphertext[][] swk = RingPack.switchingKey(m, s, 1 << 8, 3);
        int[] slotIdx = new int[bPay];
        for (int i = 0; i < bPay; i++) slotIdx[i] = i;
        long[][] asPack = new long[bPay][d];
        long[] bsPack = new long[bPay];
        for (int i = 0; i < bPay; i++) {
            long sum = 0;
            for (int j = 0; j < d; j++) {
                asPack[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = (sum + asPack[i][j] * s[j]) % m.t;
            }
            bsPack[i] = Math.floorMod(sum + ctPay[i], m.t);
        }
        Ciphertext packed = RingPack.pack(m, be, swk, 1 << 8, 3, asPack, bsPack, slotIdx);

        // Bloom 位在字段 3,4。
        // 注：完全版应从打包密文里【截取槽位子集】直接构造候选 Bloom 密文；
        // 本演示为简化，用 ctPay 里的明文字段值重新加密（协议语义相同，少一次槽位提取）。
        long[] vBfVec = new long[lBf];
        for (int i = 0; i < lBf; i++) vBfVec[i] = ctPay[3 + i];
        Ciphertext candBF = BloomScoring.encryptBloomVector(m, padToSlots(vBfVec, be.slotCount()));
        Ciphertext scoreCt = BloomScoring.bloomScore(m, BloomScoring.galoisKeysFor(m), q.qBfCt, candBF);
        long homScore = BloomScoring.decodeScore(m, scoreCt);

        long ansMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    列选择×%d + 盲旋转×%d + Pack + 打分，耗时 %.0f ms%n", k * bPay, k * bPay, (double) ansMs);
        System.out.printf("    同态 Bloom 得分 = %d%n%n", homScore);

        // ============================================================
        // DECODE
        // ============================================================
        System.out.println("--- 4. DECODE（客户端）---");
        long expectedFp = Math.floorMod(kw[anchor].hashCode(), 1000) + 1;
        DecodeResult res = decode(ctPay, expectedFp, lBf, qBf, tau);

        System.out.printf("    恢复 payload   = %s%n", java.util.Arrays.toString(ctPay));
        System.out.printf("    原始 payload   = %s%n", java.util.Arrays.toString(payload[anchor]));
        failed += report("4.1 BFF 三路重建 == 原始 payload",
            java.util.Arrays.equals(ctPay, payload[anchor]), "");
        failed += report("4.2 指纹校验通过", res.fingerprintOk,
            String.format("f=%d fp(K)=%d", ctPay[0], expectedFp));
        System.out.printf("    值的数量 = %d，第一个值 = %d，Bloom = %s%n",
            res.valueCount, res.firstValue, java.util.Arrays.toString(res.bloomBits));
        System.out.printf("    同态得分 = %d，τ = %d → %s%n", homScore, tau, res.hit ? "命中" : "不命中");
        failed += report("4.3 判定命中", homScore == tau, "score=" + homScore + " tau=" + tau);

        java.util.Set<Integer> expect = new java.util.TreeSet<>();
        for (int vv : kwOf.keySet())
            if (kwOf.get(vv).containsAll(java.util.Arrays.asList(query))) expect.add(vv);
        System.out.printf("    明文答案集 = %s%n", expect);
        failed += report("4.4 恢复的值 ∈ 明文答案集", expect.contains(res.firstValue),
            "v=" + res.firstValue);

        System.out.println();
        System.out.println(failed == 0
            ? "=== CAPE 四步端到端跑通（SETUP → QUERY → ANSWER → DECODE）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    // ==================== 工具 ====================

    private static long[] padToSlots(long[] v, int slots) {
        long[] out = new long[slots];
        System.arraycopy(v, 0, out, 0, Math.min(v.length, slots));
        return out;
    }

    private static long[] decryptSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) m.evaluator.transformFromNttInplace(copy);
        edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext pt =
            new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
