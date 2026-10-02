package com.fusepir.rgsw;

import java.nio.file.Paths;

/**
 * <b>表构造的纯 Java 几何回归测试。</b>不碰任何加密，跑得很快，失败即非零退出。
 *
 * <p>存在的理由是一段真实事故：{@code CapeDemoData} 里曾把「尾部补零」的判据写成
 * {@code cc*r + rr >= L_BFF}，用**多项式列号**去比**槽位下标**（两者量纲不同），
 * 于是第 8 列起被整列清零；症状在加密侧只表现为一句
 * {@code native SEAL: result ciphertext is transparent}，完全看不出是哪一步错的。
 * 那次排查花掉的时间，就是这几条断言的价值。
 *
 * <p>所以这里把「数据半径」和「每个关键词能否按查询的方式取回载荷」钉死：
 * <ol>
 *   <li>三路 share 求和 == payload（逐系数、逐关键词）；</li>
 *   <li>数据半径之外严格全零、半径之内没有整 cell 为空；</li>
 *   <li>模拟查询：对每个关键词按 {@code (colIdx, rowIdx)} 取回载荷并比对；</li>
 *   <li>同列关键词的行区间互不重叠（否则掩码会把别人的 share 卷进来）。</li>
 * </ol>
 *
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeTableDiag [db] [N]}
 * —— 全部通过时以 0 退出，任一失败抛异常并以非零退出。
 */
public final class CapeTableDiag {

    private static final int R = 16;
    private static final int K = 3;

    private static int failures = 0;

    private static void check(boolean ok, String what, Object... args) {
        String msg = args.length == 0 ? what : String.format(what, args);
        if (ok) {
            System.out.println("  PASS  " + msg);
        } else {
            System.out.println("  FAIL  " + msg);
            failures++;
        }
    }

    public static void main(String[] args) throws Exception {
        String dbPath = args.length > 0 ? args[0] : "cape-demo/db/keywords.json";
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 8192;

        CapeDemoData db = CapeDemoData.load(Paths.get(dbPath));
        long t = db.longMeta("plainModulus", 65537L);
        int maxValues = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = Math.max(1, R / maxValues);
        int c = Math.max(1, (kwTotal + cellsPerCol - 1) / cellsPerCol);

        System.out.println("=== CAPE table geometry check ===");
        System.out.printf("  N=%d maxValues=%d kwTotal=%d cellsPerCol=%d C=%d t=%d%n",
            n, maxValues, kwTotal, cellsPerCol, c, t);

        CapeDemoData.Tables tb = db.buildTables(n, c, R, K, t, 20261013L);
        int lBff = cellsPerCol * c;
        int dataRadius = (cellsPerCol - 1) * maxValues + K;
        System.out.printf("  tb: c=%d r=%d k=%d bPay=%d lBf=%d  L_BFF=cellsPerCol*C=%d"
            + "  dataRadius=%d%n", tb.c, tb.r, tb.k, tb.bPay, tb.lBf, lBff, dataRadius);

        // ---- 1. payload 自身必须处处非 0（0 指纹会被误判成"未命中"） ----
        System.out.println("\n[1] payload 健全性");
        int zeroFp = 0;
        for (int i = 0; i < kwTotal; i++) {
            if (tb.payload[i][0] == 0) {
                zeroFp++;
            }
        }
        check(zeroFp == 0, "payload[i][0] 非零（0 个 0 值，实得 %d）", zeroFp);

        // ---- 2. 三路 share 求和 == payload ----
        //     这是 BFF 的定义（Reconstruct 的 Σ d_j ≡ y），也是整个方案的正确性根基。
        System.out.println("\n[2] BFF 三路 share 求和");
        int shareBad = 0;
        String firstBad = "";
        for (int i = 0; i < kwTotal; i++) {
            for (int b = 0; b < tb.bPay; b++) {
                long s = 0;
                for (int a = 0; a < K; a++) {
                    s = (s + tb.p[tb.colOf[i]][b][tb.rowOf[i] + a]) % t;
                }
                if (s != tb.payload[i][b]) {
                    if (firstBad.isEmpty()) {
                        firstBad = "（首个失配 kw=" + db.keywords.get(i) + " col=" + tb.colOf[i]
                            + " row=" + tb.rowOf[i] + " b=" + b + "）";
                    }
                    shareBad++;
                }
            }
        }
        check(shareBad == 0, "失配系数 = %d / %d %s", shareBad, kwTotal * tb.bPay, firstBad);

        // ---- 3. 数据半径 ----
        //     半径 = 被行掩码寻址到的最大系数下标 + 1。半径算错就是那次整列清零事故。
        System.out.println("\n[3] 数据半径");
        check(dataRadius == (cellsPerCol - 1) * maxValues + K,
            "dataRadius = (cellsPerCol-1)*maxValues + k = %d", dataRadius);
        int beyond = 0;
        for (int cc = 0; cc < tb.c; cc++) {
            for (int rr = dataRadius; rr < n; rr++) {
                for (int b = 0; b < tb.bPay; b++) {
                    if (tb.p[cc][b][rr] != 0) {
                        beyond++;
                    }
                }
            }
        }
        check(beyond == 0, "半径之外的非零系数 = %d（应为 0）", beyond);

        int emptyCell = 0;
        for (int cc = 0; cc < tb.c; cc++) {
            for (int cell = 0; cell < cellsPerCol; cell++) {
                long acc = 0;
                for (int a = 0; a < maxValues; a++) {
                    acc |= tb.p[cc][0][cell * maxValues + a];
                }
                if (acc == 0) {
                    emptyCell++;
                }
            }
        }
        check(emptyCell == 0, "半径内整 cell 为空（bit0 全 0）的 cell 数 = %d（应为 0）",
            emptyCell);

        // ---- 4. 模拟查询：按 (colIdx,rowIdx) 取回每个关键词的载荷 ----
        //     完全照老路径的读法：列 = u/cellsPerCol，行 = (u%cellsPerCol)*maxValues + a。
        System.out.println("\n[4] 模拟查询（逐个关键词）");
        int retrieveBad = 0;
        for (int i = 0; i < kwTotal; i++) {
            int cc = tb.colOf[i];
            int ro = tb.rowOf[i];
            boolean ok = true;
            for (int b = 0; b < tb.bPay; b++) {
                long s = 0;
                for (int a = 0; a < K; a++) {
                    s = (s + tb.p[cc][b][ro + a]) % t;
                }
                if (s != tb.payload[i][b]) {
                    ok = false;
                }
            }
            if (!ok) {
                retrieveBad++;
            }
        }
        check(retrieveBad == 0, "取回失配的关键词数 = %d / %d", retrieveBad, kwTotal);

        // 论文里的那组已知用例，单独点名，方便对着报告看。
        for (String kw : new String[]{"Adam Sandler", "family"}) {
            Integer idx = tb.kwIndex.get(kw);
            if (idx == null) {
                check(false, "关键词 %s 不在库里", kw);
                continue;
            }
            int cc = tb.colOf[idx];
            int ro = tb.rowOf[idx];
            long[] got = new long[tb.bPay];
            for (int b = 0; b < tb.bPay; b++) {
                long s = 0;
                for (int a = 0; a < K; a++) {
                    s = (s + tb.p[cc][b][ro + a]) % t;
                }
                got[b] = s;
            }
            check(java.util.Arrays.equals(got, tb.payload[idx]),
                "%-16s idx=%-4d col=%-3d row=%-3d 取回 == payload", kw, idx, cc, ro);
        }

        // ---- 5. 同列行区间互不重叠 ----
        System.out.println("\n[5] 同列行区间不重叠");
        int overlap = 0;
        for (int i = 0; i < kwTotal; i++) {
            for (int j = i + 1; j < kwTotal; j++) {
                if (tb.colOf[i] != tb.colOf[j]) {
                    continue;
                }
                boolean ov = !(tb.rowOf[i] + K <= tb.rowOf[j]
                    || tb.rowOf[j] + K <= tb.rowOf[i]);
                if (ov) {
                    overlap++;
                }
            }
        }
        check(overlap == 0, "重叠对数 = %d（应为 0）", overlap);

        // ---- 6. 槽位表约束 ----
        System.out.println("\n[6] 槽位表约束");
        check(lBff > kwTotal, "L_BFF = %d > kwCount = %d（BFF 需要空槽）", lBff, kwTotal);
        check(tb.r <= n, "R = %d ≤ N = %d（P_{c,b} 的次数必须 < N）", tb.r, n);

        System.out.println();
        if (failures == 0) {
            System.out.println("=== ALL CHECKS PASSED ===");
        } else {
            System.out.printf("=== %d CHECK(S) FAILED ===%n", failures);
            throw new IllegalStateException(failures + " table geometry check(s) failed");
        }
    }
}
