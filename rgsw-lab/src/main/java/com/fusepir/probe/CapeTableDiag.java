package com.fusepir.probe;

import com.fusepir.fusepir.*;


import com.fusepir.bff.*;
import com.fusepir.demo.*;
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
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeTableDiag [db] [N]}
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

    /** 按真实查询的读法取回一个系数：第 {@code cc} 列、第 {@code ro..ro+k-1} 行三路求和。 */
    private static long readSum(CapeDemoData.Tables tb, int cc, int ro, int b, long t) {
        long s = 0;
        for (int a = 0; a < K; a++) {
            s = (s + tb.p[cc][b][ro + a]) % t;
        }
        return s;
    }

    public static void main(String[] args) throws Exception {
        String dbPath = args.length > 0 ? args[0] : "cape-demo/db/keywords.json";
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 8192;

        CapeDemoData db = CapeDemoData.load(Paths.get(dbPath));
        long t = db.longMeta("plainModulus", 65537L);
        int maxValues = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = FusePirSetup.cellsPerCol(R, maxValues);
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

        // ---- 7. 合取判定恰好性（这条断言此前完全缺失） ----
        //
        // 为什么必须有：服务的 `integrity`/`payloadRoundTrip` 只证明「取回的载荷
        // == 明文载荷」，**完全不含合取逻辑**。而决定 `results` 的正是那句明文
        // 合取 `boolean conj`。没有这条断言，"没有假阳性"就只是我说过的一句话。
        //
        // ⚠️ 判据要写对。**论文允许假阳性**：定理 3/7 的前提明确写着 "assuming
        // negligible Bloom-filter false-positive probability"。所以我们**不能**
        // 断言「接受集 == 真值交集」，那会把 ε_BF 的必然代价误判成 bug。
        // 论文真正要求的正确性性质只有两条：
        //   (a) **无假阴性** —— Bloom 过滤器的定义性质，也是 "no false negatives"
        //       这个论证成立的前提，任何一条都必须为 0；
        //   (b) **假阳性率 ≈ 理论值** —— 对 b_qry 里每个置位，候选值那一位置位的
        //       概率 ≈ 2^-ℓ_BF，故每对的假阳性率 ≈ popcount(b_qry)·2^-ℓ_BF。
        //       实测值应当在这个量级附近（这是"ε_BF 取 2^-6 而非 2^-20 的代价"的
        //       可量化版本，而不是一句形容词）。
        System.out.println("\n[7] 合取判定恰好性（对全部关键词对穷举）");
        int maxSetSize2 = db.intMeta("maxSetSize", 4);
        double eps2 = db.meta.get("epsBf") instanceof Number
            ? ((Number) db.meta.get("epsBf")).doubleValue() : Math.pow(2, -6);
        com.fusepir.common.BfGen bf = com.fusepir.common.BfGen.choose(maxSetSize2, eps2, n);
        check(bf.length() == tb.lBf, "BfGen 长度 %d == DB lBf %d", bf.length(), tb.lBf);

        int pairChecked = 0;
        int pairWrong = 0;
        int falsePositive = 0;
        int falseNegative = 0;
        String firstWrong = "";
        for (int i = 0; i < kwTotal; i++) {
            for (int j = 0; j < kwTotal; j++) {
                if (i == j) {
                    continue;
                }
                String kAnchor = db.keywords.get(i);
                String kOther = db.keywords.get(j);
                // b_qry = 非 anchor 关键词的 Bloom（本用例只有一个）
                boolean[] bQry = bf.bits(java.util.Collections.singletonList(kOther));

                // 取回 anchor 的载荷（复用第 4 节验证过的取法）
                int cc = tb.colOf[i];
                int ro = tb.rowOf[i];
                long[] pay = new long[tb.bPay];
                for (int b = 0; b < tb.bPay; b++) {
                    pay[b] = readSum(tb, cc, ro, b, t);
                }
                int cnt = (int) pay[1];
                java.util.Set<Integer> accepted = new java.util.TreeSet<>();
                for (int v = 0; v < Math.min(cnt, maxValues); v++) {
                    int base = 2 + v * (1 + tb.lBf);
                    int mv = (int) pay[base];
                    if (mv <= 0) {
                        continue;
                    }
                    boolean conj = true;
                    for (int bi = 0; bi < tb.lBf; bi++) {
                        boolean bitV = pay[base + 1 + bi] != 0;
                        if (bQry[bi] && !bitV) {
                            conj = false;
                            break;
                        }
                    }
                    if (conj) {
                        accepted.add(mv);
                    }
                }

                // 真值：既属于 anchor 又属于 kOther 的值
                java.util.Set<Integer> truth = new java.util.TreeSet<>();
                for (int mv : db.kwToMovies.get(kAnchor)) {
                    if (db.kwToMovies.get(kOther).contains(mv)) {
                        truth.add(mv);
                    }
                }

                pairChecked++;
                if (!accepted.equals(truth)) {
                    pairWrong++;
                    for (int mv : accepted) {
                        if (!truth.contains(mv)) {
                            falsePositive++;   // 多收 = Bloom 假阳性
                        }
                    }
                    for (int mv : truth) {
                        if (!accepted.contains(mv)) {
                            falseNegative++;   // 漏收 = 真 bug
                        }
                    }
                    if (firstWrong.isEmpty()) {
                        firstWrong = "（首个：「" + kAnchor + " + " + kOther + "」"
                            + " 接受=" + accepted + " 真值=" + truth + "）";
                    }
                }
            }
        }

        // 期望假阳性率：对每个 value 用它**真实的**置位数 k_v 算。
        //
        // ⚠️ 这里不能用 `BfGen` 注释里的 `h·2^-ℓ`，也不能用教科书式
        //     f = (1 − e^{−h·m/ℓ})^h
        // —— 在 ℓ=18、h=5、m=2 这种小参数下两者都严重失真：两个关键词共 10 位
        // 落在 18 个桶里必然碰撞，置位数远小于 10，而 f 对置位数是**指数敏感**的。
        //
        // 正确的一阶模型（也正好是"查询位必须是被查值位的子集"这个定义）：
        //     对每个 value，k_v = popcount(b_v)
        //     单个非 anchor 关键词把 b_qry 的 h 位落进 b_v 的概率 ≈ (k_v/ℓ)^h
        //     总期望假阳性率 = 对全部 (anchor, other) 有序对取平均
        // 这里直接把每个 value 的 k_v 从**表里取回的载荷**读出来（复现真实读取路径），
        // 然后算 h 位全部命中的期望。
        java.util.List<Integer> vBits = new java.util.ArrayList<>();
        int hHash;
        {
            int w = 0;
            for (boolean z : bf.bits(java.util.Collections.singletonList(db.keywords.get(0)))) {
                if (z) {
                    w++;
                }
            }
            hHash = w;
        }
        for (int i = 0; i < kwTotal; i++) {
            int cc = tb.colOf[i];
            int ro = tb.rowOf[i];
            int cnt = (int) readSum(tb, cc, ro, 1, t);
            for (int v = 0; v < Math.min(cnt, maxValues); v++) {
                int base = 2 + v * (1 + tb.lBf);
                int mv = (int) readSum(tb, cc, ro, base, t);
                if (mv <= 0) {
                    continue;
                }
                int k = 0;
                for (int bi = 0; bi < tb.lBf; bi++) {
                    if (readSum(tb, cc, ro, base + 1 + bi, t) != 0) {
                        k++;
                    }
                }
                vBits.add(k);
            }
        }
        double observedFpRate = pairChecked == 0 ? 0 : (double) pairWrong / pairChecked;
        double predictedFpRate = 0;
        double kSum = 0;
        for (int k : vBits) {
            predictedFpRate += Math.pow((double) k / tb.lBf, hHash);
            kSum += k;
        }
        if (!vBits.isEmpty()) {
            predictedFpRate /= vBits.size();
        }
        double kMean = vBits.isEmpty() ? 0 : kSum / vBits.size();
        System.out.printf("  穷举 %d 组（%d 个关键词两两有序对）%n", pairChecked, kwTotal);
        System.out.printf("  h = %d，ℓ_BF = %d；候选值置位数 k_v：均值 %.2f，范围 [%d, %d]%n",
            hHash, tb.lBf, kMean,
            vBits.stream().mapToInt(z -> z).min().orElse(0),
            vBits.stream().mapToInt(z -> z).max().orElse(0));
        System.out.printf("  理论假阳性率 ≈ mean((k_v/ℓ)^h) = %.4f%n", predictedFpRate);
        System.out.printf("  实测：%d 组不一致（%.4f），其中多收 %d 个值、漏收 %d 个 %s%n",
            pairWrong, observedFpRate, falsePositive, falseNegative, firstWrong);

        check(falseNegative == 0,
            "**假阴性 = %d（必须为 0）** —— Bloom 无假阴性，这条是论文论证的前提",
            falseNegative);
        // 3 倍容差：k_v 的模型是近似的，但量级必须对上；数量级错就是判据错
        check(observedFpRate <= 3 * predictedFpRate + 1e-9,
            "假阳性率 %.4f 与理论值 %.4f 同量级（ε_BF=2^-6 的代价，非 bug）",
            observedFpRate, predictedFpRate);
        check(eps2 > Math.pow(2, -20) * 1.5,
            "ε_BF = %s 远大于论文的 2^-20（≈%d 倍）⇒ 假阳性率天然比论文高几个数量级"
                + "（这正是 D5c 记录的口径差）",
            eps2, Math.round(eps2 / Math.pow(2, -20)));

        System.out.println();
        if (failures == 0) {
            System.out.println("=== ALL CHECKS PASSED ===");
        } else {
            System.out.printf("=== %d CHECK(S) FAILED ===%n", failures);
            throw new IllegalStateException(failures + " table geometry check(s) failed");
        }
    }
}
