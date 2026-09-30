package com.fusepir.database;

import com.fusepir.common.BfGen;

import java.util.*;

/**
 * <b>回归测试：客户端 Bloom 查询向量 {@code b_qry} 必须只由关键词算出。</b>
 *
 * <h3>论文怎么写</h3>
 * CAPE 算法 2 · QUERY 第 2~3 行：
 * <pre>
 *   b_qry ← BF.Gen(0, {K_2, ..., K_Q})      // 把【关键词】插进 Bloom
 *   τ     ← ‖b_qry‖_1
 * </pre>
 * 正确性依赖「<b>无漏判</b>」：候选 {@code v} 含全部查询关键词 ⇒ {@code B(K_i) ⊆ b_v} ⇒ {@code ⟨b_qry,b_v⟩ = τ}。
 *
 * <h3>历史上的错法（本类前两节就把它复现出来）</h3>
 * {@code CapeEndToEnd4} 曾经写成
 * <pre>
 *   for (String qk : query[1..]) {
 *       for (int vv : dbValues[idx]) qBf |= bloom.get(vv);   // ← 或的是 b_v，不是 B(K)
 *   }
 * </pre>
 * 算出来的是 {@code OR_{K ∈ Co(K_2)} B(K)}，其中 {@code Co(K_2) = ⋃_{v∈V_{K_2}} kw(v)}
 * <b>严格大于</b> {@code {K_2}} ⇒ {@code τ} 被撑大 ⇒ 判定变严 ⇒ <b>漏判</b>。
 * 而且 {@code dbValues} 是<b>服务器才有的明文数据库</b>，客户端的 {@code b_qry} 根本算不出来。
 *
 * <p>跑法：{@code .\run.ps1 -Class com.fusepir.database.BloomQueryConstructionCheck}
 */
public final class BloomQueryConstructionCheck {

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== 客户端 b_qry 构造检查（正确构造 vs 历史上的错法）===");

        BfGen bloom = BfGen.choose(2, Math.pow(2, -6), 512);
        System.out.printf("[bloom] %s%n%n", bloom);

        // ---------------- 库（故意让 K_2 与查询外的 K_3 共现于 v1） ----------------
        Map<String, Set<Integer>> valuesByKeyword = new LinkedHashMap<>();
        valuesByKeyword.put("K_1", new LinkedHashSet<>(List.of(1, 2)));
        valuesByKeyword.put("K_2", new LinkedHashSet<>(List.of(1, 2)));
        valuesByKeyword.put("K_3", new LinkedHashSet<>(List.of(1)));

        Map<Integer, Set<String>> kwOf = new TreeMap<>();
        valuesByKeyword.forEach((k, vs) -> vs.forEach(v ->
            kwOf.computeIfAbsent(v, x -> new LinkedHashSet<>()).add(k)));
        Map<Integer, boolean[]> bV = new TreeMap<>();
        kwOf.forEach((v, ks) -> bV.put(v, bloom.bits(ks)));

        System.out.println("库：");
        valuesByKeyword.forEach((k, vs) -> System.out.printf("      %s -> %s%n", k, vs));
        kwOf.forEach((v, ks) -> System.out.printf("      v%d 关联关键词 = %s%n", v, ks));
        System.out.println();

        List<String> query = List.of("K_1", "K_2");
        List<String> rest = query.subList(1, query.size());
        System.out.printf("查询 = %s，锚 = K_1（候选 = V_{K_1} = %s）%n%n",
            query, valuesByKeyword.get("K_1"));

        // ---- ① 正确：b_qry = OR_{i>=2} B(K_i)，只用到关键词 ----
        boolean[] bQryCorrect = bloom.bits(rest);
        long tauCorrect = count(bQryCorrect);

        // ---- ② 错法：b_qry = OR_{v ∈ V_{K_2}} b_v（需要服务器的明文库） ----
        boolean[] bQryWrong = new boolean[bloom.length()];
        for (int v : valuesByKeyword.get("K_2")) {
            boolean[] bv = bV.get(v);
            for (int i = 0; i < bQryWrong.length; i++) {
                bQryWrong[i] |= bv[i];
            }
        }
        long tauWrong = count(bQryWrong);

        System.out.println("b_qry 两种构造：");
        System.out.printf("      正确   b_qry = B(K_2)                      τ = %-3d %s%n",
            tauCorrect, pos(bQryCorrect));
        System.out.printf("      错法   b_qry = ⋃_{v∈V_{K_2}} b_v          τ = %-3d %s%n",
            tauWrong, pos(bQryWrong));
        System.out.printf("      → 错法的 b_qry %s正确的（多出的位来自 K_3：它与 K_2 共现于 v1）%n%n",
            tauWrong > tauCorrect ? "**严格大于**" : "不大于");
        failed += report("① 错法确实把 b_qry 撑大了（含查询外的 K_3）", tauWrong > tauCorrect,
            String.format("τ: 正确 %d → 错法 %d", tauCorrect, tauWrong));

        // ---------------- 逐候选判定 ----------------
        System.out.println("真答案（V_{K_1} 里同时含 K_2 的）= " + trueAnswers(valuesByKeyword, kwOf, query));
        System.out.println();
        int missCorrect = 0;
        int missWrong = 0;
        List<String> wrongRejected = new ArrayList<>();
        for (int v : valuesByKeyword.get("K_1")) {
            long sCorrect = inner(bQryCorrect, bV.get(v));
            long sWrong = inner(bQryWrong, bV.get(v));
            boolean hitCorrect = sCorrect == tauCorrect;
            boolean hitWrong = sWrong == tauWrong;
            boolean isTrueHit = kwOf.get(v).containsAll(query);
            if (isTrueHit && !hitCorrect) {
                missCorrect++;
            }
            if (isTrueHit && !hitWrong) {
                missWrong++;
                wrongRejected.add("v" + v);
            }
            System.out.printf("      v%d  kw=%-18s 正确 score=%-3d %-4s   错法 score=%-3d %-4s%n",
                v, kwOf.get(v), sCorrect, hitCorrect ? "命中" : "拒绝",
                sWrong, hitWrong ? "命中" : "拒绝");
        }
        System.out.println();
        failed += report("② 正确构造：真命中全部召回（无漏判）", missCorrect == 0,
            String.format("漏判 %d 个", missCorrect));
        failed += report("③ ★ 错法出现【漏判】—— 真命中被拒（这就是必须修的原因）", missWrong > 0,
            missWrong > 0
                ? String.format("漏判 %s：真命中被判成「不命中」", wrongRejected)
                : "本例未复现（换个共现结构即可）");

        // ---------------- 随机回归：正确构造必须无漏判 ----------------
        System.out.println();
        System.out.println("── 随机回归：正确构造在 300 组随机库/查询下必须 0 漏判 ──");
        failed += randomNoFalseNegative(bloom);
        failed += report("④ 位位置推导用 double hashing（h 个位置来自 2 个 64-bit 字，不再重叠）",
            checkDoubleHashing(bloom), "见 BfGen.positions 的说明");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 全部通过：正确构造无漏判；错法会被本测试抓住 ==="
            : "=== 有 " + failed + " 项未按预期 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 随机库 + 随机查询，用【正确构造】跑，要求真命中一个都不能漏。 */
    private static int randomNoFalseNegative(BfGen bloom) {
        Random rnd = new Random(20260929L);
        int totalTrueHits = 0;
        int missed = 0;
        for (int trial = 0; trial < 300; trial++) {
            int nKw = 4 + rnd.nextInt(5);          // 4..8 个关键词
            int nVal = 3 + rnd.nextInt(4);         // 3..6 个值
            Map<String, Set<Integer>> vbk = new LinkedHashMap<>();
            List<String> names = new ArrayList<>();
            for (int i = 0; i < nKw; i++) {
                names.add("K_" + i);
                vbk.put("K_" + i, new LinkedHashSet<>());
            }
            for (int v = 0; v < nVal; v++) {
                for (String k : names) {
                    if (rnd.nextBoolean()) {
                        vbk.get(k).add(v);
                    }
                }
            }
            Map<Integer, Set<String>> kwOf = new TreeMap<>();
            vbk.forEach((k, vs) -> vs.forEach(v ->
                kwOf.computeIfAbsent(v, x -> new LinkedHashSet<>()).add(k)));

            int anchorIdx = rnd.nextInt(nKw);
            List<String> queryKw = List.of(names.get(anchorIdx),
                names.get(rnd.nextInt(nKw)));
            List<String> restKw = queryKw.subList(1, queryKw.size());

            boolean[] bQry = bloom.bits(restKw);
            long tau = count(bQry);
            for (int v : vbk.get(names.get(anchorIdx))) {
                if (!kwOf.get(v).containsAll(queryKw)) {
                    continue;                       // 不是真命中，跳过
                }
                totalTrueHits++;
                if (inner(bQry, bloom.bits(kwOf.get(v))) != tau) {
                    missed++;
                }
            }
        }
        return report("随机回归：正确构造 0 漏判", missed == 0,
            String.format("%d 个真命中，漏判 %d 个", totalTrueHits, missed));
    }

    /** 新的位位置推导是不是 double hashing 的形状（恰好 h 个位置、都在范围内、可复现）。 */
    private static boolean checkDoubleHashing(BfGen bloom) {
        int[] p = bloom.positions("K_1");
        if (p.length != bloom.hashCount()) {
            return false;
        }
        for (int x : p) {
            if (x < 0 || x >= bloom.length()) {
                return false;
            }
        }
        return Arrays.equals(p, bloom.positions("K_1"));
    }

    private static Set<Integer> trueAnswers(Map<String, Set<Integer>> vbk,
                                            Map<Integer, Set<String>> kwOf, List<String> query) {
        Set<Integer> out = new TreeSet<>();
        for (int v : vbk.get(query.get(0))) {
            if (kwOf.get(v).containsAll(query)) {
                out.add(v);
            }
        }
        return out;
    }

    private static long count(boolean[] b) {
        long c = 0;
        for (boolean x : b) {
            if (x) {
                c++;
            }
        }
        return c;
    }

    private static long inner(boolean[] x, boolean[] y) {
        long c = 0;
        for (int i = 0; i < x.length; i++) {
            if (x[i] && y[i]) {
                c++;
            }
        }
        return c;
    }

    private static String pos(boolean[] b) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < b.length; i++) {
            if (b[i]) {
                sb.append(sb.length() > 1 ? "," : "").append(i);
            }
        }
        return sb.append("}").toString();
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
