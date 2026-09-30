package com.fusepir.database;

import com.fusepir.common.BfGen;

import java.util.*;

/**
 * Bloom 合取判定的最小端到端验证 —— <b>测试原理能否跑通，不追求规模</b>。
 *
 * <h3>这是什么</h3>
 * CAPE 相对 FusePIR 的核心增量就是这个判定。对每个**候选 value** {@code v}：
 * <pre>
 *   服务端: b_v    = Σ_{K' ∈ keywords(v)} B(K')   ← 该 value 关联的全部关键词的位
 *   客户端: b_qry  = Σ_{i=2..Q} B(K_i)            ← 查询里除锚关键词外的其余关键词
 *   判定:   ⟨b_qry, b_v⟩ == τ ?   （τ = b_qry 的位计数）
 * </pre>
 * {@code = τ} 说明<b>查询的每一个关键词都出现在 v 的关键词集合里</b> → v 是合取命中。
 *
 * <h3>验收标准（区分"真命中"与"假阳性"）</h3>
 * <ol>
 *   <li><b>必须召回全部真命中</b> —— 一个都不能漏（这是正确性）；</li>
 *   <li><b>不应漏判</b>：真命中的 value 判定必须为命中；</li>
 *   <li><b>假阳性率受 ε_BF 控制</b> —— 偶发误命中是 Bloom 的固有性质，不是 bug。
 *       ε_BF 越小假阳性越少，但 ℓ_BF 会变大（受 ℓ ≤ N 约束）。</li>
 * </ol>
 *
 * <h3>为什么必须"位位置只依赖关键词"</h3>
 * 客户端只有关键词，它<b>无法</b>算出 {@code B(K : v)}。所以服务端的位也必须只是 {@code B(K)}。
 * 早期实现写的是 {@code digest(keyword + ":" + value)}，两边位位置永远对不上、内积恒为 0。
 * 第 4 组检查专门钉死这条性质。
 */
public final class BloomConjunctionCheck {

    private static int failed = 0;

    public static void main(String[] args) {
        CapeParameters params = CapeParameters.testMinimal();
        System.out.println("=== Bloom 合取判定（最小参数，验证原理）===");
        System.out.println("[params] " + params.describe());

        // ---- 小数据库：关键词 → value 集合 ----
        final int V = 12;
        Map<String, Set<Integer>> valuesByKeyword = new LinkedHashMap<>();
        valuesByKeyword.put("sci-fi",      new LinkedHashSet<>(List.of(1, 2, 3, 5)));
        valuesByKeyword.put("action",      new LinkedHashSet<>(List.of(2, 3, 4, 7)));
        valuesByKeyword.put("comedy",      new LinkedHashSet<>(List.of(1, 4, 6, 9)));
        valuesByKeyword.put("drama",       new LinkedHashSet<>(List.of(3, 5, 8, 11)));
        valuesByKeyword.put("animation",   new LinkedHashSet<>(List.of(0, 2, 6, 10)));
        valuesByKeyword.put("documentary", new LinkedHashSet<>(List.of(5, 7, 8, 9)));

        // 反向关系：value → 关联的关键词（服务端侧）
        Map<Integer, Set<String>> keywordsByValue = new TreeMap<>();
        for (int v = 0; v < V; v++) keywordsByValue.put(v, new LinkedHashSet<>());
        valuesByKeyword.forEach((keyword, values) -> values.forEach(v -> keywordsByValue.get(v).add(keyword)));

        int maxSetSize = keywordsByValue.values().stream().mapToInt(Set::size).max().orElse(0);
        BfGen bloom = params.bloomParameters(maxSetSize);
        System.out.printf("[bloom] maxSetSize=%d -> h=%d, lBF=%d bits (上限 N=%d) %s%n",
            maxSetSize, bloom.hashCount(), bloom.length(), params.ringDegreeN(),
            bloom.length() <= params.ringDegreeN() ? "OK" : "超出!");

        // 服务端：每个 value 一个 Bloom
        Map<Integer, boolean[]> serverBloom = new TreeMap<>();
        keywordsByValue.forEach((v, keywords) -> serverBloom.put(v, bloom.bits(keywords)));

        // ---- 1) 必须召回全部真命中 ----
        List<List<String>> queries = List.of(
            List.of("sci-fi", "action"),
            List.of("sci-fi", "comedy"),
            List.of("action", "comedy", "drama"),
            List.of("sci-fi", "documentary"),
            List.of("action", "documentary"),
            List.of("comedy", "documentary"),
            List.of("drama", "documentary"),
            List.of("sci-fi", "action", "drama"));
        System.out.println();
        System.out.println("--- 1) 真命中必须全部召回（漏判 = 正确性问题）---");
        int missedTotal = 0, trueHitTotal = 0;
        for (List<String> query : queries) {
            Set<Integer> expected = new TreeSet<>();
            for (int v = 0; v < V; v++) if (keywordsByValue.get(v).containsAll(query)) expected.add(v);
            Set<Integer> got = new TreeSet<>();
            for (int v = 0; v < V; v++) if (matches(bloom, serverBloom.get(v), query)) got.add(v);
            boolean recalled = got.containsAll(expected);
            if (!recalled) missedTotal += expected.size() - intersect(expected, got).size();
            trueHitTotal += expected.size();
            System.out.printf("      %-38s 真命中=%-12s 判定命中=%-24s %s%n",
                query, expected, got, recalled ? "" : "<-- 漏判!");
        }
        failed += report("真命中全部召回", missedTotal == 0,
            String.format("共 %d 个真命中，漏判 %d 个", trueHitTotal, missedTotal));

        // ---- 2) 假阳性率是否受 ε_BF 控制 ----
        System.out.println();
        System.out.println("--- 2) 假阳性（ε_BF 的固有性质，不是 bug）---");
        int falsePositive = 0, notRelated = 0;
        for (int v = 0; v < V; v++) {
            for (String keyword : valuesByKeyword.keySet()) {
                if (keywordsByValue.get(v).contains(keyword)) continue;
                notRelated++;
                if (containsAll(serverBloom.get(v), bloom.bits(keyword))) falsePositive++;
            }
        }
        double observed = notRelated == 0 ? 0 : (double) falsePositive / notRelated;
        double target = params.bloomFalsePositiveTarget();
        System.out.printf("      单关键词不相关组合 %d 个，误命中 %d 个 -> 实测 %.4f（目标 %.4f）%n",
            notRelated, falsePositive, observed, target);
        // 实测在目标的 2.5 倍以内即认为符合（样本只有几十个，波动正常）
        failed += report("单关键词假阳性率与 ε_BF 同量级", observed <= target * 2.5 + 0.02,
            String.format("实测 %.4f vs 目标 %.4f", observed, target));
        System.out.println("      注：合取 Q 个关键词时需同时误命中，约 ε_BF^(Q-1) —— 合取反而更准。");

        // ---- 3) 位位置只依赖关键词（value 混入哈希会失败）----
        System.out.println();
        System.out.println("--- 3) 位位置只依赖关键词 ---");
        boolean independent = true;
        int checked = 0;
        for (String keyword : valuesByKeyword.keySet()) {
            boolean[] single = bloom.bits(keyword);
            for (int v = 0; v < V; v++) {
                checked++;
                boolean expectedMember = keywordsByValue.get(v).contains(keyword);
                boolean actuallyMember = containsAll(serverBloom.get(v), single);
                if (expectedMember != actuallyMember) independent = false;
            }
        }
        failed += report("B(K) 与 value 无关，且 value 的 Bloom 恰含其关键词的位", independent,
            String.format("检查 %d 个 (value, keyword) 组合，%s", checked,
                independent ? "全部一致" : "有不一致"));

        // ---- 4) 位位置诊断（人工可核）----
        System.out.println();
        System.out.println("--- 4) 位位置一览（抽查用）---");
        System.out.println("      lBF=" + bloom.length() + " 位, h=" + bloom.hashCount());
        for (String keyword : valuesByKeyword.keySet()) {
            System.out.printf("      B(%-12s) = %s%n", keyword, positions(bloom.bits(keyword)));
        }
        for (Map.Entry<Integer, boolean[]> entry : serverBloom.entrySet()) {
            System.out.printf("      b_v(%-3d)          = %s  %s%n",
                entry.getKey(), positions(entry.getValue()), keywordsByValue.get(entry.getKey()));
        }

        System.out.println();
        System.out.println(failed == 0 ? "=== Bloom 合取判定全部通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 合取判定：⟨b_qry, b_v⟩ == τ（τ = b_qry 的位计数） */
    private static boolean matches(BfGen bloom, boolean[] valueBloom, List<String> query) {
        boolean[] queryBits = bloom.bits(query);
        int tau = 0, intersection = 0;
        for (int i = 0; i < queryBits.length; i++) {
            if (queryBits[i]) {
                tau++;
                if (valueBloom[i]) intersection++;
            }
        }
        return intersection == tau;
    }

    private static boolean containsAll(boolean[] haystack, boolean[] needle) {
        for (int i = 0; i < needle.length; i++) if (needle[i] && !haystack[i]) return false;
        return true;
    }

    private static Set<Integer> intersect(Set<Integer> a, Set<Integer> b) {
        Set<Integer> r = new TreeSet<>(a);
        r.retainAll(b);
        return r;
    }

    private static String positions(boolean[] bits) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (int i = 0; i < bits.length; i++) {
            if (bits[i]) {
                if (!first) sb.append(",");
                sb.append(i);
                first = false;
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
