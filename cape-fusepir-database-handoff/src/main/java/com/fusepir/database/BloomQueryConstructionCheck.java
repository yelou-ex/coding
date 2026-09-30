package com.fusepir.database;

import java.util.*;

/**
 * <b>查 `CapeEndToEnd4` / `CapeDemo` 里客户端 Bloom 查询向量 {@code b_qry} 的构造。</b>
 *
 * <h3>论文怎么写</h3>
 * CAPE 算法 2 · QUERY 第 2~3 行：
 * <pre>
 *   b_qry ← BF.Gen(0, {K_2, ..., K_Q})      // 把【关键词】插进 Bloom
 *   τ     ← ‖b_qry‖_1
 * </pre>
 * 也就是说 {@code b_qry = OR_{i≥2} B(K_i)}，<b>只用到关键词</b>。
 * 正确性依赖"<b>无漏判</b>"：候选 {@code v} 含全部查询关键词 ⇒ {@code B(K_i) ⊆ b_v} ⇒ {@code ⟨b_qry,b_v⟩ = τ}。
 *
 * <h3>演示代码怎么写</h3>
 * {@code CapeEndToEnd4} 的 QUERY 段是：
 * <pre>
 *   for (String qk : query[1..]) {
 *       int idx = 该关键词在库里的下标;
 *       for (int vv : dbValues[idx]) {          // ← 遍历这个关键词的【值集合 V_{K_2}】
 *           qBf |= bloom.get(vv);               // ← 或上的是 b_v，不是 B(K)
 *       }
 *   }
 * </pre>
 * 两个问题：
 * <ol>
 *   <li><b>用的是客户端拿不到的数据。</b>{@code dbValues[idx]} 是<b>服务器才有的明文数据库</b>。
 *       客户端的 {@code b_qry} 必须只由关键词算出 —— 所以这段代码<b>不是一个合法客户端查询</b>，
 *       它"能过"只是因为演示里客户端和服务器在同一个 JVM。</li>
 *   <li><b>即使忽略第 1 点，OR 的对象也错了。</b>它算出来的是
 *       {@code OR_{K ∈ Co(K_2)} B(K)}，其中 {@code Co(K_2) = ⋃_{v∈V_{K_2}} kw(v)}
 *       是这个关键词"共现过的全部关键词"集合，<b>严格大于</b> {@code {K_2}}。
 *       {@code b_qry} 变大 ⇒ {@code τ} 变大 ⇒ 判定条件变严 ⇒ <b>会把真命中判掉（漏判 / false negative）</b>。
 *       而论文的正确性证明恰恰依赖"无漏判"。</li>
 * </ol>
 *
 * <p>本类用<b>真实的 {@link BloomParameters} 代码</b>构造一个反例，把漏判跑出来。
 *
 * <p>跑法：{@code javac -d out src/main/java/com/fusepir/database/*.java} 后
 * {@code java -cp out com.fusepir.database.BloomQueryConstructionCheck}
 */
public final class BloomQueryConstructionCheck {

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== 客户端 b_qry 构造检查（CapeEndToEnd4 的写法 vs 论文）===");

        // 参数就用真实代码：maxSetSize=2、ε=2^-6、上限 512
        BloomParameters bloom = BloomParameters.choose(2, Math.pow(2, -6), 512);
        System.out.printf("[bloom] h=%d, ℓ=%d%n%n", bloom.hashCount(), bloom.length());

        // ---------------- 库（故意让 K_2 与查询外的 K_3 共现） ----------------
        //   K_1 -> {v1, v2}
        //   K_2 -> {v1, v2}
        //   K_3 -> {v1}        ← K_3 不在查询里，但和 K_2 共现于 v1
        Map<String, Set<Integer>> valuesByKeyword = new LinkedHashMap<>();
        valuesByKeyword.put("K_1", new LinkedHashSet<>(List.of(1, 2)));
        valuesByKeyword.put("K_2", new LinkedHashSet<>(List.of(1, 2)));
        valuesByKeyword.put("K_3", new LinkedHashSet<>(List.of(1)));

        Map<Integer, Set<String>> kwOf = new TreeMap<>();
        valuesByKeyword.forEach((k, vs) -> vs.forEach(v -> kwOf.computeIfAbsent(v, x -> new LinkedHashSet<>()).add(k)));
        Map<Integer, boolean[]> bV = new TreeMap<>();
        kwOf.forEach((v, ks) -> bV.put(v, bloom.bits(ks)));

        System.out.println("库：");
        valuesByKeyword.forEach((k, vs) -> System.out.printf("      %s -> %s%n", k, vs));
        kwOf.forEach((v, ks) -> System.out.printf("      v%d 关联关键词 = %s%n", v, ks));
        System.out.println();

        // ---------------- 查询：锚 K_1，其余 {K_2} ----------------
        List<String> query = List.of("K_1", "K_2");
        System.out.printf("查询 = %s，锚 = K_1（候选 = V_{K_1} = %s）%n%n",
            query, valuesByKeyword.get("K_1"));

        // ---- 论文：b_qry = OR_{i>=2} B(K_i) = B(K_2) ----
        boolean[] bQryPaper = bloom.bits(query.subList(1, query.size()));
        long tauPaper = count(bQryPaper);

        // ---- 演示：b_qry = OR_{v ∈ V_{K_2}} b_v ----
        boolean[] bQryDemo = new boolean[bloom.length()];
        for (int v : valuesByKeyword.get("K_2")) {
            boolean[] bv = bV.get(v);
            for (int i = 0; i < bQryDemo.length; i++) bQryDemo[i] |= bv[i];
        }
        long tauDemo = count(bQryDemo);

        System.out.println("b_qry 两种构造：");
        System.out.printf("      论文   b_qry = B(K_2)                       τ = %d   %s%n",
            tauPaper, pos(bQryPaper));
        System.out.printf("      演示   b_qry = ⋃_{v∈V_{K_2}} b_v           τ = %d   %s%n",
            tauDemo, pos(bQryDemo));
        boolean bigger = tauDemo > tauPaper;
        System.out.printf("      → 演示的 b_qry %s论文的（多出的位来自 K_3：它与 K_2 共现于 v1）%n%n",
            bigger ? "**严格大于**" : "不大于");
        failed += report("演示的 b_qry 确实被 Co(K_2) 撑大了（含查询外的 K_3）", bigger,
            String.format("τ: 论文 %d → 演示 %d", tauPaper, tauDemo));

        // ---------------- 逐候选判定 ----------------
        System.out.println("真答案（V_{K_1} 里同时含 K_2 的）= {1, 2}；下面看两种构造各判成什么：");
        System.out.println();
        int fnPaper = 0;
        int fnDemo = 0;
        for (int v : valuesByKeyword.get("K_1")) {
            long sPaper = inner(bQryPaper, bV.get(v));
            long sDemo = inner(bQryDemo, bV.get(v));
            boolean hitPaper = sPaper == tauPaper;
            boolean hitDemo = sDemo == tauDemo;
            boolean isTrueHit = kwOf.get(v).containsAll(query);
            if (isTrueHit && !hitPaper) fnPaper++;
            if (isTrueHit && !hitDemo) fnDemo++;
            System.out.printf("      v%d  kw=%-18s 论文 score=%-3d %s   演示 score=%-3d %s%n",
                v, kwOf.get(v), sPaper, hitPaper ? "命中" : "拒绝",
                sDemo, hitDemo ? "命中" : "拒绝");
        }
        System.out.println();
        failed += report("论文的构造：真命中全部召回（无漏判）", fnPaper == 0,
            String.format("漏判 %d 个", fnPaper));
        failed += report("★ 演示的构造：出现【漏判】—— 真命中被拒", fnDemo > 0,
            fnDemo > 0
                ? String.format("漏判 %d 个：真命中被判成「不命中」（论文的正确性依赖无漏判）", fnDemo)
                : "本例未复现（换个共现结构即可）");

        // ---------------- 附带：intAt 的窗口重叠 ----------------
        System.out.println();
        System.out.println("── 附带：`BloomParameters.intAt` 的 4 字节窗口在 h>8 时重叠 ──");
        System.out.print("      h=16 时取的起点（SHA-256 只有 32 字节）：");
        Set<Integer> seen = new TreeSet<>();
        List<Integer> starts = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            int start = Math.floorMod(i * 4, 32 - 4 + 1);
            starts.add(start);
            seen.add(start);
        }
        System.out.println(starts);
        System.out.printf("      不同起点 %d 个 → 窗口 0..7 覆盖 [0,32)，窗口 8..15 又落在 [%d,%d] ⇒ **互相重叠**%n",
            seen.size(), Collections.min(starts.subList(8, 16)), Collections.max(starts.subList(8, 16)));
        System.out.println("      ⇒ 16 个位置并不独立（同一个摘要的相邻字节），实际假阳性率会**差于**公式值。");
        System.out.println("        这不是致命的（Kirsch–Mitzenmacher 式的复用有界），但没有理论保证；");
        System.out.println("        规范做法是用 h 个独立的哈希，或 double hashing g_i = h1 + i·h2。");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 检查完成：上面两项【都复现了】—— 即问题存在，需要修 CapeEndToEnd4 的 b_qry ==="
            : "=== 有 " + failed + " 项未按预期复现（换个共现结构再试）===");
        System.out.println();
        System.out.println("修法：让演示复用【同一套】Bloom 位函数（`BloomParameters.bits(keywords)`），"
            + "b_qry 只从关键词算；");
        System.out.println("      也就是把 BF.Gen 抽成双方共用的方法 —— 这正是对照表 `补 1` 那条。");
        System.out.println("      但注意：BloomParameters 在 cape-fusepir-database-handoff 模块里，"
            + "rgsw-lab 的 classpath 看不到它，");
        System.out.println("      所以要真正共用，得先把它挪到共享位置（或把该模块挂进 classpath）。");
    }

    private static long count(boolean[] b) {
        long c = 0;
        for (boolean x : b) if (x) c++;
        return c;
    }

    private static long inner(boolean[] x, boolean[] y) {
        long c = 0;
        for (int i = 0; i < x.length; i++) if (x[i] && y[i]) c++;
        return c;
    }

    private static String pos(boolean[] b) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < b.length; i++) if (b[i]) sb.append(sb.length() > 1 ? "," : "").append(i);
        return sb.append("}").toString();
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
