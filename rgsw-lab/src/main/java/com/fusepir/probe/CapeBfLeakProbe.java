package com.fusepir.probe;


import com.fusepir.bloom.*;
import com.fusepir.bff.*;
import com.fusepir.cape.*;
import com.fusepir.demo.*;
import com.fusepir.common.BfGen;

import java.nio.file.Paths;

/**
 * <b>出站查询的隐私探针。</b>展示「服务器用公开的 {@code H} 就能从出站 JSON 反解出查询关键词」。
 *
 * <p><b>⚠️ 这个类的前身（{@code CapeTauProbe}）建立在一个我后来撤回的判断上，留痕如下。</b>
 *
 * <p>我曾以为 {@code τ} 的口径错了：我们为了塞进 FusePIR 的 anchor 结构，把 anchor 从
 * {@code b_qry} 里排除，于是单关键词查询得到 {@code τ = 0}，我据此断言「合取检索会退化成
 * 普通关键词 PIR」。<b>回原文后这个判断被推翻了</b>：
 * <pre>
 *   附录 L885   : "a FusePIR anchor … the Bloom vector of **all non-anchor keywords**"
 *   附录 L1743- : b_j   = BF.Gen(0, {K : h(K)=r_a, i≥2})
 *   附录 L1747- : b_qry = BF.Gen(0, {K_2,…,K_Q})，τ = ‖b_qry‖₁
 * </pre>
 * 三处都写 {@code i≥2} —— <b>anchor 本来就该排除在外</b>，我们的 τ 口径与论文一致。
 * 「τ = 0 会退化」只在「实现方真的去比较 {@code s_j = τ}」时才成立，而本项目的
 * legacy 路径用明文合取判定、根本没读 τ，所以 τ=0 也不产生错答案。
 *
 * <p>所以本类<b>不再论证 τ 有问题</b>，只保留那件被实测证实的事：<b>出站 {@code bf} 字段</b>。
 *
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeBfLeakProbe [db]}
 */
public final class CapeBfLeakProbe {

    public static void main(String[] args) throws Exception {
        String dbPath = args.length > 0 ? args[0] : "cape-demo/db/keywords.json";
        CapeDemoData db = CapeDemoData.load(Paths.get(dbPath));
        int n = db.intMeta("n", 8192);
        int maxSetSize = db.intMeta("maxSetSize", 4);
        double eps = db.meta.get("epsBf") instanceof Number
            ? ((Number) db.meta.get("epsBf")).doubleValue() : Math.pow(2, -6);
        int lBf = db.intMeta("lBf", 35);

        BfGen g = BfGen.choose(maxSetSize, eps, n);
        System.out.printf("BfGen = %s   (DB lBf=%d, maxSetSize=%d, eps=%s)%n",
            g, lBf, maxSetSize, eps);
        if (g.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch " + g.length() + " vs " + lBf);
        }

        // 参考值：论文口径的 τ（b_qry 覆盖全部**非 anchor**关键词）。
        // 列在这里是为了说明「τ 留在客户端」这句话到底意味着什么 —— 它本身不是问题。
        System.out.println("\n参考：论文口径 τ = ‖BF.Gen(0, 非 anchor 关键词)‖₁（此值不进出站 JSON）");
        String[][] cases = {
            {"artificial intelligence"},
            {"Adam Sandler", "family"},
            {"murder", "police"},
        };
        for (String[] kws : cases) {
            java.util.List<String> others =
                new java.util.ArrayList<>(java.util.Arrays.asList(kws).subList(1, kws.length));
            boolean[] bits = g.bits(others);
            int w = 0;
            for (boolean b : bits) {
                if (b) {
                    w++;
                }
            }
            System.out.printf("  %-34s τ = %d%n", String.join(" + ", kws), w);
        }

        // ---- 真正的发现：出站 bf 可被反解 ----
        //
        // CapeQuery.toJson 曾无条件发送 m.put("bf", q.bfSlots)，而 bfSlots 就是
        // b_qry 的**明文**槽表示（0/1）。H 是公开参数（pp 里含 H），所以服务器拿置位
        // 集合去穷举关键词即可反解 —— 这正是 sealed 路径声称要防的事。
        System.out.println("\n出站 bf 的可反解性（服务器侧视角，只用公开的 H）");
        boolean[] victim = g.bits(java.util.Arrays.asList("family"));
        java.util.List<Integer> setPos = new java.util.ArrayList<>();
        for (int i = 0; i < victim.length; i++) {
            if (victim[i]) {
                setPos.add(i);
            }
        }
        System.out.println("  出站 bf 的置位 = " + setPos + "（共 " + setPos.size() + " 位）");
        System.out.println("  用公开 H 穷举全部 " + db.keywords.size() + " 个关键词：");
        int hits = 0;
        for (String cand : db.keywords) {
            boolean[] bits = g.bits(java.util.Arrays.asList(cand));
            java.util.List<Integer> p = new java.util.ArrayList<>();
            for (int i = 0; i < bits.length; i++) {
                if (bits[i]) {
                    p.add(i);
                }
            }
            if (p.equals(setPos)) {
                hits++;
                System.out.println("    ===> 匹配: \"" + cand + "\"");
            }
        }
        System.out.printf("  %d 个候选 → %d 个匹配 ⇒ %s%n", db.keywords.size(), hits,
            hits == 1 ? "**唯一恢复出明文查询关键词**" : "（需人工判断，但候选集已从 128 缩到 "
                + hits + "）");
        System.out.println();
        System.out.println("  ⇒ 结论：`bf` 字段默认不得外发（已改为 -Dcape.d2=true 才发、"
            + "且字段名带 d2PlaintextBf 前缀）。");
        System.out.println("     D2 的正确接入口是**加密后**的 q_BF"
            + "（BloomScoring.encryptBloomVector），不是明文位向量。");
    }
}
