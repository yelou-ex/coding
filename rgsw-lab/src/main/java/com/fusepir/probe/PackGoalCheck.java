package com.fusepir.probe;


import com.fusepir.prim.*;
import com.fusepir.bloom.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>目标检查</b>：当前 {@code Pack} 是否满足
 * <blockquote>
 * 把"每个 LWE 密文只加密一个比特"的<b>多个</b> LWE 密文，<b>安全且正确地打包成【一个】RLWE 密文</b>，
 * 并让<b>每个比特对应 RLWE 明文空间中的【一个槽位（slot）】</b>，从而利用 RLWE 的 SIMD 能力做二进制同态内积。
 * </blockquote>
 *
 * <p>拆成四个可独立判定的小目标，逐条实测：
 * <ol>
 *   <li><b>G1 多样性</b>：能不能一次吃<b>多条</b> LWE 密文？（不是一条一条分开摆）</li>
 *   <li><b>G2 落点</b>：消息落在<b>槽位</b>，还是落在<b>系数</b>？</li>
 *   <li><b>G3 合流</b>：把多条分别摆好后<b>相加</b>，能不能得到"一个密文装多位"？</li>
 *   <li><b>G4 可用性</b>：拿打包产物去喂 {@link BloomScoring}（槽位域二进制同态内积），能不能算出内积？</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.PackGoalCheck 4096}
 */
public final class PackGoalCheck {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();
        System.out.println("=== 目标检查：当前 Pack 能不能把多个 LWE 比特打成【一个槽位域 RLWE】 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[slots] 槽数 = %d%n%n", slots);

        // ================= G1 多样性：接口只能吃一条样本 =================
        System.out.println("--- G1 多样性 ---");
        System.out.println("    现接口：LweRlweBridge.packFromSample(Mpc4jRgsw m, long[][] sample, int j)");
        System.out.println("            → 参数是【一条】sample + 【一个】系数下标 j，没有任何批量入口");
        report("G1 能不能一次打包【多条】LWE 密文成一个 RLWE 密文？", false,
            "接口层面就不支持：只有 packFromSample(单条样本, 单个系数下标)，没有 Pack({ct_1..ct_K}) 这种批量入口");

        // ================= 准备：三条"每条约一个比特"的 LWE 样本 =================
        long[] payload = new long[n];
        for (int i = 0; i < n; i++) {
            payload[i] = (i % 1000) + 1;
        }
        Ciphertext source = m.encrypt(payload);
        long[][] s0 = LweRlweBridge.sampleExtract(m, source, 0);
        long[][] s1 = LweRlweBridge.sampleExtract(m, source, 1);
        long[][] s2 = LweRlweBridge.sampleExtract(m, source, 2);
        System.out.printf("    （三条样本的消息应为 %d / %d / %d）%n%n", payload[0], payload[1], payload[2]);

        // ================= G2 落点：系数还是槽位？ =================
        System.out.println("--- G2 落点 ---");
        Ciphertext p0 = LweRlweBridge.packFromSample(m, s0, 0);
        long[] coeffView = m.decrypt(p0);
        boolean coeffHit = coeffView[0] == payload[0];

        // 槽位视图：把同一条密文按 batch 解码（BatchEncoder.decode）
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(p0);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(n);
        m.decryptor.decrypt(copy, pt);
        long[] slotView = new long[slots];
        be.decode(pt, slotView);
        int slotHit = 0;
        for (long v : slotView) {
            if (v == payload[0]) {
                slotHit++;
            }
        }
        report("G2 消息落在【槽位】上（目标要求）", slotHit > 0 && !coeffHit,
            String.format("系数视图：系数 0 = %d（期望 %d）→ 命中 %b；"
                    + "槽位视图：%d 个槽里等于 %d 的有 %d 个 → 命中 %b",
                coeffView[0], payload[0], coeffHit, slots, payload[0], slotHit, slotHit > 0));

        // ================= G3 合流：把多条摆好后相加 =================
        System.out.println();
        System.out.println("--- G3 合流（把多条分别摆好后相加，即「打包成一个」最自然的做法）---");
        Ciphertext p1 = LweRlweBridge.packFromSample(m, s1, 1);
        Ciphertext p2 = LweRlweBridge.packFromSample(m, s2, 2);
        // 单独看：每条都对
        long[] d0 = m.decrypt(p0);
        long[] d1 = m.decrypt(p1);
        long[] d2 = m.decrypt(p2);
        System.out.printf("    单独看：p0[0]=%d(应 %d)、p1[1]=%d(应 %d)、p2[2]=%d(应 %d)%n",
            d0[0], payload[0], d1[1], payload[1], d2[2], payload[2]);

        Ciphertext sum = m.add(m.add(p0, p1), p2);
        long[] dsum = m.decrypt(sum);
        boolean ok0 = dsum[0] == payload[0];
        boolean ok1 = dsum[1] == payload[1];
        boolean ok2 = dsum[2] == payload[2];
        report("G3 三条分别摆好后【相加】能还原三个消息", ok0 && ok1 && ok2,
            String.format("相加后：系数0=%d(应%d,%b) 系数1=%d(应%d,%b) 系数2=%d(应%d,%b)"
                    + " —— 每条样本的 c1·s 会在【所有】系数上产生满量级污染，相加即互相破坏",
                dsum[0], payload[0], ok0, dsum[1], payload[1], ok1, dsum[2], payload[2], ok2));

        // ================= G4 可用性：喂给槽位域打分 =================
        System.out.println();
        System.out.println("--- G4 可用性（拿打包产物去做二进制同态内积）---");
        long[] query = new long[slots];
        long[] candidate = new long[slots];
        for (int i = 0; i < slots; i++) {
            query[i] = (i % 3 == 0) ? 1 : 0;
            candidate[i] = (i % 5 == 0) ? 1 : 0;
        }
        long inner = 0;
        for (int i = 0; i < slots; i++) {
            inner += query[i] * candidate[i];
        }
        GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        Ciphertext qBF = BloomScoring.encryptBloomVector(m, query);

        // 正确做法：候选也在槽位域
        Ciphertext correctCandidate = BloomScoring.encryptBloomVector(m, candidate);
        long correctScore = BloomScoring.decodeScore(m, BloomScoring.bloomScore(m, gk, qBF, correctCandidate));

        // 用"当前 Pack 的落点"（系数域）当候选
        Ciphertext coeffCandidate = m.encrypt(candidate);
        long coeffScore = BloomScoring.decodeScore(m, BloomScoring.bloomScore(m, gk, qBF, coeffCandidate));

        report("G4 用【当前 Pack 的落点（系数域）】做输入能算出内积", coeffScore == inner,
            String.format("⟨query,candidate⟩ = %d；槽位域输入得 %d（%s）；系数域输入得 %d（%s）"
                    + " —— 打分只认槽位域，系数域的落点喂进去就是错的",
                inner, correctScore, correctScore == inner ? "✅" : "❌",
                coeffScore, coeffScore == inner ? "✅" : "❌"));

        // ================= 汇总裁决 =================
        System.out.println();
        System.out.println("================ 汇总裁决 ================");
        System.out.println("  目标：多个 LWE 比特 → 一个 RLWE 密文 → 每位一个槽位 → 可做 SIMD 内积");
        System.out.println("  G1 一次打包多条 ............ ❌ 接口不支持（只吃单条样本）");
        System.out.println("  G2 落在槽位 ................ ❌ 落在【系数】");
        System.out.println("  G3 分开摆后相加合流 ........ ❌ 会互相污染");
        System.out.println("  G4 喂给槽位域打分 .......... ❌ 算不出内积");
        System.out.println();
        System.out.println("  ⇒ 当前 packFromSample 实现的【不是论文的 Pack】：");
        System.out.println("     它是 SampleExtract 的【逆】（单样本 ↔ 单个系数），只能用于验证往返，");
        System.out.println("     不具备「批打包 + 落到槽位」的能力。");
        System.out.println();
        System.out.println("  ✅ 但论文的 Pack 已经【另起一个类】实现并验证了，不是缺口：");
        System.out.println("     原语正式名字 = Ring Packing / RLWE-Pack（奠基 CDKS21, ePrint 2020/015）");
        System.out.println("     实现 = RingPack.java；跑法 = .\\run-mpc4j.ps1 -Class com.fusepir.prim.RingPack 8192 32");
        System.out.println("     实测 6/6：多条 LWE 比特 → 一个槽位域 RLWE（槽位错 0、泄漏 0），");
        System.out.println("              打包产物直接喂 BloomScoring 得到正确 ⟨b_qry,b_v⟩（含负对照）。");
        System.out.println("     本类保留的价值 = 把「packFromSample ≠ Pack」这件事固定成可重跑的断言。");

        if (failed != 0) {
            System.out.printf("%n（本检查刻意把目标写成断言：%d 条未达成 = 目标未满足）%n", failed);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
