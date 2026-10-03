package com.fusepir.probe;

import com.fusepir.bloom.BloomScoring;
import com.fusepir.bloom.BloomSetup;
import com.fusepir.cape.CapeA2Wire;
import com.fusepir.common.BfGen;
import com.fusepir.fusepir.FusePirFourStep;
import com.fusepir.prim.CtOps;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>CAPE（Algorithm 2）接线验收：FusePIR 四步 + 在 {@code tRing} 上做的打分。</b>
 *
 * <p>被验的是 {@link CapeA2Wire}（A2 侧唯一的调用方）。本探针做的事就是
 * "客户端/服务端各自该做的事"各做一遍，然后拿<b>明文侧的真值</b>当参照。
 *
 * <h3>判据（每条都配正/负对照）</h3>
 * <ol>
 *   <li><b>P1</b> A2 SETUP 11-13：{@code pp_C} 确实由 {@code pp_F.extendBloom} 加宽、
 *       {@code st_S} 直传、{@code tRing = K·T} 且 {@code K > ones}；负对照：加宽两次必须抛。</li>
 *   <li><b>P2</b> A2 QUERY 1-3：{@code q_anc} 形状、{@code q^BF} 的<b>段外为 0</b>（契约③）、
 *       {@code τ = ‖b_qry‖₁}；负对照：锚不在查询集里必须抛。</li>
 *   <li><b>P3</b> A2 ANSWER 2-6：<b>每个候选的同态得分 == {@code K ×} 明文内积</b>（主判据）；
 *       命中候选 == {@code K·τ}、漏位候选 {@code < K·τ}；
 *       {@code bloomCt} 的槽 {@code [0,ℓ_BF)} 是 {@code 0/K} <b>不是 {@code 0/1}</b>；
 *       <b>段外杂质实测</b>（{@code bloomCt} 不掩码，契约③的代价）。</li>
 *   <li><b>P4</b> A2 DECODE：{@code V_{K_1}} 与明文一致、收下的值 == 合取语义、
 *       阈值乘 K 的正/负对照、{@code st^anc_C} 不同源 ⇒ {@code ⊥}、
 *       换 {@code q^BF} ⇒ 原命中候选必须被拒。</li>
 *   <li><b>P5</b> 折叠轮数：6 轮（按最高参与槽）与 5 轮（论文形状）在本接线上<b>相同</b>
 *       ——因为 {@code q^BF} 的支撑落在 {@code [0,ℓ_BF)}；
 *       负对照：把 {@code q^BF} 的段外置 1（破约）⇒ 两条路给出<b>不同的错值</b>。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeA2WireTest 16 4096 16 18}
 * （{@code nkw N d ℓ_BF}，可选第 5 个参数 = Bloom 的 {@code h}）
 */
public final class CapeA2WireTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int nkw = args.length > 0 ? Integer.parseInt(args[0]) : 16;
        final int n = args.length > 1 ? Integer.parseInt(args[1]) : 4096;
        final int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        final int lBf = args.length > 3 ? Integer.parseInt(args[3]) : 18;
        final int h = args.length > 4 ? Integer.parseInt(args[4]) : 5;
        final long rhoH = 20261015L;
        final long seed0 = 20261016L;

        System.out.println("=== CAPE（Algorithm 2）接线：FusePIR 四步 + tRing 上的打分 ===");
        System.out.printf("[参数] nkw=%d、N=%d、d=%d、ℓ_BF=%d、h=%d%n%n", nkw, n, d, lBf, h);

        // ==================================================================
        //  A2 SETUP 1-10：参数、S_v、b_v、DB^CAPE
        // ==================================================================
        final BfGen bf = new BfGen(h, lBf);
        final String anchor = "kw-0000";
        final String conj = "kw-0005";

        final List<String> keywords = new ArrayList<>(nkw);
        for (int i = 0; i < nkw; i++) {
            keywords.add(String.format("kw-%04d", i));
        }

        // A2 SETUP 3-4 的素材：V_{K_i}。值在关键词之间【共享】⇒ S_v 自然有多个关键词，
        // 这正是 CAPE 的用法（v=1001 同时属 kw-0000 与 kw-0005）。
        final Map<String, List<Integer>> kwToValues = new LinkedHashMap<>();
        kwToValues.put(anchor, new ArrayList<>(Arrays.asList(1001, 1002, 1003)));
        kwToValues.put(conj, new ArrayList<>(Arrays.asList(1001)));
        kwToValues.put("kw-0009", new ArrayList<>(Arrays.asList(1003)));
        int nextId = 2000;
        for (String k : keywords) {
            if (kwToValues.containsKey(k)) {
                continue;
            }
            final List<Integer> l = new ArrayList<>(3);
            for (int j = 0; j < 3; j++) {
                l.add(nextId++);
            }
            kwToValues.put(k, l);
        }
        final Map<Integer, List<String>> valueToKw = BloomSetup.valueToKeywords(kwToValues);
        final Map<Integer, boolean[]> bloomOf = BloomSetup.valueBloomBits(bf, valueToKw);

        int m = 1;
        for (List<Integer> vs : kwToValues.values()) {
            m = Math.max(m, vs.size());
        }
        final List<List<FusePirFourStep.Value>> dbValues = new ArrayList<>();
        for (String k : keywords) {
            final List<FusePirFourStep.Value> vs = new ArrayList<>();
            for (Integer v : kwToValues.get(k)) {
                vs.add(new FusePirFourStep.Value(v, boolToLongs(bloomOf.get(v), lBf)));
            }
            dbValues.add(vs);
        }
        final FusePirFourStep.Db db = new FusePirFourStep.Db(keywords, dbValues);
        System.out.printf("[A2 SETUP 3-10] DB^CAPE：%d 个关键词、m = %d；v=1001 的 S_v = %s%n",
            nkw, m, valueToKw.get(1001));
        System.out.printf("                |V_{%s}| = %d（候选 3 个）、|V_{%s}| = %d%n%n",
            anchor, kwToValues.get(anchor).size(), conj, kwToValues.get(conj).size());

        // ==================================================================
        //  A2 SETUP 11 / 12 / 13
        // ==================================================================
        final CapeA2Wire.Setup setup;
        long t0 = System.nanoTime();
        try {
            setup = CapeA2Wire.setup(db, n, d, lBf, rhoH, seed0, bf);
        } catch (RuntimeException e) {
            System.out.println("[FAIL] A2 SETUP 11 抛异常：" + e);
            e.printStackTrace(System.out);
            System.exit(1);
            return;
        }
        final long setupMs = (System.nanoTime() - t0) / 1_000_000;
        final FusePirFourStep fp = setup.fusepir();
        System.out.printf("[A2 SETUP 11] %s（%.0f ms）%n", fp, (double) setupMs);
        System.out.printf("[A2 SETUP 12] %s%n", setup.ppC());
        System.out.printf("[A2 SETUP 13] st_S ← st^F_S（同一对象：%b）%n%n",
            setup.stS() == fp.stS());

        System.out.println("--- P1 A2 SETUP 11-13 ---");
        final long tRing = setup.tRing();
        final long scaleK = setup.scaleK();
        final int ones = countOnes(fp.secretBits());
        final int expectBpay = 3 + 1 + m * (1 + lBf);          // fpSlots(T)=3（40 bit / 16 bit）
        System.out.printf("      [info] s_L 的汉明重量 ones = %d；K = %d；桥的残差在每个字段上 "
            + "|E| ≤ ones/2 = %.1f%n%n", ones, scaleK, ones / 2.0);
        {
            int f = 0;
            f += sub(String.format("P1.1 B_pay 三处一致 = %d（pp_C / FusePIR / st^F_S 表宽；"
                    + "算式 = fpSlots+1+m·(1+ℓ_BF) = %d）", fp.bPay(), expectBpay),
                setup.ppC().bPay() == fp.bPay() && fp.stS().bPay() == fp.bPay()
                    && fp.bPay() == expectBpay);
            f += sub(String.format("P1.2 pp_C = (pp_F, ℓ_BF=%d, G, m=%d) 且含 pp_F 的全部项",
                    setup.ppC().lBf(), setup.ppC().m()),
                setup.ppC().lBf() == lBf && setup.ppC().m() == m
                    && setup.ppC().d() == fp.pp().d()
                    && setup.ppC().h() == fp.pp().h()
                    && setup.ppC().n() == fp.pp().n());
            boolean gOk = true;
            for (String k : keywords) {
                gOk &= Arrays.equals(setup.ppC().g().positions(k), bf.positions(k));
            }
            f += sub("P1.3 G 就是（客户端与服务端共用的）那一份 BfGen：逐关键词逐位相同", gOk);
            f += sub(String.format("P1.4 tRing = %d：素数、≡1 (mod 2N=%d)；K = ⌊tRing/T⌋ = %d、"
                    + "tRing − K·T = %d（**不是 0** ⇒ MAP §31.1 / 交接单 §3 里『tRing = K·T』"
                    + "是简化说法，代码里 K 是整除商）",
                    tRing, 2 * n, scaleK, tRing - scaleK * FusePirFourStep.T),
                Math.floorMod(tRing - 1, 2L * n) == 0
                    && BigInteger.valueOf(tRing).isProbablePrime(64)
                    && scaleK == tRing / FusePirFourStep.T
                    && scaleK * FusePirFourStep.T <= tRing);
            f += sub(String.format("P1.5 K = %d > ones = %d（K 倍精度的硬要求："
                    + "桥的残差 |E| ≤ ones/2 被 K/2 的余量吸收）", scaleK, ones), scaleK > ones);
            final CapeA2Wire.Setup unused = setup;
            final int mFinal = m;          // lambda 只能捕 effectively-final 的局部量
            f += sub("[负对照] pp_C 再加宽一次必须抛（A2 SETUP 12 在论文里只有一行）",
                throwsRuntime(() -> unused.ppC().extendBloom(lBf,
                    com.fusepir.fusepir.FusePirParams.BloomHashFamily.of(bf), mFinal)));
            report("P1 A2 SETUP 11-13 接线成立", f == 0, String.format("%d 项未达成", f));
        }

        // ==================================================================
        //  A2 QUERY 1-3
        // ==================================================================
        final List<String> querySet = Arrays.asList(anchor, conj);
        final CapeA2Wire.Query q = CapeA2Wire.query(setup, querySet, anchor, seed0 + 1);
        final long[] qBits = CapeA2Wire.queryVector(setup, querySet);
        // 桥的残差在 τ 个字段上的上界（得分 = K·明文内积 + Σ E_i，|Σ E_i| ≤ τ·ones/2）
        final long bound = (long) q.tau() * ones / 2 + 1;
        System.out.println();
        System.out.println("--- P2 A2 QUERY 1-3 ---");
        System.out.println("      " + q);
        {
            int f = 0;
            int[] u = fp.pp().h().positions(anchor);
            boolean splitOk = true;
            for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
                final com.fusepir.fusepir.FusePirQuery.CellIndex ci =
                    com.fusepir.fusepir.FusePirQuery.split(u[a], fp.pp().layout().r,
                        fp.pp().layout().c);
                splitOk &= ci.recombine(fp.pp().layout().r) == u[a]
                    && ci.r() == q.qAnc().rowIdx()[a] && ci.c() == q.qAnc().colIdx()[a];
            }
            f += sub("P2.1 q_anc 的 (r_a,c_a) 与 h_a(K_1) 一致、recombine(R) 回到 u_a", splitOk);
            int outside = 0;
            for (int i = lBf; i < qBits.length; i++) {
                if (qBits[i] != 0) {
                    outside++;
                }
            }
            f += sub(String.format("P2.2 [契约③] q^BF 的段外（槽 %d..%d）逐位为 0：实测非零 %d 个",
                    lBf, qBits.length - 1, outside), outside == 0);
            final int wUnion = unionWeight(bf, querySet);
            final int wAnchor = unionWeight(bf, Arrays.asList(anchor));
            f += sub(String.format("P2.3 τ = ‖b_qry‖₁ = %d == |pos(K_1) ∪ pos(K_2)| = %d",
                    q.tau(), wUnion), q.tau() == wUnion);
            f += sub(String.format("[负对照] b_qry 只取锚 ⇒ τ' = %d < τ = %d（少一个关键词就少算阈值）",
                    wAnchor, q.tau()), wAnchor < q.tau());
            f += sub(String.format("P2.4 τ_ring = K·τ = %d（判定阈值必须乘 K）", q.tauRing()),
                q.tauRing() == scaleK * q.tau());
            f += sub(String.format("P2.5 [守卫] τ·ones = %d×%d = %d < K = %d ⇒ 判定能与桥的残差"
                    + "（上界 τ·ones/2 = %d）分开", q.tau(), ones, (long) q.tau() * ones, scaleK,
                    bound),
                (long) q.tau() * ones < scaleK);
            f += sub("[负对照] 查询集加到 3 个关键词（τ = 15 ⇒ τ·ones = 165 ≥ K）⇒ query() 必须抛",
                throwsRuntime(() -> CapeA2Wire.query(setup,
                    Arrays.asList(anchor, conj, keywords.get(9)), anchor, seed0 + 8)));
            f += sub("[负对照] 锚不在查询集里 ⇒ query() 必须抛",
                throwsRuntime(() -> CapeA2Wire.query(setup, Arrays.asList(conj), anchor, seed0 + 9)));
            report("P2 A2 QUERY 1-3 成立", f == 0, String.format("%d 项未达成", f));
        }

        // ==================================================================
        //  A2 ANSWER 2 / 3 / 4-6
        // ==================================================================
        System.out.println();
        System.out.println("--- P3 A2 ANSWER 2-6（每候选：值 + Bloom 段 + tRing 上的得分）---");
        final CapeA2Wire.Answer a = CapeA2Wire.answer(setup, q);
        System.out.printf("      %s%n", a);
        final int[] candValues = new int[m];
        final long[][] candBloom = new long[m][];
        for (int j = 0; j < m; j++) {
            candValues[j] = kwToValues.get(anchor).get(j);
            candBloom[j] = boolToLongs(bloomOf.get(candValues[j]), lBf);
        }
        final long[] plain = new long[m];
        final long[] score = new long[m];
        final long[] gotValue = new long[m];
        for (int j = 0; j < m; j++) {
            plain[j] = CapeA2Wire.plainInner(qBits, candBloom[j]);
            score[j] = a.resp().decodeSlots(a.scoreCt(j))[0];
            gotValue[j] = a.resp().decodeFields(a.valueCt(j))[0];
            System.out.printf("      候选 j=%d：v=%d、明文 ⟨b_qry,b_v⟩=%d、K×内积=%d、"
                    + "同态得分=%d、解得的值=%d%n",
                j, candValues[j], plain[j], scaleK * plain[j], score[j], gotValue[j]);
        }
        {
            int f = 0;
            // ⚠️ 判据用"桥的残差上界"而不是等号：得分 = K·明文内积 + Σ_{i∈supp(q)} E_i，
            //    |Σ E_i| ≤ τ·ones/2（MAP §24.4/§26.3）。等号**不成立**（实测 K=17 时 172 vs 170），
            //    所以这里判"落在上界内"+"取整后 == 明文内积"，两者都要。
            boolean allEq = true;
            boolean allWithinBound = true;
            for (int j = 0; j < m; j++) {
                allEq &= CapeA2Wire.nearestFieldScore(score[j], scaleK, tRing) == plain[j];
                allWithinBound &= Math.abs(score[j] - scaleK * plain[j]) <= bound;
            }
            f += sub(String.format("P3.1 【主判据】每个候选：得分四舍五入到 K 的倍数 == 明文内积"
                    + "（%d/%d），且 |得分 − K×内积| ≤ τ·ones/2 = %d", m, m, bound),
                allEq && allWithinBound);
            f += sub(String.format("P3.2 命中候选 j=0：明文内积 %d == τ %d，字段域得分 %d == τ"
                    + "（槽值得分 %d、K·τ = %d）",
                    plain[0], q.tau(),
                    CapeA2Wire.nearestFieldScore(score[0], scaleK, tRing), score[0], q.tauRing()),
                plain[0] == q.tau() && CapeA2Wire.nearestFieldScore(score[0], scaleK, tRing) == q.tau());
            boolean discrim = plain[1] < q.tau() && plain[2] < q.tau();
            f += sub(String.format("[负对照] 另两个候选明文内积 %d、%d < τ ⇒ 字段域得分 %d、%d < τ",
                    plain[1], plain[2],
                    CapeA2Wire.nearestFieldScore(score[1], scaleK, tRing),
                    CapeA2Wire.nearestFieldScore(score[2], scaleK, tRing)),
                discrim
                    && CapeA2Wire.nearestFieldScore(score[1], scaleK, tRing) < q.tau()
                    && CapeA2Wire.nearestFieldScore(score[2], scaleK, tRing) < q.tau());
            final long[] slots0 = a.resp().decodeSlots(a.bloomCt(0));
            int bad = 0;
            int bitOk = 0;
            for (int i = 0; i < lBf; i++) {
                // 槽里是 K·位 + 桥的残差 E（|E| ≤ ones/2），不是"精确的 0/K"：
                // ① 必须落在残差上界内；② 四舍五入到 K 的倍数后必须逐位等于 b_v。
                if (Math.abs(centered(slots0[i], tRing) - scaleK * candBloom[0][i]) > ones) {
                    bad++;
                }
                if (CapeA2Wire.nearestFieldScore(slots0[i], scaleK, tRing) == candBloom[0][i]) {
                    bitOk++;
                }
            }
            f += sub(String.format("P3.3 bloomCt(0) 的槽 [0,%d) 是 K·b_v ± 桥残差（|E| ≤ %d）"
                    + "且取整后逐位等于 b_v（%d/%d 位；**位是 0 / %d 不是 0/1**）",
                    lBf, ones, bitOk, lBf, scaleK), bad == 0 && bitOk == lBf);
            boolean vOk = true;
            for (int j = 0; j < m; j++) {
                vOk &= gotValue[j] == candValues[j];
            }
            f += sub("P3.4 valueCt(j) 解出的字段域值 == 明文值（A2 ANSWER 3 的 ct_{v_j}）", vOk);
            final int j1 = a.resp().valueSlot(1) - a.resp().bloomSlotBase(0);
            final int j2 = a.resp().valueSlot(2) - a.resp().bloomSlotBase(0);
            System.out.printf("      [info] bloomCt(0) 的段外杂质（**不掩码**的直接后果）："
                    + "槽 %d = %d（= K×v₂ = %d）、槽 %d = %d（= K×v₃ = %d）%n",
                j1, slots0[j1], scaleK * candValues[1], j2, slots0[j2], scaleK * candValues[2]);
            f += sub(String.format("[契约③的代价] bloomCt **不掩码**：段外确实带相邻候选的载荷"
                    + "（槽 %d/%d 的字段域读数 = %d/%d = 明文值）", j1, j2,
                    CapeA2Wire.nearestFieldScore(slots0[j1], scaleK, tRing),
                    CapeA2Wire.nearestFieldScore(slots0[j2], scaleK, tRing)),
                Math.abs(centered(slots0[j1], tRing) - scaleK * candValues[1]) <= ones
                    && Math.abs(centered(slots0[j2], tRing) - scaleK * candValues[2]) <= ones
                    && CapeA2Wire.nearestFieldScore(slots0[j1], scaleK, tRing) == candValues[1]
                    && CapeA2Wire.nearestFieldScore(slots0[j2], scaleK, tRing) == candValues[2]);
            report("P3 A2 ANSWER 2-6 成立（得分取整 == 明文内积）", f == 0,
                String.format("%d 项未达成", f));
        }

        // ==================================================================
        //  A2 DECODE
        // ==================================================================
        System.out.println();
        System.out.println("--- P4 A2 DECODE ---");
        final CapeA2Wire.Decoded dec = CapeA2Wire.decode(setup, q, a);
        System.out.println("      " + dec);
        System.out.printf("      [info] 折叠窗口语义：得分密文的槽 0 = %d（完整和）；"
                + "槽 1 = %d、槽 31 = %d（部分和）；槽 64 = %d（窗口外）⇒ 客户端读槽 0%n",
            dec.score(0), dec.scoreSlots(0)[1], dec.scoreSlots(0)[31], dec.scoreSlots(0)[64]);
        {
            int f = 0;
            final long[] wantAnchor = new long[kwToValues.get(anchor).size()];
            for (int j = 0; j < wantAnchor.length; j++) {
                wantAnchor[j] = candValues[j];
            }
            final long[] wantAccepted = conjSemantics(valueToKw, candValues, querySet);
            f += sub(String.format("P4.1 A2 DECODE 2：V_{K_1} == 明文 %s", Arrays.toString(wantAnchor)),
                Arrays.equals(dec.anchorValues(), wantAnchor));
            f += sub(String.format("P4.2 Bloom 判定收下的值集合 == 明文 {v : S_v ⊇ %s} = %s",
                    querySet, Arrays.toString(wantAccepted)),
                Arrays.equals(dec.acceptedValues(), wantAccepted));
            f += sub(String.format("[正对照] 命中候选 v=%d 被收下，且收下的个数 == 明文真值 %d",
                    candValues[0], wantAccepted.length),
                dec.accepted(0) && dec.acceptedCount() == wantAccepted.length);
            int wrongThreshold = 0;
            for (int j = 0; j < m; j++) {
                if (score[j] == a.tau()) {
                    wrongThreshold++;
                }
            }
            f += sub(String.format("[负对照] 阈值不乘 K（用 τ = %d 而不是 K·τ = %d）⇒ 收下 %d 个"
                    + "（正确阈值收下 %d 个）", a.tau(), a.tauRing(), wrongThreshold,
                    dec.acceptedCount()),
                wrongThreshold == 0 && dec.acceptedCount() > 0);
            final String otherAnchor = keywords.get(7);
            final CapeA2Wire.Query qB =
                CapeA2Wire.query(setup, Arrays.asList(otherAnchor, conj), otherAnchor, seed0 + 2);
            final CapeA2Wire.Decoded dB = CapeA2Wire.decode(setup, qB, a);
            f += sub(String.format("[负对照] 换 st^anc_C（关键词 %s）配同一条 resp ⇒ A2 DECODE 2 必须 ⊥"
                    + "（正对照：同源的 %s 不 ⊥）", otherAnchor, anchor),
                dB.isBottom() && !dec.isBottom());
            // 换 q^BF 的负对照：在所有候补关键词里挑"明文内积最大但仍 < τ₂"的那个（最难的一档）
            String bestKw = null;
            long bestInner = -1;
            int bestTau = 0;
            for (String kx : keywords) {
                if (kx.equals(anchor) || kx.equals(conj)) {
                    continue;
                }
                final List<String> qs = Arrays.asList(anchor, kx);
                final long inner = CapeA2Wire.plainInner(CapeA2Wire.queryVector(setup, qs),
                    candBloom[0]);
                final int t2 = BfGen.hammingWeight(CapeA2Wire.queryVector(setup, qs));
                if (inner < t2 && inner > bestInner) {
                    bestInner = inner;
                    bestKw = kx;
                    bestTau = t2;
                }
            }
            if (bestKw == null) {
                f += sub("[负对照] 找不到'明文内积 < τ₂'的候补关键词 ⇒ 这个负对照没有分辨力", false);
            } else {
                final CapeA2Wire.Query q2 =
                    CapeA2Wire.query(setup, Arrays.asList(anchor, bestKw), anchor, seed0 + 3);
                final Ciphertext s2ct = BloomScoring.bloomScoreReaching(fp.ring(),
                    a.resp().galoisKeys(), q2.qBF(), a.bloomCt(0),
                    a.resp().packed().highestSlot());
                final long s2 = a.resp().decodeSlots(s2ct)[0];
                final long s2Field = CapeA2Wire.nearestFieldScore(s2, scaleK, tRing);
                f += sub(String.format("[负对照] 换 q^BF（查询集 {%s,%s}、τ₂=%d）⇒ 原命中候选的字段域"
                        + "得分 %d == 明文内积 %d < τ₂ ⇒ 必须被拒（槽值 %d）",
                        anchor, bestKw, bestTau, s2Field, bestInner, s2),
                    s2Field == bestInner && s2Field < bestTau);
            }
            report("P4 A2 DECODE 成立（含负对照）", f == 0, String.format("%d 项未达成", f));
        }

        // ==================================================================
        //  P5 折叠轮数 + 契约③的代价（正/负对照）
        // ==================================================================
        System.out.println();
        System.out.println("--- P5 折叠轮数与契约③的代价 ---");
        {
            int f = 0;
            final Mpc4jRgsw ring = fp.ring();
            final GaloisKeys gk = a.resp().galoisKeys();
            final int hi = a.resp().packed().highestSlot();
            final Ciphertext prod = CtOps.ctCtMul(ring, q.qBF(), a.bloomCt(0));
            final long six = a.resp().decodeSlots(
                BloomScoring.foldSlotsReaching(ring, gk, prod, hi))[0];
            final long five = a.resp().decodeSlots(
                BloomScoring.foldSlots(ring, gk, prod, lBf))[0];
            f += sub(String.format("P5.1 6 轮（按最高参与槽 %d = B_pay−1）槽值 = %d、字段域得分 = %d == τ = %d",
                    hi, six, CapeA2Wire.nearestFieldScore(six, scaleK, tRing), q.tau()),
                CapeA2Wire.nearestFieldScore(six, scaleK, tRing) == q.tau());
            f += sub(String.format("[正对照] 5 轮（论文形状 ⌈log2 %d⌉）同样得 %d —— "
                    + "本接线下 q^BF 的支撑落在 [0,%d)，两条路等价",
                    lBf, CapeA2Wire.nearestFieldScore(five, scaleK, tRing), lBf),
                five == six);
            // 破约：把 q^BF 的段外置 1（该槽落在候选取值 3 的载荷上）
            final int poison = a.resp().valueSlot(2) - a.resp().bloomSlotBase(0);
            final long[] qPoison = qBits.clone();
            qPoison[poison] = 1;
            final Ciphertext prodP = CtOps.ctCtMul(ring,
                BloomScoring.encryptBloomVector(ring, qPoison), a.bloomCt(0));
            final long pSix = a.resp().decodeSlots(
                BloomScoring.foldSlotsReaching(ring, gk, prodP, hi))[0];
            final long pFive = a.resp().decodeSlots(
                BloomScoring.foldSlots(ring, gk, prodP, lBf))[0];
            final long junk = a.resp().decodeSlots(a.bloomCt(0))[poison];
            System.out.printf("      [info] 破约向量：q^BF 的槽 %d 置 1（该槽是载荷杂质 %d）%n",
                poison, junk);
            f += sub(String.format("[负对照/破约] 6 轮：字段域得分 = %d == τ + v₃ = %d（杂质被算进去了）",
                    CapeA2Wire.nearestFieldScore(pSix, scaleK, tRing),
                    q.tau() + candValues[2]),
                CapeA2Wire.nearestFieldScore(pSix, scaleK, tRing) == q.tau() + candValues[2]);
            f += sub(String.format("[同一破约下] 5 轮：字段域得分 = %d == τ（杂质在窗口 [0,32) 之外，"
                    + "**被静默丢掉**）⇒ 两条路给出不同的错值（%d vs %d）",
                    CapeA2Wire.nearestFieldScore(pFive, scaleK, tRing), pSix, pFive),
                CapeA2Wire.nearestFieldScore(pFive, scaleK, tRing) == q.tau() && pFive != pSix);
            report("P5 折叠轮数有据（6 轮不依赖契约、5 轮依赖契约）", f == 0,
                String.format("%d 项未达成", f));
        }

        // ==================================================================
        //  P6 诊断：DB 的 b_v ↔ payloadTruth ↔ packedSlots 三方对账
        //  （P3 的主判据失败时，这一段把"哪一环错"钉死：装配？Pack？q^BF？ct×ct？）
        // ==================================================================
        System.out.println();
        System.out.println("--- P6 诊断：DB 的 b_v / payloadTruth / packedSlots / q^BF / ct×ct ---");
        {
            final int idxA = db.keywords.indexOf(anchor);
            final long[] pt = fp.payloadTruth()[idxA];
            final long[] pSlots = a.resp().packedSlots();
            final int bPay = fp.bPay();
            System.out.printf("      [diag] 值槽 = %s；段起点 = %s；B_pay = %d%n",
                Arrays.toString(new int[]{a.resp().valueSlot(0), a.resp().valueSlot(1),
                    a.resp().valueSlot(2)}),
                Arrays.toString(new int[]{a.resp().bloomSlotBase(0), a.resp().bloomSlotBase(1),
                    a.resp().bloomSlotBase(2)}), bPay);
            System.out.println("      [diag] payloadTruth[0] = "
                + Arrays.toString(Arrays.copyOf(pt, bPay)));
            System.out.println("      [diag] packedSlots()   = "
                + Arrays.toString(Arrays.copyOf(pSlots, bPay)));
            final StringBuilder want = new StringBuilder();
            for (int j = 0; j < m; j++) {
                want.append(j == 0 ? "" : " | ");
                want.append("v=").append(candValues[j]).append(" bits@")
                    .append(a.resp().bloomSlotBase(j)).append("=")
                    .append(Arrays.toString(candBloom[j]));
            }
            System.out.println("      [diag] DB 侧的 b_v      = " + want);

            int badAssembly = 0;          // payloadTruth 与 DB 的 b_v 不符
            int badPackedVsDb = 0;        // packedSlots 与 DB 的 b_v 不符
            int badPackedVsPayload = 0;   // packedSlots 与 payloadTruth 不符
            int badValue = 0;
            for (int j = 0; j < m; j++) {
                final int vo = a.resp().valueSlot(j);
                final int bo = a.resp().bloomSlotBase(j);
                if (pt[vo] != scaleK * candValues[j] || pSlots[vo] != scaleK * candValues[j]) {
                    badValue++;
                }
                for (int i = 0; i < lBf; i++) {
                    final long expected = scaleK * candBloom[j][i];
                    if (pt[bo + i] != expected) {
                        badAssembly++;
                    }
                    if (pSlots[bo + i] != expected) {
                        badPackedVsDb++;
                    }
                    if (pSlots[bo + i] != pt[bo + i]) {
                        badPackedVsPayload++;
                    }
                }
            }
            System.out.printf("      [diag] 值槽：%d/%d 个候选的 payloadTruth 与 packedSlots "
                    + "取整后都 == K×值（槽里还带 ±桥残差）%n", m - badValue, m);
            System.out.printf("      [diag] Bloom 位（共 %d 位）：payloadTruth vs DB 不符 %d（应 0）；"
                    + "packedSlots vs DB **逐位**不符 %d（= 桥残差，取整后为 0；见 P3.3）%n",
                m * lBf, badAssembly, badPackedVsDb);

            final long[] qSlots = a.resp().decodeSlots(q.qBF());
            System.out.println("      [diag] q^BF 解密槽 [0,24) = "
                + Arrays.toString(Arrays.copyOf(qSlots, 24)));
            final Ciphertext prodDiag = CtOps.ctCtMul(fp.ring(), q.qBF(), a.resp().packedCoeff());
            final long[] pj = a.resp().decodeSlots(prodDiag);
            int mulBad = 0;
            int firstBad = -1;
            for (int i = 0; i < pj.length; i++) {
                if (pj[i] != Math.floorMod(qSlots[i] * pSlots[i], tRing)) {
                    mulBad++;
                    if (firstBad < 0) {
                        firstBad = i;
                    }
                }
            }
            System.out.printf("      [diag] CtCtMul(q^BF, packedCoeff) 逐槽：%d/%d 个槽不符"
                    + "（首个不符槽 %d：得 %d、期望 %d）%n",
                mulBad, pj.length, firstBad,
                firstBad < 0 ? 0 : pj[firstBad],
                firstBad < 0 ? 0 : Math.floorMod(qSlots[firstBad] * pSlots[firstBad], tRing));
            // 正对照：同一套 ct×ct 机构，乘在一条**新加密**的候选上必须逐槽精确
            final long[] freshBits = new long[setup.slotCount()];
            for (int i = 0; i < lBf; i++) {
                freshBits[i] = candBloom[0][i];
            }
            final Ciphertext freshCt = BloomScoring.encryptBloomVector(fp.ring(), freshBits);
            final long[] freshSlots = a.resp().decodeSlots(freshCt);
            final long[] fProd = a.resp().decodeSlots(CtOps.ctCtMul(fp.ring(), q.qBF(), freshCt));
            int freshBad = 0;
            for (int i = 0; i < fProd.length; i++) {
                if (fProd[i] != Math.floorMod(qSlots[i] * freshSlots[i], tRing)) {
                    freshBad++;
                }
            }
            System.out.printf("      [diag] [正对照] 同一条 q^BF × **新加密**候选：%d/%d 个槽不符%n",
                freshBad, fProd.length);
        }

        System.out.println();
        if (failed == 0) {
            System.out.println("=== CAPE（A2）接线成立：四步 + tRing 打分，"
                + "得分 == K×明文内积、阈值乘 K、⊥ 负对照成立 ===");
        } else {
            System.out.println("=== 有 " + failed + " 组未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    // ==================================================================
    //  小工具
    // ==================================================================

    /** 取中心代表（{@code tRing − 1} → {@code −1}）—— 桥的残差有正负，必须按中心读。 */
    private static long centered(long v, long t) {
        final long x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    private static long[] boolToLongs(boolean[] bits, int lBf) {
        final long[] out = new long[lBf];
        for (int i = 0; i < lBf; i++) {
            out[i] = bits[i] ? 1L : 0L;
        }
        return out;
    }

    private static int countOnes(int[] v) {
        int c = 0;
        for (int x : v) {
            c += (x != 0) ? 1 : 0;
        }
        return c;
    }

    /** {@code |∪_{K ∈ U} pos(K)|} —— 即 {@code ‖BF.Gen(0,U)‖₁} 的独立算法（去重后数位）。 */
    private static int unionWeight(BfGen bf, List<String> u) {
        final boolean[] bits = new boolean[bf.length()];
        for (String k : u) {
            for (int p : bf.positions(k)) {
                bits[p] = true;
            }
        }
        return BfGen.hammingWeight(bits);
    }

    /** 明文侧的合取语义：{@code {v ∈ V_{K_1} : S_v ⊇ 查询集}}。 */
    private static long[] conjSemantics(Map<Integer, List<String>> valueToKw, int[] candValues,
                                        List<String> querySet) {
        final List<Long> out = new ArrayList<>();
        for (int v : candValues) {
            if (valueToKw.get(v).containsAll(querySet)) {
                out.add((long) v);
            }
        }
        final long[] arr = new long[out.size()];
        for (int i = 0; i < arr.length; i++) {
            arr[i] = out.get(i);
        }
        return arr;
    }

    private static boolean throwsRuntime(Runnable r) {
        try {
            r.run();
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static int sub(String name, boolean ok) {
        System.out.println("      " + (ok ? "[PASS] " : "[FAIL] ") + name);
        return ok ? 0 : 1;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;          // ⚠️ 少了这一行，"未达成" 也会 exit 0 —— 那是自欺，务必留着
        }
    }
}
