package com.fusepir.probe;

import com.fusepir.bff.BffEncode;
import com.fusepir.fusepir.AnswerOps;
import com.fusepir.fusepir.FusePirFourStep;
import com.fusepir.fusepir.FusePirClientState;
import com.fusepir.fusepir.FusePirQuery;
import com.fusepir.fusepir.FusePirSetup;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Arrays;
import java.util.List;

/**
 * <b>FusePIR 四个入口，按 CAPE（Algorithm 2）的调用顺序驱动一遍。</b>
 *
 * <h3>它复现的调用序列（逐字来自 A2 原文）</h3>
 * <pre>
 * A2 SETUP  11: (pp_F, st^F_S, sk) ← FusePIR.Setup(1^λ, DB^CAPE)     ← 传的是 CAPE 加宽后的 DB
 * A2 QUERY   1: (q_anc, st^anc_C) ← FusePIR.Query(pp_F, sk, K_1)
 * A2 ANSWER  2: resp_anc ← FusePIR.Answer(st_S, q_anc)
 * A2 ANSWER  3: Parse {(ct_{v_j}, ct^BF_j)}_{j=1}^m from resp_anc    ← ★ 本探针的 P5
 * A2 DECODE  2: V_{K_1} ← FusePIR.Decode(sk, st^anc_C, resp_anc)
 * </pre>
 *
 * <h3>判据</h3>
 * <ol>
 *   <li>{@code DB^CAPE} 是**加宽**的（每个值带 {@code b_v}）⇒ {@code perValue = 1+ℓ_BF}、
 *       {@code B_pay = 61}（与 MAP §18.5 的 CAPE 列一致）—— 这是"CAPE 那条路"的标志；</li>
 *   <li>明文侧重构 {@code Σ_a D[h_a(K)] = y_K}；</li>
 *   <li>四步端到端：{@code Decode} 出正确的值集合；</li>
 *   <li><b>P5（CAPE 专属）</b>：{@code resp.valueCt(j)} 的槽 0 == 第 j 个候选的值；
 *       {@code resp.bloomCt(j)} 的槽 {@code [0,ℓ_BF)} == 该候选的 {@code b_v} 位
 *       —— 这正是 A2 ANSWER 3 要的 {@code ct^BF_j}；</li>
 *   <li>负对照：换关键词的 {@code st^anc_C} ⇒ 必须 {@code ⊥}。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirFourStepTest 16 4096 16 18}
 * （{@code nkw N d ℓ_BF}）
 */
public final class FusePirFourStepTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int nkw = args.length > 0 ? Integer.parseInt(args[0]) : 16;
        final int n = args.length > 1 ? Integer.parseInt(args[1]) : 4096;
        final int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        final int lBf = args.length > 3 ? Integer.parseInt(args[3]) : 18;
        final long rhoH = 20261015L;
        final long seed0 = 20261016L;

        System.out.println("=== FusePIR 四入口（按 CAPE 的调用顺序）===");
        // A2 SETUP 3-10：先把每个值配对成 (v, b_v) —— 这就是 DB^CAPE
        FusePirFourStep.Db db = FusePirFourStep.Db.synthetic(nkw, 3, lBf > 0, lBf, seed0);
        System.out.printf("[DB^CAPE] %d 个关键词，每个 1..3 个 (v, b_v)，b_v ∈ {0,1}^%d%n%n",
            nkw, lBf);

        // ============ A2 SETUP 11 ============
        long t0 = System.nanoTime();
        final FusePirFourStep fp;
        try {
            fp = FusePirFourStep.setup(db, n, d, lBf, rhoH, seed0);
        } catch (RuntimeException e) {
            System.out.println("[FAIL] FusePIR.Setup 抛异常：" + e);
            e.printStackTrace(System.out);
            System.exit(1);
            return;
        }
        System.out.printf("[setup ] %s%n", fp);
        System.out.printf("[setup ] %.0f ms；t=%d（可批处理）、perValue=%d%n%n",
            (System.nanoTime() - t0) / 1e6, FusePirFourStep.T, FusePirSetup.perValue(lBf));

        // ---- P1 SETUP 形状 ----
        System.out.println("--- P1 FusePIR.Setup 的形状 ---");
        int p1 = 0;
        final int expectBpay = FusePirSetup.payloadBpay(
            FusePirSetup.fpSlots(FusePirFourStep.T), 3, 1 + lBf);
        p1 += sub(String.format("P1.1 B_pay = %d（= fpSlots+1+m·(1+ℓ_BF) = %d，CAPE 加宽口径）",
            fp.bPay(), expectBpay), fp.bPay() == expectBpay);
        p1 += sub(String.format("P1.2 R·C = %d ≥ L_BFF = %d，R = %d ≤ N",
                (long) fp.pp().layout().r * fp.pp().layout().c, fp.pp().layout().lBff,
                fp.pp().layout().r),
            (long) fp.pp().layout().r * fp.pp().layout().c >= fp.pp().layout().lBff
                && fp.pp().layout().r <= n);
        p1 += sub("P1.3 铺开后的秘密：非零数 == s_L 里 1 的个数，且下标全 < d",
            liftedSupportOk(fp));
        p1 += sub("P1.4 st^F_S 的表宽 == B_pay", fp.stS().bPay() == fp.bPay());
        report(String.format("P1 形状正确（BFF.Encode 用了 %d 次尝试）", fp.encodeAttempts()),
            p1 == 0, String.format("%d 项未达成", p1));

        // ---- P2 明文侧重构 ----
        System.out.println();
        System.out.println("--- P2 明文侧重构 Σ_a D[h_a(K)] = y_K ---");
        int bad = 0;
        for (int i = 0; i < nkw; i++) {
            long[] rec = BffEncode.reconstruct(fp.bffArray(), fp.positions()[i],
                FusePirFourStep.K_PATHS, fp.bPay(), fp.ringModulus());
            if (!Arrays.equals(rec, fp.payloadTruth()[i])) {
                bad++;
            }
        }
        report(String.format("P2 %d/%d 个关键词满足重构恒等式", nkw - bad, nkw), bad == 0,
            String.format("%d 个不满足", bad));

        // ============ A2 QUERY 1 ============
        final int probeIdx = Math.min(3, nkw - 1);            // 故意不查第 0 个
        final String anchor = db.keywords.get(probeIdx);
        FusePirFourStep.Query q = fp.query(anchor, seed0 + 1);
        System.out.println();
        System.out.println("--- P3 FusePIR.Query ---");
        System.out.println("      " + q);
        int p3 = 0;
        int[] u = fp.pp().h().positions(anchor);
        boolean splitOk = true;
        for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
            FusePirQuery.CellIndex ci = FusePirQuery.split(u[a], fp.pp().layout().r,
                fp.pp().layout().c);
            splitOk &= ci.recombine(fp.pp().layout().r) == u[a]
                && ci.r() == q.rowIdx()[a] && ci.c() == q.colIdx()[a];
        }
        p3 += sub("P3.1 (r_a,c_a) 与 h_a(K_1) 一致，recombine(R) 回到 u_a", splitOk);
        boolean inRange = true;
        for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
            inRange &= q.rowIdx()[a] >= 0 && q.rowIdx()[a] < fp.pp().layout().r
                && q.colIdx()[a] >= 0 && q.colIdx()[a] < fp.pp().layout().c
                && q.qRow()[a][0].length == d
                && q.qCol()[a].length == fp.pp().layout().c;
        }
        p3 += sub("P3.2 r_a ∈ [0,R)、c_a ∈ [0,C)、q^row 长 d、q^col 有 C 条", inRange);
        p3 += sub("P3.3 st^anc_C 只带关键词", anchor.equals(q.stC().keyword()));
        report("P3 Query 形状正确", p3 == 0, String.format("%d 项未达成", p3));

        // ============ A2 ANSWER 2 ============
        System.out.println();
        System.out.println("--- P4 FusePIR.Answer（含真槽位域 Pack）---");
        long t1 = System.nanoTime();
        FusePirFourStep.Resp resp = fp.answer(q);
        System.out.printf("      %s%n", resp);
        System.out.printf("      ANSWER %.0f ms%n", (System.nanoTime() - t1) / 1e6);

        // ============ P4.00 隔离实验：列选择之后、盲旋转之前 ============
        //  这一条把"列选择错"与"旋转落点错"分开（MAP §27.3 指定的最小实验）。
        {
            final int bProbe = 4;                       // 挑一个有真值的字段
            int cA = (int) q.colIdx()[0];
            Ciphertext accDbg = com.fusepir.fusepir.AnswerOps.columnSelect(
                fp.ring(), q.qCol()[0], fp.stS(), bProbe);
            long[] poly = fp.ring().decrypt(accDbg);
            long[] want = fp.stS().polynomial(cA, bProbe);
            int diff = 0;
            int firstDiff = -1;
            for (int i = 0; i < want.length; i++) {
                if (Math.floorMod(poly[i], fp.ringModulus())
                        != Math.floorMod(want[i], fp.ringModulus())) {
                    if (firstDiff < 0) {
                        firstDiff = i;
                    }
                    diff++;
                }
            }
            report(String.format("P4.00 列选择 acc == P_{c_a,b}（c_a=%d, b=%d）：%d/%d 个系数不符",
                    cA, bProbe, diff, want.length),
                diff == 0,
                diff == 0
                    ? "⇒ 列选择是对的，错在盲旋转那一步（P4.0 的偏差来自旋转落点）"
                    : String.format("⇒ 列选择就错了（首个不符在下标 %d：解出 %d，期望 %d）"
                        + "—— 盲旋转还没参与", firstDiff,
                        Math.floorMod(poly[firstDiff], fp.ringModulus()),
                        Math.floorMod(want[firstDiff], fp.ringModulus())));
            System.out.printf("      [info] want[0..3]=%s  poly[0..3]=%s%n",
                Arrays.toString(Arrays.copyOf(want, 4)),
                Arrays.toString(Arrays.copyOf(
                    new long[]{Math.floorMod(poly[0], fp.ringModulus()),
                        Math.floorMod(poly[1], fp.ringModulus()),
                        Math.floorMod(poly[2], fp.ringModulus()),
                        Math.floorMod(poly[3], fp.ringModulus())}, 4)));

            // ---- P4.0d 形态实测（不依赖 isNttForm 标志） ----
            //  原理：NTT ∘ iNTT = 恒等。
            //    · 若 acc 本来是【系数形态】，先 NTT 再 iNTT 应当**还原** ⇒ 解出来还是 P；
            //    · 若 acc 本来是【NTT 形态】，再来一次 NTT 会把它**搞坏** ⇒ 解出来不再是 P。
            //  —— 所以"往返后还对不对"就是形态的判据，比任何标志都硬。
            {
                Ciphertext round = new Ciphertext();
                round.copyFrom(accDbg);
                if (!round.isNttForm()) {
                    fp.ring().evaluator.transformToNttInplace(round);      // 先转 NTT
                }
                fp.ring().evaluator.transformFromNttInplace(round);        // 再转回系数
                long[] poly2 = fp.ring().decrypt(round);
                int diff2 = 0;
                for (int i = 0; i < want.length; i++) {
                    if (Math.floorMod(poly2[i], fp.ringModulus())
                            != Math.floorMod(want[i], fp.ringModulus())) {
                        diff2++;
                    }
                }
                System.out.printf("      [info] acc.isNttForm() 报告 = %s；"
                        + "多标签往返后 %d/%d 个系数不符%n",
                    accDbg.isNttForm(), diff2, want.length);
                report(String.format("P4.0d acc 的真实形态：往返后 %d/%d 系数不符", diff2, want.length),
                    diff2 == 0,
                    diff2 == 0
                        ? "⇒ acc 本来就是【系数形态】（NTT∘iNTT 还原成功）⇒ 盲旋转的输入形态是对的，"
                            + "形态不是 bug 的原因"
                        : "⇒ acc 本来是【NTT 形态】⇒ 盲旋转拿它做 multiplyPowerOfX 是错的"
                            + "（NTT 域乘 X^k ≠ 乘单项式）—— 这就是 ANSWER 6 错的原因");
            }
        }

        // ============ P4.0 先单独验 ANSWER 5-11（与 Pack 完全无关的判据） ============
        //  ⚠️ 这里**必须分两层**报，否则会把"桥的残差"误报成"盲旋转错"（本轮之前正是这么错的，
        //     结果是 0/61 挂了很久、还顺带否掉了三条本来没错的假设）：
        //   ① 交付层：`rnsToT` 把 β 与 N 个 a_k **各自**舍入到 Z_t ⇒ 相位多出 Σδ_k·s_k
        //      （上界 #ones/2）。判据只能是"|偏差| ≤ 上界"，且必须同时报精确命中数。
        //   ② 算术层：`AnswerOps.phaseOfRns` 先在 Z_{q_R} 里把相位算完、**只舍入一次**
        //      ⇒ "相位 == 真值"在这一层是**精确**判据（这是真正在判 ANSWER 5-6 的算术）。
        {
            long[][][] rnsAll = fp.answerRnsSamples(q);
            long[] truth = fp.payloadTruth()[probeIdx];
            final int[] sB = fp.secretBits();
            int ones = 0;
            for (int v : sB) {
                ones += (v != 0) ? 1 : 0;
            }
            final long tol = ones;
            long[] phaseRaw = new long[fp.bPay()];       // 同一批，**未除 K**（落点搜索要用它）
            long[] exactRaw = new long[fp.bPay()];
            long[] phase = new long[fp.bPay()];          // 交付层（过 rnsToT）
            long[] exact = new long[fp.bPay()];          // 算术层（Z_q 上算完只舍入一次）
            int wrong = 0;                               // 交付层：超出残差上界
            int inTol = 0;                               // 交付层：在残差上界内
            int exactHit = 0;                            // 交付层：恰好相等
            int mathHit = 0;                             // 算术层：精确相等
            long worst = 0;
            final long tRing = fp.ringModulus();
            final long kScale = fp.scale();
            for (int b = 0; b < fp.bPay(); b++) {
                long[] zt = AnswerOps.toTruncatedZLwe(fp.ring(), rnsAll[b], sB.length);
                long[] a = Arrays.copyOfRange(zt, 1, zt.length);
                long beta = zt[0];
                long acc = 0;
                for (int k = 0; k < a.length; k++) {
                    acc += a[k] * sB[k];
                }
                // 槽/样本域是 tRing，且字段被存成 K·field ⇒ 先还原到**字段域**再比真值。
                //   🔴 "两个模数混淆"是本轮最容易犯的静默错：不除 K 就是 K 倍差、不换模就是取模差。
                final long rawPhase = Math.floorMod(beta - Math.floorMod(acc, tRing), tRing);
                final long rawExact = AnswerOps.phaseOfRns(fp.ring(), rnsAll[b], sB);
                phaseRaw[b] = rawPhase;
                exactRaw[b] = rawExact;
                phase[b] = FusePirSetup.divideScale(new long[]{rawPhase}, kScale, tRing,
                    FusePirFourStep.T)[0];
                exact[b] = FusePirSetup.divideScale(new long[]{rawExact}, kScale, tRing,
                    FusePirFourStep.T)[0];
                final long truthField = truth[b] / kScale;      // truth 就是 K·field（整除）
                final long dev = Math.abs(centered(phase[b], FusePirFourStep.T)
                    - centered(truthField, FusePirFourStep.T));
                worst = Math.max(worst, dev);
                if (dev != 0) {
                    wrong++;
                    if (wrong <= 5) {
                        System.out.printf("      [info] 字段 %d：相位 %d，真值 %d（偏差 %d）%n",
                            b, phase[b], truthField, dev);
                    }
                } else {
                    exactHit++;
                }
                if (dev <= tol) {
                    inTol++;
                }
                if (exact[b] == Math.floorMod(truthField, FusePirFourStep.T)) {
                    mathHit++;
                }
            }
            System.out.printf("      [info] 交付层精确命中 %d/%d；在残差上界内 %d/%d；最大偏差 %d"
                    + "（K = %d，除 K 之前的残差上界 = #ones = %d）%n",
                exactHit, fp.bPay(), inTol, fp.bPay(), worst, kScale, tol);
            System.out.printf("      [info] 算术层（Z_{q_R} 上算完只舍入一次）精确命中 %d/%d%n",
                mathHit, fp.bPay());
            report(String.format("P4.0a ★ ANSWER 5-11 的**算术层**相位 == 真值：%d/%d 个字段"
                    + "（Z_{q_R} 上算完相位、只舍入一次 ⇒ 无容差）", mathHit, fp.bPay()),
                mathHit == fp.bPay(),
                "这是唯一一条**精确**判据；它对而 P4.0b 用未除 K 的槽值时偏差 ≤ #ones/2，"
                    + "就说明那点偏差是 q_R→Z_t 桥的缩放残差（MAP §24.4/§26.3）、不是 ANSWER 的算术错");
            report(String.format("P4.0b ANSWER 5-11 的**交付层**相位（除以 K 之后）== 真值："
                    + "%d/%d 个字段（最大偏差 %d）", inTol, fp.bPay(), worst),
                inTol == fp.bPay(),
                "字段以 K 倍精度存放 ⇒ 除以 K 一次舍入就把残差整个吸收掉（K > ones 是硬要求）");

            // ---- P4.0b 正/负对照：符号假设 & 落点规则（都与**未除 K** 的相位比）----
            //  ⚠️ 必须用 `exactRaw`（未除 K）：`bffArray()` 里存的就是 K·field，
            //     拿它跟"除过 K"的相位比就是差 K 倍 —— 本轮踩过一次。
            {
                final int R = fp.pp().layout().r;
                int[] uu = fp.positions()[probeIdx];
                final long t = fp.ringModulus();
                long[] signed = new long[fp.bPay()];
                long[] plain = new long[fp.bPay()];
                StringBuilder par = new StringBuilder();
                boolean mixedParity = false;
                for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
                    int r = uu[a] % R;
                    int c = uu[a] / R;
                    par.append(r).append(r % 2 == 1 ? "(奇,+) " : "(偶,−) ");
                    long sign = (r % 2 == 1) ? 1L : -1L;          // (−1)^{r+1}
                    if (r % 2 == 0) {
                        mixedParity = true;
                    }
                    for (int b = 0; b < fp.bPay(); b++) {
                        signed[b] = Math.floorMod(signed[b] + sign * fp.bffArray()[r + c * R][b], t);
                        plain[b] = Math.floorMod(plain[b] + fp.bffArray()[r + c * R][b], t);
                    }
                }
                int hit = 0;
                int hitPlain = 0;
                for (int b = 0; b < fp.bPay(); b++) {
                    if (Math.floorMod(signed[b], t) == Math.floorMod(exactRaw[b], t)) {
                        hit++;
                    }
                    if (Math.floorMod(plain[b], t) == Math.floorMod(exactRaw[b], t)) {
                        hitPlain++;
                    }
                }
                System.out.printf("      [info] 三路 r_a = %s⇒ 带符号和命中 %d/%d、"
                    + "不带符号和命中 %d/%d 个字段%n", par, hit, fp.bPay(), hitPlain, fp.bPay());
                report(String.format("P4.0b [正对照] 不带符号的重构和 == 算术层相位（未除 K）：%d/%d",
                        hitPlain, fp.bPay()),
                    hitPlain == fp.bPay(),
                    "BFF 的重构恒等式（Σ_a D[h_a(K)] = y_K）在密文侧成立 ⇒ "
                        + "旋转落点就是 +P[r_a]，不带任何奇偶符号");
                report(String.format("P4.0b2 [负对照] 带符号和 (−1)^{r_a+1} == 相位：%d/%d"
                        + "（三路 r_a 奇偶%s）", hit, fp.bPay(),
                        mixedParity ? "混杂 ⇒ 必须不全中" : "全奇 ⇒ 与不带符号不能区分，本条跳过"),
                    !mixedParity || hit != fp.bPay(),
                    mixedParity
                        ? "既证伪「常数项带 (−1)^{r+1} 符号」（MAP §27.3.1 的 P4.0b 假设）"
                        : "本条对全奇的 r_a 没有分辨力（如实说明，不硬凑）");
            }
            // ---- P4.0c 暴力找"落点规则"：每路贡献 ±P[k] 还是 0？ ----
            //  真规则必须对**全部 61 个字段**都成立（规则不该依赖 b），这是个强筛子。
            {
                final int RR = fp.pp().layout().r;
                int[] uu2 = fp.positions()[probeIdx];
                final long t = fp.ringModulus();
                int[][] cand = new int[FusePirFourStep.K_PATHS][];
                final int candN = 2 * RR + 1;
                for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
                    cand[a] = new int[]{uu2[a] % RR, uu2[a] / RR};
                }
                int found = 0;
                StringBuilder desc = new StringBuilder();
                for (int i0 = 0; i0 < candN; i0++) {
                    for (int i1 = 0; i1 < candN; i1++) {
                        for (int i2 = 0; i2 < candN; i2++) {
                            int[] pick = {i0, i1, i2};
                            int match = 0;
                            for (int b = 0; b < fp.bPay(); b++) {
                                long sum = 0;
                                for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
                                    if (pick[a] == candN - 1) {
                                        continue;                 // 0 这一档
                                    }
                                    final int k = pick[a] / 2;
                                    final long sg = (pick[a] % 2 == 0) ? 1L : -1L;
                                    sum = Math.floorMod(sum
                                        + sg * fp.bffArray()[k + cand[a][1] * RR][b], t);
                                }
                                if (Math.floorMod(sum, t) == Math.floorMod(exactRaw[b], t)) {
                                    match++;
                                }
                            }
                            if (match == fp.bPay()) {
                                found++;
                                if (found <= 4) {
                                    for (int a = 0; a < FusePirFourStep.K_PATHS; a++) {
                                        final String how = (pick[a] == candN - 1) ? "0"
                                            : ((pick[a] % 2 == 0 ? "+" : "-")
                                                + "P[" + (pick[a] / 2) + "]");
                                        desc.append(String.format("路%d(r=%d):%s ",
                                            a, uu2[a] % RR, how));
                                    }
                                    desc.append(" | ");
                                }
                            }
                        }
                    }
                }
                report(String.format("P4.0c 落点规则搜索：%d 个组合能让全部 %d 个字段同时成立",
                        found, fp.bPay()),
                    found > 0,
                    found > 0
                        ? ("候选规则： " + desc + "（对照：论文应为每路 +P[r_a]，"
                            + "只应该有这一个组合）")
                        : "没有组合（±P[k] 或 0）能同时解释 61 个字段 ⇒ 落点不是"
                            + "「P 的某个系数」这种形式，问题可能在旋转量本身");
            }
        }

        // ============ ★ 四步端到端：SETUP→QUERY→ANSWER→DECODE ============
        {
            long[] got0 = decodeSafe(fp, q.stC(), resp);
            final List<FusePirFourStep.Value> v0 = db.values.get(probeIdx);
            final long[] truth0 = new long[v0.size()];
            for (int j = 0; j < v0.size(); j++) {
                truth0[j] = v0.get(j).id;
            }
            int p4b = 0;
            p4b += sub("P4.1 未被判 ⊥（A1 DECODE 6 的指纹校验通过）", got0 != null);
            p4b += sub(String.format("P4.2 V_{K_1} 恰好等于真值集合 %s（实得 %s）",
                    Arrays.toString(truth0), Arrays.toString(got0)),
                got0 != null && Arrays.equals(got0, truth0));
            report("P4 四步端到端：SETUP→QUERY→ANSWER（真 Pack）→DECODE 恢复出正确的值集合",
                p4b == 0, String.format("%d 项未达成", p4b));
        }

        // ============ A2 ANSWER 3：parse 出每个候选的 (ct_{v_j}, ct^BF_j) ============
        System.out.println();
        System.out.println("--- P5 ★ A2 ANSWER 3：从 resp_anc 里 parse 每个候选 ---");
        int p5 = 0;
        int valueOk = 0;
        int bloomOk = 0;
        final long[] pSlots = resp.packedSlots();
        int alignVal = 0;
        int alignBf = 0;
        for (int j = 0; j < fp.mCount(); j++) {
            long[] sVal = resp.decodeSlots(resp.valueCt(j));
            if (sVal[0] == pSlots[resp.valueSlot(j)]) {
                alignVal++;
            }
            if (lBf > 0) {
                long[] sBf = resp.decodeSlots(resp.bloomCt(j));
                boolean ok = true;
                for (int i = 0; i < lBf; i++) {
                    if (sBf[i] != pSlots[resp.bloomSlotBase(j) + i]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    alignBf++;
                }
            }
        }
        final StringBuilder slotInfo = new StringBuilder("值槽 [");
        for (int j = 0; j < fp.mCount(); j++) {
            slotInfo.append(j > 0 ? "," : "").append(resp.valueSlot(j));
        }
        slotInfo.append("]；Bloom 段起点 [");
        for (int j = 0; j < fp.mCount(); j++) {
            slotInfo.append(j > 0 ? "," : "").append(resp.bloomSlotBase(j));
        }
        slotInfo.append("]（旋转密钥里只有 {0}∪{1,2,4,…}）");
        System.out.printf("      [info] %s%n", slotInfo);
        p5 += sub(String.format("P5.0a [§4.2] ct_{v_j} 的槽 0 == 打包密文的槽 %d：%d/%d 个候选",
                resp.valueSlot(0), alignVal, fp.mCount()), alignVal == fp.mCount());
        if (lBf > 0) {
            p5 += sub(String.format("P5.0b [§4.2] ct^BF_j 的槽 [0,ℓ_BF) == 打包密文的槽 "
                    + "[base, base+ℓ_BF)：%d/%d 个候选", alignBf, fp.mCount()),
                alignBf == fp.mCount());
            // ---- P5.0e/g：把"旋转"与"掩码"分开（掩码那一步在打包件上不成立）----
            {
                final int base = resp.bloomSlotBase(0);
                final Ciphertext rotOnly = FusePirFourStep.rotateRowsByComposedBits(
                    fp.ring(), resp.packedCoeff(), base, resp.galoisKeys());
                final long[] rot = resp.decodeSlots(rotOnly);
                final int show = Math.min(6, lBf);
                final long[] wantSlice = Arrays.copyOfRange(pSlots, base, base + show);
                p5 += sub(String.format("P5.0e [正对照] 只旋转 base=%d（4+1，不是 2 的幂）："
                        + "槽[0..%d) 与打包件槽[%d..%d) 逐位相同（%s）", base, show, base,
                        base + show, Arrays.toString(Arrays.copyOf(rot, show))),
                    Arrays.equals(Arrays.copyOf(rot, show), wantSlice));

                final edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder beD =
                    new edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder(fp.ring().context);
                final long[] maskArr = new long[beD.slotCount()];
                for (int i = 0; i < lBf; i++) {
                    maskArr[i] = 1;
                }
                final edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext maskPt =
                    new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext();
                beD.encode(maskArr, maskPt);
                fp.ring().evaluator.transformToNttInplace(maskPt, fp.ring().context.firstParmsId());
                final long[] poly = new long[fp.ring().n];
                for (int i = 0; i < poly.length; i++) {
                    poly[i] = 100 + i;
                }
                final Ciphertext fresh = fp.ring().encrypt(poly);
                final long[] freshSlots = resp.decodeSlots(fresh);
                final Ciphertext freshNtt = new Ciphertext();
                freshNtt.copyFrom(fresh);
                fp.ring().evaluator.transformToNttInplace(freshNtt);
                final Ciphertext freshProd = new Ciphertext();
                fp.ring().evaluator.multiplyPlain(freshNtt, maskPt, freshProd);
                final long[] freshOut = resp.decodeSlots(freshProd);
                int freshOk = 0;
                for (int i = 0; i < freshOut.length; i++) {
                    if (freshOut[i] == Math.floorMod(freshSlots[i] * maskArr[i],
                            fp.ringModulus())) {
                        freshOk++;
                    }
                }
                p5 += sub(String.format("P5.0f [正对照] 同一条稠密掩码乘在**新加密**密文上："
                        + "%d/%d 个槽精确 ⇒ 掩码这套机构本身没错", freshOk, freshOut.length),
                    freshOk == freshOut.length);

                final Ciphertext packedMasked = new Ciphertext();
                fp.ring().evaluator.multiplyPlain(resp.packed().ct(), maskPt, packedMasked);
                final long[] pm = resp.decodeSlots(packedMasked);
                int pmOk = 0;
                for (int i = 0; i < pm.length; i++) {
                    if (pm[i] == Math.floorMod(pSlots[i] * maskArr[i], fp.ringModulus())) {
                        pmOk++;
                    }
                }
                final Ciphertext packedConst = new Ciphertext();
                fp.ring().evaluator.multiplyPlain(resp.packed().ct(),
                    com.fusepir.prim.RingPack.plainConstant(fp.ring(), 1L), packedConst);
                final long[] pc = resp.decodeSlots(packedConst);
                int pcOk = 0;
                for (int i = 0; i < pc.length; i++) {
                    if (pc[i] == pSlots[i]) {
                        pcOk++;
                    }
                }
                p5 += sub(String.format("P5.0g [缺陷断言] 掩码乘**打包件**：%d/%d 个槽对"
                        + "（刻意期望它错）；同一打包件 × 常数明文 1：%d/%d 个槽还原 "
                        + "⇒ 原因只能是「稠密明文的系数域乘积越界」，与噪声无关",
                        pmOk, pm.length, pcOk, pc.length),
                    pmOk == 0 && pcOk == pc.length);
            }
        }
        // 负对照：转错一格 ⇒ 必须对不上（证明 P5.0a 在分辨"对齐"，不是恒真）
        {
            final int s0 = resp.valueSlot(0);
            final Ciphertext wrong = FusePirFourStep.rotateRowsByComposedBits(
                fp.ring(), resp.packedCoeff(), s0 + 1, resp.galoisKeys());
            final long wrongSlot0 = resp.decodeSlots(wrong)[0];
            p5 += sub(String.format("P5.0c [负对照] 多转一格（槽 %d）⇒ 槽 0 解出 %d ≠ 槽 %d 的 %d",
                    s0 + 1, wrongSlot0, s0, pSlots[s0]),
                wrongSlot0 != pSlots[s0]);
        }
        // 正对照（§4.2 的精确性）：2 的幂组合 == 一次旋转 s0 —— 用"转过去再转回来"验
        {
            final int s0 = resp.valueSlot(0);
            final Ciphertext there = FusePirFourStep.rotateRowsByComposedBits(
                fp.ring(), resp.packedCoeff(), s0, resp.galoisKeys());
            final Ciphertext back = FusePirFourStep.rotateRowsByComposedBits(
                fp.ring(), there, fp.ring().n / 2 - s0, resp.galoisKeys());
            final long[] b = resp.decodeSlots(back);
            int same = 0;
            for (int i = 0; i < b.length; i++) {
                if (b[i] == pSlots[i]) {
                    same++;
                }
            }
            p5 += sub(String.format("P5.0d [§4.2 正对照] 组合旋转 s0=%d 后按 N/2−s0 转回 ⇒ "
                    + "槽逐位还原 %d/%d（复合确实等于一次旋转 s0，不是近似）",
                    s0, same, b.length), same == b.length);
        }

        final List<FusePirFourStep.Value> vs = db.values.get(probeIdx);
        for (int j = 0; j < fp.mCount(); j++) {
            long[] slotsVal = resp.decodeFields(resp.valueCt(j));
            final long wantVal = (j < vs.size()) ? vs.get(j).id : 0L;
            if (slotsVal[0] == wantVal) {
                valueOk++;
            }
            if (lBf > 0) {
                long[] slotsBf = resp.decodeFields(resp.bloomCt(j));
                boolean bitsOk = true;
                for (int i = 0; i < lBf; i++) {
                    final long wantBit = (j < vs.size()) ? vs.get(j).bloom[i] : 0L;
                    if (slotsBf[i] != wantBit) {
                        bitsOk = false;
                        break;
                    }
                }
                if (bitsOk) {
                    bloomOk++;
                }
                if (j == 0) {
                    System.out.printf("      [info] 候选 0：值槽解出 %d（真值 %d，偏差 %d）；"
                            + "Bloom 槽 [0,%d) 与真值%s%n",
                        slotsVal[0], wantVal, slotsVal[0] - wantVal, lBf,
                        Arrays.equals(Arrays.copyOf(slotsBf, lBf),
                            Arrays.copyOf((j < vs.size() ? vs.get(j).bloom : new long[lBf]), lBf))
                            ? "一致" : "不一致");
                }
            }
        }
        p5 += sub(String.format("P5.1 ct_{v_j} 的**字段域**值 == 真值：%d/%d 个候选",
                valueOk, fp.mCount()), valueOk == fp.mCount());
        if (lBf > 0) {
            p5 += sub(String.format("P5.2 ct^BF_j 的 ℓ_BF 位（字段域）== 真值：%d/%d 个候选",
                bloomOk, fp.mCount()), bloomOk == fp.mCount());
        }
        report("P5 A2 ANSWER 3 的 parse 成立（槽对齐 + 字段域取值）", p5 == 0,
            String.format("%d 项未达成", p5));

        // ============ A2 DECODE 2 ============
        System.out.println();
        System.out.println("--- P6 FusePIR.Decode ---");
        long[] got = decodeSafe(fp, q.stC(), resp);
        int p6 = 0;
        p6 += sub("P6.1 没被判 ⊥（指纹校验通过）", got != null);
        final long[] truth = new long[vs.size()];
        for (int j = 0; j < vs.size(); j++) {
            truth[j] = vs.get(j).id;
        }
        p6 += sub(String.format("P6.2 V_{K_1} 恰好等于真值集合 %s", Arrays.toString(truth)),
            got != null && Arrays.equals(got, truth));
        report("P6 Decode 恢复出正确的 V_{K_1}", p6 == 0, String.format("%d 项未达成", p6));

        // ============ P7 负对照 + 覆盖 ============
        System.out.println();
        System.out.println("--- P7 负对照与覆盖 ---");
        final String other = db.keywords.get((probeIdx + 1) % nkw);
        FusePirFourStep.Query qOther = fp.query(other, seed0 + 2);
        long[] wrong = decodeSafe(fp, qOther.stC(), resp);
        report("P7.1 [负对照] 用 " + other + " 的 st^anc_C 解同一个 resp_anc ⇒ 必须 ⊥",
            wrong == null, wrong == null ? "已拒（指纹不符）" : "没拒！指纹校验形同虚设");

        int covered = 0;
        int ok = 0;
        for (int i : new int[]{0, 1, Math.max(0, nkw / 2), nkw - 1}) {
            covered++;
            FusePirFourStep.Query qq = fp.query(db.keywords.get(i), seed0 + 10 + i);
            FusePirFourStep.Resp rr = fp.answer(qq);
            long[] dd = decodeSafe(fp, qq.stC(), rr);
            final List<FusePirFourStep.Value> vv = db.values.get(i);
            final long[] tt = new long[vv.size()];
            for (int j = 0; j < vv.size(); j++) {
                tt[j] = vv.get(j).id;
            }
            if (Arrays.equals(dd, tt)) {
                ok++;
            } else {
                System.out.printf("      [FAIL] 关键词 #%d（%s）→ %s；真值 %s%n",
                    i, db.keywords.get(i), Arrays.toString(dd), Arrays.toString(tt));
                final long[] yGot = FusePirSetup.divideScale(rr.decodeSlots(rr.packed().ct()),
                    rr.scale(), fp.ringModulus(), FusePirFourStep.T);
                final long[] yWant = fp.payloadTruth()[i];
                final long sc = fp.scale();
                final int nShow = Math.min(6, yGot.length);
                final long[] wantField = new long[nShow];
                for (int jj = 0; jj < nShow; jj++) {
                    wantField[jj] = yWant[jj] / sc;
                }
                System.out.printf("      [info] 字段域 y（前 %d）：实得 %s；真值 %s%n",
                    nShow, Arrays.toString(Arrays.copyOf(yGot, nShow)),
                    Arrays.toString(wantField));
            }
        }
        report(String.format("P7.2 抽查 %d 个关键词，%d 个恢复正确", covered, ok), ok == covered,
            String.format("%d 个不对", covered - ok));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== FusePIR 四个入口全部通过（含真槽位域 Pack 与 A2 ANSWER 3 的 parse）===");
        } else {
            System.out.println("=== 有 " + failed + " 项未达成 ===");
        }
        if (failed != 0) {
            System.exit(1);
        }
    }

    /**
     * <b>包一层 {@code decode}：载荷被破坏时它会抛，探针要如实报出来。</b>
     *
     * <p>不包的话，一次 {@code IllegalArgumentException} 会把 P5/P6/P7 全部带走 ——
     * 那样报告里只剩"崩了"，看不出到底哪几层是对的。
     */
    private static long[] decodeSafe(FusePirFourStep fp, FusePirClientState stC,
                                     FusePirFourStep.Resp resp) {
        try {
            return fp.decode(stC, resp);
        } catch (RuntimeException e) {
            System.out.println("      [info] decode 抛异常：" + e.getMessage());
            return null;
        }
    }

    private static boolean liftedSupportOk(FusePirFourStep fp) {
        long[] s = com.fusepir.prim.LweRlweConversion.rlweSecretCoefficientsCentered(fp.ring());
        int[] sL = fp.secretBits();
        int ones = 0;
        for (int v : sL) {
            ones += (v != 0) ? 1 : 0;
        }
        int nz = 0;
        int maxIdx = -1;
        for (int i = 0; i < s.length; i++) {
            if (s[i] != 0) {
                nz++;
                maxIdx = i;
            }
        }
        System.out.printf("      [info] 秘密非零 %d 个（s_L 里 1 有 %d 个）、最高下标 %d（d=%d）%n",
            nz, ones, maxIdx, sL.length);
        return nz == ones && maxIdx < sL.length;
    }

    private static long centered(long v, long t) {
        long x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    private static int sub(String name, boolean ok) {
        return sub("", name, ok);
    }

    private static int sub(String id, String name, boolean ok) {
        System.out.println("      " + (ok ? "[PASS] " : "[FAIL] ") + id + " " + name);
        return ok ? 0 : 1;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}