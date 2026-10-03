package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.fusepir.AnswerOps;
import com.fusepir.fusepir.FusePirFourStep;
import com.fusepir.fusepir.FusePirPackSlot;
import com.fusepir.fusepir.FusePirQuery;
import com.fusepir.prim.BlindRotateOps;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * <b>ANSWER 6（盲旋转）的二分辨识探针</b>（2026-10-15，承接 HANDOFF §4.1）。
 *
 * <h3>它要回答的两个问题</h3>
 * <ol>
 *   <li><b>Q1：盲旋转本身对不对？</b> 用 HANDOFF §4.1 的①②③ 三步：
 *       ① 把 {@code HashGenRhoTest} P-9 那条已知通过的配方原样搬进本管线
 *       （同源比特 + 直接加密的累加器），并用 {@code r_a} 奇/偶各跑一遍；
 *       ② {@code Mpc4jRgsw.cmux} 的分支方向（bit=1 到底返回哪个）；
 *       ③ {@code β ≡ ⟨a,s_L⟩ + r_a (mod 2N)} 逐路核对。</li>
 *   <li><b>Q2：判据里的"真值"本身对不对？</b> 即建表用的位置函数种子与
 *       {@code pp} 里发布的 ρ_H 是不是同一个。
 *       <p><b>为什么必须问这个</b>：{@code BffHash.positions(K, seed, hg)} 的
 *       {@code seed} 与 {@code hg.rhoH} 是<b>同一个量而函数不校验一致</b>
 *       （{@code BffHash.java:490}）；{@code BffEncode.encode} 的
 *       {@code seed = seed0 + attempt − 1} 又<b>不是</b>调用方传进来的 ρ_H。
 *       两处一旦取不同常量，协议会<b>静默</b>查不到库里已有的关键词。</li>
 * </ol>
 *
 * <h3>⚠️ 这份探针的意义在于"分开"</h3>
 * 主探针 {@code FusePirFourStepTest} 的 P4.0 是一条<b>端到端</b>判据
 * （相位 == {@code payloadTruth}）。它一旦为 0/61，就把"旋转错"与"真值错"
 * 混在一起了。本探针把两者拆成两条互不依赖的断言：
 * <ul>
 *   <li><b>落点自洽</b>：相位 == {@code P_{c_a,b}[r_a]}（用<b>查询自己</b>给出的 (r_a,c_a)）；
 *       —— 它不问"这对 (r_a,c_a) 对不对"，只问"旋转有没有把那个系数搬到常数项"；</li>
 *   <li><b>真值同源</b>：{@code Σ_a D[u_a][b] == payloadTruth[b]} 用的是<b>哪一套</b> u_a。</li>
 * </ul>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.FusePirAnswerBisectTest 16 4096 16 18}
 */
public final class FusePirAnswerBisectTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int nkw = args.length > 0 ? Integer.parseInt(args[0]) : 16;
        final int n = args.length > 1 ? Integer.parseInt(args[1]) : 4096;
        final int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        final int lBf = args.length > 3 ? Integer.parseInt(args[3]) : 18;
        final long rhoH = 20261015L;
        final long seed0 = 20261016L;

        System.out.println("=== ANSWER 6 二分辨识（Q1 旋转本身 / Q2 真值同源）===");
        final FusePirFourStep.Db db = FusePirFourStep.Db.synthetic(nkw, 3, lBf > 0, lBf, seed0);
        final FusePirFourStep fp = FusePirFourStep.setup(db, n, d, lBf, rhoH, seed0);
        System.out.printf("[setup] %s%n", fp);
        System.out.printf("[setup] 探针传入：ρ_H = %d（A3 SETUP 8 的位置函数种子）、"
            + "seed0 = %d（BFF.Encode 重试用）%n%n", rhoH, seed0);

        final int probeIdx = Math.min(3, nkw - 1);
        final String anchor = db.keywords.get(probeIdx);
        final List<String> kws = db.keywords;
        final int k = FusePirFourStep.K_PATHS;
        final int R = fp.pp().layout().r;

        // ==================================================================
        //  Q2：建表位置函数 vs pp 里发布的 ρ_H —— 同源吗？
        // ==================================================================
        System.out.println("--- Q2 建表侧位置 vs pp 发布的位置（同源判据）---");
        final int[][] posTab = fp.positions();                       // 建表实际用的
        final int[][] posPp = new int[nkw][];
        for (int i = 0; i < nkw; i++) {
            posPp[i] = fp.pp().h().positions(kws.get(i));            // 查询实际用的
        }
        int badKw = 0;
        for (int i = 0; i < nkw; i++) {
            if (!Arrays.equals(posTab[i], posPp[i])) {
                badKw++;
            }
        }
        System.out.printf("      [info] %d/%d 个关键词的两套位置**不一致**%n", badKw, nkw);
        System.out.printf("      [info] 锚关键词 %s：建表 %s；pp %s%n",
            anchor, Arrays.toString(posTab[probeIdx]), Arrays.toString(posPp[probeIdx]));
        report(String.format("Q2.1 建表位置函数与 pp 的位置函数逐位一致（%d/%d 个关键词不符）",
                badKw, nkw),
            badKw == 0,
            badKw == 0
                ? "⇒ 同源，P4.0 的 0/61 与种子无关"
                : "⇒ **不同源**：查询选的是别的格子 ⇒ 相位不可能是真值（P4.0 的 0/61 由此而来）");

        // ---- Q2.2 找出建表到底用了哪个种子（不是猜，是搜） ----
        //  正对照：必须**恰好一个**种子能复现 posTab；否则说明"位置函数"本身不可复现。
        final BffHash.BffParams bp = BffHash.allocate(nkw, k);
        long tabSeed = Long.MIN_VALUE;
        int seedHits = 0;
        for (long s = rhoH - 4; s <= rhoH + 4; s++) {
            final int[][] cand = BffHash.positions(kws, s, bp, k);
            boolean same = true;
            for (int i = 0; i < nkw && same; i++) {
                same = Arrays.equals(cand[i], posTab[i]);
            }
            if (same) {
                tabSeed = s;
                seedHits++;
            }
        }
        System.out.printf("      [info] 在 [%d, %d] 里搜到 %d 个种子能复现建表位置：%s%n",
            rhoH - 4, rhoH + 4, seedHits, seedHits == 1 ? String.valueOf(tabSeed) : "—");
        System.out.printf("      [info] 建表 seed = %s；调用方传的 ρ_H = %d；"
            + "pp 用的种子 = %s%n", seedHits == 1 ? String.valueOf(tabSeed) : "?",
            rhoH, seedHits == 1 && Arrays.equals(
                BffHash.positions(kws, tabSeed, bp, k)[probeIdx], posPp[probeIdx])
                ? String.valueOf(tabSeed) : "（与建表不同！）");
        // 真正的不变量不是"seed == ρ_H"，而是"**pp 的种子 == 建表的种子**"
        // （重试成功时两者都不等于调用方传的 ρ_H，那时上面那条等式不再成立，但这条仍必须成立）。
        boolean seedSame = seedHits == 1;
        if (seedSame) {
            final int[][] candTab = BffHash.positions(kws, tabSeed, bp, k);
            for (int i = 0; i < nkw && seedSame; i++) {
                seedSame = Arrays.equals(candTab[i], posPp[i]);
            }
        }
        report("Q2.2 建表种子可被唯一复现，且 pp 用的就是那一个（ρ_H = tab.seed）",
            seedSame,
            seedSame
                ? String.format("建表 seed = %d；ρ_H = %d ⇒ 首次尝试即成功，两者相等", tabSeed, rhoH)
                : "⇒ pp 发布的 ρ_H 与建表用的种子不是同一个（这正是 0/61 的根因）");

        // ---- Q2.3 两套 u_a 给出的明文侧和：只有一套能等于真值 ----
        final int bProbe = 4;
        final long[] truth = fp.payloadTruth()[probeIdx];
        final long[] sumTab = new long[fp.bPay()];
        final long[] sumPp = new long[fp.bPay()];
        final int[][] posWrong = BffHash.positions(kws, rhoH + 1, bp, k);   // 故意错一号种子
        final long[] sumWrong = new long[fp.bPay()];
        for (int a = 0; a < k; a++) {
            for (int b = 0; b < fp.bPay(); b++) {
                sumTab[b] = Math.floorMod(sumTab[b] + fp.bffArray()[posTab[probeIdx][a]][b],
                    fp.ringModulus());
                sumPp[b] = Math.floorMod(sumPp[b] + fp.bffArray()[posPp[probeIdx][a]][b],
                    fp.ringModulus());
                sumWrong[b] = Math.floorMod(sumWrong[b] + fp.bffArray()[posWrong[probeIdx][a]][b],
                    fp.ringModulus());
            }
        }
        int okTab = 0;
        int okPp = 0;
        int okWrong = 0;
        for (int b = 0; b < fp.bPay(); b++) {
            if (sumTab[b] == truth[b]) {
                okTab++;
            }
            if (sumPp[b] == truth[b]) {
                okPp++;
            }
            if (sumWrong[b] == truth[b]) {
                okWrong++;
            }
        }
        report(String.format("Q2.3 [正对照] 建表那套 u_a 的和 == 真值：%d/%d 个字段", okTab, fp.bPay()),
            okTab == fp.bPay(),
            "这一条与 P2 同源（BFF 重构恒等式），用建表位置 ⇒ 必须全中");
        report(String.format("Q2.4 [负对照] 把种子挪一号（ρ_H+1）再求和 == 真值：%d/%d 个字段",
                okWrong, fp.bPay()),
            okWrong != fp.bPay(),
            "这一条**必须不全中** —— 否则说明「位置函数换种子却不影响结果」，"
                + "Q2.1/Q2.3 都是空检查");
        report(String.format("Q2.4b pp 那套 u_a 的和 == 真值：%d/%d 个字段", okPp, fp.bPay()),
            okPp == fp.bPay(),
            okPp == fp.bPay()
                ? "⇒ 修好之后 pp 与建表同源（这一条在修复前是 0/61）"
                : "⇒ 仍然不同源：pp 与建表用的还不是同一个种子");

        // ---- Q2.5 [负对照] 守卫真的会抛（守卫不能只是"写在旁边没人用"） ----
        {
            final com.fusepir.fusepir.FusePirParams bad = new com.fusepir.fusepir.FusePirParams(
                com.fusepir.fusepir.FusePirParams.bffPositions(rhoH + 1, bp.hashGen(rhoH + 1)),
                com.fusepir.fusepir.FusePirParams.fingerprint(),
                fp.pp().layout(), d, FusePirFourStep.T, fp.ring().q);
            boolean threw = false;
            try {
                FusePirFourStep.requirePositionsMatch(bad, kws, posTab);
            } catch (IllegalStateException e) {
                threw = true;
            }
            boolean okThrew = false;
            try {
                FusePirFourStep.requirePositionsMatch(fp.pp(), kws, posTab);   // 正例：不许抛
                okThrew = true;
            } catch (IllegalStateException e) {
                okThrew = false;
            }
            report("Q2.5 守卫 requirePositionsMatch：拿错种子的 pp ⇒ 必须抛；"
                + "拿正取的 pp ⇒ 必须不抛",
                threw && okThrew,
                "这一条防的是 §18.6 那类「守卫写在旁边没人用」：只断言「它存在」是不够的，"
                    + "要真调它一次看它会不会响");        }

        // ==================================================================
        //  Q1：盲旋转本身 —— 用**查询自己**给出的 (r_a,c_a)
        // ==================================================================
        final FusePirFourStep.Query q = fp.query(anchor, seed0 + 1);
        System.out.println();
        System.out.println("--- Q1 盲旋转本身 ---");
        System.out.printf("      [info] %s%n", q);

        final Mpc4jRgsw m = fp.ring();
        final int[] sL = fp.secretBits();
        final long t = fp.ringModulus();
        final int qL = 2 * n;
        final Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(sL[i]);            // 与 setup 逐字同一构造
        }

        // ---- ③ β ≡ ⟨a,s_L⟩ + r_a (mod 2N) ----
        int betaBad = 0;
        final StringBuilder betaInfo = new StringBuilder();
        for (int a = 0; a < k; a++) {
            final long[] av = q.qRow()[a][0];
            final long beta = q.qRow()[a][1][0];
            long ip = 0;
            for (int i = 0; i < d; i++) {
                ip = (ip + av[i] * sL[i]) % qL;
            }
            final long want = Math.floorMod(q.rowIdx()[a], qL);
            betaInfo.append(String.format("路%d: β−⟨a,s⟩=%d, r_a=%d; ", a,
                Math.floorMod(beta - ip, qL), want));
            if (Math.floorMod(beta - ip, qL) != want) {
                betaBad++;
            }
        }
        report(String.format("Q1.1 [§4.1③] β ≡ ⟨a,s_L⟩ + r_a (mod %d)：%d/%d 路成立（%s）",
                qL, k - betaBad, k, betaInfo.toString().trim()),
            betaBad == 0, betaBad == 0 ? "相位约定成立" : "q^row 的 β 与 (a,s_L,r_a) 不自洽");

        // ---- ② cmux 的分支方向 ----
        {
            final long[] ca = new long[n];
            final long[] cb = new long[n];
            ca[0] = 111L;
            cb[0] = 222L;
            final Ciphertext A = m.encrypt(ca);
            final Ciphertext B = m.encrypt(cb);
            final long got1 = Math.floorMod(m.decrypt(m.cmux(m.encryptRgswConstant(1), A, B))[0], t);
            final long got0 = Math.floorMod(m.decrypt(m.cmux(m.encryptRgswConstant(0), A, B))[0], t);
            System.out.printf("      [info] cmux(RGSW(1),A=111,B=222) → %d；"
                + "cmux(RGSW(0),A,B) → %d%n", got1, got0);
            report("Q1.2 [§4.1②] cmux 的分支方向：c=0 得 an(=A)、c=1 得 bn(=B) "
                + "⇒ 「bit=1 时返回第二个参数」",
                got1 == 222 && got0 == 111,
                (got1 == 222 && got0 == 111)
                    ? "⇒ 与 blindRotateByBits 注释一致（z_i=1 时取旋转支）⇒ 方向不是 bug"
                    : "⇒ **方向反了**：累的会是 X^{Σa_i(1−s_i)}，相位看起来就像随机数");
        }

        // ---- ① P-9 配方原样搬进本管线（同一把 m：铺开秘密 + N=4096）----
        //  P-9 与这里的**唯一**差别就是 acc 的来源：P-9 是 m.encrypt(P)，本管线是 columnSelect 的产物。
        //
        //  ⚠️ 判据必须容忍 `rnsToT` 的**缩放残差**（不是旋转错）：
        //     `rnsToT` 把 β 与 N 个 a_k **各自**从 q_R 四舍五入到 Z_t，相位里因此多出
        //     Σ_k δ_k·s_k（δ_k ∈ (−½,½]）⇒ |残差| ≤ #ones/2（实测 §24.4 / §26.3：最大 1–2）。
        //     判据因此写"|偏差| ≤ ones"，而**不是** == 0；与旋转错的区分靠"错 r 的偏差大得多"这条负对照。
        {
            final long[] p = new long[n];
            for (int i = 0; i < n; i++) {
                p[i] = (i % (t - 1)) + 1;
            }
            final Ciphertext accDirect = m.encrypt(p);
            final Random rnd = new Random(20261015L);
            int ones = 0;
            for (int v : sL) {
                ones += (v != 0) ? 1 : 0;
            }
            final long tol = ones;                       // 残差上界：#ones/2 向上取整 ⇒ 用 #ones 更松
            final int[] rs = {5, 2, 1, 0, 3, 6};
            int exact = 0;
            long maxDev = 0;
            final StringBuilder det = new StringBuilder();
            for (int rA : rs) {
                final long[][] qRow = BlindRotateOps.lweEncryptIndex(sL, rA, qL, rnd);
                final Ciphertext ap = BlindRotateOps.blindRotateRow(m, bk, accDirect,
                    qRow[0], qRow[1][0]);
                final long[] zt = FusePirPackSlot.rnsToT(m, AnswerOps.sampleExtract0Rns(m, ap));
                final long got = AnswerOps.phaseOf(Arrays.copyOf(zt, d + 1), sL, t);
                final long want = Math.floorMod(p[rA], t);
                final long dev = Math.abs(centered(got, t) - centered(want, t));
                if (dev == 0) {
                    exact++;
                }
                maxDev = Math.max(maxDev, dev);
                det.append(String.format("r=%d:%d/%d(偏差%d) ", rA, got, want, dev));
            }
            System.out.printf("      [info] 残差上界 tol = #ones = %d；精确命中 %d/%d%n",
                tol, exact, rs.length);
            report(String.format("Q1.3 [§4.1①] P-9 配方（直接加密的累加器 + 同源比特）"
                    + "在本管线里 6/6 个 r_a 读回 p_r（偏差 ≤ %d；%s）", tol,
                    det.toString().trim()),
                maxDev <= tol,
                (maxDev <= tol)
                    ? String.format("⇒ 盲旋转 + 真密文自举密钥在这把 m（铺开秘密、N=%d）上正确，"
                        + "奇偶 r 都行；非零偏差只有 %d（= rnsToT 的缩放残差）"
                        + " ⇒ 问题只可能在 acc 的来源或 (r_a,c_a) 本身", n, maxDev)
                    : "⇒ P-9 配方在**本管线**上就不成立（偏差 " + maxDev + " 远超残差上界）"
                        + " ⇒ 先修这里，别去动 columnSelect");
        }

        // ---- ①a 负对照：同一个配方，r 取错 ⇒ 偏差必须远超残差上界 ----
        {
            final long[] p = new long[n];
            for (int i = 0; i < n; i++) {
                p[i] = (i % (t - 1)) + 1;
            }
            final Ciphertext accDirect = m.encrypt(p);
            int ones = 0;
            for (int v : sL) {
                ones += (v != 0) ? 1 : 0;
            }
            final Random rnd = new Random(20261015L);
            final long[][] qRow = BlindRotateOps.lweEncryptIndex(sL, 5, qL, rnd);   // β ≡ ⟨a,s⟩+5
            // 但按 r=4 的期望去读 ⇒ 必须差得远（否则 Q1.3 的判据没有分辨力）
            final Ciphertext ap = BlindRotateOps.blindRotateRow(m, bk, accDirect,
                qRow[0], qRow[1][0]);
            final long[] zt = FusePirPackSlot.rnsToT(m, AnswerOps.sampleExtract0Rns(m, ap));
            final long got = AnswerOps.phaseOf(Arrays.copyOf(zt, d + 1), sL, t);
            // ⚠️ 期望值必须取**离得远**的那一格：先前取 p[4]（= 5）时，旋转残差 −1 恰好让
            //    got = 5 = p[4]，负对照因此"通过"了却什么也没证明。这就是判据没分辨力的形态。
            final long wrongWant = Math.floorMod(p[5 + 100], t);                // 故意错 100 格
            final long dev = Math.abs(centered(got, t) - centered(wrongWant, t));
            // ⚠️ 2026-10-15 修正：这里原来写的是 `centered(got,t) == centered(p[5],t)`（**逐位精确**），
            //    与同一条断言里的 `dev > ones`（认了 ≤ #ones 的残差）**自相矛盾** ⇒
            //    只要 r=5 那一次的 rnsToT 残差不是 0，它就会红（实测读回 5 而 p[5] = 6，差 1）。
            //    而残差是**每次运行都不同**的：同一个探针两次运行的 r=2 偏差分别是 1 和 2
            //    （`m.encrypt` 每次重新随机化 `a`）⇒ 这是一条**非确定性**断言，不是接线回归。
            //    负对照真正要证的是"判据在分辨 r"：与正确格子的差 ≤ ones、与错 100 格的差 ≫ ones。
            final long devNear = Math.abs(centered(got, t) - centered(Math.floorMod(p[5], t), t));
            report(String.format("Q1.3b [负对照] 拿 r=105 的期望去读 r=5 的结果 ⇒ 偏差 %d 必须 > %d",
                    dev, ones),
                dev > ones && devNear <= ones,
                String.format("读回 %d：与 p[5] = %d 差 %d（≤ 残差上界 %d ✓）；"
                    + "与 p[105] = %d 差 %d（≫ %d ⇒ 判据确实在分辨 r，不是恒真）",
                    got, p[5], devNear, ones, wrongWant, dev, ones));
        }

        // ---- ①b 落点自洽：真 acc + 真 qRow，逐路问"常数项是不是 P_{c_a,b}[r_a]" ----
        {
            int okLand = 0;
            long maxDevLand = 0;
            int ones = 0;
            for (int v : sL) {
                ones += (v != 0) ? 1 : 0;
            }
            final StringBuilder det = new StringBuilder();
            for (int a = 0; a < k; a++) {
                final Ciphertext acc = AnswerOps.columnSelect(m, q.qCol()[a], fp.stS(), bProbe);
                final Ciphertext ap = AnswerOps.blindRotateStep(m, bk, acc,
                    q.qRow()[a][0], q.qRow()[a][1][0]);
                final long[] zt = FusePirPackSlot.rnsToT(m, AnswerOps.sampleExtract0Rns(m, ap));
                final long got = AnswerOps.phaseOf(Arrays.copyOf(zt, d + 1), sL, t);
                final long want = Math.floorMod(
                    fp.stS().polynomial((int) q.colIdx()[a], bProbe)[(int) q.rowIdx()[a]], t);
                final long dev = Math.abs(centered(got, t) - centered(want, t));
                if (dev <= ones) {
                    okLand++;
                }
                maxDevLand = Math.max(maxDevLand, dev);
                det.append(String.format("路%d(r=%d,c=%d):%d/%d(偏差%d) ", a,
                    q.rowIdx()[a], q.colIdx()[a], got, want, dev));
            }
            report(String.format("Q1.4 ★ 真 acc + 真 qRow：常数项 == P_{c_a,b}[r_a]（b=%d）"
                    + "%d/%d 路（偏差 ≤ %d；%s）", bProbe, okLand, k, ones, det.toString().trim()),
                okLand == k,
                (okLand == k)
                    ? "⇒ **ANSWER 5 与 ANSWER 6 都是对的**：旋转把查询指定的那个系数精确搬到了常数项"
                        + "（非零偏差只有 " + maxDevLand + "，即 rnsToT 的缩放残差）"
                        + " ⇒ 剩下的唯一问题是「查询指定的 (r_a,c_a) 是不是锚关键词所在的格子」"
                    : "⇒ 旋转没把 P_{c_a,b}[r_a] 搬到常数项（最大偏差 " + maxDevLand
                        + " 远超残差上界）⇒ ANSWER 6 真有问题，继续查它");
        }

        // ---- ①c 负对照：把 β 加 1 ⇒ 落点必须变（否则 Q1.4 是恒真检查） ----
        {
            final Ciphertext acc = AnswerOps.columnSelect(m, q.qCol()[0], fp.stS(), bProbe);
            final Ciphertext ap = AnswerOps.blindRotateStep(m, bk, acc,
                q.qRow()[0][0], Math.floorMod(q.qRow()[0][1][0] + 1, qL));
            final long[] zt = FusePirPackSlot.rnsToT(m, AnswerOps.sampleExtract0Rns(m, ap));
            final long got = AnswerOps.phaseOf(Arrays.copyOf(zt, d + 1), sL, t);
            final long want = Math.floorMod(
                fp.stS().polynomial((int) q.colIdx()[0], bProbe)[(int) q.rowIdx()[0]], t);
            report("Q1.5 [负对照] β+1 ⇒ 常数项必须变（证明 Q1.4 有分辨力）",
                got != want, String.format("β+1 读回 %d，原落点 %d", got, want));
        }

        // ---- ①d 探针 P4.0c 的搜索空间为什么会 0 命中（解释，不是断言） ----
        System.out.println();
        System.out.println("--- Q3 P4.0c 的搜索空间为什么必然 0 命中 ---");
        for (int a = 0; a < k; a++) {
            final int uTab = posTab[probeIdx][a];
            final int uPp = posPp[probeIdx][a];
            System.out.printf("      路%d：建表 u=%d（r=%d,c=%d）｜查询 u=%d（r=%d,c=%d）%n",
                a, uTab, uTab % R, uTab / R, uPp, uPp % R, uPp / R);
        }
        System.out.println("      ⇒ P4.0c 用建表那套 u 固定列，而相位来自查询那套 u 的列；"
            + "两列不同 ⇒ 组合空间里根本不含真解（0/729 是结构性的，不是'落点不是 P 的系数'）");

        System.out.println();
        System.out.println(failed == 0
            ? "=== 二分辨识：全部断言达成 ==="
            : "=== 有 " + failed + " 项未达成 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 把 {@code v ∈ Z_t} 取到中心代表（{@code (−t/2, t/2]}），用于算"差几个单位"。 */
    private static long centered(long v, long t) {
        final long x = Math.floorMod(v, t);
        return x > t / 2 ? x - t : x;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[达成] " : "[未达成] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
