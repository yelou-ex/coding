package com.fusepir.probe;

import com.fusepir.bff.BffHash;
import com.fusepir.bff.CapeDemoData;
import com.fusepir.prim.BlindRotateOps;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.Mpc4jRgsw;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * <b>把伪代码里"一次调用"的两处补成一次调用之后的验收（纯 Java：无服务、无 HTTP、无 native）</b>。
 *
 * <pre>
 *   Run（cwd = coding\rgsw-lab，即 run-mpc4j.ps1 所在目录）:
 *     .\run-mpc4j.ps1 -Class com.fusepir.probe.HashGenRhoTest "..\cape-demo\db\keywords.json"
 *     .\run-mpc4j.ps1 -Class com.fusepir.probe.HashGenRhoTest "..\cape-demo\db\keywords.json" 2048 64
 *
 *   out_cape.txt:1908-1913  A3 SETUP 8-9: ρ_H ←$ {0,1}^λ ;
 *                                        H = {h_j : K → [L_BFF]} ← BFF.HashGen(ρ_H, L_BFF, s, k).
 *   out_cape.txt:885-889    A1 ANSWER 6:  Acc'_{a,b} ← BlindRotate(q_a^row, Acc_{a,b}).
 * </pre>
 *
 * <h3>它补的是哪两处"伪代码一行、代码两处"</h3>
 * <table border="1">
 *   <tr><th>缺口</th><th>此前</th><th>现在</th><th>本探针怎么验</th></tr>
 *   <tr><td><b>GAP 1</b> {@code BFF.HashGen} 缺 {@code ρ_H}</td>
 *       <td>{@code hashGen(L_BFF, s, k)} 只管尺寸；{@code ρ_H} 另外传给
 *           {@code positions(K, ρ_H, hg)} —— 一次调用被拆成两处</td>
 *       <td>{@link BffHash#hashGen(long, int, int, long)} + {@link BffHash.HashGen#positions(String)}</td>
 *       <td>128 个关键词（demo DB）× k=3 路 = 384 个位置，
 *           <b>与旧的两调用形态逐位比对</b>，并与<b>现场重算</b>的 h_a 比</td></tr>
 *   <tr><td><b>GAP 2</b> {@code BlindRotate(q^row, Acc)} 没有名字</td>
 *       <td>只有 {@code blindRotate(m, bk, acc, a[], b)} / {@code blindRotateByBits(...)}，
 *           收的是 {@code (a, b)} 或逐位控制位，<b>不是</b> {@code (q^row, Acc)}</td>
 *       <td>{@link BlindRotateOps#blindRotateRow(Mpc4jRgsw, Mpc4jRgsw.Rgsw[], Ciphertext, long[], long)}</td>
 *       <td>真密文跑一次 ANSWER 5-6-7：常数项必须是 {@code P_{c_a,b}[r_a]}
 *           （{@code p_i = i+1} ⇒ 期望 {@code r_a+1}），并配三条负对照</td></tr>
 * </table>
 *
 * <h3>⚠️ 哪条负对照抓哪种错误（没有负对照的等价性检查是恒真的检查）</h3>
 * <table border="1">
 *   <tr><th>负对照</th><th>模拟的错误</th><th>抓它的检查</th></tr>
 *   <tr><td><b>N-1</b> 用<b>没用过的</b>种子 {@code ρ_H=0} 当"客户端传的种子"</td>
 *       <td>种子被<b>忽略</b>：{@code HashGen} 照旧用 {@code 0}，或 {@code positions}
 *           忘了把 {@code ρ_H} 传下去（"新入口接了种子但没接线"）</td>
 *       <td>P-5 换种子必须让位置变</td></tr>
 *   <tr><td><b>N-2</b> 关键词改一个字符</td>
 *       <td>位置函数<b>不是关键词的函数</b>（常量函数 / 忘了把 K 喂进去）</td>
 *       <td>P-6 换关键词必须让位置变</td></tr>
 *   <tr><td><b>N-3</b> 把 {@code (L_BFF, s)} 悄悄换成另一组能落地的参数</td>
 *       <td>段结构被换掉（例如 {@code s} 差一倍）——位置仍落在值域内、仍互异，
 *           <b>只有与旧形态逐位比才抓得到</b></td>
 *       <td>P-4 独立重算 + P-3 旧形态逐位一致</td></tr>
 *   <tr><td><b>N-4</b> {@code β} 的符号写反（{@code β = ⟨a,s⟩ − r} 而不是 {@code + r}）</td>
 *       <td>ANSWER 6 的相位方向错 —— 本项目实测过一次（{@code BlindRotateSignProbe}）</td>
 *       <td>P-8 常数项必须等于 {@code P[r_a]}；本条<b>必须失败</b>（读回 1 或读回错值）</td></tr>
 *   <tr><td><b>N-5</b> 自举密钥比 {@code d} 短</td>
 *       <td>少转几圈 —— <b>原实现不会报错</b>，只会静默算错</td>
 *       <td>P-9 新入口必须在入口处抛</td></tr>
 * </table>
 *
 * <h3>⚠️ 本探针<b>不</b>验的东西（别把它当端到端验收）</h3>
 * <ul>
 *   <li><b>它证明不了协议路径改用了新入口。</b>生产路径的
 *       {@code CapeDemoData.buildTablesPaper} 是否真的走
 *       {@code hashGen(L_BFF, s, k, ρ_H)}，本探针只能验<b>值</b>（拿两条形态各算一遍、
 *       与 {@code tb.pos} 逐位比）—— 那是"等价"的证据，不是"接线"的证据。
 *       接线的证据是代码本身（一行 lambda），以及 {@code FusePirQueryOpsTest} 那条
 *       对表断言（它吃的是建表侧的位置表，而它<b>故意</b>保留旧的两调用形态，
 *       因为对表必须把种子与段结构分开传；见 {@link BffHash#positions(String, long, BffHash.HashGen)}）。</li>
 *   <li><b>ANSWER 6 那一半不是生产路径的验收。</b>我们的 ANSWER 步骤 4-8 跑在
 *       native/C++（{@code rgsw_blindrotate.cpp:494-512} 的 {@code blind_rotate}，
 *       在 {@code cape_answer_core:680} 被调用）。本探针用 Java 密文跑同一个式子，
 *       证明的是"<b>伪代码那一行在 Java 侧可调用、且算的是对的</b>"，
 *       <b>不是</b>"Java 那条路被生产代码用了"（它没有：0 个生产调用方，见该函数 javadoc）。</li>
 *   <li>不验 LWE 的<b>噪声</b>：{@link BlindRotateOps#lweEncryptIndex} 是本项目的
 *       "无噪声索引"约定（Δ=1、无误差项 e），所以本探针<b>不能</b>用来支持任何安全性论证。
 *       旋转对 {@code e} 零容忍（MAP §6 / README 3.4），加真实噪声后本节结论必须重跑。</li>
 *   <li>不验 {@code BFF.Encode} 的剥皮/回填（那是 {@code BffLayerTest} 的事），
 *       本探针只验位置函数与种子。</li>
 * </ul>
 */
public final class HashGenRhoTest {

    private static int checks;
    private static int fails;

    /** A3 SETUP 8 的位置函数种子：与 demo DB 的建表口径同源（不是 0 —— 0 要留给负对照）。 */
    private static final long RHO_H = 20261014L;
    /** 负对照 N-1 用的"没被用过"的种子。 */
    private static final long RHO_H_UNUSED = 0L;

    private static final int K = 3;

    private HashGenRhoTest() {
    }

    public static void main(String[] args) {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "../cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 2048;
        final int d = args.length > 2 ? Integer.parseInt(args[2]) : 64;

        try {
            gap1(dbPath);
            gap2(ringDim, d);
        } catch (Exception | AssertionError e) {
            System.out.println("  [FAIL] 探针自身抛异常（这本身就是一项失败）：");
            e.printStackTrace(System.out);
            fails++;
        }

        System.out.println();
        System.out.println((fails == 0 ? "✅ 全部通过" : "❌ 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败");
        System.out.println("   覆盖：A3 SETUP 8-9（HashGen(ρ_H, L_BFF, s, k) 四参入口 + h_a）、"
            + "A1 ANSWER 6（BlindRotate(q^row, Acc) 具名入口）");
        if (fails != 0) {
            System.exit(1);
        }
    }

    // ==================================================================
    //  GAP 1 —— BFF.HashGen(ρ_H, L_BFF, s, k)
    // ==================================================================

    private static void gap1(Path dbPath) throws Exception {
        final CapeDemoData db = CapeDemoData.load(dbPath);
        final List<String> kws = db.keywords;
        final int n = kws.size();

        System.out.println("=== GAP 1：A3 SETUP 9 的四个入参一次给全 ===");
        System.out.println("  数据库 = " + dbPath + "（关键词 " + n + " 个）");
        System.out.println("  旧形态：BffParams bp = allocate(n,k); HashGen hg = bp.hashGen();"
            + "  positions(K, ρ_H, hg)");
        System.out.println("  新形态：HashGen hg = BffHash.hashGen(L_BFF, s, k, ρ_H);  hg.positions(K)");

        check(n == 128,
            "验收口径：关键词数 = %d（本探针要求 demo DB 的 128 个 ⇒ %d × %d = %d 个位置）",
            n, n, K, n * K);
        check(db.intMeta("maxValues", -1) > 0 && db.intMeta("lBf", -1) > 0,
            "DB 载入成功且 meta 可读（maxValues=%d, l_Bf=%d, assoc=%d）",
            db.intMeta("maxValues", -1), db.intMeta("lBf", -1), db.intMeta("assoc", -1));

        // ── 建 hg：两条形态，尺寸必须来自同一个 allocate(n, k) ────────────
        final BffHash.BffParams bp = BffHash.allocate(n, K);
        final BffHash.HashGen hgNew =
            BffHash.hashGen(bp.arrayLength, bp.segmentLength, K, RHO_H);
        final BffHash.HashGen hgOld = bp.hashGen();          // 三参形态（ρ_H 钉成 0 的那个）
        final BffHash.HashGen hgViaParams = bp.hashGen(RHO_H); // BffParams 的带种子重载

        System.out.println("  " + hgNew.describe());
        System.out.println("  三个长度：L_BFF(arrayLength) = " + bp.arrayLength
            + ", s = " + bp.segmentLength + ", segmentCountLength = " + bp.segmentCountLength
            + "（CAPE Alg3 L3 的闭式 L_BFF 在 n=128 给 "
            + com.fusepir.bff.BffSetup.paperLBff(K, n, true) + "，见 MAP §12.6）");

        // ── P-1：尺寸三项逐项相同（新形态只是多带了一个种子，没有换布局）──
        check(hgNew.lBff == bp.arrayLength && hgNew.s == bp.segmentLength && hgNew.k == K
                && hgNew.segmentCount == bp.segmentCount
                && hgNew.segmentCountLength == bp.segmentCountLength,
            "P-1 新形态的段结构与 allocate(n,k) 逐项相同（L_BFF=%d, s=%d, k=%d, segCount=%d）",
            hgNew.lBff, hgNew.s, hgNew.k, hgNew.segmentCount);

        // ── P-2：ρ_H 真的装进了对象（三条路径：四参 / BffParams 带种子 / 三参）──
        check(hgNew.rhoH == RHO_H && hgViaParams.rhoH == RHO_H,
            "P-2a ρ_H 装进 HashGen：四参入口 hg.rhoH=%d、bp.hashGen(ρ_H).rhoH=%d（都 = %d）",
            hgNew.rhoH, hgViaParams.rhoH, RHO_H);
        check(hgOld.rhoH == 0L,
            "P-2b 三参入口 hashGen(L_BFF,s,k) 存的是 ρ_H=%d（**有意为之**：它不含种子参数）",
            hgOld.rhoH);

        // ── P-3 / P-4：★ 核心等价性 ──────────────────────────────────────
        //   三个证人：① 新形态（单次调用） ② 旧形态（两次调用） ③ 现场重算（独立公式）
        int newVsOldBad = 0;
        int newVsInlineBad = 0;
        int firstBadKw = -1;
        final List<String> samples = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final String kw = kws.get(i);
            final int[] viaNew = hgNew.positions(kw);                      // ① 伪代码那一行
            final int[] viaOld = BffHash.positions(kw, RHO_H, hgNew);      // ② 两次调用形态
            final int[] inline = inlinePositions(kw, RHO_H, hgNew);        // ③ 现场重算
            if (!Arrays.equals(viaNew, viaOld)) {
                newVsOldBad++;
            }
            if (!Arrays.equals(viaNew, inline)) {
                newVsInlineBad++;
            }
            if (firstBadKw < 0 && (!Arrays.equals(viaNew, viaOld) || !Arrays.equals(viaNew, inline))) {
                firstBadKw = i;
            }
            if (i < 3) {
                samples.add(kw + " → " + Arrays.toString(viaNew));
            }
        }
        System.out.println("  前 3 个关键词：" + samples);
        check(newVsOldBad == 0,
            "P-3 ★ 单次调用形态 hg.positions(K) 与旧的两调用形态 positions(K, ρ_H, hg) "
                + "对**全部 %d 个关键词 × %d 路 = %d 个位置**逐位一致",
            n, K, n * K);
        check(newVsInlineBad == 0,
            "P-4 ★ 与**现场重算**的 h_a 公式（mulhi + (h+s)^… 三条式）逐位一致 ⇒ P-3 不是拿函数跟自己对",
            null, null);
        if (firstBadKw >= 0) {
            System.out.println("    首个不一致：kw=" + firstBadKw + "（" + kws.get(firstBadKw) + "）");
        }
        // 现场重算里手写的 mulhi 必须与 JDK 的 unsignedMultiplyHigh 同一个函数
        boolean mulhiSame = true;
        final int mulhiSamples = Math.min(64, n);
        for (int i = 0; i < mulhiSamples; i++) {
            final long x = BffHash.oracleHash(kws.get(i), RHO_H);
            if (unsignedMulHi(x, hgNew.segmentCountLength)
                != Math.unsignedMultiplyHigh(x, hgNew.segmentCountLength)) {
                mulhiSame = false;
            }
        }
        check(mulhiSame,
            "P-4b 现场重算里的 mulhi（拆 32 位乘）与 Math.unsignedMultiplyHigh 逐位相同（%d 个样本）",
            (long) mulhiSamples, null);
        // ⚠️ 只有"两个实现都算对"还不足以说明 P-4b 有分辨力：再钉一条已知乘积。
        //    mulhi(2^63, 2^63) = ⌊2^126 / 2^64⌋ = 2^62。
        check(unsignedMulHi(Long.MIN_VALUE, Long.MIN_VALUE) == (1L << 62)
                && Math.unsignedMultiplyHigh(Long.MIN_VALUE, Long.MIN_VALUE) == (1L << 62),
            "[正对照] 已知乘积：mulhi(2^63, 2^63) = 2^62 —— 两个实现都给 %d",
            unsignedMulHi(Long.MIN_VALUE, Long.MIN_VALUE));

        // ── 同一个 HashGen 实例反复用 ⇒ 同一个结果（实例不是有状态的一次性对象）──
        int reusableBad = 0;
        for (int i = 0; i < n; i++) {
            if (!Arrays.equals(hgNew.positions(kws.get(i)), hgNew.positions(kws.get(i)))) {
                reusableBad++;
            }
        }
        check(reusableBad == 0,
            "P-5a 同一个 HashGen 反复调 h_a 结果不变（%d 个关键词各算两遍）—— "
                + "客户端与服务端各持一份 H 时必须一致", n, null);

        // ── P-5 / N-1：换种子必须换位置（种子被忽略就抓得到）─────────────
        final BffHash.HashGen hgZero =
            BffHash.hashGen(bp.arrayLength, bp.segmentLength, K, RHO_H_UNUSED);
        int seedChanged = 0;
        for (int i = 0; i < n; i++) {
            if (!Arrays.equals(hgNew.positions(kws.get(i)), hgZero.positions(kws.get(i)))) {
                seedChanged++;
            }
        }
        check(seedChanged > n / 2,
            "P-5 ★ [负对照 N-1] 换 ρ_H（%d → %d）⇒ %d/%d 个关键词的位置变了 —— "
                + "种子确实进到了 h_a 里（若实现忽略种子，这里是 0/%d）",
            RHO_H, RHO_H_UNUSED, seedChanged, n, n);

        // ── P-6 / N-2：换关键词必须换位置（h_a 是关键词的函数）───────────
        int kwChanged = 0;
        for (int i = 0; i < n; i++) {
            final String kw = kws.get(i);
            if (!Arrays.equals(hgNew.positions(kw), hgNew.positions(kw + "·"))) {
                kwChanged++;
            }
        }
        check(kwChanged > n / 2,
            "P-6 ★ [负对照 N-2] 关键词加一个字符 ⇒ %d/%d 个关键词的位置变了 —— "
                + "h_a 确实是 K 的函数（常量函数会在这里是 0/%d）", kwChanged, n, n);

        // ── P-7：值域 / 互异 / 连续段（新入口不改变 h_a 的三条构造性质）────
        int outOfRange = 0;
        int collisionInKw = 0;
        int notConsecutive = 0;
        int slotCollision = 0;
        final int[] occupancy = new int[bp.arrayLength];
        for (int i = 0; i < n; i++) {
            final int[] u = hgNew.positions(kws.get(i));
            for (int a = 0; a < K; a++) {
                if (u[a] < 0 || u[a] >= bp.arrayLength) {
                    outOfRange++;
                } else {
                    occupancy[u[a]]++;
                }
            }
            for (int a = 0; a < K; a++) {
                for (int b = a + 1; b < K; b++) {
                    if (u[a] == u[b]) {
                        collisionInKw++;
                    }
                }
            }
            final int seg0 = u[0] / bp.segmentLength;
            for (int a = 1; a < K; a++) {
                if (u[a] / bp.segmentLength != seg0 + a) {
                    notConsecutive++;
                }
            }
        }
        for (int u = 0; u < occupancy.length; u++) {
            if (occupancy[u] > 1) {
                slotCollision += occupancy[u] - 1;
            }
        }
        check(outOfRange == 0, "P-7a h_a 全部落在 [0, L_BFF) = [0, %d)", (long) bp.arrayLength, null);
        check(collisionInKw == 0,
            "P-7b 同一个关键词的 k=%d 个位置互异（原文 “k distinct locations”）", (long) K, null);
        check(notConsecutive == 0,
            "P-7c k 个位置落在 **k 个连续段**里（“three distinct and consecutive segments”）", null, null);
        // ⚠️ 跨关键词的槽共用是**允许的**（BFF 就是靠它换空间），这里只打印不判定。
        System.out.println("    跨关键词槽共用（**不是**错误，BFF 靠它换空间）："
            + slotCollision + " 次；被用到的槽 " + countUsed(occupancy) + "/" + bp.arrayLength);

        // ── P-8：HashGen 只有那一条真实用法（CapeDemoData 走的就是它）────
        //    没有 DB / 建表对象时退化为"值等价"的验，不假装验了接线。
        final long lBffOfPaper = com.fusepir.bff.BffSetup.paperLBff(K, n, true);
        boolean rejected = false;
        String rejectMsg = "";
        try {
            BffHash.hashGen(lBffOfPaper, bp.segmentLength, K, RHO_H);
        } catch (IllegalArgumentException e) {
            rejected = true;
            rejectMsg = e.getMessage();
        }
        check(rejected,
            "P-8 四参入口同样拒绝 CAPE Alg3 闭式那组 (L_BFF=%d, s=%d)：描述不出 BFF 布局",
            lBffOfPaper, (long) bp.segmentLength);
        if (rejected) {
            System.out.println("      拒绝理由: " + rejectMsg);
        }
        checkThrowsIae("N-5（GAP1 侧）s 不是 2 的幂必须抛",
            () -> BffHash.hashGen(bp.arrayLength, 48, K, RHO_H));
        checkThrowsIae("s = 0 必须抛（否则 mask 无意义）",
            () -> BffHash.hashGen(bp.arrayLength, 0, K, RHO_H));
        checkThrowsIae("L_BFF 不是 s 的整数倍必须抛",
            () -> BffHash.hashGen(bp.arrayLength + 1, bp.segmentLength, K, RHO_H));
        checkThrowsIae("k = 1 必须抛（BFF 的 arity 至少 2）",
            () -> BffHash.hashGen(bp.arrayLength, bp.segmentLength, 1, RHO_H));
        checkThrowsIae("(L_BFF, s) 反解出 segmentCount < 1 必须抛（L_BFF = s ⇒ segCount = 2−k < 0）",
            () -> BffHash.hashGen(bp.segmentLength, bp.segmentLength, K, RHO_H));
        // 正对照：同一条判据在合法参数上**不许**抛
        boolean accepted = true;
        try {
            BffHash.hashGen(bp.arrayLength, bp.segmentLength, K, RHO_H);
        } catch (IllegalArgumentException e) {
            accepted = false;
        }
        check(accepted, "[正对照] 上面那五条判据在合法参数 (L_BFF=%d, s=%d, k=%d) 上都不抛 ⇒ 判据有分辨力",
            (long) bp.arrayLength, (long) bp.segmentLength, (long) K);
    }

    /**
     * 现场重算的 {@code h_a} —— <b>照抄 BFF 参考实现的三条式</b>，
     * 不调用 {@code BffHash.positions}（否则就是拿函数跟自己对，恒真）。
     *
     * <pre>
     *   hash = SHA-256(ρ_H ‖ 0x00 ‖ K) 的前 8 字节（大端）
     *   h_0  = mulhi(hash, segmentCountLength)
     *   h_a  = (h_{a−1} + s) ^ ((hash >> (18·(k−1−a))) &amp; (s−1))
     * </pre>
     */
    private static int[] inlinePositions(String keyword, long rhoH, BffHash.HashGen hg) {
        final long hash = BffHash.oracleHash(keyword, rhoH);
        final int[] out = new int[hg.k];
        out[0] = (int) unsignedMulHi(hash, hg.segmentCountLength);
        for (int a = 1; a < hg.k; a++) {
            final int shift = 18 * (hg.k - 1 - a);
            out[a] = (out[a - 1] + hg.s) ^ (int) ((hash >>> shift) & hg.mask());
        }
        return out;
    }

    /** 手写版 mulhi（拆成 32×32 的四个部分积）—— 与 {@code Math.unsignedMultiplyHigh} 独立。 */
    private static long unsignedMulHi(long a, long b) {
        final long aLo = a & 0xFFFFFFFFL;
        final long aHi = a >>> 32;
        final long bLo = b & 0xFFFFFFFFL;
        final long bHi = b >>> 32;
        final long t0 = aLo * bLo;
        long w0 = t0 & 0xFFFFFFFFL;
        long k = t0 >>> 32;
        final long t1 = aHi * bLo + k;
        w0 |= (t1 << 32);
        long w1 = t1 >>> 32;
        final long t2 = aLo * bHi + (w0 & 0xFFFFFFFFL);
        k = t2 >>> 32;
        w1 += aHi * bHi + k;
        return w1;
    }

    private static int countUsed(int[] occ) {
        int c = 0;
        for (int v : occ) {
            if (v > 0) {
                c++;
            }
        }
        return c;
    }

    // ==================================================================
    //  GAP 2 —— BlindRotate(q^row, Acc)
    // ==================================================================

    private static void gap2(int ringDim, int d) {
        final int n = ringDim;
        final int qL = 2 * n;
        final long t = 65537L;
        final int cA = 2;                        // A1 QUERY 3 的 c_a
        final long rA = 5;                       // A1 QUERY 3 的 r_a

        System.out.println();
        System.out.println("=== GAP 2：A1 ANSWER 6 的具名入口 BlindRotate(q^row, Acc) ===");
        System.out.println("  N = " + n + ", d = " + d + ", q_L = 2N = " + qL + ", t = " + t
            + ", c_a = " + cA + ", r_a = " + rA);
        System.out.println("  A1 ANSWER 5 → 6 → 7 一次跑完（真密文，Java 侧）");

        final Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        System.out.println("  " + m.describe());

        // ── SETUP：载荷多项式 P(X)，p_i = i+1（这样"读回第 r_a 项"就是 r_a+1）──
        final long[] p = new long[n];
        for (int i = 0; i < n; i++) {
            p[i] = (i % (t - 1)) + 1;
        }
        // ── ANSWER 5：Acc_{a,b} = Enc(P)（CtPtMul 那一步在 Java 侧没有调用方，见 CtOps.ctPtMul）──
        final Ciphertext acc = m.encrypt(p);

        // ── LWE 密钥 s（= 自举密钥的各比特）与 q^row ────────────────────
        final Random rnd = new Random(20261015L);
        final int[] sBits = new int[d];
        for (int i = 0; i < d; i++) {
            sBits[i] = rnd.nextInt(2);
        }
        final Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(sBits[i]);
        }
        final long[][] qRow = BlindRotateOps.lweEncryptIndex(sBits, rA, qL, rnd);
        final long[] a = qRow[0];
        final long beta = qRow[1][0];

        // ── ANSWER 6：伪代码那一行 ──────────────────────────────────────
        final Ciphertext accPrime = BlindRotateOps.blindRotateRow(m, bk, acc, a, beta);
        // ── ANSWER 7：SampleExtract_0 ───────────────────────────────────
        final long[][] sample = LweRlweBridge.sampleExtract(m, accPrime, 0);
        final long got = LweRlweBridge.decryptSampleViaPack(m, sample, 0);
        final long want = p[(int) rA];

        System.out.println("    q^row = (a[" + a.length + "], β=" + beta + ")，"
            + "β ≡ ⟨a,s⟩ + r_a = ⟨a,s⟩ + " + rA + " (mod " + qL + ")");
        check(want == rA + 1,
            "前置：载荷 p_i = i+1 ⇒ 期望读回 p_{r_a} = %d（本探针自己的约定，不是论文的）",
            want, rA);
        check(got == want,
            "P-9 ★ ANSWER 6 的具名入口：常数项 = P_{c_a,b}[r_a]（读回 %d，期望 %d）",
            got, want);
        // 整条一致的系数个数（不止常数项）—— 补一句"不是只对了一个数"
        final long[] dec = m.decrypt(accPrime);
        int matching = 0;
        for (int i = 0; i < n; i++) {
            final int src = (int) ((i + rA) % n);
            final long expect = (i + rA) < n ? p[src] : (p[src] == 0 ? 0 : t - p[src]);
            if (dec[i] == expect) {
                matching++;
            }
        }
        System.out.println("    整条系数一致 " + matching + "/" + n
            + "（跨过 X^N 的项带负号，与 BlindRotateOps.countMatch 的口径一致）");
        check(matching > n / 2,
            "P-10 [正对照] 不只是常数项对：按 X^{−r_a}·P 的理想结果比，%d/%d 个系数一致",
            (long) matching, (long) n);

        // ── 负对照 N-4：β 的符号写反（β = ⟨a,s⟩ − r_a）──────────────────
        //   ⚠️ 这一条必须失败 —— 否则 P-9 是恒真的检查。
        final long[][] qRowMinus = BlindRotateOps.lweEncryptIndex(sBits, -rA, qL, rnd);
        final Ciphertext wrongSign =
            BlindRotateOps.blindRotateRow(m, bk, acc, qRowMinus[0], qRowMinus[1][0]);
        final long gotMinus = LweRlweBridge.decryptSampleViaPack(
            m, LweRlweBridge.sampleExtract(m, wrongSign, 0), 0);
        check(gotMinus != want,
            "P-11 ★ [负对照 N-4] β = ⟨a,s⟩ − r_a（符号写反）⇒ 常数项读回 %d ≠ 期望 %d "
                + "—— 证明 P-9 抓得住相位方向错", gotMinus, want);

        // ── 负对照 N-6：换一个 r_a，结果必须跟着变（否则 r 没进到旋转里）──
        final long rOther = (rA + 7) % n;
        final long[][] qRowOther = BlindRotateOps.lweEncryptIndex(sBits, rOther, qL, rnd);
        final Ciphertext otherAcc =
            BlindRotateOps.blindRotateRow(m, bk, acc, qRowOther[0], qRowOther[1][0]);
        final long gotOther = LweRlweBridge.decryptSampleViaPack(
            m, LweRlweBridge.sampleExtract(m, otherAcc, 0), 0);
        check(gotOther == p[(int) rOther] && gotOther != want,
            "P-12 ★ [负对照 N-6] r_a 换成 %d ⇒ 常数项读回 %d = P[%d] ≠ %d —— "
                + "加密下标确实驱动了旋转（不是恒等变换）",
            rOther, gotOther, rOther, want);

        // ── 负对照 N-5：自举密钥比 d 短 —— 原实现不报错，新入口必须抛 ────
        final Mpc4jRgsw.Rgsw[] shortBk = new Mpc4jRgsw.Rgsw[d - 1];
        System.arraycopy(bk, 0, shortBk, 0, d - 1);
        checkThrowsIae("P-13 [负对照 N-5] bk 比 q^row 的 a 短（" + (d - 1) + " < " + d
                + "）⇒ 新入口在入口处就抛（旧实现会静默少转几圈）",
            () -> BlindRotateOps.blindRotateRow(m, shortBk, acc, a, beta));
        checkThrowsIae("P-14 q^row 的 a 为 null ⇒ 抛",
            () -> BlindRotateOps.blindRotateRow(m, bk, acc, null, beta));
        checkThrowsIae("P-15 自举密钥为 null ⇒ 抛",
            () -> BlindRotateOps.blindRotateRow(m, null, acc, a, beta));
        // 正对照：长度正好相等时**不许**抛（判据必须是 `bk.length < a.length`，不是 `<=`）
        boolean exactOk = true;
        try {
            BlindRotateOps.blindRotateRow(m, bk, acc, a, beta);
        } catch (IllegalArgumentException e) {
            exactOk = false;
        }
        check(exactOk,
            "[正对照] bk.length == a.length == %d 时不抛 ⇒ P-13 的判据是「短了才抛」，不是「一律抛」",
            (long) d, null);

        System.out.println();
        System.out.println("  ⚠️ 这一段的定位：生产路径的 ANSWER 4-8 在 native/C++"
            + "（rgsw_blindrotate.cpp:494-512 blind_rotate，cape_answer_core:680 调用），"
            + "**Java 这个具名入口目前只有本探针调用**（0 个生产调用方）。"
            + "本探针证明的是「伪代码那一行在 Java 侧可调用、且算的是对的」，"
            + "不是「生产路径改用了它」。");
    }

    // ==================================================================
    //  工具
    // ==================================================================

    private interface ThrowingRunnable {
        void run();
    }

    private static void checkThrowsIae(String what, ThrowingRunnable body) {
        checks++;
        try {
            body.run();
            System.out.println("  [FAIL] " + what + "  —— 竟然没抛");
            fails++;
        } catch (IllegalArgumentException e) {
            System.out.println("  [PASS] " + what);
        } catch (RuntimeException e) {
            // 抛了别的异常也算不合格：这里要的就是 IllegalArgumentException 这条契约。
            System.out.println("  [FAIL] " + what + "  —— 抛的是 " + e.getClass().getSimpleName());
            fails++;
        }
    }

    /**
     * ⚠️ <b>varargs + {@code String.format} 兜底</b>。
     *
     * <p>本仓库的其它探针用过固定 2/3/4 参数的版本，结果占位符数与参数个数不匹配时
     * 抛 {@code MissingFormatArgumentException}，把"检查失败"伪装成"探针崩溃"，
     * 而且<b>后面的检查根本没跑</b>（本项目为此栽过三次）。
     * 这里一律 varargs，且格式化失败时把失败原因打出来，<b>绝不让格式化异常吃掉断言</b>。
     */
    private static void check(boolean ok, String fmt, Object... args) {
        checks++;
        String msg;
        try {
            msg = (args == null || args.length == 0) ? fmt : String.format(fmt, args);
        } catch (RuntimeException e) {
            msg = fmt + "   [⚠️ 格式化失败：" + e.getClass().getSimpleName() + " —— 断言本身仍按 ok 计]";
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
