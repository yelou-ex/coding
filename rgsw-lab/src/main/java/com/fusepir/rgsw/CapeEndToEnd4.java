package com.fusepir.rgsw;

import com.fusepir.common.BfGen;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * <b>CAPE 四步端到端</b>：SETUP → QUERY → ANSWER → DECODE。
 *
 * <p>对应论文算法 1（FusePIR）与算法 2（CAPE）。四步的分工：
 * <ul>
 *   <li><b>SETUP</b>（服务器，全明文）：BFF 位置 → 二维布局 → {@code P_{c,b}(X)}</li>
 *   <li><b>QUERY</b>（客户端）：列选择子（C 个密文）+ 行选择子（LWE）+ Bloom 查询向量 {@code b_qry}</li>
 *   <li><b>ANSWER</b>（服务器）：列选择 → 盲旋转 → {@code SampleExtract_0} → 密文域三路相加。
 *       <b>全程不解密</b></li>
 *   <li><b>DECODE</b>（客户端）：<b>唯一一次解密</b> → 载荷解析 → 指纹校验 → 阈值判定</li>
 * </ul>
 *
 * <h3>2026-09-29 修的六件事（详见 {@code coding/docs/缺陷总表.md}）</h3>
 * <table border="1">
 *   <tr><th>编号</th><th>原问题</th><th>现在</th></tr>
 *   <tr><td>P0-2</td>
 *       <td>客户端 {@code b_qry} 用 {@code b_v} 或起来、还用了服务器才有的明文值集合 ⇒ <b>漏判</b></td>
 *       <td>{@code b_qry = BfGen.bits(查询关键词)}，<b>只由关键词算出</b>，且与服务器共用同一份
 *           {@link BfGen}（来自共享模块 {@code common}）</td></tr>
 *   <tr><td>P0-3</td>
 *       <td>用解密后的明文现造 {@code RingPack} 输入，而且 {@code packed} 算完<b>再没被引用</b>（死代码）</td>
 *       <td><b>删掉</b>，并在 ANSWER 里显式标注 Pack 未接通</td></tr>
 *   <tr><td>P0-4</td>
 *       <td>{@code Query} 混装客户端私有量与服务端可见量</td>
 *       <td>拆成 {@link ClientState}（不发送）与 {@link ServerQuery}（发出去），并打印边界</td></tr>
 *   <tr><td>P1-4</td>
 *       <td>三个 BFF 位置落在同一列（{@code c} 恒为 0），列 1..C−1 从未走到</td>
 *       <td>位置改成 {@code u_a = a·R + i} ⇒ {@code c = a} 覆盖 0..2，并打印覆盖度</td></tr>
 *   <tr><td>P1-7</td>
 *       <td>协议密钥（LWE 的 {@code s}、{@code a}）也来自固定种子的 {@code java.util.Random}</td>
 *       <td>拆开：<b>演示向量</b>用固定种子（可复现）、<b>协议密钥</b>用 {@link SecureRandom}</td></tr>
 *   <tr><td>P2-3</td>
 *       <td>{@code padToSlots} 用 {@code Math.min} <b>静默截断</b></td>
 *       <td>{@code ℓ_BF > N} 时<b>直接抛异常</b>（该分段就分段，不许静默算错）</td></tr>
 * </table>
 *
 * <h3>⚠️ 仍然是玩具参数（引结论时必须一起说）</h3>
 * <ul>
 *   <li>{@code ε_BF = 2⁻⁶}（论文 2⁻²⁰）、行索引<b>无噪声</b>（{@code b = ⟨a,s⟩ + r}，Δ=1、e=0）。
 *       盲旋转对 {@code e=±1} 零容忍 ⇒ 正确性只在 {@code e=0} 成立、安全性一条都不能引。
 *       <b>这是最大的一条未修项，见缺陷总表 P0-1。</b></li>
 *   <li>BFF 位置是构造的（不是 {@code h_a(K)} 哈希派生）；指纹是截断字符串哈希（非论文 40-bit）。</li>
 *   <li>候选 Bloom 密文仍由<b>解密后的明文位重新加密</b>，不是从检索密文同态导出（P0-3 的另一半）。</li>
 * </ul>
 */
public final class CapeEndToEnd4 {

    private static int failed = 0;

    /** 演示用的目标假阳性率。<b>玩具值</b> —— 论文是 2⁻²⁰。 */
    private static final double DEMO_EPS_BF = Math.pow(2, -6);

    // ==================================================================
    //  QUERY 的两半：客户端私有 vs 服务端可见（P0-4）
    // ==================================================================

    /**
     * <b>客户端私有状态 —— 不发送给服务器。</b>
     *
     * <p>论文里客户端本地保留：查询关键词、锚关键词、三个 BFF 位置对应的 {@code (r_a, c_a)}、
     * Bloom 查询向量 {@code b_qry}、阈值 {@code τ}。服务器一个都不该看到。
     */
    static final class ClientState {
        List<String> query;
        int anchor;
        int[] u;                // 三个 BFF 位置
        int[] r;                // 行索引 r_a
        int[] c;                // 列索引 c_a
        long[] bQry;            // Bloom 查询向量（0/1，长度 ℓ_BF）
        long tau;               // ‖b_qry‖₁
        long expectedFingerprint;
    }

    /**
     * <b>客户端发出去的东西 —— 服务端可见。</b>
     *
     * <p>只有：列选择子（C 个密文）、行选择子（LWE 的 {@code a} 与 {@code β}）、
     * 自举密钥（setup 材料）、Bloom 查询密文。**没有任何明文坐标。**
     */
    static final class ServerQuery {
        /**
         * <b>压缩后的列选择子</b>：每条路只有 1 个单项式 {@code Enc(x^{c_a})}（原来要 C 个密文）。
         * 服务端用 {@link #expandKeys} 把它同态扩展成 C 个选择子。见 {@link ExpandOps}。
         */
        Ciphertext[] colMonomial;
        /** Galois 指数 {@code e_j = N/2^j + 1}（每层一个）。 */
        int[] expandExps;
        /** 每层一套 Galois 公钥（建一次即可复用）。 */
        GaloisKeys[] expandKeys;
        Mpc4jRgsw.Rgsw[] bk;    // 自举密钥（setup 材料，非本次查询特有）
        long[][] a;             // LWE 的 a 分量
        long[] beta;            // LWE 的 β 分量
        Ciphertext qBfCt;       // 加密的 Bloom 查询向量
    }

    /** DECODE 的结果。 */
    static final class DecodeResult {
        boolean fingerprintOk;
        int valueCount;
        int firstValue;
        boolean hit;
    }

    // ==================================================================
    //  入口
    // ==================================================================

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        if (run(n, d) != 0) {
            System.exit(1);
        }
    }

    /**
     * 跑一次四步端到端，返回<b>失败项数</b>。
     *
     * <p>与 {@link #main} 的区别：<b>不调用 {@code System.exit}</b>，所以可以被
     * {@link CapeDemo} 批量调用（N=2048 会在 Bloom 打分那步抛异常，那是参数下限、不是 bug，
     * 演示要能捕获它继续跑下一个规模）。
     */
    public static int run(int n, int d) {
        failed = 0;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        System.out.println("=== CAPE 四步端到端：SETUP → QUERY → ANSWER → DECODE ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d, 槽数=%d%n%n", d, 2 * n, be.slotCount());

        // ---- P1-7：两个随机源分开 ----
        //   demoRnd：演示向量（数据库、载荷、BFF 位置、明文参考）—— 固定种子，保证可复现
        //   keyRnd ：协议密钥材料（LWE 的秘密 s 与样本 a）—— 密码学安全，不复现
        Random demoRnd = new Random(20261013L);
        SecureRandom keyRnd = new SecureRandom();
        System.out.println("[随机源] 演示向量 = new Random(20261013L)（可复现）；协议密钥 = SecureRandom");
        System.out.println();

        // ============================================================
        // 1. SETUP（服务器，全明文）
        // ============================================================
        final int C = 4;
        final int R = 16;
        final int k = 3;
        String[] kw = {"K_1", "K_2", "K_3"};
        int[][] dbValues = {{11, 22}, {11}, {33}};

        System.out.println("--- 1. SETUP（服务器，全明文）---");

        // 每个 value 关联的关键词集合 S_v
        Map<Integer, Set<String>> kwOf = new TreeMap<>();
        for (int i = 0; i < dbValues.length; i++) {
            for (int v : dbValues[i]) {
                kwOf.computeIfAbsent(v, x -> new TreeSet<>()).add(kw[i]);
            }
        }
        int maxSetSize = kwOf.values().stream().mapToInt(Set::size).max().orElse(1);
        int maxValues = Arrays.stream(dbValues).mapToInt(x -> x.length).max().orElse(0);

        // P0-2：Bloom 位函数来自【共享模块】BfGen（= 论文的 BF.Gen）。
        //       服务端的 b_v 与客户端的 b_qry 因此【必然是同一份实现】。
        BfGen bfGen = BfGen.choose(maxSetSize, DEMO_EPS_BF, n);
        Map<Integer, boolean[]> bV = new TreeMap<>();
        kwOf.forEach((v, ks) -> bV.put(v, bfGen.bits(ks)));

        int lBf = bfGen.length();
        int bPay = 2 + maxValues * (1 + lBf);
        System.out.printf("    %s（ε_BF=2^%.0f 是【玩具值】，论文 2^-20）%n",
            bfGen, Math.log(DEMO_EPS_BF) / Math.log(2));
        System.out.printf("    R×C = %d×%d = %d，B_pay = %d，maxValues = %d%n",
            R, C, R * C, bPay, maxValues);

        // 载荷：fp(1) ‖ 值的个数(1) ‖ 每个值 [值(1) ‖ ℓ_BF 个 Bloom 位]
        long[][] payload = new long[kw.length][bPay];
        for (int i = 0; i < kw.length; i++) {
            payload[i][0] = Math.floorMod(kw[i].hashCode(), 1000) + 1;
            payload[i][1] = dbValues[i].length;
            for (int j = 0; j < dbValues[i].length; j++) {
                int base = 2 + j * (1 + lBf);
                payload[i][base] = dbValues[i][j];
                boolean[] bv = bV.get(dbValues[i][j]);
                for (int bi = 0; bi < lBf; bi++) {
                    payload[i][base + 1 + bi] = bv[bi] ? 1 : 0;
                }
            }
        }

        // ---- P1-4：BFF 位置摊到不同列 ----
        //   令 u_a = a·R + i ⇒ c = u/R = a（覆盖 0..k−1）、r = u%R = i。
        //   原来用 pool++（0..8）配 R=16 使 c 恒为 0，列 1..C−1 从未走到。
        int[][] pos = new int[kw.length][k];
        for (int i = 0; i < kw.length; i++) {
            for (int a = 0; a < k; a++) {
                pos[i][a] = a * R + i;
            }
        }
        Set<Integer> usedColumns = new TreeSet<>();
        for (int a = 0; a < k; a++) {
            usedColumns.add(pos[0][a] / R);
        }
        System.out.printf("    BFF 位置（u_a = a·R + i）：%s ⇒ 覆盖列 %s（C=%d）%n",
            Arrays.toString(pos[0]), usedColumns, C);

        // 三份 BFF 份额：前两份随机，第三份反推，保证 Σ_a D[h_a(K)][b] = payload[b]
        long[][][] D = new long[kw.length][k][bPay];
        for (int i = 0; i < kw.length; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    D[i][a][b] = demoRnd.nextInt((int) m.t);
                    sum[b] = (sum[b] + D[i][a][b]) % m.t;
                }
            }
            for (int b = 0; b < bPay; b++) {
                D[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], m.t);
            }
        }

        // 二维布局：P_{c,b}(X) = Σ_r D[r + cR][b]·X^r
        // 先把每列每行都填上数据（真实数据库本来就如此），再覆盖 3 个 BFF 位置。
        // ⚠️ 若留着全零列：常数编码下 Enc(0) ⊛ 全零明文 = 全零密文，会被 SEAL 判为 transparent。
        long[][][] P = new long[C][bPay][n];
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int rr = 0; rr < R; rr++) {
                    P[c][b][rr] = 1 + demoRnd.nextInt((int) m.t - 1);
                }
            }
        }
        for (int i = 0; i < kw.length; i++) {
            for (int a = 0; a < k; a++) {
                int u = pos[i][a];
                int r = u % R;
                int c = u / R;
                if (c >= C) {
                    continue;
                }
                for (int b = 0; b < bPay; b++) {
                    P[c][b][r] = D[i][a][b];
                }
            }
        }
        // ★ α 折叠：EXPAND 的输出是「恰好一个选择子加密常数 C、其余 0」，
        //   所以把服务端的表在【明文侧】乘上 α = C^{-1} mod t：
        //       Σ_c CtPtMul(C·1_{c=c*}, α·P_c) = (C·α)·P_{c*} = P_{c*}  ✓
        //   这样密文侧一次 α 乘法都不需要，SealPIR Theorem 2 里那个 t 因子（约 16 bit）消失。
        //   等价性已由 ExpandProbe 在 N=4096/C=4 上实测（D 段：解出的就是原表）。
        long alpha = ExpandOps.alphaFor(m.t, C);
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int i = 0; i < n; i++) {
                    P[c][b][i] = java.math.BigInteger.valueOf(alpha)
                        .multiply(java.math.BigInteger.valueOf(P[c][b][i]))
                        .mod(java.math.BigInteger.valueOf(m.t)).longValueExact();
                }
            }
        }
        System.out.printf("    %d 条明文多项式 P_{c,b}(X)（已折 α=%d 供扩展后的选择子使用）%n%n",
            C * bPay, alpha);

        // ============================================================
        // 2. QUERY（客户端）—— 产出 ClientState（私有）+ ServerQuery（发出去）
        // ============================================================
        List<String> query = List.of("K_1", "K_2");
        int anchor = 0;
        System.out.println("--- 2. QUERY（客户端）---");
        System.out.printf("    查询 = %s，锚 = %s（BFF 位置 %s）%n",
            query, kw[anchor], Arrays.toString(pos[anchor]));

        ClientState client = new ClientState();
        client.query = query;
        client.anchor = anchor;
        client.u = pos[anchor].clone();
        client.r = new int[k];
        client.c = new int[k];
        for (int a = 0; a < k; a++) {
            client.r[a] = client.u[a] % R;
            client.c[a] = client.u[a] / R;
        }

        // P0-2 ★：b_qry = BF.Gen(0, {K_2,…,K_Q}) —— **只由关键词算出**。
        //   原来写的是 `for (vv : dbValues[idx]) qBf |= bloom.get(vv)`：
        //   ① 或的是 b_v 不是 B(K) ⇒ 算出的是"共现关键词集合"的位、τ 被撑大 ⇒ 漏判；
        //   ② dbValues 是服务器才有的明文库 ⇒ 客户端根本算不出来。
        List<String> restKeywords = query.subList(1, query.size());
        boolean[] bQryBits = bfGen.bits(restKeywords);
        client.bQry = new long[lBf];
        for (int i = 0; i < lBf; i++) {
            client.bQry[i] = bQryBits[i] ? 1 : 0;
        }
        client.tau = Arrays.stream(client.bQry).sum();
        client.expectedFingerprint = Math.floorMod(kw[anchor].hashCode(), 1000) + 1;

        // ---- 发出去的部分 ----
        ServerQuery sq = new ServerQuery();
        sq.colMonomial = new Ciphertext[k];
        for (int a = 0; a < k; a++) {
            long[] mono = new long[n];
            mono[client.c[a]] = 1;                  // Enc(x^{c_a})：只暴露"一个单项式"
            sq.colMonomial[a] = m.encrypt(mono);
        }
        sq.expandExps = ExpandOps.expsFor(n, C);
        sq.expandKeys = ExpandOps.keysFor(m, C);
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = keyRnd.nextInt(2);                       // P1-7：协议密钥用 SecureRandom
        }
        sq.bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            sq.bk[i] = m.encryptRgswConstant(s[i]);
        }
        int qL = 2 * n;
        long[][] lweA = new long[k][];
        long[] lweBeta = new long[k];
        for (int a = 0; a < k; a++) {
            long sum = 0;
            lweA[a] = new long[d];
            for (int i = 0; i < d; i++) {
                lweA[a][i] = Math.floorMod(keyRnd.nextLong(), qL);
                sum = (sum + lweA[a][i] * s[i]) % qL;
            }
            // ⚠️ P0-1：无噪声索引。论文是 b = ⟨a,s⟩ + Δ·m + e，这里 Δ=1、e=0。
            lweBeta[a] = Math.floorMod(sum + client.r[a], qL);
        }
        sq.a = lweA;
        sq.beta = lweBeta;
        sq.qBfCt = BloomScoring.encryptBloomVector(m, toSlots(client.bQry, be.slotCount()));

        System.out.printf("    列选择器：%d 路 × 1 个单项式 Enc(x^{c_a})（压缩后；原来是 %d 路 × %d 个独立密文）%n",
            k, k, C);
        System.out.printf("    服务端扩展：Galois 指数 %s，%d 套公钥；输出 %d 个选择子（恰好一个加密常数 %d）%n",
            Arrays.toString(sq.expandExps), sq.expandKeys.length, C, C);
        System.out.printf("    行选择器：%d 个 RGSW + %d 条 LWE%n", d, k);
        System.out.printf("    b_qry = %s，τ = %d%n", Arrays.toString(client.bQry), client.tau);
        System.out.println();
        System.out.println("    [QUERY 的边界] 客户端私有（**不发**）：query、anchor、u、r、c、b_qry、τ");
        System.out.printf("    服务端可见（**发出去**）：colMonomial（%d 个密文，压缩前 %d）、bk、a、beta、qBfCt%n%n",
            k, k * C);

        // ============================================================
        // 3. ANSWER（服务器）—— 只用 ServerQuery + 明文表，全程不解密
        // ============================================================
        System.out.println("--- 3. ANSWER（服务器）---");
        long t0 = System.nanoTime();

        long[][][][] sample = new long[k][bPay][][];
        for (int a = 0; a < k; a++) {
            // ★ 服务端把压缩的选择子扩展成 C 个 one-hot（恰好一个加密常数 C，其余 0）。
            //   与原来「客户端送 C 个独立密文」逐位等价，只是把 C 折进了明文表（见上面的 α）。
            Ciphertext[] sel = ExpandOps.expand(m, n, sq.colMonomial[a], C, sq.expandExps, sq.expandKeys);
            for (int b = 0; b < bPay; b++) {
                // 第 5 行：Acc ← Σ_{c=0}^{C−1} CtPtMul(sel[c], P_{c,b}(X))
                //   **全部 C 项都算并累加**：选中的那一项密文里是常数 C、其余是 0×α 折过，
                //   选择发生在同态内部，服务器看不到 c_a。
                Ciphertext acc = columnSelect(m, n, P, sel, b, C);
                // 第 6 行：盲旋转（要求系数域）
                if (acc.isNttForm()) {
                    m.evaluator.transformFromNttInplace(acc);
                }
                Ciphertext rotated = BlindRotateOps.blindRotate(m, sq.bk, acc, sq.a[a], sq.beta[a]);
                // 第 7 行：SampleExtract_0 —— 出的是**密文**（q_R 下的 CRT 残数），服务端不解密
                sample[a][b] = LweRlweBridge.sampleExtract(m, rotated, 0);
            }
        }
        // 第 11 行：三路相加 —— 在【密文域】逐分量相加
        long[][][] ctPaySample = new long[bPay][][];
        for (int b = 0; b < bPay; b++) {
            ctPaySample[b] = addSamples(m, sample[0][b], sample[1][b], sample[2][b]);
        }
        long ansMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    列选择×%d + 盲旋转×%d + 密文域三路相加 = %d 个单元，耗时 %.0f ms%n",
            k * bPay, k * bPay, k * bPay, (double) ansMs);
        System.out.println("    ★ 服务器全程未解密（SampleExtract_0 出的是密文，三路相加也在密文域）");
        System.out.println("    ⚠️ 第 13 行 Pack **未接通**：上一版在这里用解密后的明文现造 RingPack 输入，"
            + "而且算出的 packed 从头到尾没被引用（死代码），已按缺陷总表 P0-3 删除。");
        System.out.println("       真接通需要让 ring packing 在原生模数上做 —— 见 SampleToPackLink 量出的缩放障碍。");

        // ============================================================
        // 负对照：列选择器必须是"承重"的
        // ============================================================
        long[] ctPayZero = recoverAll(m, n, P, sq, s, client, k, C, bPay, 0, true, keyRnd, qL);
        long[] ctPayShift = recoverAll(m, n, P, sq, s, client, k, C, bPay, 1, false, keyRnd, qL);
        boolean zeroAll = true;
        for (long v : ctPayZero) {
            if (v != 0) {
                zeroAll = false;
            }
        }
        failed += report("4.5 负对照：全零列选择器 ⇒ 载荷必须全 0", zeroAll,
            "得到 " + Arrays.toString(ctPayZero));
        failed += report("4.6 负对照：列选择器错位一列 ⇒ 载荷必须改变",
            !Arrays.equals(ctPayShift, payload[anchor]),
            "错位列得到 " + Arrays.toString(ctPayShift));
        System.out.printf("    [覆盖度] 三个 BFF 位置用到的列号 = %s（C=%d）%n", usedColumns, C);

        // ============================================================
        // 4. DECODE（客户端）—— 整个流程唯一的解密处
        // ============================================================
        System.out.println("--- 4. DECODE（客户端，唯一解密处）---");
        long[] ctPay = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            ctPay[b] = LweRlweBridge.decryptSampleViaPack(m, ctPaySample[b], 0);
        }

        // ---- §3.7 的 Bloom 打分演示 ----
        // ⚠️ 诚实标注：这一段【不是】全程同态。
        //    候选 Bloom 密文由解密后的 ctPay 重新加密而来，而不是从上面的密文里同态取出。
        //    为什么取不出来（已实测，见 SampleToPackLink）：
        //      要把它变成槽位密文需要 ring packing，而 RingPack 要求输入样本已在 Z_t 上；
        //      从 q_R 缩放过去会引入 ≈√N 的舍入噪声（N=4096 实测 |残差| 最大 28、理论 std ≈ 15），
        //      **是 Bloom 位值 1 的十几~几十倍** ⇒ 打包出来的位不再精确，s_j == τ 的精确判定不成立。
        long[] vBfVec = new long[lBf];
        for (int i = 0; i < lBf; i++) {
            vBfVec[i] = ctPay[3 + i];
        }
        Ciphertext candBF = BloomScoring.encryptBloomVector(m, toSlots(vBfVec, be.slotCount()));
        long homScore = BloomScoring.decodeScore(m,
            BloomScoring.bloomScore(m, BloomScoring.galoisKeysFor(m), sq.qBfCt, candBF));
        System.out.printf("    ⚠️ Bloom 得分（非全程同态，见上注释）= %d%n%n", homScore);

        DecodeResult res = new DecodeResult();
        res.fingerprintOk = ctPay[0] == client.expectedFingerprint;
        res.valueCount = (int) ctPay[1];
        res.firstValue = (int) ctPay[2];
        res.hit = homScore == client.tau;

        System.out.printf("    恢复 payload   = %s%n", Arrays.toString(ctPay));
        System.out.printf("    原始 payload   = %s%n", Arrays.toString(payload[anchor]));
        failed += report("4.1 BFF 三路重建 == 原始 payload",
            Arrays.equals(ctPay, payload[anchor]), "");
        failed += report("4.2 指纹校验通过", res.fingerprintOk,
            String.format("f=%d fp(K)=%d", ctPay[0], client.expectedFingerprint));
        System.out.printf("    值的数量 = %d，第一个值 = %d，Bloom = %s%n",
            res.valueCount, res.firstValue, Arrays.toString(Arrays.copyOfRange(ctPay, 3, 3 + lBf)));
        System.out.printf("    同态得分 = %d，τ = %d → %s%n", homScore, client.tau,
            res.hit ? "命中" : "不命中");
        failed += report("4.3 判定命中", homScore == client.tau,
            "score=" + homScore + " tau=" + client.tau);

        Set<Integer> expect = new TreeSet<>();
        for (int v : kwOf.keySet()) {
            if (kwOf.get(v).containsAll(query)) {
                expect.add(v);
            }
        }
        System.out.printf("    明文答案集 = %s%n", expect);
        failed += report("4.4 恢复的值 ∈ 明文答案集", expect.contains(res.firstValue),
            "v=" + res.firstValue);

        System.out.println();
        System.out.println(failed == 0
            ? "=== CAPE 四步端到端跑通（SETUP → QUERY → ANSWER → DECODE）==="
            : "=== 有 " + failed + " 项失败 ===");
        return failed;
    }

    // ==================================================================
    //  工具
    // ==================================================================

    /** 第 5 行：{@code Acc ← Σ_{c} CtPtMul(sel[c], P_{c,b}(X))}，全程同态、不碰明文列号。 */
    private static Ciphertext columnSelect(Mpc4jRgsw m, int n, long[][][] P,
                                           Ciphertext[] sel, int b, int C) {
        Ciphertext acc = null;
        for (int c = 0; c < C; c++) {
            Ciphertext ct = new Ciphertext();
            ct.copyFrom(sel[c]);
            if (!ct.isNttForm()) {
                m.evaluator.transformToNttInplace(ct);
            }
            edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext pPoly =
                new edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext(n);
            for (int i = 0; i < n; i++) {
                pPoly.set(i, P[c][b][i]);
            }
            if (!pPoly.isNttForm()) {
                m.evaluator.transformToNttInplace(pPoly, m.context.firstParmsId());
            }
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(ct, pPoly, prod);
            if (acc == null) {
                acc = prod;
            } else {
                m.evaluator.addInplace(acc, prod);
            }
        }
        return acc;
    }

    /**
     * 三路相加：在【密文域】把多条 LWE 样本逐分量相加。
     *
     * <p>每条样本是 {@code long[L][n+1]}（{@code [pi][0] = β}，{@code [pi][1..n] = a}），
     * 每个分量都是对应素数下的残数 ⇒ 按素数分别取模相加即可。这正是论文
     * 第 11 行 {@code ct_pay,b ← CtCtAdd(CtCtAdd(ct_0,b, ct_1,b), ct_2,b)} 的做法。
     */
    private static long[][] addSamples(Mpc4jRgsw m, long[][]... samples) {
        int L = samples[0].length;
        int len = samples[0][0].length;
        long[][] out = new long[L][len];
        for (int pi = 0; pi < L; pi++) {
            long mod = m.primes[pi].value();
            for (int k = 0; k < len; k++) {
                long v = 0;
                for (long[][] s : samples) {
                    v = (v + s[pi][k]) % mod;
                }
                out[pi][k] = v;
            }
        }
        return out;
    }

    /**
     * 用指定选择器重跑一遍「列选择 → 盲旋转 → 抽常数项 → 三路相加」。<b>仅供负对照。</b>
     *
     * @param shift   选择器指向的列 = {@code (c_a + shift) mod C}
     * @param allZero 所有选择器都加密常数 0（选不中任何列）
     */
    private static long[] recoverAll(Mpc4jRgsw m, int n, long[][][] P, ServerQuery sq, int[] s,
                                     ClientState client, int k, int C, int bPay,
                                     int shift, boolean allZero, Random keyRnd, int qL) {
        int d = sq.bk.length;
        long[][] rec = new long[k][bPay];
        for (int a = 0; a < k; a++) {
            // 与 QUERY 同样：压缩的选择子（一条单项式）+ 服务端扩展；负对照靠改单项式的指数实现
            int target = allZero ? -1 : Math.floorMod(client.c[a] + shift, C);
            Ciphertext[] sel;
            if (target < 0) {
                sel = new Ciphertext[C];                    // 全零选择子：C 个 Enc(0)
                long[] zero = new long[n];
                for (int c = 0; c < C; c++) {
                    sel[c] = m.encrypt(zero);
                }
            } else {
                long[] mono = new long[n];
                mono[target] = 1;
                sel = ExpandOps.expand(m, n, m.encrypt(mono), C, sq.expandExps, sq.expandKeys);
            }
            // 与 QUERY 同样地造一条 LWE 行选择子（无噪声索引，见 P0-1）
            long[] aVec = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                aVec[i] = Math.floorMod(keyRnd.nextLong(), qL);
                sum = (sum + aVec[i] * s[i]) % qL;
            }
            long beta = Math.floorMod(sum + client.r[a], qL);
            for (int b = 0; b < bPay; b++) {
                Ciphertext acc = columnSelect(m, n, P, sel, b, C);
                if (acc.isNttForm()) {
                    m.evaluator.transformFromNttInplace(acc);
                }
                Ciphertext rot = BlindRotateOps.blindRotate(m, sq.bk, acc, aVec, beta);
                rec[a][b] = Math.floorMod(m.decrypt(rot)[0], m.t);
            }
        }
        long[] out = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            long sum = 0;
            for (int a = 0; a < k; a++) {
                sum += rec[a][b];
            }
            out[b] = Math.floorMod(sum, m.t);
        }
        return out;
    }

    /**
     * 把 Bloom 向量补到槽数。
     *
     * <p><b>P2-3</b>：原来用 {@code Math.min(v.length, slots)} <b>静默截断</b> ——
     * 一旦 {@code ℓ_BF > N} 就会悄悄丢掉低位、算出一个错的内积。
     * 现在超长<b>直接抛异常</b>（该分段就分段）。
     */
    private static long[] toSlots(long[] v, int slots) {
        if (v.length > slots) {
            throw new IllegalArgumentException(String.format(
                "Bloom 向量 %d 位 > 槽数 %d：ℓ_BF > N，必须分段（见缺陷总表 P2-5）", v.length, slots));
        }
        long[] out = new long[slots];
        System.arraycopy(v, 0, out, 0, v.length);
        return out;
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
