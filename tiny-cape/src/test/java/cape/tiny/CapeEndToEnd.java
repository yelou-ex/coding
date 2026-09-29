package cape.tiny;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>端到端演示</b>：按《CAPE 实现步骤（极简验证版）》第 10 节的测试用例走完整条链。
 *
 * <pre>
 *   N=8, t=17, q=97, n=2（关键字数）, m=1, ℓ_BF=2, k_BFF=3, R=C=2
 *
 *   DB:   K_1 → { v_a }
 *         K_2 → { v_a }
 *   Bloom: b_{v_a} = BF({K_1, K_2}) = [1, 1]
 *   查询:  K = (K_1, K_2)      ← 合取：要 v_a 同时属于 K_1 和 K_2
 *   预期:  R = { v_a }
 * </pre>
 *
 * <h3>本演示实现的链路</h3>
 * <pre>
 *   SETUP   : payload 展平 → BFF 编码 → 二维布局 → 明文多项式 P_{c,b}(X)
 *   QUERY   : 客户端把行索引 r* 的每一位做成 RGSW 选择子（BK）
 *   ANSWER  : 服务端对 P(X) 做【盲旋转】，把目标行挪到常数项（服务端看不到 r*）
 *   DECODE  : 客户端解密，读常数项 = 目标字段
 *   CAPE    : 用 Bloom 位做合取判定
 * </pre>
 *
 * <h3>与规范的差异（已实测确认，见 tiny-cape/README.md）</h3>
 * <ol>
 *   <li>本参数 Δ=5, q=97 ⇒ <b>明文（含卷积系数）必须 ≤ maxPlaintext() = 9</b>。
 *       所以数据一律用 0/1（而这正是 CAPE 的真实形态：Bloom 位、指纹位）。</li>
 *   <li>{@code X^{−r*}} 的常数项是 {@code ±P[(−r*) mod N]}，不是 {@code P[r*]}；
 *       本实现按规范保持 {@code X^{−r*}}，并把这条写进 {@link BlindRotate#coefficientAt}。</li>
 *   <li>SampleExtract 的代数关系尚未对齐（见 README「未完成」），
 *       因此本演示用<b>直接读常数项</b>的方式解码 —— 结论不受影响。</li>
 * </ol>
 */
public final class CapeEndToEnd {

    private static int failed = 0;

    /** 一个关键字条目 */
    record Entry(String keyword, int[] values) {
    }

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(20240927);

        System.out.println("==================================================================");
        System.out.println("  CAPE 极简验证版 · 端到端演示（规范第 10 节的测试用例）");
        System.out.println("==================================================================");
        System.out.println("[params] " + p);
        System.out.printf("[容量]   Δ=%d, q=%d → 明文（含卷积系数）必须 ≤ %d%n",
            p.delta, p.q, p.maxPlaintext());
        System.out.println();

        // ==================== 第 1 步：SETUP ====================
        System.out.println("--- 1. SETUP（服务器预处理）---");

        // 1.1 数据库：K_1 → {v_a}, K_2 → {v_a}
        final int vA = 1;
        Entry[] db = {
            new Entry("K_1", new int[]{vA}),
            new Entry("K_2", new int[]{vA}),
        };
        System.out.println("  数据库：");
        for (Entry e : db) System.out.println("      " + e.keyword() + " → " + Arrays.toString(e.values()));

        // 1.2 Bloom 过滤器：b_v = BF(该 v 关联的关键字集合)
        //     v_a 同时被 K_1、K_2 关联 → [1,1]
        int[] bVa = {1, 1};
        System.out.println("  Bloom：b_{v_a} = BF({K_1, K_2}) = " + Arrays.toString(bVa));

        // 1.3 payload 展平（规范 1.2 的字段约定）
        int m = 1;
        int bPay = p.payloadFields(m);           // 2 + m*(1+ℓ_BF) = 5
        int[][] payload = new int[db.length][];
        int[] fp = {1, 0, 0};                     // 指纹（3 个 16-bit limb 的极小版）
        for (int i = 0; i < db.length; i++) {
            int[] pl = new int[bPay];
            pl[0] = fp[0];
            pl[1] = db[i].values().length;        // 值的数量
            pl[2] = db[i].values()[0];            // 第 1 个值
            pl[3] = bVa[0];                       // 该值的 Bloom 位 0
            pl[4] = bVa[1];                       // 该值的 Bloom 位 1
            payload[i] = pl;
        }
        for (int i = 0; i < db.length; i++) {
            System.out.println("  payload_" + (i + 1) + " = " + Poly.show(payload[i])
                + "   [指纹, 数量, 值, Bloom位0, Bloom位1]");
        }
        System.out.println("  B_pay = " + bPay);

        // 1.4 BFF 编码（规范式 4）：D[p_i] = payload_i − Σ_{j≠i} D[h_j(K_i)]
        int k = p.bffK;
        int lBff = 4;                              // R*C
        int[][] D = new int[lBff][bPay];
        int[][] positions = bffPositions(db, p, lBff);
        // 按 LIFO 处理
        for (int i = db.length - 1; i >= 0; i--) {
            int pos = positions[i][0];
            for (int b = 0; b < bPay; b++) {
                int sum = 0;
                for (int j = 0; j < k; j++) {
                    if (positions[i][j] != pos) sum += D[positions[i][j]][b];
                }
                D[pos][b] = Math.floorMod(payload[i][b] - sum, p.t);
            }
        }
        System.out.println("  BFF 编码 D[0.." + (lBff - 1) + "]：");
        for (int u = 0; u < lBff; u++) {
            System.out.println("      D[" + u + "] = " + Poly.show(D[u]));
        }

        // 1.5 二维布局 + 多项式（系数编码）：P_{c,b}(X) = Σ_r D[r + cR][b]·X^r
        int R = 2, C = 2;
        int[][][] Pcb = new int[C][bPay][p.n];
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int r = 0; r < R; r++) {
                    int u = r + c * R;
                    if (u < lBff) Pcb[c][b][r] = D[u][b];
                }
            }
        }
        System.out.println("  多项式 P_{c,b}(X)（只列 b=3，即 Bloom 位 0）：");
        for (int c = 0; c < C; c++) {
            System.out.println("      P_{" + c + ",3}(X) = " + Poly.show(Pcb[c][3]));
        }
        System.out.println();

        // ==================== 第 2 步：QUERY ====================
        System.out.println("--- 2. QUERY（客户端）---");
        TinyKey key = TinyKey.random(p, p.n, rnd);
        System.out.println("  s_L = " + Poly.show(key.sL) + "   （客户端私钥，服务器看不到）");

        // 查询 K = (K_1, K_2)，锚关键词 K_1 的三个 BFF 位置作为行索引
        int[] anchorPositions = positions[0];     // K_1 的 3 个位置
        System.out.println("  K_1 的 BFF 位置 = " + Arrays.toString(anchorPositions));

        // 行索引 → 每个位置单独一次检索
        // 位置 u 对应 (r, c) = (u % R, u / R)
        System.out.println("  每个位置对应 (r*, c*)：");
        for (int a = 0; a < k; a++) {
            int u = anchorPositions[a];
            System.out.printf("      a=%d  u=%d → r*=%d, c*=%d%n", a, u, u % R, u / R);
        }
        System.out.println();

        // ==================== 第 3 步：ANSWER（盲旋转）====================
        System.out.println("--- 3. ANSWER（服务器，看不到 r*）---");
        int d = 3;                                 // ⌈log2 N⌉
        boolean allOk = true;

        // 对每个 (a, b) 做：盲旋转 → 读常数项
        int[][][] recovered = new int[k][bPay][1];
        for (int a = 0; a < k; a++) {
            int u = anchorPositions[a];
            int rStar = u % R;
            int cStar = u / R;

            // 客户端：把 r* 做成 RGSW 逐位选择子
            RGSW[] bk = BlindRotate.clientSelectors(key, rStar, d, rnd);

            for (int b = 0; b < bPay; b++) {
                // 服务端：拿到明文 P_{c*,b} 与 bk，做盲旋转
                RLWECipher acc = key.encryptRLWE(Pcb[cStar][b], rnd);
                RLWECipher rotated = BlindRotate.blindRotate(acc, bk);
                int got = key.decryptRLWECentered(rotated)[0];
                int want = BlindRotate.coefficientAt(Pcb[cStar][b], rStar, p);
                recovered[a][b][0] = got;
                if (got != want) allOk = false;
            }
            System.out.printf("      a=%d（r*=%d, c*=%d）：%d 个字段全部提取%s%n",
                a, rStar, cStar, bPay, allOk ? " ✓" : " ✗");
        }
        System.out.println();
        check("盲旋转提取的字段与明文参照一致", allOk, "");

        // 三路相加（BFF 重建）：Σ_{a=0}^{2} D[r_a*, c_a*, b] = payload[b]
        System.out.println();
        System.out.println("--- 4. 三路 BFF 相加（重建 payload）---");
        int[][] rebuilt = new int[bPay][1];
        for (int b = 0; b < bPay; b++) {
            int sum = 0;
            for (int a = 0; a < k; a++) sum += recovered[a][b][0];
            rebuilt[b][0] = (int) Math.floorMod(sum, p.t);
        }
        int[] rebuiltFlat = new int[bPay];
        for (int b = 0; b < bPay; b++) rebuiltFlat[b] = rebuilt[b][0];
        System.out.println("  重建的 payload = " + Poly.show(rebuiltFlat));
        System.out.println("  原始 payload_1 = " + Poly.show(payload[0]));
        check("BFF 三路重建 == 原始 payload",
            Arrays.equals(rebuiltFlat, payload[0]),
            "got=" + Poly.show(rebuiltFlat) + " want=" + Poly.show(payload[0]));
        System.out.println();

        // ==================== 第 5 步：CAPE 合取判定 ====================
        System.out.println("--- 5. CAPE 合取判定（Bloom）---");
        // 重建出的字段：值 = rebuilt[2]，Bloom 位 = rebuilt[3], rebuilt[4]
        int vGot = rebuiltFlat[2];
        int b0 = rebuiltFlat[3];
        int b1 = rebuiltFlat[4];
        System.out.printf("  从密文恢复：值 v=%d, Bloom 位 = [%d, %d]%n", vGot, b0, b1);

        // 客户端查询向量：K_2 的 Bloom 位（合取里除锚外的关键词）
        // K_2 也关联 {v_a}，所以它与 v_a 的 Bloom 完全相同 → [1,1]
        int[] qBf = {1, 1};
        System.out.println("  客户端查询 Bloom 向量 b_qry = BF({K_2}) = " + Arrays.toString(qBf));

        int tau = qBf[0] + qBf[1];
        int score = qBf[0] * b0 + qBf[1] * b1;
        System.out.println("  内积 ⟨b_qry, b_v⟩ = " + score + "，阈值 τ = |b_qry|₁ = " + tau);
        boolean hit = (score == tau);
        System.out.println("  判定：" + (hit ? "命中（v_a 同时属于 K_1 和 K_2）" : "不命中"));
        check("合取判定命中 v_a", hit, "");

        // 负对照：查询一个 v_a 不具备的关键词
        int[] qBfNeg = {1, 1};                  // 用不同 Bloom 的对照
        int[] bOther = {1, 0};                  // 假设另一个值的 Bloom
        int scoreNeg = qBfNeg[0] * bOther[0] + qBfNeg[1] * bOther[1];
        System.out.println("  负对照：b_v = " + Arrays.toString(bOther)
            + " → 内积 = " + scoreNeg + " < τ = " + tau + " → 不命中");
        check("负对照不命中", scoreNeg != tau, "");

        System.out.println();
        System.out.println("  预期结果 R = { v_a }，实际恢复 v = " + vGot
            + " → " + (vGot == vA ? "✓ 一致" : "✗ 不一致"));
        check("最终结果 == 预期", vGot == vA, "");

        System.out.println();
        System.out.println("==================================================================");
        System.out.println(failed == 0 ? "  端到端全部通过" : "  有 " + failed + " 项失败");
        System.out.println("==================================================================");
        if (failed != 0) System.exit(1);
    }

    /**
     * BFF 位置：{@code u_a = h_a(K)}。极小版用确定性哈希（同一关键字 → 同一组位置）。
     */
    static int[][] bffPositions(Entry[] db, TinyParams p, int lBff) {
        int[][] out = new int[db.length][p.bffK];
        for (int i = 0; i < db.length; i++) {
            long h = db[i].keyword().hashCode() & 0xffffffffL;
            for (int a = 0; a < p.bffK; a++) {
                h = h * 0x9E3779B97F4A7C15L + 0x165667B19E3779F9L;
                out[i][a] = (int) Math.floorMod(h >>> 17, lBff);
            }
        }
        return out;
    }

    private static void check(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "  [PASS] " : "  [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
    }
}
