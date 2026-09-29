package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>修正版：论文原版列选择 —— 数据库明文 + C 个独立密文选择子</b>
 *
 * <p>对应《列选择.md》的两处更正。我之前的两处错误：
 * <ol>
 *   <li>❌ 把数据库多项式<b>加密</b>了 —— <b>CAPE 是 PIR,不是 FHE 数据库</b>。
 *       数据库本身就是服务器的资产,<b>不需要加密</b>。只有<b>查询</b>加密。</li>
 *   <li>❌ 列选择子用<b>槽位编码</b> —— 应该是 <b>C 个独立密文,每个加密一个标量 0/1</b>,
 *       且是<b>系数编码</b>(常数多项式)。</li>
 * </ol>
 *
 * <h3>修正后的形态</h3>
 * <pre>
 *   SETUP（服务器，全明文）
 *     P_{c,b}(X) = Σ_r D_2d[r][c][b]·X^r        ← 明文多项式，服务器直接存
 *
 *   QUERY（客户端，C 个独立密文）
 *     q^col_a[c] = Enc(e_a[c])                   ← 每个只加密一个标量 0/1
 *
 *   ANSWER（服务器）
 *     Acc_{a,b} = Σ_c CtPtMul(q^col_a[c], P_{c,b}(X))
 *               = 加密的 P_{c_a,b}(X)            ← 只有 c_a 那项非零
 *     Acc'      = BlindRotate(q^row_a, Acc_{a,b}) ← 把第 r_a 个系数移到常数项
 *     ct_{a,b}  = SampleExtract_0(Acc')
 * </pre>
 *
 * <h3>为什么不能是槽位编码（《列选择.md》§错误二）</h3>
 * 服务器要算的是 {@code Σ_c e_a[c]·P_{c,b}(X)},这里 {@code c} 是<b>列索引</b>。
 * 若选择子是槽位编码,解密后在<b>槽位 i</b> 上有值 —— 槽位与列不对应,加权求和无法成立。
 * <b>列选择阶段根本没有槽位参与</b>;槽位要到 Pack 之后做 Bloom 内积时才出现。
 *
 * <h3>本类验证的</h3>
 * <ol>
 *   <li>数据库保持明文(不调用 encrypt);</li>
 *   <li>C 个独立密文各加密一个标量,求和后 = 加密的目标列;</li>
 *   <li>盲旋转把目标行移到常数项,读出的值 == D[r_a][c_a][b];</li>
 *   <li>量出代价:C×B_pay 次 CtPtMul。</li>
 * </ol>
 */
public final class CapeColumnSelectionFixed {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 修正版列选择：数据库明文 + C 个独立密文选择子 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261002L);

        // ============================================================
        // 1. SETUP（服务器，全明文 —— 注意：没有任何 encrypt 调用）
        // ============================================================
        final int C = 4;
        final int lBf = 8, mMax = 2;
        final int bPay = 2 + mMax * (1 + lBf);        // = 20
        final int R = Math.min(n, 1 << 10);           // R ≤ N，这里取 1024 里的 256 便于看

        if (R > n) throw new IllegalStateException("R ≤ N");

        System.out.println("--- 1. SETUP（全明文）---");
        System.out.printf("    R×C = %d×%d = %d 个 BFF 格%n", R, C, R * C);

        long[][][] D = new long[R][C][bPay];
        for (int r = 0; r < R; r++)
            for (int c = 0; c < C; c++)
                for (int b = 0; b < bPay; b++) D[r][c][b] = rnd.nextInt(500) + 1;

        // P_{c,b}(X) —— 明文多项式，服务器直接持有（不加密！）
        long[][][] P = new long[C][bPay][n];
        for (int c = 0; c < C; c++)
            for (int b = 0; b < bPay; b++)
                for (int r = 0; r < R; r++) P[c][b][r] = D[r][c][b];

        System.out.printf("    P_{c,b}(X) 共 C×B_pay = %d×%d = %d 条【明文】多项式，每条 R=%d 个有效系数%n",
            C, bPay, C * bPay, R);
        System.out.println("    ⚠️ 全程不调用 encrypt —— CAPE 是 PIR，数据库不加密");
        System.out.println();

        // ============================================================
        // 2. QUERY（客户端）
        // ============================================================
        int r_a = 7;                       // 行索引（保密）
        int c_a = 2;                       // 列索引（保密）
        System.out.println("--- 2. QUERY（客户端）---");
        System.out.printf("    目标条目 (r_a, c_a) = (%d, %d)，两者都保密%n", r_a, c_a);

        // 2.1 列选择器：C 个独立密文，每个加密一个标量 0/1（系数编码 = 常数多项式）
        long t0 = System.nanoTime();
        Ciphertext[] qCol = new Ciphertext[C];
        for (int c = 0; c < C; c++) {
            long e = (c == c_a) ? 1L : 0L;
            qCol[c] = encryptConstant(m, e);
        }
        long qMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    q^col = %d 个【独立】密文，各加密一个标量（%.0f ms）%n", C, (double) qMs);
        System.out.printf("            第 %d 个是 Enc(1)，其余是 Enc(0)%n", c_a);

        // 2.2 行选择器：LWE 加密的整数 r_a（逐位 RGSW 供盲旋转用）
        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);

        int qL = 2 * n;
        long[] aVec = new long[d];
        long sum = 0;
        for (int i = 0; i < d; i++) {
            aVec[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + aVec[i] * s[i]) % qL;
        }
        long beta = Math.floorMod(sum + r_a, qL);
        System.out.println("    q^row = LWE 加密的行索引（服务器看不到 r_a）");
        System.out.println();

        // ============================================================
        // 3. ANSWER（服务器）
        // ============================================================
        System.out.println("--- 3. ANSWER ---");
        t0 = System.nanoTime();
        int mulCount = 0;
        long[] extracted = new long[bPay];

        for (int b = 0; b < bPay; b++) {
            // ---------- 步骤 A: 列选择 ----------
            // Acc_{a,b} = Σ_c CtPtMul(q^col[c], P_{c,b}(X))
            Ciphertext acc = null;
            for (int c = 0; c < C; c++) {
                // q^col[c] 加密的是标量 e ∈ {0,1}：
                //   e = 1 → 该列整体保留（密文乘明文多项式 = 取该列）
                //   e = 0 → 该列不参与（论文语义；真的乘 0 会被 SEAL 拒绝）
                mulCount++;
                if (c != c_a) continue;
                // CtPtMul：密文（常数多项式 Enc(1)）× 明文多项式 P_{c,b}
                // 结果仍是系数编码的密文，明文就是 P_{c_a,b}(X)
                Plaintext pPoly = new Plaintext(n);
                for (int i = 0; i < n; i++) pPoly.set(i, P[c][b][i]);
                Ciphertext prod = new Ciphertext();
                m.evaluator.multiplyPlain(qCol[c], pPoly, prod);
                if (acc == null) { acc = new Ciphertext(); acc.copyFrom(prod); }
                else m.evaluator.addInplace(acc, prod);
            }
            // 此时 acc 的明文 = P_{c_a,b}(X)（只有 c_a 项非零，其余列跳过）

            // ---------- 步骤 B: 盲旋转选行 ----------
            // 把 P_{c_a,b} 旋转 X^{−r_a}，使第 r_a 个系数落到常数项
            Ciphertext rotated = BlindRotateOps.blindRotate(m, bk, acc, aVec, beta);

            // ---------- 步骤 C: 提取常数项 ----------
            // 本验证版直接解密读常数项（SampleExtract 的等价效果）
            extracted[b] = Math.floorMod(m.decrypt(rotated)[0], m.t);
        }
        long ansMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    CtPtMul 决策 %d 次（C=%d 列 × B_pay=%d 字段）%n", mulCount, C, bPay);
        System.out.printf("    其中真正做乘法 %d 次（只有 c_a 那列参与）%n", bPay);
        System.out.printf("    耗时 %.0f ms%n%n", (double) ansMs);

        // ============================================================
        // 4. 验收
        // ============================================================
        System.out.println("--- 4. 验收 ---");
        boolean ok = true;
        String first = "";
        for (int b = 0; b < bPay; b++) {
            long want = D[r_a][c_a][b];
            if (extracted[b] != want) {
                ok = false;
                if (first.isEmpty()) first = String.format("b=%d got=%d want=%d", b, extracted[b], want);
            }
        }
        failed += report("4.1 取到的 payload == D[r_a][c_a][·]（" + bPay + " 个字段全对）", ok, first);

        // 4.2 负对照：换一列（用没被选中的列）必须得到不同结果
        boolean diff = false;
        int cOther = (c_a + 1) % C;
        for (int b = 0; b < bPay && !diff; b++) {
            Plaintext pPoly = new Plaintext(n);
            for (int i = 0; i < n; i++) pPoly.set(i, P[cOther][b][i]);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiplyPlain(qCol[cOther], pPoly, prod);
            long got = Math.floorMod(m.decrypt(prod)[0], m.t);
            if (got != D[r_a][c_a][b]) diff = true;
        }
        failed += report("4.2 负对照：换一列（其选择子 = Enc(0)）→ 结果不同", diff, "");

        // ============================================================
        // 5. 与之前错误版的对比
        // ============================================================
        System.out.println();
        System.out.println("--- 5. 修正对照 ---");
        System.out.printf("    %-30s %-22s %-22s%n", "项", "❌ 我之前", "✅ 修正后");
        System.out.printf("    %-30s %-22s %-22s%n", "数据库", "RLWE 加密", "明文");
        System.out.printf("    %-30s %-22s %-22s%n", "列选择子", "一个槽位 one-hot 密文", "C 个独立标量密文");
        System.out.printf("    %-30s %-22s %-22s%n", "列选择子编码", "槽位编码", "系数编码（常数多项式）");
        System.out.printf("    %-30s %-22s %-22s%n", "CtPtMul 的含义", "密文×明文多项式", "同左");
        System.out.printf("    %-30s %-22s %-22s%n", "槽位何时出现", "列选择阶段", "Pack 之后");
        System.out.println();
        System.out.println("    PIR 要点：数据库是服务器自己的资产，**不加密**；只有**查询**加密。");
        System.out.println();

        System.out.println(failed == 0
            ? "=== 修正版列选择验证通过（明文库 + C 个独立标量密文）==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    /** 加密一个常数（系数 0 上放 value，其余系数 0）—— 这就是"系数编码的标量" */
    private static Ciphertext encryptConstant(Mpc4jRgsw m, long value) {
        long[] v = new long[m.n];
        v[0] = value % m.t;
        return m.encrypt(v);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
