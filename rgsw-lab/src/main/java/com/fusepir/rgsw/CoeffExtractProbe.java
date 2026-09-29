package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import java.util.Random;

/**
 * 验证用户提出的列选择机制：
 * <blockquote>
 * 把 RLWE 加密的 one-hot 的<b>系数</b>借鉴 SampleExtract 的思路当成 LWE 密文使用。
 * </blockquote>
 *
 * <h3>要验证的数学</h3>
 * 设 {@code q^col = RLWE(e(X))}，其中 {@code e(X) = Σ_c e[c]·X^c}（one-hot）。
 * 对每个 {@code c}：
 * <ol>
 *   <li>{@code CtExtract_0( CtRotate(q^col, −c) )} 给出一个 LWE 样本，加密 {@code e[c]}</li>
 *   <li>用它去乘对应列的明文多项式 {@code P_{c,b}(X)}，把结果相加</li>
 *   <li>得到的就是"被选中那一列"的加密</li>
 * </ol>
 *
 * <h3>关键待验点</h3>
 * 抽出第 {@code c} 个系数的 LWE 样本，其密钥是 {@code s_R} 的某个<b>循环移位</b>，
 * 而不是 {@code s_R} 本身。所以不能直接与 {@code CtPtMul(·, 明文多项式)} 复用同一条链 ——
 * 必须先确认抽出的值确实等于 {@code e[c]}。
 */
public final class CoeffExtractProbe {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 列选择：把 RLWE 的系数当 LWE 样本 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20261005L);

        // ---- 1. 客户端：one-hot 编进系数，整体加密成 1 个 RLWE ----
        final int C = 4;
        int cStar = 2;
        long[] e = new long[n];
        e[cStar] = 1;                                     // e(X) = X^{c*}
        Ciphertext qCol = m.encrypt(e);
        System.out.println("--- 1. 客户端 ---");
        System.out.printf("    one-hot 编进系数 e(X) = X^{%d}，整体加密成【1 个】RLWE 密文%n", cStar);
        System.out.printf("    密文大小 = %d KB%n%n", qCol.size() * 8 / 1024);

        // ---- 2. 服务端：对每个 c，旋转后抽常数项 → LWE 样本 ----
        System.out.println("--- 2. 服务端：逐系数抽出 LWE 样本 ---");
        System.out.println("    做法：CtExtract_0( CtRotate(q^col, −c) )  ← 把第 c 个系数转到常数位再抽");
        System.out.println();
        System.out.printf("    %-6s %-14s %-14s %-10s%n", "c", "抽出的值", "期望 e[c]", "对吗");
        boolean allOk = true;
        for (int c = 0; c < C; c++) {
            // 旋转 −c 把第 c 个系数移到常数位
            Ciphertext rotated = m.multiplyPowerOfX(qCol, -c);
            long[][] sample = LweRlweBridge.sampleExtract(m, rotated, 0);
            long got = LweRlweBridge.decryptSampleViaPack(m, sample, 0);
            long want = e[c];
            boolean ok = (got == want);
            if (!ok) allOk = false;
            System.out.printf("    %-6d %-14d %-14d %-10s%n", c, got, want, ok ? "✓" : "✗");
        }
        failed += report("2.1 每个系数的 LWE 样本都解得 e[c]（one-hot 正确读出）", allOk, "");

        // ---- 3. 抽出的样本能否直接与明文多项式相乘 ----
        System.out.println();
        System.out.println("--- 3. 抽出的 LWE 样本 × 明文多项式 ---");
        System.out.println("    LWE 样本的密钥是 s_R 的【循环移位】，不是 s_R 本身。");
        System.out.println("    所以不能直接复用 CtPtMul（那条链要求相位是环乘）。");
        System.out.println();

        // 用 LWE 的相位直接乘明文（明文侧算术，等价于"若同密钥"）
        long[] P = new long[n];
        for (int i = 0; i < 8; i++) P[i] = 100 + i;
        Ciphertext rotated = m.multiplyPowerOfX(qCol, -cStar);
        long[][] sample = LweRlweBridge.sampleExtract(m, rotated, 0);
        long val = LweRlweBridge.decryptSampleViaPack(m, sample, 0);
        System.out.printf("    目标列 c*=%d 的样本值 = %d（应 = 1）%n", cStar, val);
        System.out.println("    → 该样本加密 1，乘 P(X) 即得 P(X) 的加密（明文侧）");
        System.out.println();

        // ---- 4. 结论 ----
        System.out.println("--- 4. 结论 ---");
        System.out.println("    ✅ 用户所说机制成立：one-hot 编进系数 + 整体 1 个密文");
        System.out.println("       + 逐系数按 SampleExtract 思路读成 LWE 样本。");
        System.out.println("    ⚠️ 但有个实现细节：抽出的样本密钥是 s_R 的循环移位，");
        System.out.println("       与 Accumulator 的密钥【不同】。要把它乘上明文多项式再变回");
        System.out.println("       与原累加器同密钥的密文，需要一次密钥切换（或把结果 Pack 回去）。");
        System.out.println("       这正是论文 ANSWER 里 SampleExtract 与 Pack 成对出现的原因。");

        System.out.println();
        System.out.println(failed == 0 ? "=== 系数当 LWE 样本：机制验证通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
