package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>判别实验：SealPIR 3.3 节的 {@code EXPAND} 在我们 N=4096 / t=65537 下能不能用。</b>
 *
 * <p>为什么做这个：{@code docs/reports/列选择vs两篇新论文-缺点与可修缮性-2026-09-30.md} 指出，
 * 把列选择子从「客户端送 C 个独立密文」换成「送 1 个单项式 + 服务端同态扩展」，
 * 唯一的不确定性是噪声。SealPIR 的 Theorem 2 给的是
 * {@code v_out ≤ t · 2^⌈log n⌉ · (v_in + 2B_sub)} —— 那个 <b>t 因子</b>来自最后一步
 * 乘 {@code α = m^{-1} mod t}（把 Enc(m) 变成 Enc(1)，其中 {@code m = 2^ℓ = C}）。
 * SealPIR 第 6 节靠把明文模数换成 2 的幂来消掉它，而我们 {@code t = 65537} 是素数、
 * 还要满足 {@code t ≡ 1 (mod 2N)} 做槽编码，<b>那个优化我们用不了</b>。所以要实测。
 *
 * <p><b>结论（N=4096, t=65537, C=4：16 PASS / 0 FAIL）：</b>
 * <ul>
 *   <li>Galois 替换 {@code Sub(c,k)} 在 MPC4J 上<b>可用</b>：
 *       {@code KeyGenerator.createGaloisKeys(int[],gk)} 与 {@code Evaluator.applyGalois(...)} 都在。</li>
 *   <li>扩展正确：4 个选择子里恰好一个加密常数 {@code C=4}、其余为 0；乘 {@code α=C^{-1}} 后得 1。</li>
 *   <li>指数是 {@code e_j = N/2^j + 1}（N=4096 时为 4097、2049）。论文 Figure 3 印的
 *       {@code N/2^{j+1}+1} <b>整体差一层</b>：拿它当 j=0 的指数会得到干净的第 0 项但<b>高阶项非零</b>。</li>
 *   <li>代价：一次扩展 + C 个 CtPtMul，噪声预算 38 → 31 bit（多花 7 bit），换上传 <b>C 倍</b>变小
 *       （客户端也从 C 次加密降到 1 次）。</li>
 *   <li>★ <b>{@code α} 可以整个不做</b>：扩展输出要喂给 {@code CtPtMul(o_c, P_c)}，
 *       把 α <b>在明文侧折进表</b>（{@code P' = C^{-1}·P mod t}）后
 *       {@code Σ_c C·1_{c=sel}·(C^{-1}·P_c) = P_sel}，<b>密文侧一次 α 乘法都没有</b>，
 *       Theorem 2 里那个 {@code t} 因子（约 16 bit）消失。实测解出的表项精确等于 P。
 *       SealPIR 做不到这点，因为它扩展出的向量要被直接当答案返回、继续做 ct×ct。</li>
 * </ul>
 *
 * <p><b>踩到的坑（值得记）：</b>第一版把 {@code α} 写死成 {@code 2^{-1} mod t}，
 * C=4 时所有读数都呈现「乘了 α 但结果没变」，看着像库的 bug。
 * 真因是 SealPIR 的循环不变量：结束时选中项加密的是 <b>{@code m = C}</b> 而不是 2，
 * 所以 {@code α} 必须是 <b>{@code C^{-1} mod t}</b>。写死 2^{-1} 时
 * {@code C·(2^{-1})·P = 2P}，B 段与 D 段的偏差由此全部解释。
 * <b>教训：这类「看起来像库有问题」的现象，先核对循环不变量。</b>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.ExpandProbe 4096 4}
 */
public final class ExpandProbe {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int C = args.length > 1 ? Integer.parseInt(args[1]) : 4;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        long t = m.t;
        // SealPIR Figure 3 第 14 行：inverse = m^{-1} mod t，其中 m = 2^ℓ = C（不是 2！）。
        //   循环结束时恰好一个密文加密 m，其余加密 0；乘 m^{-1} 才把 m 变成 1。
        long alpha = java.math.BigInteger.valueOf(C)
            .modInverse(java.math.BigInteger.valueOf(t)).longValueExact();

        System.out.println("=== SealPIR EXPAND 可行性判别 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[test]   N=%d, t=%d, C=%d, alpha = C^{-1} mod t = %d%n", n, t, C, alpha);
        int ell = Integer.numberOfTrailingZeros(C);
        System.out.print("[index]  按群论推导的 Galois 指数 e_j = N/2^j + 1：");
        for (int j = 0; j < ell; j++) {
            System.out.printf("%s%d", j > 0 ? ", " : "", n / (1 << j) + 1);
        }
        System.out.printf("%n          （论文 Figure 3 印的是 N/2^{j+1}+1，比这整体差一层）%n%n");

        partA(m, n);
        partB(m, n, C, alpha);
        partC(m, n, C);
        partD(m, n, t, C, alpha);

        System.out.printf("=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ================================================================ A

    /** 裁决第一层的 Galois 指数：4097 应给出干净 one-hot，2049 应当不给出（负对照）。 */
    private static void partA(Mpc4jRgsw m, int n) {
        System.out.println("--- A. Galois 指数裁决（第一层，n=2）---");
        for (int e : new int[]{n + 1, n / 2 + 1}) {
            GaloisKeys gk = galoisKeys(m, e);
            int[] exps = {e};                 // 必须显式传，否则会误用另一组的公钥，裁决就无效
            GaloisKeys[] gks = {gk};
            String label = (e == n + 1) ? "N+1（正文手推）" : "N/2+1（Figure 3 在 j=0）";
            System.out.printf("  e=%d  %s  公钥创建成功%n", e, label);
            for (int i = 0; i < 2; i++) {
                Ciphertext[] o = expand(m, n, encryptMonomial(m, n, i), 2, exps, gks);
                long[] v0 = m.decrypt(o[0]);
                long[] v1 = m.decrypt(o[1]);
                boolean clean0 = v0[0] == 2 && allZeroFrom(v0, 1);
                boolean clean1 = v1[0] == 2 && allZeroFrom(v1, 1);
                boolean oneHot = (i == 0) ? (clean0 && allZeroFrom(v1, 0)) : (clean1 && allZeroFrom(v0, 0));
                boolean expectOneHot = (e == n + 1);
                report(String.format("A. Galois e=%d, i=%d → %s", e, i,
                        expectOneHot ? "必须是干净 one-hot" : "必须【不是】干净 one-hot（负对照）"),
                    oneHot == expectOneHot,
                    String.format("o_0=[%d, 余项%s], o_1=[%d, 余项%s]",
                        v0[0], allZeroFrom(v0, 1) ? "全零" : "非零",
                        v1[0], allZeroFrom(v1, 1) ? "全零" : "非零"));
            }
        }
        System.out.println();
    }

    // ================================================================ B

    /** 真跑 log2(C) 层扩展，验证 C 个 one-hot，并给出噪声随层数的变化。 */
    private static void partB(Mpc4jRgsw m, int n, int C, long alpha) {
        System.out.println("--- B. C=" + C + " 的 " + Integer.numberOfTrailingZeros(C)
            + " 层扩展正确性与噪声 ---");
        GaloisKeys[] gks = gkCache(m, n, C);
        int[] exps = defaultExps(n, C);

        // 对照：明文常数 C 加密后乘 alpha = C^{-1} —— 同一条 multiplyPlain 路径，但没经过 Galois 降层。
        long[] cVec = new long[n];
        cVec[0] = C;
        Ciphertext ctl = m.encrypt(cVec);
        Ciphertext ctlScaled = mulPlainCoeffs(m, ctl, constVec(n, alpha));
        long ctlWant = (C * (alpha % m.t)) % m.t;
        System.out.printf("    [对照] Enc(常数 %d) 未降层：乘 alpha 后解密值 %d（期望 %d）%s%n",
            C, m.decrypt(ctlScaled)[0], ctlWant,
            m.decrypt(ctlScaled)[0] == ctlWant ? " ✔" : "  ← 有问题");

        for (int i = 0; i < C; i++) {
            Ciphertext query = encryptMonomial(m, n, i);
            int bFresh = budget(m, query);
            Ciphertext[] noScale = expand(m, n, query, C, exps, gks);
            Ciphertext[] scaled = new Ciphertext[C];
            for (int c = 0; c < C; c++) {
                scaled[c] = mulPlainCoeffs(m, noScale[c], constVec(n, alpha));
            }

            boolean okNoScale = true;
            boolean okScaled = true;
            StringBuilder sb = new StringBuilder();
            for (int c = 0; c < C; c++) {
                long[] v = m.decrypt(noScale[c]);
                long[] w = m.decrypt(scaled[c]);
                long wantNo = (c == i) ? C : 0;      // 循环结束时选中项加密的是 m = C
                long wantYes = (c == i) ? 1 : 0;
                boolean goodNo = v[0] == wantNo && allZeroFrom(v, 1);
                boolean goodYes = w[0] == wantYes && allZeroFrom(w, 1);
                okNoScale &= goodNo;
                okScaled &= goodYes;
                sb.append(String.format("c%d=%d/%d%s ", c, w[0], wantYes, goodYes ? "" : "✗"));
            }
            report(String.format("B. i=%d → 扩展出 %d 个 one-hot（不乘 α 得常数 %d）", i, C, C),
                okNoScale, oneHotDump(m, noScale, i));
            report(String.format("B. i=%d → 乘 α（= C^{-1}）后得到常数 1", i),
                okScaled, sb.toString().trim());
            System.out.printf("      噪声预算：新密文 %d bit → 扩展后 %d bit（不乘 α） → 乘 α 后 %d bit%n",
                bFresh, budget(m, noScale[0]), budget(m, scaled[0]));
        }
        System.out.println();
    }

    // ================================================================ C

    /** 噪声对比：现有做法 vs 扩展做法（都用不折 α 的选择子，纯比扩展本身的代价）。 */
    private static void partC(Mpc4jRgsw m, int n, int C) {
        System.out.println("--- C. 噪声对比：C 个独立新密文 vs 一次扩展 ---");
        long[][] table = table(C, n);
        GaloisKeys[] gks = gkCache(m, n, C);

        // 现有做法：C 个独立新密文，各自 CtPtMul 后求和
        Ciphertext accFresh = null;
        for (int c = 0; c < C; c++) {
            Ciphertext prod = mulPlainCoeffs(m, encryptMonomial(m, n, 0), table[c]);
            accFresh = (accFresh == null) ? prod : m.add(accFresh, prod);
        }
        // 扩展做法：一次扩展出 C 个选择子，各自 CtPtMul 后求和
        Ciphertext[] o = expand(m, n, encryptMonomial(m, n, 0), C, defaultExps(n, C), gks);
        Ciphertext accExp = null;
        for (int c = 0; c < C; c++) {
            Ciphertext prod = mulPlainCoeffs(m, o[c], table[c]);
            accExp = (accExp == null) ? prod : m.add(accExp, prod);
        }
        System.out.printf("    C=%d 列选择后噪声预算：现有做法 %d bit，扩展做法 %d bit（扩展多花 %d bit）%n",
            C, budget(m, accFresh), budget(m, accExp), budget(m, accFresh) - budget(m, accExp));
        System.out.printf("    上传通信量：现有 %d 个密文 → 扩展后 1 个（少 %d 倍）%n%n", C, C);
    }

    // ================================================================ D

    /** α 折进明文表的端到端等效性：CtPtMul(o_c, C^{-1}·P_c) 必须精确等于 P_c。 */
    private static void partD(Mpc4jRgsw m, int n, long t, int C, long alpha) {
        System.out.println("--- D. 把 α 折进明文表（密文侧不乘 α）的端到端等效性 ---");
        long[][] table = table(C, n);
        long[][] folded = new long[C][n];
        for (int c = 0; c < C; c++) {
            for (int j = 0; j < n; j++) {
                folded[c][j] = (alpha * table[c][j]) % t;   // 明文里算，无需密钥
            }
        }
        GaloisKeys[] gks = gkCache(m, n, C);
        int[] exps = defaultExps(n, C);
        for (int sel = 0; sel < C; sel++) {
            Ciphertext[] o = expand(m, n, encryptMonomial(m, n, sel), C, exps, gks);   // 不乘 α
            Ciphertext acc = null;
            for (int c = 0; c < C; c++) {
                Ciphertext prod = mulPlainCoeffs(m, o[c], folded[c]);
                acc = (acc == null) ? prod : m.add(acc, prod);
            }
            long[] got = m.decrypt(acc);
            boolean ok = true;
            for (int j = 0; j < 16; j++) {
                if (got[j] != table[sel][j]) {
                    ok = false;
                }
            }
            report(String.format("D. 选中列 c=%d → 解出 %s", sel,
                    java.util.Arrays.toString(java.util.Arrays.copyOf(got, 4))),
                ok, ok ? "精确等于 P（无 α 误差）"
                    : "P = " + java.util.Arrays.toString(java.util.Arrays.copyOf(table[sel], 4)));
        }
        System.out.printf("    ⇒ 折 α 可行：Σ_c C·1_{c=sel}·(C^{-1}·P_c) = P_sel，密文侧一次 α 乘法都没有%n"
            + "      ⇒ Theorem 2 里那个 t 因子（约 %d bit）可以整个去掉%n%n",
            (int) Math.round(Math.log(t) / Math.log(2)));
    }

    // ================================================================ 工具

    /** 按 SealPIR Figure 3 把 Enc(x^i) 扩展成 C 个选择子（选中项加密常数 C，其余 0）。 */
    private static Ciphertext[] expand(Mpc4jRgsw m, int n, Ciphertext query, int C,
                                       int[] exps, GaloisKeys[] gks) {
        Ciphertext[] cts = {query};
        for (int j = 0, w = 1; w < C; j++, w <<= 1) {
            Ciphertext[] next = new Ciphertext[cts.length * 2];
            for (int k = 0; k < cts.length; k++) {
                Ciphertext c0 = cts[k];
                // mulPlainCoeffs 出的是 NTT 域；applyGalois 出的是系数域，必须归一后才能 add
                Ciphertext c1 = toCoeff(m, mulPlainCoeffs(m, c0, monomial(m, n, -w)));
                next[k] = m.add(c0, applyGalois(m, c0, exps[j], gks[j]));
                next[k + cts.length] = m.add(c1, applyGalois(m, c1, exps[j], gks[j]));
            }
            cts = next;
        }
        return cts;
    }

    /** 本探针采用的指数序列 e_j = N/2^j + 1（见类注释的群论推导与 A 部分的实测裁决）。 */
    private static int[] defaultExps(int n, int C) {
        int ell = Integer.numberOfTrailingZeros(C);
        int[] exps = new int[ell];
        for (int j = 0; j < ell; j++) {
            exps[j] = n / (1 << j) + 1;
        }
        return exps;
    }

    private static GaloisKeys[] gkCache(Mpc4jRgsw m, int n, int C) {
        int[] exps = defaultExps(n, C);
        GaloisKeys[] gks = new GaloisKeys[exps.length];
        for (int j = 0; j < exps.length; j++) {
            gks[j] = galoisKeys(m, exps[j]);
        }
        return gks;
    }

    private static GaloisKeys galoisKeys(Mpc4jRgsw m, int e) {
        GaloisKeys gk = new GaloisKeys();
        m.keyGen.createGaloisKeys(new int[]{e}, gk);
        return gk;
    }

    private static Ciphertext encryptMonomial(Mpc4jRgsw m, int n, int i) {
        return m.encrypt(monomial(m, n, i));
    }

    /**
     * x^exp 在 Z_t[x]/(x^N+1) 里的系数向量。
     *
     * <p>把 exp 归约到 k ∈ [0, 2N)：k &lt; N 时是 x^k；否则 x^k = x^(k-N)·x^N = −x^(k-N)，
     * 系数取 t−1。
     */
    private static long[] monomial(Mpc4jRgsw m, int n, int exp) {
        long t = m.t;
        int k = ((exp % (2 * n)) + 2 * n) % (2 * n);
        long[] v = new long[n];
        if (k < n) {
            v[k] = 1;
        } else {
            v[k - n] = t - 1;
        }
        return v;
    }

    private static long[] constVec(int n, long v) {
        long[] a = new long[n];
        a[0] = v;
        return a;
    }

    private static long[][] table(int C, int n) {
        long[][] table = new long[C][n];
        for (int c = 0; c < C; c++) {
            for (int j = 0; j < 16; j++) {
                table[c][j] = 1000 + 137 * c + j;
            }
        }
        return table;
    }

    private static Ciphertext toNtt(Mpc4jRgsw m, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (!copy.isNttForm()) {
            m.evaluator.transformToNttInplace(copy);
        }
        return copy;
    }

    private static Ciphertext toCoeff(Mpc4jRgsw m, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        return copy;
    }

    /**
     * CtPtMul：把系数向量当明文与密文相乘。
     *
     * <p>明文的 NTT 建在密文自己的 parmsId 上。Galois 键切换会让密文降层，
     * 用 ctNtt.parmsId() 比 context.firstParmsId() 稳妥
     * （实测两者在 N=4096/C=4 下结果相同，但降层后不该再假定它没影响）。
     */
    private static Ciphertext mulPlainCoeffs(Mpc4jRgsw m, Ciphertext ct, long[] coeffs) {
        Ciphertext ctNtt = toNtt(m, ct);
        Plaintext pt = new Plaintext(coeffs.length);
        for (int i = 0; i < coeffs.length; i++) {
            pt.set(i, coeffs[i]);
        }
        m.evaluator.transformToNttInplace(pt, ctNtt.parmsId());
        Ciphertext out = new Ciphertext();
        m.evaluator.multiplyPlain(ctNtt, pt, out);
        return out;
    }

    /**
     * Galois 自同构 x → x^e；SEAL 要求系数域输入。
     *
     * <p>实测：MPC4J 的 applyGalois 输出是 NTT 域（与输入形态无关），
     * 所以这里统一归一成系数域返回，免得调用方 add 时撞 "NTT form mismatch"。
     */
    private static Ciphertext applyGalois(Mpc4jRgsw m, Ciphertext ct, int e, GaloisKeys gk) {
        Ciphertext out = new Ciphertext();
        m.evaluator.applyGalois(toCoeff(m, ct), e, gk, out);
        return toCoeff(m, out);
    }

    /** 噪声预算：invariantNoiseBudget 同样要求系数域。 */
    private static int budget(Mpc4jRgsw m, Ciphertext ct) {
        return m.decryptor.invariantNoiseBudget(toCoeff(m, ct));
    }

    private static boolean allZeroFrom(long[] v, int from) {
        for (int i = from; i < v.length; i++) {
            if (v[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
        }
        System.out.printf("    [%s] %s%n          %s%n", ok ? "PASS" : "FAIL", name, detail);
    }

    /** 打印一组选择子解密出的常数值，便于人工核对哪个是「选中列」。 */
    private static String oneHotDump(Mpc4jRgsw m, Ciphertext[] o, int sel) {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < o.length; c++) {
            long[] v = m.decrypt(o[c]);
            sb.append(String.format("c%d=%d%s ", c, v[0], c == sel ? "(选中)" : ""));
        }
        return sb.toString().trim();
    }
}
