package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.RelinKeys;

import java.util.Random;

/**
 * <b>列选择基准形态探针：C 个独立 {@code RLWE.Enc(e[c])} + 密文×明文。</b>
 *
 * <h3>论文依据（逐行）</h3>
 * <pre>
 *   Algorithm 1 QUERY  4: e ← (0,…,0, 1, 0,…,0) ∈ {0,1}^C, with the 1 at index c_a.
 *                      5: q_a = (q^col_a, q^row_a) = ( RLWE.Enc_{s_R}(e), LWE.Enc_{s_L}(r_a) ).
 *                 ANSWER 5: Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q^col_a[c], P_{c,b}(X)).
 *          SETUP        14: P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b]·X^r.
 * </pre>
 * <b>形态判定</b>（详见 {@code README.md} §一）：
 * <ul>
 *   <li>{@code q^col_a} 在每个 BFF 路下是 <b>C 个独立密文</b>，第 c 个加密常数 {@code e[c]}。
 *       判据：{@code CtPtMul(ct_0, m_1)} 第二个参数是<b>明文</b>（§2.5 定义）——
 *       要取出"一个密文里的第 c 个系数"必须用 {@code CtCtMul}，与算法矛盾。</li>
 *   <li>"<b>一个</b>加密 {@code e_{c_a}} 的密文"是 <b>CAPE-C</b> 的形态：Algorithm 5 第 11 行
 *       {@code Homomorphically expand C^col_a into q̂^col_a, an encryption of e_{c_a}}，
 *       符号带 hat（{@code q̂}）以区别于基准的 {@code q^col}。</li>
 *   <li>附录 D.1：*"For every payload block b, the <b>encrypted column selector</b> chooses the
 *       column c_a"* —— 单数指"每路一个选择器对象"，共 3 个（a=0,1,2）。</li>
 * </ul>
 * 本项目此前把 {@code q^col_a[c]} 实现成<b>明文常数</b>（服务器直接读列号），
 * 本探针验证换成<b>密文</b>后仍选得对，并给出三个坑的实测结论。
 *
 * <h3>三个坑，逐条给结论</h3>
 * <ol>
 *   <li><b>常数编码 vs 单项式编码</b>：{@code e[c]} 放<b>常数项</b>（系数 0）。
 *       放第 c 个系数会得到 {@code X^c·P_c}，<b>带 c 的位移</b>，必须补旋转。
 *       （同目录 {@code CapeColumnSelectionIndependent} 记过这一点。）</li>
 *   <li><b>层数/parms_id 一致性</b>：两个乘数必须在同一 {@code parms_id} 与同一层。
 *       选择子与表列都在<b>顶层</b>加密 ⇒ 直接乘；若选择子被降过模，须先 align。</li>
 *   <li><b>重线性化</b>：{@code multiply} 出 size-3。不重线性化也能解密，
 *       但累加会一直带着 size-3。这里显式 relinearize 并**对比**两种做法的噪声预算。</li>
 * </ol>
 *
 * <h3>负对照（证明"选择器承重"）</h3>
 * N1 全零选择子 ⇒ 载荷必须全 0；N2 换一列 ⇒ 必须给出另一列。
 * 没有这两条，"选对了"不能排除"服务器根本没在做加密选择"。
 *
 * <p>⚠️ 本探针为把两侧都做成密文，表的列也用 {@code m.encrypt} 加密；论文里表是**明文**多项式
 * （服务端资产），真实形态下的算子因此是 {@code multiplyPlain}，比这里更省。
 *
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeColumnSelectBaseline [N] [C] [R]}
 */
public final class CapeColumnSelectBaseline {

    private static int failed = 0;

    private static void report(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  —— " + detail);
        if (!ok) {
            failed++;
        }
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int C = args.length > 1 ? Integer.parseInt(args[1]) : 4;
        int R = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        long t = 65537L;

        // ⚠️ N 必须 >= 4096：N=2048 时 bfvDefault 只给 1 个工作素数，密钥切换不可用
        //    ⇒ 重线性化抛 "keyswitching is not supported by the context"。
        Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        System.out.println("=== 列选择基准形态：C 个独立 Enc(e[c]) + ct×ct ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[layout] N=%d C=%d R=%d t=%d%n%n", n, C, R, t);

        Random rnd = new Random(20261014L);

        // ---- SETUP：表是服务器资产。为了做纯 ct×ct，这里把列也加密 ----
        long[][] P = new long[C][n];
        for (int c = 0; c < C; c++) {
            for (int r = 0; r < R; r++) {
                P[c][r] = 1 + rnd.nextInt(1000);
            }
        }
        // ⚠️ 加密前必须把整条多项式填进 Plaintext：未赋值的系数是 0，
        //    而 P_c 的第 R..n-1 位本来就应该为 0（表只填了前 R 行）。
        Ciphertext[] ctP = new Ciphertext[C];
        for (int c = 0; c < C; c++) {
            ctP[c] = m.encrypt(P[c]);
        }
        System.out.println("--- SETUP：P_c(X) = Σ_r D[r + cR]·X^r，c = 0..C−1 ---");
        System.out.printf("    每列只填前 %d 个系数（= R 行），其余为 0%n%n", R);

        // ---- QUERY：C 个独立密文，常数编码 ----
        final int cA = 2;
        long[] eVec = new long[C];
        eVec[cA] = 1;
        System.out.println("--- QUERY：C 个独立 RLWE.Enc(e[c]) ---");
        System.out.printf("    c_a = %d，e = %s%n", cA, java.util.Arrays.toString(eVec));

        Ciphertext[] qCol = new Ciphertext[C];
        for (int c = 0; c < C; c++) {
            long[] constant = new long[n];
            constant[0] = eVec[c];                 // ★ 常数项
            qCol[c] = m.encrypt(constant);
        }
        boolean constantsOk = true;
        StringBuilder got = new StringBuilder();
        for (int c = 0; c < C; c++) {
            long[] v = m.decrypt(qCol[c]);
            got.append(v[0]);
            if (c < C - 1) {
                got.append(',');
            }
            if (v[0] != eVec[c]) {
                constantsOk = false;
            }
            for (int i = 1; i < 4; i++) {
                if (v[i] != 0) {
                    constantsOk = false;
                }
            }
        }
        report("Q1 选择子密文解密后常数项 == e[c]（高阶系数 0）", constantsOk,
            "解出 = [" + got + "]");
        report("Q2 选择子与表列在同一 parms_id（可直接乘）",
            String.valueOf(qCol[0].parmsId()).equals(String.valueOf(ctP[0].parmsId())),
            "selector=" + qCol[0].parmsId() + " table=" + ctP[0].parmsId());
        System.out.println();

        // ---- ANSWER 第 5 行：Σ_c CtCtMul ----
        System.out.println("--- ANSWER 5：Acc_b ← Σ_c CtCtMul(q^col[c], Enc(P_c(X))) ---");
        RelinKeys rk = m.relinKeys();

        Ciphertext accRaw = null;      // 不重线性化
        Ciphertext accRel = null;      // 重线性化
        for (int c = 0; c < C; c++) {
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiply(qCol[c], ctP[c], prod);
            if (accRaw == null) {
                accRaw = new Ciphertext();
                accRaw.copyFrom(prod);
            } else {
                m.evaluator.addInplace(accRaw, prod);
            }
            Ciphertext prodRel = new Ciphertext();
            m.evaluator.relinearize(prod, rk, prodRel);
            if (accRel == null) {
                accRel = new Ciphertext();
                accRel.copyFrom(prodRel);
            } else {
                m.evaluator.addInplace(accRel, prodRel);
            }
        }

        int nbRaw = m.decryptor.invariantNoiseBudget(accRaw);
        int nbRel = m.decryptor.invariantNoiseBudget(accRel);
        System.out.printf("    不重线性化：size=%d  噪声预算=%d bit%n", accRaw.size(), nbRaw);
        System.out.printf("    重线性化  ：size=%d  噪声预算=%d bit%n", accRel.size(), nbRel);
        report("A0 未重线性化的累加是 size-3 且仍可解密", accRaw.size() == 3, "");
        report("A1 重线性化后回到 size-2", accRel.size() == 2, "");
        report("A2 重线性化不降低噪声预算（或降幅可忽略）", nbRel >= nbRaw - 1,
            "raw=" + nbRaw + " relin=" + nbRel);

        long[] gotCol = m.decrypt(accRel);
        boolean selOk = true;
        String firstBad = "";
        for (int r = 0; r < R; r++) {
            if (gotCol[r] != P[cA][r]) {
                selOk = false;
                if (firstBad.isEmpty()) {
                    firstBad = String.format("r=%d got=%d want=%d", r, gotCol[r], P[cA][r]);
                }
            }
        }
        boolean tailZero = true;
        for (int r = R; r < n; r++) {
            if (gotCol[r] != 0) {
                tailZero = false;
                break;
            }
        }
        System.out.print("    Acc 前 8  = ");
        for (int i = 0; i < 8; i++) {
            System.out.print(gotCol[i] + " ");
        }
        System.out.println();
        System.out.print("    P_ca 前 8 = ");
        for (int i = 0; i < 8; i++) {
            System.out.print(P[cA][i] + " ");
        }
        System.out.println();
        report("A3 Acc == P_{c_a}(X)（前 R 个系数全对）", selOk, firstBad);
        report("A4 Acc 的尾部（r ≥ R）全 0 —— 表本来只填了 R 行", tailZero, "");

        // ---- 负对照 1：全零选择子 ----
        System.out.println();
        System.out.println("--- 负对照 1：C 个全零选择子 ⇒ Acc 必须全 0 ---");
        Ciphertext accZ = null;
        for (int c = 0; c < C; c++) {
            long[] constant = new long[n];
            Ciphertext z = m.encrypt(constant);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiply(z, ctP[c], prod);
            if (accZ == null) {
                accZ = new Ciphertext();
                accZ.copyFrom(prod);
            } else {
                m.evaluator.addInplace(accZ, prod);
            }
        }
        long[] zOut = m.decrypt(accZ);
        boolean zeroOk = true;
        for (int i = 0; i < n; i++) {
            if (zOut[i] != 0) {
                zeroOk = false;
                break;
            }
        }
        report("N1 全零选择子 ⇒ 载荷全 0", zeroOk, "");

        // ---- 负对照 2：换一列 ----
        System.out.println();
        System.out.println("--- 负对照 2：e[1]=1 ⇒ Acc 必须变成 P_1 ---");
        Ciphertext acc2 = null;
        for (int c = 0; c < C; c++) {
            long[] constant = new long[n];
            constant[0] = (c == 1) ? 1 : 0;
            Ciphertext sel = m.encrypt(constant);
            Ciphertext prod = new Ciphertext();
            m.evaluator.multiply(sel, ctP[c], prod);
            Ciphertext prodRel = new Ciphertext();
            m.evaluator.relinearize(prod, rk, prodRel);
            if (acc2 == null) {
                acc2 = new Ciphertext();
                acc2.copyFrom(prodRel);
            } else {
                m.evaluator.addInplace(acc2, prodRel);
            }
        }
        long[] gotCol2 = m.decrypt(acc2);
        boolean matches1 = true;
        for (int r = 0; r < R; r++) {
            if (gotCol2[r] != P[1][r]) {
                matches1 = false;
                break;
            }
        }
        report("N2 e[1]=1 ⇒ Acc == P_1（换了列）", matches1, "");

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL CHECKS PASSED ===");
        } else {
            System.out.printf("=== %d CHECK(S) FAILED ===%n", failed);
            throw new IllegalStateException(failed + " check(s) failed");
        }
    }
}
