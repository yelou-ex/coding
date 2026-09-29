package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>列选择 → 提取 的耗时基准。</b>
 *
 * <h3>测的是论文 ANSWER 的哪一段</h3>
 * <pre>
 *   算法 1 ANSWER 第 2 行（对 a = 0..2，对 b = 1..B_pay）：
 *     Acc_{a,b}   ← Σ_c CtPtMul(q_{col,a}[c], P_{c,b}(X))   ← ① 列选择
 *     Acc'_{a,b}  ← BlindRotate(q_{row,a}, Acc_{a,b})       ← ② 盲旋转
 *     ct_{a,b}    ← SampleExtract_0(Acc'_{a,b})             ← ③ 样本提取
 * </pre>
 * 本文件把 ①②③ 分开计时，再给出"一次查询 = 3 × B_pay 个单元"的外推。
 *
 * <h3>三个容易搞错的地方</h3>
 * <ol>
 *   <li><b>单元数不是 3，是 3·B_pay</b>。论文的循环是 {@code a} 与 {@code b} <b>嵌套</b>的，
 *       每个 payload 块 b 都要单独做一遍"列选择 + 盲旋转 + 提取"。</li>
 *   <li><b>自举密钥 BK 是离线材料</b>（SETUP），不计入在线耗时；但它的体积决定了
 *       哪些参数组合在本机（16 GB）根本跑不起来。本文件把两者都打印。</li>
 *   <li><b>盲旋转耗时 ∝ d</b>（d 轮 CMUX）。所以 d=512 与 d=N=16384 是两个量级的事，
 *       本文件按 {d=512, d=2048, d=N} 三档外推（外推值标注为"外推"，不是实测）。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.SelToExtractBench 4096 512 32 32 5}
 * <br>参数：{@code N d R C [reps]}
 */
public final class SelToExtractBench {

    private static final long T = 65537L;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 512;
        int rows = args.length > 2 ? Integer.parseInt(args[2]) : 32;    // R
        int cols = args.length > 3 ? Integer.parseInt(args[3]) : 32;    // C
        int reps = args.length > 4 ? Integer.parseInt(args[4]) : 5;
        if ((long) rows * cols > n) {
            System.out.printf("!! R*C = %d > N = %d，列选择的系数区间前提不成立，退出%n", rows * cols, n);
            return;
        }

        Mpc4jRgsw m = new Mpc4jRgsw(n, T, 0, 1 << 16);
        System.out.println("=== 列选择 → 提取 耗时基准 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[layout] R=%d 行 × C=%d 列 = %d 系数（≤ N=%d ✓）；LWE 维数 d=%d；重复 %d 次%n%n",
            rows, cols, rows * cols, n, d, reps);

        Random rnd = new Random(20260928L);

        // ---------------- 离线（SETUP）：自举密钥 BK = {RGSW(s_i)}_{i<d} ----------------
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        double bkMs = ms(t0);
        double bkMb = d * 2.0 * m.workingPrimeCount * (2.0 * m.workingPrimeCount * n * 8) / 1048576.0;
        System.out.printf("[setup-离线] BK：%d 个 RGSW，%s；体积 ≈ %s%n",
            d, fmtMs(bkMs), fmtBytes(bkMb));
        if (bkMb > 8000) {
            System.out.println("             ⚠️ BK 体积已接近/超过本机内存（16 GB）——下面若 OOM 就换更小的 d 或 N");
        }

        // ---------------- 离线（SETUP）：服务端把表组装成一个明文多项式 A(X) ----------------
        long[] D = new long[rows * cols];
        for (int i = 0; i < D.length; i++) {
            D[i] = Math.floorMod(rnd.nextLong(), T);
        }
        long[] A = new long[n];
        System.arraycopy(D, 0, A, 0, rows * cols);
        Plaintext ptA = new Plaintext(A);
        System.out.printf("[setup-离线] 表明文 A(X)：%d 个系数，组装 %.1f ms%n%n", n, 0.0);

        // ---------------- 挑一个位置，先验正确性，再计时 ----------------
        int u = rows + 3;                       // 第 1 列第 3 行（避开 c=0 的退化分支）
        int r = u % rows;
        int c = u / rows;
        long want = D[r + c * rows];

        long[] sel = new long[n];
        if (c == 0) {
            sel[0] = 1;
        } else {
            sel[n - c * rows] = T - 1;
        }

        // 正确性：走满整条链，看读回的是不是 D[r + cR]
        long[][] lwe = BlindRotateOps.lweEncryptIndex(s, r, 2 * n, rnd);
        Ciphertext acc0 = columnSelect(m, sel, ptA);
        Ciphertext rot0 = BlindRotateOps.blindRotate(m, bk, acc0, lwe[0], lwe[1][0]);
        long got = LweRlweBridge.decryptSampleViaPack(m, LweRlweBridge.sampleExtract(m, rot0, 0), 0);
        System.out.printf("[正确性自检] 位置 u=%d（r=%d, c=%d）：读回 %d，期望 D[%d] = %d  →  %s%n",
            u, r, c, got, r + c * rows, want, got == want ? "✓" : "✗ 计时结果无意义！");

        // ---- 逐列【全系数】对拍：这是"列选择本身对不对"的严格判据 ----
        // 单点对拍只能证明 Acc[r] 对，证明不了"整列"对。而 AnswerPathMini 因为
        // bffPositions(kw) = {3kw,3kw+1,3kw+2} 配合 R=64，**只走到 c=0**
        // （c=0 是退化分支 E(X)=X^0=1）——真正需要验证的 X^{-cR} = -X^{N-cR}
        // 负指数分支它一次都没走过。所以这里显式把 c=0 / 1 / C-1 都扫一遍，
        // 且每个 c 都逐系数对拍全部 R 个系数。详见 README §1.2 的"待与 artifact 对齐"。
        boolean colOk = true;
        for (int cc : new int[]{0, 1, cols - 1}) {
            long[] selC = new long[n];
            if (cc == 0) {
                selC[0] = 1;
            } else {
                selC[n - cc * rows] = T - 1;
            }
            long[] gotC = m.decrypt(columnSelect(m, selC, ptA));
            int wrong = 0;
            StringBuilder firstWrong = new StringBuilder();
            for (int rr = 0; rr < rows; rr++) {
                if (gotC[rr] != D[rr + cc * rows]) {
                    wrong++;
                    if (wrong <= 2) {
                        firstWrong.append(String.format(" [r=%d got=%d want=%d]",
                            rr, gotC[rr], D[rr + cc * rows]));
                    }
                }
            }
            int nonzeroTail = 0;   // [R, N) 上的"垃圾"，预期非零且无害
            for (int k = rows; k < n; k++) {
                if (gotC[k] != 0) {
                    nonzeroTail++;
                }
            }
            colOk &= wrong == 0;
            System.out.printf("      c=%-3d 系数 [0,%d) 对拍：错 %d/%d%s；[R,N) 上非零 %d 个（预期，不影响结果）%n",
                cc, rows, wrong, rows, firstWrong, nonzeroTail);
        }
        System.out.printf("[列选择严格判据] c = 0 / 1 / C−1 的整列都对  →  %s%n%n",
            colOk ? "✓" : "✗ 列选择实现有错！");

        // ---------------- 预热（JIT） ----------------
        for (int i = 0; i < 2; i++) {
            Ciphertext a = columnSelect(m, sel, ptA);
            Ciphertext x = BlindRotateOps.blindRotate(m, bk, a, lwe[0], lwe[1][0]);
            LweRlweBridge.sampleExtract(m, x, 0);
        }

        // ---------------- 计时 ----------------
        double[] tClient = new double[reps];
        double[] tSel = new double[reps];
        double[] tRot = new double[reps];
        double[] tExt = new double[reps];
        double[] tUnit = new double[reps];

        for (int i = 0; i < reps; i++) {
            long a = System.nanoTime();
            Ciphertext ctCol = m.encrypt(sel);
            tClient[i] = ms(a);

            Ciphertext cNtt = new Ciphertext();
            cNtt.copyFrom(ctCol);
            a = System.nanoTime();
            if (!cNtt.isNttForm()) {
                m.evaluator.transformToNttInplace(cNtt);
            }
            Plaintext pt = new Plaintext(A);
            m.evaluator.transformToNttInplace(pt, cNtt.parmsId());
            Ciphertext acc = new Ciphertext();
            m.evaluator.multiplyPlain(cNtt, pt, acc);
            tSel[i] = ms(a);

            a = System.nanoTime();
            Ciphertext rot = BlindRotateOps.blindRotate(m, bk, acc, lwe[0], lwe[1][0]);
            tRot[i] = ms(a);

            a = System.nanoTime();
            long[][] sample = LweRlweBridge.sampleExtract(m, rot, 0);
            tExt[i] = ms(a);

            tUnit[i] = tSel[i] + tRot[i] + tExt[i];
        }

        Arrays.sort(tClient);
        Arrays.sort(tSel);
        Arrays.sort(tRot);
        Arrays.sort(tExt);
        Arrays.sort(tUnit);

        double selMed = med(tSel);
        double rotMed = med(tRot);
        double extMed = med(tExt);
        double unitMed = med(tUnit);

        System.out.println("[在线耗时]（单位 ms，取中位数；min..max）");
        row("① 列选择 CtPtMul", tSel);
        row("② 盲旋转 BlindRotate(d=" + d + ")", tRot);
        row("③ 提取 SampleExtract_0", tExt);
        row("   单元合计 ①②③", tUnit);
        System.out.println();
        System.out.printf("    客户端侧（不计入服务端）：加密列选择子 %.2f ms%n", med(tClient));
        System.out.printf("    盲旋转单轮（1 次 CMUX）≈ %.2f ms%n", rotMed / d);
        System.out.printf("    占比：列选择 %.1f%% ／ 盲旋转 %.1f%% ／ 提取 %.1f%%%n%n",
            100 * selMed / unitMed, 100 * rotMed / unitMed, 100 * extMed / unitMed);

        // 为什么盲旋转这么贵：1 次 CMUX = 1 次 externalProduct = 2 组 × levels 次"密文×明文"
        int lv = m.levels;
        System.out.println("    [分解] 1 次 CMUX = 1 次 RGSW⊗ct = 2 组 × " + lv + " 层 = " + (2 * lv)
            + " 次「密文×明文」，量级与①列选择同源");
        System.out.printf("           于是 1 次盲旋转 ≈ d × %d = %d 次①的运算量%n", 2 * lv, d * 2 * lv);
        System.out.printf("           实测 ① = %.2f ms，则盲旋转的理论下限 ≈ %.2f ms（实测 %.2f ms，比值 %.1f×）%n%n",
            selMed, d * 2 * lv * selMed, rotMed, rotMed / Math.max(0.01, d * 2 * lv * selMed));

        // ---------------- 外推：一次查询 = 3 × B_pay 个单元 ----------------
        System.out.println("[外推] 一次 ANSWER 查询 = 3 个 BFF 位置 × B_pay 个 payload 块 = 3·B_pay 个单元");
        System.out.printf("       （每个单元 = 列选择 + 盲旋转 + 提取，实测 %.2f ms）%n%n", unitMed);
        System.out.printf("    %-10s %-14s %-14s %-14s%n", "B_pay", "单元数", "合计(秒)", "其中盲旋转(秒)");
        for (int bpay : new int[]{1, 16, 64, 256, 1024, 4096}) {
            double units = 3.0 * bpay;
            System.out.printf("    %-10d %-14.0f %-14.2f %-14.2f%n",
                bpay, units, units * unitMed / 1000.0, units * rotMed / 1000.0);
        }

        // ---------------- 外推：d 的影响（盲旋转 ∝ d） ----------------
        System.out.println();
        System.out.println("[外推] 盲旋转 ∝ d（每轮一次 CMUX）。本机实测点之外按线性外推，**不是实测值**：");
        System.out.printf("        d=%d 实测 %.2f s/单元", d, unitMed / 1000.0);
        int prev = d;
        for (int ds : new int[]{2048, n}) {
            if (ds <= d || ds == prev) {
                continue;
            }
            prev = ds;
            double scale = (double) ds / d;
            double rotD = rotMed * scale;
            System.out.printf("；d=%d 外推 %.2f s/单元", ds, (selMed + extMed + rotD) / 1000.0);
        }
        System.out.println();
        System.out.println();
        System.out.println("（注：本机 16 GB 内存，N=16384 且 d=512 时 BK ≈ 16 GB，跑不起来；");
        System.out.println("   要复现论文规模的 N=16384 必须先在内存 ≥64 GB 的机器上把 BK 持久化。）");
    }

    /** 列选择：CtPtMul(加密的列选择子, 表明文多项式)。 */
    private static Ciphertext columnSelect(Mpc4jRgsw m, long[] sel, Plaintext ptA) {
        Ciphertext ctCol = m.encrypt(sel);
        if (!ctCol.isNttForm()) {
            m.evaluator.transformToNttInplace(ctCol);
        }
        Plaintext pt = new Plaintext();
        pt.copyFrom(ptA);
        m.evaluator.transformToNttInplace(pt, ctCol.parmsId());
        Ciphertext acc = new Ciphertext();
        m.evaluator.multiplyPlain(ctCol, pt, acc);
        return acc;
    }

    private static void row(String name, double[] sorted) {
        System.out.printf("    %-30s %8.2f   (%.2f .. %.2f)%n",
            name, med(sorted), sorted[0], sorted[sorted.length - 1]);
    }

    private static double med(double[] sorted) {
        return sorted[sorted.length / 2];
    }

    private static double ms(long t0) {
        return (System.nanoTime() - t0) / 1e6;
    }

    private static String fmtMs(double v) {
        return v >= 1000 ? String.format("%.1f s", v / 1000) : String.format("%.0f ms", v);
    }

    private static String fmtBytes(double mb) {
        return mb >= 1024 ? String.format("%.2f GB", mb / 1024) : String.format("%.0f MB", mb);
    }
}
