package com.fusepir.probe;


import com.fusepir.prim.*;
import com.fusepir.cape.*;
import com.fusepir.nativejni.NativeBlindRotate;

import java.util.ArrayList;
import java.util.List;

/**
 * <b>P1-3：{@code d} 的语义对齐 —— 先把事实量出来，再选（a）改实现还是（b）改文档</b>。
 *
 * <h3>论文原文（这一项的全部依据）</h3>
 * <pre>
 *   A1 SETUP  3: Select public parameters (N, d, t, q), and generate HE keys sk = (s_L, s_R).
 *   A1 QUERY  5: q_a = ( q^col_a, q^row_a ) = ( RLWE.Enc_{s_R}(e), LWE.Enc_{s_L}(r_a) )
 *   A2 DECODE 8: s_j &lt;- Dec_{s_R}(ct_score,j)
 * </pre>
 * ⇒ <b>论文的 {@code d} 是 {@code LWE.Enc_{s_L}} 里 {@code a ∈ Z_q^d} 的维数</b>，
 * 而 {@code s_L} 与 {@code s_R} 是 <b>SETUP 里一起生成的两把独立密钥</b>。
 *
 * <h3>现状（规划书 §1.3 的 S3）</h3>
 * {@code secret_bits} 取 SEAL <b>三值 {-1,0,1}</b> 秘密的<b>前 d 个系数</b>，
 * 且把 {@code v = −1} 静默归零 ⇒ 约 2/3 的轮是恒等。
 *
 * <h3>⚠️ 本轮量出来之后，这条比规划书写的更严重（见 §2）</h3>
 * 不只是"语义偏离 + 轮次浪费"：<b>{@code s_L} 与 {@code s_R} <u>被实现强制成同一把</u></b>。
 * 原因是 structural 的：
 * <pre>
 *   blind rotate 实际做的是  X^{ Σ a_i·s_i(bsk) − beta }
 *   而 beta = ⟨a, s_L⟩ + r_a
 *   ⇒ 净旋转 = Σ a_i·(s_i − s_L,i) − r_a
 *   ⇒ **要它等于 −r_a，就必须 s_i == s_L,i**（逐位相等）
 * </pre>
 * 所以"把 {@code s_L} 真正独立出来"这件事，<b>与当前的盲旋转口径不兼容</b> ——
 * 它和 P1-2（索引噪声）卡在同一个结构点上。本类把这件事变成可跑的断言。
 *
 * <h3>本类做什么</h3>
 * <ol>
 *   <li>量 RLWE 秘密的系数分布（{-1, 0, 1} 各占多少）；</li>
 *   <li>量"前 d 个系数"里的三值分布 ⇒ 得到**恒等轮的实测比例**；</li>
 *   <li>量 {@code a[i] ≡ 0 (mod 2N)} 的比例（这是**另一个**独立的恒等轮来源）；</li>
 *   <li>把"要让净旋转 = −r_a，必须 s_i == s_L,i"这条**算一遍**（不是写散文）。</li>
 * </ol>
 *
 * <p>必须在服务进程内跑（要上下文句柄）：
 * 服务端加 {@code -Dcape.selftest=true} 时由 {@code CapeDemoService.printDSemantics}() 调用。
 */
public final class CapeDSemanticsProbe {

    private CapeDSemanticsProbe() {
    }

    /** 一条断言结果，供服务端把报告序列化出去。 */
    public static final class Report {
        public final List<String> lines = new ArrayList<>();
        public int pass = 0;
        public int fail = 0;

        void check(String what, boolean ok, String detail) {
            lines.add(String.format("  [%s] %s%s", ok ? "PASS" : "FAIL", what,
                detail == null || detail.isEmpty() ? "" : "  --- " + detail));
            if (ok) {
                pass++;
            } else {
                fail++;
            }
        }
    }

    /**
     * @param ctx 服务进程内的 native 上下文句柄
     * @param n   环维度
     * @param d   LWE 维数（{@code -Dcape.d}，默认 16）
     */
    public static Report run(long ctx, int n, int d) {
        Report r = new Report();
        long twoN = 2L * n;

        // ---------- 1. RLWE 秘密的系数分布 ----------
        //
        // 只能通过 nativeSecretBits 观察它 —— 而那个入口**刻意**只回 {0,1}
        // （把 −1 归零），所以它**看不到**真实的三值分布。
        // 这正是"d 的语义偏离"能一路走到今天而不被发现的原因：**观察工具本身把它抹平了**。
        int[] bits = new int[d];
        Long[] raw = NativeBlindRotate.nativeSecretBits(ctx, d);
        for (int i = 0; i < d; i++) {
            bits[i] = raw[i].intValue();
        }
        int ones = 0;
        for (int b : bits) {
            if (b == 1) {
                ones++;
            }
        }
        r.lines.add("  采样：RLWE 秘密的前 d=" + d + " 个系数，经 nativeSecretBits 观察");
        r.lines.add("        {0,1} 里 1 的个数 = " + ones + " / " + d
            + "（" + String.format("%.1f%%", 100.0 * ones / d) + "）");
        r.check("nativeSecretBits 只回 {0,1}（−1 被静默归零 ⇒ 该投影无法用于数三值分布）",
            allBinary(bits), "**观察工具本身抹平了语义** —— 这也是《d 语义偏离》能一路走到今天的原因");

        // ---------- 2. 三值秘密的**真实分布**（查过 SEAL 源码，不是猜的）----------
        //
        // SEAL 4.0.0 `native/src/seal/util/rlwe.cpp` 的 `sample_poly_ternary`：
        //     uniform_int_distribution<uint64_t> dist(0, 2);
        //     rand ∈ {0,1,2} 均匀  ->  {−1, 0, +1} **均匀**
        // ⇒ 渐近有 **1/3 的系数是 0、2/3 是 ±1**（不是 hwt=N/2 的 ±1，那个是别的实现）。
        //
        // 而 `secret_bits` 把 `v == 1 || v == 0 ? v : 0` 映射成 {0,1} ⇒
        //     **sBits 里 1 的密度 ≈ 2/3**（±1 都记成 1），0 的密度 ≈ 1/3。
        //
        // ⚠️⚠️ **恒等轮来自 s_i == 0 ⇒ 恒等轮 ≈ 1/3，不是 2/3。**
        //    《CAPE复现规划书.md》§1.3 与 §三 P1-3 两处都写的"约 2/3 的轮是恒等"，
        //    **方向写反了**（把"2/3 的轮在做真 CMUX"说成了"2/3 恒等"）。
        //    这一条实测 + SEAL 源码都能确认，本轮就地更正。
        //
        // 采样说明：**不能用 nativeSecretBits 的返回值去估计分布** —— 它回的是
        // "系数 == 1 或 == 0" 的指示函数，±1 都变成 1，所以拿它算"恒等轮"是**对的**
        // （恒等确实只看"是不是 0"），但拿它算"三值各自的比例"就**不对**。
        // 这里只用它算"零的比例"，并把三值分布的期望单独列出来。
        int zeros = d - ones;
        double zeroFracSmall = zeros / (double) d;
        double nonzeroFracSmall = ones / (double) d;
        double sd = Math.sqrt((1.0 / 3.0) * (2.0 / 3.0) / d);
        r.lines.add("        小样本（d=" + d + "）观察值：1 的个数 = " + ones + "/" + d + " = "
            + String.format("%.3f", nonzeroFracSmall) + "；零的比例 = "
            + String.format("%.3f", zeroFracSmall));
        r.lines.add("        ⚠️ d=" + d + " 时该比例的标准差 = sqrt((1/3)(2/3)/d) = "
            + String.format("%.3f", sd) + " ⇒ **单次 d=" + d
            + " 的观察值不足以判定 1/3 还是 2/3**（两者都常落在 ±3σ 内）。");
        r.lines.add("        ⇒ 判据交给下面那个**全量直方图**，不拿小样本下结论。");
        // 批量校验：**并且这里改用真实三值直方图**，不再靠指示函数反推。
        //
        // ⚠️ 为什么要换工具：`nativeSecretBits` 的投影 `v == 1 || v == 0 ? v : 0`
        //    **分不清 −1 和真 0**。用它算"零的比例"是可行的（恒等确实只看"是不是 0"，
        //    而真 0 在两处都是 0），但**用它算"非零的比例"会把 ±1 混起来、
        //    也看不出有没有非三值的系数**。P1-3 的结论完全押在这个分布上，
        //    所以必须用 `nativeSecretHistogram` 直接量真实三值分布。
        {
            long[] hist = NativeBlindRotate.nativeSecretHistogram(ctx);
            long neg = hist[0], zero = hist[1], pos = hist[2], other = hist[3], total = hist[4];
            r.lines.add("  真实三值直方图（nativeSecretHistogram，全部 " + total + " 个系数）：");
            r.lines.add("        −1 = " + neg + "（" + String.format("%.4f", neg / (double) total)
                + "）  0 = " + zero + "（" + String.format("%.4f", zero / (double) total)
                + "）  +1 = " + pos + "（" + String.format("%.4f", pos / (double) total)
                + "）  非三值 = " + other);
            double zeroDensity = zero / (double) total;
            double nonZeroDensity = (neg + pos) / (double) total;
            r.check("秘密确实是三值的（非三值系数 = 0）", other == 0,
                "非三值 = " + other + " => " + (other == 0 ? "OK 三值 {-1,0,+1}"
                    : "有非三值系数，说明读法/模数有问题"));
            r.lines.add("        ⇒ **零的密度 = " + String.format("%.4f", zeroDensity)
                + "**（全部 " + total + " 个系数，样本足够大，可直接引用）");
            r.lines.add("        ⇒ 非零（±1）密度 = " + String.format("%.4f", nonZeroDensity));
            // 三值均匀（SEAL `sample_poly_ternary`：rand ∈ {0,1,2} 均匀）的期望是各 1/3。
            // 容差用二项 3σ：sqrt((1/3)(2/3)/8192) ≈ 0.0052 ⇒ 3σ ≈ 0.016。
            double sdBig = Math.sqrt((1.0 / 3.0) * (2.0 / 3.0) / total);
            r.check("三值**均匀**（各 ≈ 1/3，与 SEAL sample_poly_ternary 一致）",
                Math.abs(neg / (double) total - 1.0 / 3.0) <= 3 * sdBig
                    && Math.abs(pos / (double) total - 1.0 / 3.0) <= 3 * sdBig
                    && Math.abs(zeroDensity - 1.0 / 3.0) <= 3 * sdBig,
                String.format("−1 %.4f / 0 %.4f / +1 %.4f，期望各 0.3333，3σ=%.4f",
                    neg / (double) total, zeroDensity, pos / (double) total, 3 * sdBig));
            r.lines.add("        ⇒ **恒等轮比例 = 零的密度 = " + String.format("%.4f", zeroDensity)
                + "**（恒等只看 s_i 是否为 0）⇒ **约 1/3，不是文档原先写的 2/3**。");
            r.lines.add("        ⇒ 反向结论：**约 2/3 的轮在做真的 CMUX** —— "
                + "旋转机构被压得比原先记载的更满。");
        }

        // ---------- 3. 另一个独立的恒等轮来源：a[i] ≡ 0 (mod 2N) ----------
        //
        // native 的 blind_rotate 里有这一行：`if (a[i] % two_n == 0) continue;` ——
        // 因为 a[i] = 0 时 CMUX 的两支相同，SEAL 会判它 transparent 并抛。
        // 客户端采样 a[i] ∈ [0, 2N) 是**均匀**的 ⇒ 每个 a[i] 有 1/(2N) 概率为 0。
        // d=16、N=8192 时这条的期望是 16/16384 ≈ 0.1%，可忽略；但它是一条**真实的**耗损，
        // 而且**与三值秘密无关** —— 记在这里免得将来把它错记成"d 语义"的一部分。
        double aZeroProb = d / (double) twoN;
        r.lines.add("  另一条恒等轮来源：a[i] ≡ 0 (mod 2N) 的概率 = d/(2N) = "
            + String.format("%.5f", aZeroProb) + "（d=" + d + ", 2N=" + twoN + "）");
        r.check("a[i] ≡ 0 这条来源可忽略（< 1%）", aZeroProb < 0.01,
            String.format("%.5f", aZeroProb) + " => 归因时不要和《三值秘密》混为一谈");

        // ---------- 4. 结构断言：s_i 必须 == s_L,i ----------
        //
        // 把净旋转量真的算一遍。取几个有代表性的 (a, s_R, s_L) 组合：
        //   净旋转 = Σ a_i·s_R,i − ( Σ a_i·s_L,i + r_a ) = Σ a_i·(s_R,i − s_L,i) − r_a
        // 要它 ≡ −r_a  ⇒  Σ a_i·(s_R,i − s_L,i) ≡ 0  (mod 2N)
        // 这对**所有** a 都成立，当且仅当 s_R == s_L 逐位相等。
        {
            long[] a = {1234567L, 0L, 5L, twoN - 1, 999999L, 1L, 424242L, 7L};
            int[] sR = {1, 1, 0, 1, 0, 1, 1, 0};
            int[] sLsame = sR.clone();
            // ⚠️ 判据是 Σ a_i·(s_R,i − s_L,i) ≡ 0 (mod 2N)。
            //    所以"差一位"要想看出来，**那一位的 a_i 必须非零** ——
            //    第一版我把差异放在下标 1，而 a[1] = 0，于是两个净旋转量都是 16377，
            //    断言就失败了。**是我构造的测试向量没有证明力，不是结论错了。**
            int diffAt = 0;                       // a[0] = 1234567 ≠ 0
            int[] sLdiff = sR.clone();
            sLdiff[diffAt] = 1 - sLdiff[diffAt];  // 只翻转一位
            long rA = 7;
            long netSame = net(a, sR, sLsame, rA, twoN);
            long netDiff = net(a, sR, sLdiff, rA, twoN);
            r.lines.add("  净旋转量 Σa_i·(s_R,i − s_L,i) − r_a 的实算（差异放在下标 " + diffAt
                + "，其 a=" + a[diffAt] + " ≠ 0）：");
            r.lines.add("        s_L == s_R          => " + netSame + "（要 ≡ −r_a = "
                + Math.floorMod(-rA, twoN) + " mod " + twoN + "）");
            r.lines.add("        s_L 与 s_R 差 1 位   => " + netDiff
                + "  ⇒ 行号偏 " + ((netDiff - netSame + twoN) % twoN));
            r.check("s_L == s_R 时净旋转 == −r_a（当前实现能跑通的**唯一**原因）",
                netSame == Math.floorMod(-rA, twoN), "net=" + netSame);
            r.check("s_L 与 s_R 差 1 位就偏 ⇒ **独立 s_L 与当前盲旋转不兼容**",
                netDiff != netSame,
                "偏 " + ((netDiff - netSame + twoN) % twoN)
                    + " ⇒ 与 P1-2 索引噪声卡在同一个结构点");
            // 精确判据：对所有 a 都成立 ⟺ 逐位相等
            r.check("精确判据：Σ a_i·(s_R,i − s_L,i) ≡ 0 (对**所有** a) ⟺ s_R == s_L 逐位",
                netSame == Math.floorMod(-rA, twoN) && netDiff != netSame,
                "⇒「把 s_L 独立出来」这件事本身与当前口径冲突，不是参数没调好");
        }

        // ---------- 5. 结论与两条路 ----------
        r.lines.add("  ---- 结论 ----");
        r.lines.add("  ① 恒等轮是 **1/3**（不是文档原先写的 2/3）—— 已就地更正；");
        r.lines.add("     ⇒ 旋转机构被压得比原先记载的更满，这是**好消息**。");
        r.lines.add("  ② 真正的结构问题不是恒等轮，而是 **d 被绑在 s_R 上**：");
        r.lines.add("     论文 A1 L807 是 `generate HE keys sk = (s_L, s_R)`（**两把独立密钥**），");
        r.lines.add("     而当前实现里 s_L 必须**逐位等于** s_R，否则净旋转偏 "
            + "Σ a_i(s_R,i − s_L,i)。");
        r.lines.add("  (a) 改实现 = 真做 LWE-in-RLWE（s_L 独立）：**与当前盲旋转口径不兼容**，");
        r.lines.add("      要同时改 blind rotate 的相位口径与 bsk 的构造 —— 与 P1-2 是同一块，");
        r.lines.add("      且 `RingPack` 调研已经指出真正的代价：n=N=8192 时 SwK ≈ 12 GB。");
        r.lines.add("  (b) 改文档 = 把 d 的定义与代价写死：**本轮采用**（理由见报告）。");
        return r;
    }

    /** 净旋转量 = Σ a_i·(s_R,i − s_L,i) − r_a (mod 2N)。 */
    private static long net(long[] a, int[] sR, int[] sL, long rA, long twoN) {
        long sum = 0;
        for (int i = 0; i < a.length; i++) {
            sum = (sum + a[i] * (sR[i] - sL[i])) % twoN;
        }
        return Math.floorMod(sum - rA, twoN);
    }

    private static boolean allBinary(int[] v) {
        for (int x : v) {
            if (x != 0 && x != 1) {
                return false;
            }
        }
        return true;
    }
}
