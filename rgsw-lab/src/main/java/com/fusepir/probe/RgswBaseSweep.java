package com.fusepir.probe;

import com.fusepir.nativejni.NativeBlindRotate;

/**
 * 扫 RGSW gadget 分解基 {@code base = 2^b}，看能不能把盲旋转做快。
 *
 * <h3>为什么这是唯一的杠杆</h3>
 * 一次 CMUX = 1 次 external product =
 * <pre>
 *   2 × levels × [ transform_from_ntt + CRT 重组 + 分解 + transform_to_ntt + multiply_plain ]
 * </pre>
 * 而 {@code levels = min l : base^l > q}（`rgsw_blindrotate.cpp` 第 510–523 行）。
 * 所以 **base 翻倍 ⇒ 层数减半 ⇒ CMUX 里的 NTT/乘法/分解次数基本减半**。
 * 这是唯一能线性砍掉盲旋转那 98% 的旋钮。
 *
 * <h3>为什么以前以为它锁死了</h3>
 * {@code decomposeValueMw} 用 {@code r = x[0] & (base-1)} 取低位、{@code carry = r > base/2}
 * 做平衡位，还调了个 {@code mwShiftRight16}，看着像「位宽必须是 16」。实际上：
 * <ul>
 *   <li>平衡分解的误差界是 {@code base/2}，与 base 大小无关；</li>
 *   <li>负位存成 {@code r - base + t}，只要 mod t 的结果正确即可，
 *       进位阈值用 {@code base >> 1} 而非硬编码 32768 就成立。</li>
 * </ul>
 * 所以真正要现场验证的只有两件：**(a) levels 降没降，(b) 噪声预算够不够**。
 *
 * <h3>⚠️ 还有个连带发现</h3>
 * {@code build_rgsw_constant} 只建 {@code levels} 个密钥，而 {@code blind_rotate}
 * 按 {@code d} 轮索引 {@code bk[i]} ⇒ **必须 d >= levels，否则越界读**。
 * 现网的 {@code d=16} 与 {@code base=2^16} 是巧合一致的，一旦 base 变了
 * {@code d} 必须跟着变 —— 这正是本探针要确认的事。
 *
 * <p>用法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.RgswBaseSweep [N]}
 */
public final class RgswBaseSweep {

    private RgswBaseSweep() {
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        if (args.length > 1 && "noise".equalsIgnoreCase(args[1])) {
            noiseReport(args);
            return;
        }

        System.out.println("=== RGSW 分解基 sweep：base = 2^b ===");
        System.out.printf("N=%d%n%n", n);

        // 两个 t 都扫：t 决定「一个平衡位能有多大」，而位宽又被 base 决定。
        // 换句话说 base <= 2^16 是被 t=65537 顶住的，不是被安全参数顶住的 ——
        // 所以「抬 t 换大 base」这条要一起试。
        for (long t : new long[] {65537L, 1L << 32}) {
            System.out.printf("---------- t = %d ----------%n", t);
            System.out.printf("%4s %7s %7s %10s %12s %12s %14s %8s%n",
                "b", "levels", "qBits", "1 次旋转", "ms/CMUX", "相对首行", "盲旋转噪声", "正确性");

            double ref = -1;
            for (int b : new int[] {16, 20, 24, 28, 32, 36, 40}) {
                double[] row = probe(n, t, b, ref);
                if (row != null && ref < 0) {
                    ref = row[0];
                }
            }
            System.out.println();
        }

        System.out.println("判据：levels 明显下降 + 正确性 PASS + 噪声预算 > 20 bit = 可用。");
        System.out.println("注意 t 变大本身会让 BFV 噪声变差，所以噪声列必须一起看。");
    }

    /** @return {rotMs, levels} 或 null（失败时自己打印） */
    private static double[] probe(int n, long t, int b, double ref) {
        long h = 0;
        try {
            h = NativeBlindRotate.nativeCreateContext(n, t, b);
            String desc = NativeBlindRotate.nativeDescribe(h);
            int levels = extractInt(desc, "levels=");
            int qBits = extractInt(desc, "q=");
            if (levels <= 0) {
                System.out.printf("%4d %7s %7s %10s %12s %12s %14s %8s   [描述无法解析: %s]%n",
                    b, "?", "?", "-", "-", "-", "-", "-", desc);
                return null;
            }

            long[] st = NativeBlindRotate.nativeSelfTest(h, levels, 1);
            boolean ok = st[1] == 1 && st[3] == 1;

            // 整条盲旋转之后的噪声余量 —— 这才是生产里真正要活的数
            int noise = noiseOfBlindRotate(h, levels, levels);

            long job = NativeBlindRotate.nativePrepare(h, levels);
            NativeBlindRotate.nativeRunWithCtx(h, job, 2);          // warm-up
            long ta = System.nanoTime();
            NativeBlindRotate.nativeRunWithCtx(h, job, 3);
            long tb = System.nanoTime();
            NativeBlindRotate.nativeFreeJob(job);
            double rotMs = (tb - ta) / 1e6 / 3.0;

            String rel = ref > 0 ? String.format("%+.1f%%", 100.0 * (rotMs / ref - 1.0)) : "-";
            System.out.printf("%4d %7d %7d %10.1f %12.2f %12s %14s %8s%n",
                b, levels, qBits, rotMs, rotMs / levels, rel,
                noise == Integer.MIN_VALUE ? "?" : (noise + " bit"),
                ok ? "PASS" : "FAIL");
            return new double[] {rotMs, levels};
        } catch (Throwable ex) {
            System.out.printf("%4d %7s %7s %10s %12s %12s %14s %8s   [FAIL %s]%n",
                b, "-", "-", "-", "-", "-", "-", "-", shortMsg(ex));
            return null;
        } finally {
            if (h != 0) {
                try {
                    NativeBlindRotate.nativeDestroyContext(h);
                } catch (Throwable ignored) {
                    // best effort
                }
            }
        }
    }

    private static int noiseAfterProduct(long h) {
        // 一次「单轮」盲旋转 = 一次 external product，用真正的引导密钥（d=1）
        return noiseOfBlindRotate(h, 1, 1);
    }

    /**
     * 只测「噪声预算」这一件事 —— 这是判断 t=2^32 能不能用的唯一关键。
     *
     * <p>{@code t} 变大本身就会让 BFV 噪声变差（消息占的位宽多了 16 bit），
     * 所以「levels 从 11 降到 6」换来的速度必须用噪声余量来付。自测里的
     * {@code [PASS]} 只证明「解密出来是对的」，**不证明还有余量**：
     * 余量归零时它会在下一次乘法才崩，而不是当场报错。
     *
     * <p>用法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.RgswBaseSweep noise [N]}
     * （原文写的是 {@code com.fusepir.rgsw.RgswBaseNoise} —— **那个类从来没有存在过**，
     *   是这条 javadoc 的笔误；噪声报告就在本类的 {@code noiseReport} 里。）
     */
    public static void noiseReport(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        System.out.println("=== 噪声预算对比：t=65537/base=2^16  vs  t=2^32/base=2^k ===");
        System.out.printf("N=%d%n%n", n);
        System.out.printf("%12s %4s %7s %7s %14s %16s %16s%n",
            "t", "b", "levels", "qBits", "E⊗之后", "1 轮 CMUX 之后", "整条盲旋转之后");

        long[][] cases = {
            {65537L, 16},
            {1L << 32, 16},
            {1L << 32, 20},
            {1L << 32, 24},
            {1L << 32, 28},
            {1L << 32, 32},
        };
        for (long[] cs : cases) {
            long t = cs[0];
            int b = (int) cs[1];
            long h = 0;
            try {
                h = NativeBlindRotate.nativeCreateContext(n, t, b);
                String desc = NativeBlindRotate.nativeDescribe(h);
                int levels = extractInt(desc, "levels=");
                int qBits = extractInt(desc, "q=");
                int nbEp = noiseAfterOneRound(h);
                int nbCmux = noiseAfterOneRound(h);
                int nbRot = noiseOfBlindRotate(h, levels, levels);
                System.out.printf("%12d %4d %7d %7d %14s %16s %16s%n",
                    t, b, levels, qBits, bit(nbEp), bit(nbCmux), bit(nbRot));
            } catch (Throwable ex) {
                System.out.printf("%12d %4d %7s %7s %14s %16s %16s   [FAIL %s]%n",
                    t, b, "-", "-", "-", "-", "-", shortMsg(ex));
            } finally {
                if (h != 0) {
                    try {
                        NativeBlindRotate.nativeDestroyContext(h);
                    } catch (Throwable ignored) {
                        // best effort
                    }
                }
            }
        }
        System.out.println();
        System.out.println("判据：盲旋转之后的余量 > 0 才有意义；< 20 bit 就不要再叠加后续运算了。");
    }

    private static String bit(int v) {
        return v == Integer.MIN_VALUE ? "?" : (v + " bit");
    }    /**
     * ⚠️ 接口口径（踩过一次，直接段错误把 JVM 打崩）：
     * {@code nativeExternalProductH} 返回的是**解密后的系数值 long[]**，不是句柄；
     * 只有 {@code nativeBlindRotateH} / {@code nativeEncryptToStore} / {@code nativeStoreBytes}
     * 返回句柄。把 long[] 当句柄传给 {@code nativeNoiseBudgetH} 会让 {@code as_ctx}
     * 拿到垃圾指针 → EXCEPTION_ACCESS_VIOLATION。
     *
     * <p>还有一条：{@code nativeRgswConstant} 建的是**长度 1** 的密钥向量，
     * 配 d&gt;1 的 {@code a} 会让 {@code blind_rotate} 越界读 {@code bk[i]}。
     * 任何 d&gt;1 的场合都必须用 {@code nativeBuildBootstrapKey(h, d)}。
     */
    private static int noiseAfterOneRound(long h) {
        return noiseOfBlindRotate(h, 1, 1);
    }

    /** 整条盲旋转（rounds 轮 CMUX）之后的余量 —— 生产里真正要活的数。 */
    private static int noiseOfBlindRotate(long h, int d, int rounds) {
        int noise = Integer.MIN_VALUE;
        long bkh = 0;
        long accH = 0;
        long rotH = 0;
        try {
            // ⚠️ 必须用 nativeBuildBootstrapKey：它建 d 个 RGSW 密钥（= levels 个，
            //    与 decompose 的层数一致）。nativeRgswConstant 只建 **1** 个，
            //    拿它配 d>1 的 a 会让 blind_rotate 越界读 bk[i]（同 d>=levels 那条约束）。
            bkh = NativeBlindRotate.nativeBuildBootstrapKey(h, d);
            accH = NativeBlindRotate.nativeEncryptToStore(h, new long[] {0});
            long[] a = new long[rounds];
            for (int i = 0; i < rounds; i++) {
                a[i] = 1;                    // 非 0 ⇒ 每一轮真的做一次 CMUX
            }
            rotH = NativeBlindRotate.nativeBlindRotateH(h, bkh, accH, a, 0);
            if (rotH != 0) {
                noise = NativeBlindRotate.nativeNoiseBudgetH(h, rotH);
            }
        } catch (Throwable ignored) {
            // best effort
        } finally {
            if (rotH != 0) {
                try { NativeBlindRotate.nativeFreeCt(rotH); } catch (Throwable ignored) { }
            }
            if (accH != 0) {
                try { NativeBlindRotate.nativeFreeCt(accH); } catch (Throwable ignored) { }
            }
            if (bkh != 0) {
                try { NativeBlindRotate.nativeDestroyKey(bkh); } catch (Throwable ignored) { }
            }
        }
        return noise;
    }

    private static int extractInt(String desc, String key) {
        int i = desc.indexOf(key);
        if (i < 0) {
            return -1;
        }
        i += key.length();
        int j = i;
        while (j < desc.length() && Character.isDigit(desc.charAt(j))) {
            j++;
        }
        if (j == i) {
            return -1;
        }
        return Integer.parseInt(desc.substring(i, j));
    }

    private static String shortMsg(Throwable t) {
        String m = String.valueOf(t.getMessage());
        return m.length() > 70 ? m.substring(0, 70) + "..." : m;
    }
}
