package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

/**
 * 一次 CMUX 的时间到底花在哪 —— 决定「decompose 值不值得改」。
 *
 * <p>背景：仓库里「{@code decompose} 占 CMUX 的 24%」出自数月前另一个参数集
 * （levels=11, t=65537）的独立剖面。现在 levels 已经降到 6、t 抬到 2³²，
 * 拿那个旧比例去推算「改掉多字 CRT 往返能省 19%」是**没有依据的外推**。
 * 这里直接测。
 *
 * <p>报告的四段互斥且覆盖全部 CMUX 时间（同一个 external_product 里顺序执行）：
 * <pre>
 *   分解·正向NTT   transform_from_ntt，把密文转回系数域（每个分量一次）
 *   分解·多字算术  crtComposeMw + decomposeValueMw（Garner 重组 + 取平衡位）
 *   明文NTT        每个 (层,行) 的 transform_to_ntt
 *   multiply_plain 每个 (层,行) 的密文×明文 + 累加
 * </pre>
 * 差值（总时间 − 四段）是 sub/add/调度开销。
 *
 * <p>用法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CmuxBreakdown [N]}
 */
public final class CmuxBreakdown {

    private CmuxBreakdown() {
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;

        // 两组参数对照：现网（t=65537, base=2^16）与提速后（t=2^32, base=2^32）
        long[][] cases = {{65537L, 16}, {1L << 32, 32}};
        int rounds = Integer.getInteger("cape.prof.rounds", 3);

        System.out.println("=== 一次 CMUX 的成本拆解 ===");
        System.out.printf("N=%d, 每档跑 %d 轮真实盲旋转%n%n", n, rounds);
        System.out.printf("%-26s %5s %8s %9s %9s %9s %9s %9s %8s%n",
            "参数", "d", "总 ms", "正向NTT", "多字算术", "明文NTT", "mul_plain", "其他", "校验");

        for (long[] cs : cases) {
            long t = cs[0];
            int b = (int) cs[1];
            long h = 0;
            try {
                h = NativeBlindRotate.nativeCreateContext(n, t, b);
                String desc = NativeBlindRotate.nativeDescribe(h);
                int levels = extractInt(desc, "levels=");
                int d = Math.max(levels, 16);

                long[] v = NativeBlindRotate.nativeCmuxProfile(h, d, rounds);
                double total = v[0] / 1e3;
                double fwdNtt = v[1] / 1e3;
                double arith = v[2] / 1e3;
                double ptNtt = v[3] / 1e3;
                double mul = v[4] / 1e3;
                long decomCalls = v[5];
                long mulCalls = v[6];
                long r = v[7];

                double other = total - fwdNtt - arith - ptNtt - mul;
                // 一次 CMUX = 一次 external product，而每轮盲旋转做 d 次 CMUX
                double perCmux = total / (r * d);

                String label = String.format("t=%d base=2^%d L=%d", t, b, levels);
                System.out.printf("%-26s %5d %8.2f %8.1f%% %8.1f%% %8.1f%% %8.1f%% %7.1f%% %8s%n",
                    label, d, perCmux,
                    100 * fwdNtt / total, 100 * arith / total,
                    100 * ptNtt / total, 100 * mul / total, 100 * other / total,
                    decomCalls == (long) r * d * 2 && mulCalls == (long) r * d * levels * 2
                        ? "OK" : "ODD");

                System.out.printf("      ms/CMUX = %.2f ；decompose 调用 %d 次（应 %d），"
                        + "multiply_plain %d 次（应 %d）%n",
                    perCmux, decomCalls, (long) r * d * 2, mulCalls, (long) r * d * levels * 2);
                System.out.printf("      分解合计（正向NTT+多字算术）占 CMUX 的 %.1f%%%n%n",
                    100 * (fwdNtt + arith) / total);
            } catch (Throwable ex) {
                System.out.printf("%-26s [FAIL %s]%n%n",
                    "t=" + t + " base=2^" + b, shortMsg(ex));
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

        System.out.println("读法：能省的上限就是「分解合计」里可以避开的那部分。");
        System.out.println("      正向NTT 是密文转系数域，decompose 的入参本来就是 NTT 域密文 ⇒ 绕不开；");
        System.out.println("      多字算术才是「逐素数提取」能替代掉的那块。");
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
        return j == i ? -1 : Integer.parseInt(desc.substring(i, j));
    }

    private static String shortMsg(Throwable t) {
        String m = String.valueOf(t.getMessage());
        return m.length() > 80 ? m.substring(0, 80) + "..." : m;
    }
}
