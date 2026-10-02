package com.fusepir.demo;


import com.fusepir.prim.*;
import com.fusepir.bloom.*;
import com.fusepir.fusepir.*;
import com.fusepir.probe.*;
import java.util.ArrayList;
import java.util.List;

/**
 * <b>CAPE 一键演示。</b>一条命令跑完「三种规模的四步端到端」+ 关键连接点 + 状态清单。
 *
 * <h3>怎么跑</h3>
 * <pre>
 *   cd coding\rgsw-lab
 *   .\run-mpc4j.ps1 -Class com.fusepir.demo.CapeDemo
 *
 *   # 想换规模就传 N d 对（成对出现）：
 *   .\run-mpc4j.ps1 -Class com.fusepir.demo.CapeDemo 4096 16
 *   .\run-mpc4j.ps1 -Class com.fusepir.demo.CapeDemo 2048 16 4096 16 8192 16
 * </pre>
 * IDEA 里打开本目录 → 跑 {@code CapeDemo} → 点绿三角（不用填程序实参）。
 *
 * <h3>它跑什么</h3>
 * <ol>
 *   <li><b>批量四步端到端</b>（默认三种规模，就是之前手工在终端里敲的那三个）：
 *       <pre>
 *   2048 16  →  ANSWER 能跑完，但 Bloom 打分撞上「N≥4096」的参数下限（**预期内**）
 *   4096 16  →  6/6
 *   8192 16  →  6/6
 *       </pre>
 *       N=2048 那条会抛 {@code keyswitching is not supported by the context} —— 演示会
 *       <b>捕获它并标成"预期"</b>，不当作失败，因为根因是密钥切换需要 ≥2 个工作素数。</li>
 *   <li><b>{@link SampleToPackLink}</b>：量出「候选 Bloom 密文同态化」卡在
 *       {@code q_R → t} 的缩放噪声（≈√N）。</li>
 *   <li><b>状态清单</b>：与论文一致 / 已记录的偏差 / <b>本演示不证明什么</b>。</li>
 * </ol>
 *
 * <h3>⚠️ 三个必踩的前提</h3>
 * <ol>
 *   <li><b>JDK 25</b>：{@code lib/mpc4j-crypto-fhe-seal.jar} 的 class 是 major 69。</li>
 *   <li><b>完整四步要 N ≥ 4096</b>（密钥切换需 ≥2 个工作素数）。</li>
 *   <li><b>N=8192 那一档约 3 分钟</b>：盲旋转 ∝ N，且两条负对照各自会把 24 个单元整条重跑一遍。</li>
 * </ol>
 */
public final class CapeDemo {

    public static void main(String[] args) {
        int[][] scales = parseScales(args);

        banner("CAPE 一键演示",
            "复现 Submission_usenix_232 的 CAPE（算法 2）+ FusePIR（算法 1）",
            "本演示共 3 部分，全部自动跑完");

        // =============================================================
        section("演示 1 / 3：批量四步端到端（SETUP → QUERY → ANSWER → DECODE）");
        System.out.println("  三种规模，逐个跑。看什么：");
        System.out.println("    · ANSWER 段是否打印「服务器全程未解密」");
        System.out.println("    · 两条负对照 4.5 / 4.6 是否 PASS");
        System.out.println("    · N=2048 会在 Bloom 打分那步停住 —— 那是**参数下限**，不是 bug");
        System.out.println();
        List<int[]> verdicts = runScales(scales);

        // =============================================================
        section("演示 2 / 3：sampleExtract → RingPack 连接点（量出真正的障碍）");
        System.out.println("  看什么：残差那一列 —— 它**不是 0**，而是 q_R→t 的缩放噪声（≈√N）。");
        System.out.println("  含义：符号/结构正确、也能解码，但噪声是 Bloom 位值 1 的十几~几十倍，");
        System.out.println("        所以「从密文里同态取出候选 Bloom 位」这条路目前走不通。");
        System.out.println();
        int probeN = scales[scales.length - 1][0] >= 4096 ? 4096 : scales[0][0];
        SampleToPackLink.main(new String[]{String.valueOf(probeN)});

        // =============================================================
        section("演示 3 / 3：状态清单 —— 与论文一致的地方 / 已记录的偏差 / 本演示不证明什么");
        printStatus(scales[scales.length - 1][0], scales[scales.length - 1][1]);

        // =============================================================
        System.out.println();
        System.out.println("══ 演示 1 的汇总 ═══════════════════════════════════════════════");
        System.out.printf("  %-14s %-10s %-12s %-10s %s%n", "规模", "耗时", "四步", "消耗", "说明");
        for (int[] v : verdicts) {
            System.out.printf("  N=%-5d d=%-4d %-10s %-12s %-10s %s%n",
                v[0], v[1], fmtSec(v[2] / 1000.0), verdictText(v[3]),
                v[3] == 0 ? "✅" : (v[3] == -2 ? "✅ 预期" : "❌"),
                noteText(v[3]));
        }
        System.out.println();

        banner("演示结束",
            "演示 1 的三种规模全部自动跑完（含 N=2048 的预期停点）",
            "但务必读上面的「不证明什么」——它决定了这些结果能支撑什么结论");
    }

    // ==================================================================
    //  批量跑
    // ==================================================================

    /** 返回 {N, d, 耗时ms, 结论码}；结论码：0=全过，>0=失败项数，-1=异常，-2=预期内的参数下限。 */
    private static List<int[]> runScales(int[][] scales) {
        List<int[]> out = new ArrayList<>();
        for (int i = 0; i < scales.length; i++) {
            int n = scales[i][0];
            int d = scales[i][1];
            System.out.println("┌── [" + (i + 1) + "/" + scales.length + "] N=" + n + "  d=" + d
                + " " + "─".repeat(Math.max(0, 44 - String.valueOf(n).length() - String.valueOf(d).length())));
            long t0 = System.nanoTime();
            int code;
            try {
                int f = CapeEndToEnd4.run(n, d);
                code = f == 0 ? 0 : f;
            } catch (RuntimeException e) {
                String msg = String.valueOf(e.getMessage());
                if (msg.contains("keyswitching is not supported")) {
                    // 预期内：N=2048 只给 1 个工作素数，密钥切换不可用
                    System.out.println("  ⚠️ 停在这里是【预期】的：");
                    System.out.println("     " + e.getClass().getSimpleName() + ": " + msg);
                    System.out.println("     根因：Bloom 打分要构造 Galois 密钥 → 需要密钥切换 → 需要 ≥2 个工作素数，");
                    System.out.println("           而 CoeffModulus.bfvDefault(2048) 只给 1 个。");
                    System.out.println("     ⇒ 这一档的结论是：**ANSWER 已全程跑完**，只有 Bloom 打分走不过去。");
                    code = -2;
                } else {
                    System.out.println("  ❌ 抛出异常：" + e.getClass().getSimpleName() + ": " + msg);
                    code = -1;
                }
            }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            System.out.printf("└── 耗时 %.1f s%n%n", ms / 1000.0);
            out.add(new int[]{n, d, (int) Math.min(ms, Integer.MAX_VALUE), code});
        }
        return out;
    }

    /** 命令行可传 "N d N d ..." 覆盖默认规模。 */
    private static int[][] parseScales(String[] args) {
        if (args.length >= 2 && args.length % 2 == 0) {
            int[][] s = new int[args.length / 2][];
            for (int i = 0; i < s.length; i++) {
                s[i] = new int[]{Integer.parseInt(args[2 * i]), Integer.parseInt(args[2 * i + 1])};
            }
            return s;
        }
        if (args.length != 0) {
            System.out.println("!! 参数要成对出现（N d ...），已忽略，改用默认规模。\n");
        }
        // 2026-09-29：`CapeEndToEnd4` 改用真实 Bloom 参数（BfGen.choose(ε=2⁻⁶) ⇒ ℓ_BF=18），
        // B_pay 从 8 涨到 40 ⇒ 单次 ANSWER 的单元数 3×B_pay 从 24 涨到 120，
        // 再乘上两条负对照（各自整跑一遍）：N=4096 单档约 2.5 分钟、N=8192 约 20 分钟。
        // 所以默认只跑两档；要跑 8192 请显式传 `8192 16` 并留足时间。
        return new int[][]{{2048, 16}, {4096, 16}};
    }

    private static String verdictText(int code) {
        if (code == 0) return "6/6";
        if (code == -2) return "ANSWER 通过";
        return "失败 " + code + " 项";
    }

    private static String noteText(int code) {
        if (code == 0) return "全部断言通过";
        if (code == -2) return "Bloom 打分撞 N≥4096 下限（密钥切换需 ≥2 个工作素数）";
        if (code == -1) return "抛异常，需排查";
        return "有断言不通过";
    }

    private static String fmtSec(double s) {
        return s >= 60 ? String.format("%.1f min", s / 60) : String.format("%.1f s", s);
    }

    // ==================================================================
    //  状态清单
    // ==================================================================

    private static void printStatus(int lastN, int lastD) {
        System.out.println("── A. 与论文一致（有实测证据）────────────────────────────────");
        row("四步结构 = 算法 1/2", "演示 1 的 SETUP/QUERY/ANSWER/DECODE");
        row("列选择 = CtPtMul（密文×明文）", "ANSWER 第 5 行；不是 CtCtMul");
        row("列选择全 Σ_c、服务器看不到 c_a", "ANSWER 第 5 行；负对照 4.5/4.6");
        row("行选择 = 一条 LWE + 盲旋转", "ANSWER 第 6 行；不需要 LWEtoRGSW");
        row("SampleExtract_0 出密文", "ANSWER 第 7 行；服务器不解密");
        row("三路相加在密文域", "ANSWER 第 11 行；addSamples");
        row("B_pay = 2 + m·(1+ℓ_BF)", "CAPE SETUP 的 V^CAPE = {(v, b_v)}");
        row("Bloom 打分 = CtCtMul + 折叠", "BloomScoring 5/5");
        row("Pack = Ring Packing / RLWE-Pack", "RingPack 6/6（CDKS21 = ePrint 2020/015）");

        System.out.println();
        System.out.println("── B0. 2026-09-29 本轮已修（八条，详见 coding/docs/缺陷总表.md）──");
        row("P0-2 客户端 b_qry 构造", "改成只由关键词算（BfGen.bits），不再用 b_v / 服务器明文库");
        row("P0-3 packed 死代码", "删除；ANSWER 里显式标注「Pack 未接通」");
        row("P0-4 Query 混装", "拆成 ClientState（不发）/ ServerQuery（发出去）并打印边界");
        row("P1-4 列覆盖", "BFF 位置改 u_a = a·R + i ⇒ 覆盖列 0..2（原来恒为 c=0）");
        row("P1-7 随机源", "演示向量 Random(固定种子) / 协议密钥 SecureRandom");
        row("P2-2 Bloom 位推导", "h 个独立哈希（counter-mode SHA-256），消掉窗口重叠与陪集退化");
        row("P2-3 padToSlots", "ℓ_BF > N 改抛异常，不再静默截断");
        row("P2-4 choose 的 h 上限", "16 → 32（ε=2⁻²⁰ 时最优 h=20 才够用）");

        System.out.println();
        System.out.println("── B. 仍未修的偏差（**引结论时必须一起说**）──");
        row("🔴 P0-1 行索引用【无噪声】LWE", "b = ⟨a,s⟩ + r（Δ=1, e=0）—— **最大的一条**");
        row("  ↳ 后果", "正确性只在 e=0 成立；不满足 LWE 噪声模型 ⇒ 不能引 LWE 安全性论证");
        row("  ↳ 且盲旋转对 e=±1 零容忍", "实测会整体推偏一格，取到相邻记录");
        row("🔴 P0-3 候选 Bloom 密文非全程同态", "演示 2 量出的缩放噪声是障碍");
        row("🟠 P1-1 SampleExtract 的 d≠N 密钥切换", "extractLwe 强制 dimension == N");
        row("🟠 P1-2 转换舍入误差无理论界", "量级已测（std≈15），界没给");
        row("🟠 P1-3 RingPack 的 N=4096 未通过", "4096 时 P2/P3/P4 失败，8192 才是起步");
        row("🟠 P1-5 主管线客户端 Bloom 查询", "PlaintextFusePirQuery 仍无 b_qry/τ/q_BF");
        row("🟠 P1-6 Bloom 参数与论文差距", "ε_BF=2⁻⁶（论文 2⁻²⁰）；指纹非 40-bit");
        row("🟡 P2-1 RGSW gadget 参数", "只对当前 base/levels 成立");
        row("🟡 P2-5 ℓ_BF > N 需分段", "真实数据实测 ℓ_BF=5075 > 4096");
        row("🟡 P2-6 规模远小于论文", "N=4096 vs 16384；3 个手写关键词");
        row("🟡 P2-7 列选择子是 C 个独立密文", "论文写 an encryption of e_{c_a}（1 个）");

        System.out.println();
        System.out.println("── C. 本演示【不证明】什么（读结论前请先看这段）────────────");
        System.out.println("  1. 不证明查询隐私成立。");
        System.out.println("     · ANSWER 已不再用明文列号选列（已修），但演示的 `Query` 对象里");
        System.out.println("       仍然同时装着客户端私有量（K、r_a、c_a、BFF 位置 u）与服务端可见量。");
        System.out.println("       **真实部署必须把它们拆成两个结构体**，只把下面这些发给服务器：");
        System.out.println("         发出去：{q_col（C 个密文）, BK/行选择器（LWE a、β）, q_BF 密文}");
        System.out.println("         留本地：K、r_a、c_a、u、b_qry、τ");
        System.out.println("  2. 不证明 LWE 安全性 —— 行索引无噪声（见 B 表第 1 条）。");
        System.out.println("  3. 不证明「Pack + Bloom 打分」的端到端同态链路 —— 见 B 表第 4 条。");
        System.out.println("  4. 不证明论文参数下的正确性 —— 演示规模如下：");
        System.out.printf("       N 最大 %d（论文 16384）、d=%d、ℓ_BF=2（论文 ε_BF=2^-20）、%n", lastN, lastD);
        System.out.println("       3 个手写关键词（论文 n∈{128,256,512}、m∈{2^9..2^11}）、B_pay=8（论文 2+m）。");
        System.out.println("     缩小参数是用来测原理的，**不能据此声称论文配置已复现**。");
        System.out.println("  5. 不证明性能 —— pure-Java 移植比 native SEAL 慢若干个量级；");
        System.out.println("     且本演示的 ANSWER 单元数只有 3×B_pay=24（论文约 3×2050）。");

        System.out.println();
        System.out.println("── D. 因此当前成果的正确归类 ──────────────────────────────");
        System.out.println("  ✅ 密码原语层：RLWE / RGSW / CMUX / 盲旋转 / SampleExtract / Pack / Bloom 打分，");
        System.out.println("     各自有独立自检，且四步端到端能串起来跑；");
        System.out.println("  ✅ 协议层结构：与算法 1/2 逐步对得上；");
        System.out.println("  ⚠️ 但**还不是一个可保护查询隐私的完整 CAPE 协议** —— ");
        System.out.println("     B 表的每一条偏差都必须在报告里显式声明。");

        System.out.println();
        System.out.println("── E. 想接着跑别的入口 ────────────────────────────────────");
        row("RingPack 8192 8", "论文的 Pack = Ring Packing，6/6");
        row("BloomScoring 4096", "槽位域二进制同态内积，5/5");
        row("SampleToPackLink 4096", "连接点与缩放噪声（本演示的演示 2）");
        row("SelToExtractBench 4096 64 32 32 1", "列选择→提取，逐列全系数对拍");
        row("AnswerPathMini 4096 512", "最小 ANSWER 骨干（另一条实现路径）");
    }

    // ==================================================================
    //  排版工具
    // ==================================================================

    private static void banner(String title, String... lines) {
        String bar = "═".repeat(66);
        System.out.println();
        System.out.println(bar);
        System.out.println("  " + title);
        for (String s : lines) {
            System.out.println("  " + s);
        }
        System.out.println(bar);
        System.out.println();
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("┌" + "─".repeat(64));
        System.out.println("│ " + title);
        System.out.println("└" + "─".repeat(64));
    }

    private static void row(String k, String v) {
        System.out.printf("  %-38s %s%n", k, v);
    }
}
