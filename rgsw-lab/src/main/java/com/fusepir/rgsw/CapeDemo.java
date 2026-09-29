package com.fusepir.rgsw;

/**
 * <b>CAPE 一键演示。</b>一条命令跑完四步端到端 + 关键连接点测量 + 状态清单。
 *
 * <h3>怎么跑</h3>
 * <pre>
 *   cd coding\rgsw-lab
 *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDemo
 *   # 或自己指定规模：  ... CapeDemo 4096 16
 * </pre>
 * IDEA 里打开本目录 → 跑 {@code CapeDemo} → 点绿三角（不用填程序实参）。
 *
 * <h3>它演示什么</h3>
 * <ol>
 *   <li><b>演示 1</b>：{@link CapeEndToEnd4} —— SETUP → QUERY → ANSWER → DECODE 四步，
 *       并含两条"列选择器必须承重"的负对照。</li>
 *   <li><b>演示 2</b>：{@link SampleToPackLink} —— 量出「候选 Bloom 密文同态化」卡在哪：
 *       {@code sampleExtract} 的输出要缩放到 {@code Z_t} 才能喂 {@code RingPack}，
 *       而这个缩放会引入 ≈√N 的舍入噪声。</li>
 *   <li><b>演示 3</b>：打印状态清单 —— 哪些与论文一致、哪些是**已记录的偏差**、
 *       以及本演示**不证明**什么。</li>
 * </ol>
 *
 * <h3>⚠️ 三个必踩的前提</h3>
 * <ol>
 *   <li><b>JDK 25</b>：{@code lib/mpc4j-crypto-fhe-seal.jar} 的 class 是 major 69。</li>
 *   <li><b>完整四步要 N ≥ 4096</b>：Bloom 打分要构造 Galois 密钥 → 需要密钥切换 →
 *       需要 ≥2 个工作素数；而 {@code bfvDefault(2048)} 只给 1 个。</li>
 *   <li><b>默认 {@code 4096 16}</b>：{@code d} 是 LWE 维数，BK 体积 ≈ {@code d} 个 RGSW；
 *       {@code d=512} 时 BK 约 256 MB @ N=4096，会慢很多。</li>
 * </ol>
 */
public final class CapeDemo {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;

        if (n < 4096) {
            System.out.printf("!! N=%d < 4096：完整四步跑不完（Bloom 打分要密钥切换）。%n", n);
            System.out.println("   可跑「到三路相加为止」（CapeAnswerFull），但本演示会中途抛异常。");
            System.out.println("   继续跑到那一步为止，以便看清是**哪一步**卡住。\n");
        }

        banner("CAPE 一键演示",
            "复现 Submission_usenix_232 的 CAPE（算法 2）+ FusePIR（算法 1）",
            "规模：N=" + n + "，LWE 维数 d=" + d);

        // ---------------------------------------------------------------
        section("演示 1 / 3：CAPE 四步端到端（SETUP → QUERY → ANSWER → DECODE）");
        System.out.println("  看什么：");
        System.out.println("    ① ANSWER 段是否打印「服务器全程未解密」");
        System.out.println("    ② 两条负对照 4.5 / 4.6 是否 PASS");
        System.out.println("    ③ 2. QUERY 段「列选择器：3 路 × C 个独立密文」——C 个，不是 1 个（见文末偏差表）");
        System.out.println();
        CapeEndToEnd4.main(new String[]{String.valueOf(n), String.valueOf(d)});

        // ---------------------------------------------------------------
        section("演示 2 / 3：sampleExtract → RingPack 连接点（量出真正的障碍）");
        System.out.println("  看什么：残差那一列 —— 它**不是 0**，而是 q_R→t 的缩放噪声（≈√N）。");
        System.out.println("  含义：符号/结构正确、也能解码，但噪声是 Bloom 位值 1 的几十倍，");
        System.out.println("        所以「从密文里同态取出候选 Bloom 位」这条路目前走不通。");
        System.out.println();
        SampleToPackLink.main(new String[]{String.valueOf(n)});

        // ---------------------------------------------------------------
        section("演示 3 / 3：状态清单 —— 与论文一致的地方 / 已记录的偏差 / 本演示不证明什么");
        printStatus(n, d);

        banner("演示结束",
            "四步端到端已跑通，且 ANSWER 全程同态",
            "但请务必读上面的「不证明什么」——它决定了这些结果能支撑什么结论");
    }

    // ==================================================================
    //  状态清单
    // ==================================================================

    private static void printStatus(int n, int d) {
        System.out.println("── A. 与论文一致（有实测证据）────────────────────────────────");
        System.out.printf("  %-34s %s%n", "项", "证据");
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
        System.out.println("── B. 已记录的偏差（**不阻塞跑通，但引结论时必须一起说**）──");
        row("⚠️ 行索引用【无噪声】LWE", "b = ⟨a,s⟩ + r（Δ=1, e=0）—— 见 README §3.7");
        row("  ↳ 后果", "不满足 LWE 噪声模型 ⇒ 不能引 LWE 安全性论证");
        row("  ↳ 且盲旋转对 e=±1 零容忍", "实测会整体推偏一格，取到相邻记录");
        row("⚠️ 候选 Bloom 密文非全程同态", "演示 2 量出的缩放噪声是障碍");
        row("⚠️ 列选择子是 C 个独立密文", "论文写 an encryption of e_{c_a}（1 个）");
        row("⚠️ ℓ_BF = 2（退化）", "论文 ε_BF = 2^-20 ⇒ 约 80~100 位");
        row("⚠️ 指纹是 hashCode，非 40-bit", "论文 40-bit；代码里是截断的字符串哈希");
        row("⚠️ Bloom 位用 String.hashCode", "论文是公开哈希族 G = {g_1..g_h}，h≥3");
        row("⚠️ BFF 位置是顺序 0..8", "论文由 h_a(K) 哈希派生");
        row("⚠️ 表只有 c=0 有数据（本演示）", "位置 0..8 / R=16 ⇒ c 恒为 0，未覆盖 c≥1");

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
        System.out.println("  4. 不证明论文参数下的正确性 —— 本演示规模如下：");
        System.out.printf("       N=%d（论文 16384）、d=%d、ℓ_BF=2（论文 ε_BF=2^-20）、%n", n, d);
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
        row("CapeEndToEnd4", "四步端到端（本演示的演示 1）");
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
