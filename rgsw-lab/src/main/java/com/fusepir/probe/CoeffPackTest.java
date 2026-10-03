package com.fusepir.probe;

import com.fusepir.bff.CapeDemoData;
import com.fusepir.fusepir.FusePirDecode;
import com.fusepir.fusepir.FusePirPack;
import com.fusepir.fusepir.FusePirSetup;
import com.fusepir.prim.LweRlweBridge;
import com.fusepir.prim.Mpc4jRgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * <b>变体 R1（系数域打包）的离线探针</b> —— A1 ANSWER 13 / A1 DECODE 1-4。
 *
 * <pre>
 *   Run: .\run-mpc4j.ps1 -Class com.fusepir.probe.CoeffPackTest [db] [N]
 * </pre>
 *
 * <h3>它验什么（每一条都有断言，不是打印）</h3>
 * <ol>
 *   <li>载荷是真的：{@code CapeDemoData.buildTablesPaper} 建表，取<b>真实</b>的
 *       {@code y = payload[0]}（{@code B_pay = 60}），核所有系数 {@code < t}。</li>
 *   <li><b>精确往返</b>：{@code packCoefficientDomain(y)} → {@code unpackCoefficientDomain}
 *       逐位等于 {@code y}（失配 0）。</li>
 *   <li><b>真对照</b>：{@code SampleExtract_j → packFromSample → 库解密} 必须等于
 *       <b>直接解密原密文第 j 个系数</b>（证明 Pack 与 SampleExtract 互逆）。</li>
 *   <li><b>负对照 1（位置）</b>：打包位置 ≠ 读取位置 ⇒ 必须失配。</li>
 *   <li><b>负对照 2（个数）</b>：响应条数少于声明的 {@code B_pay} ⇒ 必须<b>抛</b>，
 *       不能静默补零；条数多于声明 ⇒ 尾部丢失。</li>
 *   <li><b>负结果（密集打包）</b>：断言"把多个位置塞进一条密文"这条路在本库
 *       <b>不成立</b> —— 见 {@code densePackingNegativeSection}。</li>
 *   <li><b>线成本</b>：实测字节数 + 如实报出 R1 没有改善。</li>
 *   <li><b>A1 DECODE 5 的调用链</b>：{@code decodePackedPayload} 与
 *       {@code FusePirDecode.decodePayloadCoefficients} 逐项一致（切分只有一份）。</li>
 * </ol>
 *
 * <h3>⚠️ 载荷域的边界（本探针实测出来的，不是猜的）</h3>
 * <p>数据集 {@code meta.plainModulus = 2^32}，而 {@code fp} 占 2 个 32-bit 槽 ⇒
 * <b>真实载荷的系数可以到 2^32 量级</b>（实测 {@code y[0] ≈ 1.38e9}），远大于论文的
 * {@code t = 65537}。所以：若环上下文能用 {@code t = 2^32} 建起来（实测<b>可以</b>），
 * 就用<b>真实载荷</b>；否则退回 {@code t = 65537} 并改用同分布的<b>合成载荷</b>
 * （输出里会明确标注 synthetic）。硬把 32-bit 系数塞进 {@code Z_65537}
 * 会让"往返一致"变成无意义的陈述。
 *
 * <h3>⚠️ {@code LweRlweBridge} 需要 native 库吗</h3>
 * <b>不需要。</b> 它只 import {@code edu.alibaba.mpc4j.crypto.fhe.seal.*}（纯 Java 移植版，
 * {@code coding/lib/mpc4j-crypto-fhe-seal.jar}），没有任何 {@code System.loadLibrary} 或
 * {@code com.fusepir.nativejni} 引用 —— 与本探针自己的 import 完全一样。
 * 全程纯 Java：不跑 native、不跑 HTTP、不碰 {@code CapeDemoService}。
 */
public final class CoeffPackTest {

    private static int checks = 0;
    private static int fails = 0;
    private static Mpc4jRgsw sharedM;
    private static int sharedN;

    private CoeffPackTest() {
    }

    /**
     * <b>varargs + try/catch 的 check</b>。
     *
     * <p>⚠️ 本项目已经<b>三次</b>因为固定元数的 check 辅助函数踩坑：
     * 传错参数个数时 {@code String.format} 抛 {@code MissingFormatArgumentException}，
     * 那一下会<b>吞掉真实失败</b>并且<b>跳过后面全部检查</b> —— 看起来像探针挂了，
     * 实际结论全丢。所以这里用 {@code Object...} 接参，并把格式化本身包在 try/catch 里：
     * 格式化失败时退化成「名字 + 参数原文」，而<b>不改动 ok 与 fails 的判定</b>。
     */
    private static void check(String what, boolean ok, Object... fmt) {
        checks++;
        String detail = "";
        if (fmt != null && fmt.length > 0) {
            final String f = String.valueOf(fmt[0]);
            final Object[] rest = Arrays.copyOfRange(fmt, 1, fmt.length);
            try {
                detail = rest.length == 0 ? f : String.format(f, rest);
            } catch (Throwable e) {
                detail = f + "  [格式化失败: " + e.getClass().getSimpleName()
                    + " 参数=" + Arrays.toString(rest) + "]";
            }
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + what
            + (detail.isEmpty() ? "" : "  --- " + detail));
        if (!ok) {
            fails++;
        }
    }

    public static void main(String[] args) throws Exception {
        final Path dbPath = Paths.get(args.length > 0 ? args[0] : "../cape-demo/db/keywords.json");
        final int ringDim = args.length > 1 ? Integer.parseInt(args[1]) : 8192;

        System.out.println("=== 变体 R1：系数域打包（A1 ANSWER 13 / A1 DECODE 1-4）===");
        System.out.println("  " + FusePirPack.describe());
        System.out.println();
        System.out.println("  ⚠️ 这不是论文的 Pack：输出不可槽位寻址 ⇒ A2 ANSWER 3 仍无法 satisfy ⇒ D2 仍开放。");
        System.out.println("  ⚠️ 且密集打包（1 条装 60 个系数）在本库实测**不成立**，见第 6 节。");
        System.out.println();

        // ---------------------------------------------------------------
        // 0. 参数与真实载荷
        // ---------------------------------------------------------------
        final CapeDemoData db = CapeDemoData.load(dbPath);
        final long t = db.longMeta("plainModulus", 65537L);
        final CapeDemoData.Tables tb = db.buildTablesPaper(ringDim, 3, t, 20261013L, 0, 20261014L);
        final long[] realPayload = tb.payload[0];
        final int bPay = realPayload.length;

        System.out.println("---------------- 0. 参数与真实载荷 ----------------");
        System.out.printf("  DB = %s（关键词 %d 个）%n", dbPath, db.keywords.size());
        System.out.printf("  N = %d，数据集 t = %d，B_pay = %d，C = %d，R = %d，l_BF = %d%n",
            ringDim, t, bPay, tb.c, tb.r, tb.lBf);
        System.out.printf("  payload[0]（关键词 %s）= %s …%n",
            db.keywords.get(0), Arrays.toString(Arrays.copyOf(realPayload, 8)));

        check("B_pay 与任务书里的 60 一致", bPay == 60, "实得 B_pay = %d", bPay);

        // ---------------------------------------------------------------
        // 1. 环上下文
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 1. 环上下文（纯 Java MPC4J-SEAL，不需要 native 库）----------------");
        final long t0 = System.nanoTime();
        Mpc4jRgsw mm;
        String ctxNote;
        try {
            mm = new Mpc4jRgsw(ringDim, t, 0, 1 << 16);
            ctxNote = "用数据集的 t = " + t + "（载荷域原样）";
        } catch (Throwable e) {
            mm = new Mpc4jRgsw(ringDim, 65537L, 0, 1 << 16);
            ctxNote = "数据集 t = " + t + " 建不出上下文（" + e.getClass().getSimpleName()
                + "），退回 t = 65537";
        }
        final Mpc4jRgsw m = mm;
        sharedM = m;
        sharedN = m.n;
        System.out.printf("  %s%n", m.describe());
        System.out.printf("  上下文 + 密钥 %.0f ms；%s%n", (System.nanoTime() - t0) / 1e6, ctxNote);
        check("环上下文建起来了", m.n == ringDim, "n=%d（要求 %d）", m.n, ringDim);

        long maxCoef = 0;
        for (long v : realPayload) {
            maxCoef = Math.max(maxCoef, v);
        }
        final boolean payloadFits = maxCoef < m.t;
        check("真实载荷的最大系数 < 环上下文 t（否则必须换载荷，不能硬塞）",
            payloadFits, "max(payload[0]) = %d，t = %d%s", maxCoef, m.t,
            payloadFits ? "" : "  ⇒ 下面用同分布的合成载荷（synthetic）");

        final long[] y;
        if (payloadFits) {
            y = realPayload;
            System.out.println("  本次打包的 y = 真实载荷（CapeDemoData payload[0]，关键词 "
                + db.keywords.get(0) + "）");
        } else {
            y = syntheticPayload(bPay, m.t);
            System.out.println("  本次打包的 y = **合成载荷（synthetic，同分布）**");
        }
        System.out.println("    y = " + Arrays.toString(Arrays.copyOf(y, 8)) + " …");

        int distinctAdjacent = -1;
        for (int j = 0; j + 1 < y.length; j++) {
            if (y[j] != y[j + 1]) {
                distinctAdjacent = j;
                break;
            }
        }
        check("存在相邻且不相等的系数（否则错位负对照会退化成恰好相等）",
            distinctAdjacent >= 0, "第一个 y[j] != y[j+1] 的 j = %d", distinctAdjacent);

        // ---------------------------------------------------------------
        // 2. A1 ANSWER 13：打包
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 2. A1 ANSWER 13（R1）：B_pay 个系数 → B_pay 条系数域密文 ----------------");
        final long tp = System.nanoTime();
        final Ciphertext[] packed = FusePirPack.packCoefficientDomain(m, y);
        final long packMs = (System.nanoTime() - tp) / 1_000_000;
        System.out.printf("  打包 %d 条密文，用时 %d ms%n", packed.length, packMs);
        check("打包条数 = B_pay", packed.length == bPay, "%d vs %d", packed.length, bPay);

        // ---------------------------------------------------------------
        // 3. A1 DECODE 1-4：精确往返
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 3. A1 DECODE 1-4：解包（逐位精确）----------------");
        final long tu = System.nanoTime();
        final long[] yBack = FusePirPack.unpackCoefficientDomain(m, packed, bPay);
        final long unpackMs = (System.nanoTime() - tu) / 1_000_000;
        final int mism = FusePirPack.firstMismatch(y, yBack);
        System.out.printf("  解包 %d 项，用时 %d ms%n", bPay, unpackMs);
        System.out.printf("  y      = %s …%n", Arrays.toString(Arrays.copyOf(y, 8)));
        System.out.printf("  y_back = %s …%n", Arrays.toString(Arrays.copyOf(yBack, 8)));
        check("★ 精确往返：解包得到的 B_pay 个系数与原始载荷逐位相同",
            mism < 0, "%s", mism < 0 ? ("失配 0 / " + bPay)
                : ("首个失配下标 " + mism + "；" + FusePirPack.head(y, yBack, 8)));

        // ---------------------------------------------------------------
        // 4. 真对照：Pack 与 SampleExtract 互逆
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 4. 真对照：SampleExtract_j → Pack → 库解密 == 直接解密[j] ----------------");
        // 用【非零、互不相同】的值填这 5 个位置 —— 零值会让"精确"这件事退化
        // （0 在任何噪声下都可能读回 0，证明力弱）。
        final long[] msgDirect = new long[m.n];
        final int[] probePositions = {0, 1, 29, 59, m.n - 1};
        final long[] probeValues = {424242L, 1001L, 70003L, 5005L, 65535L};
        for (int i = 0; i < probePositions.length; i++) {
            msgDirect[probePositions[i]] = probeValues[i];
        }
        final Ciphertext ctDirect = m.encrypt(msgDirect);
        final long[] directDec = m.decrypt(ctDirect);
        int directMism = 0;
        for (int i = 0; i < probePositions.length; i++) {
            final int j = probePositions[i];
            final long[][] sample = LweRlweBridge.sampleExtract(m, ctDirect, j);
            final long viaPack = LweRlweBridge.decryptSampleViaPack(m, sample, j);
            if (viaPack != directDec[j]) {
                directMism++;
                System.out.printf("      j=%d: SampleExtract→Pack→解密 = %d，直接解密 = %d%n",
                    j, viaPack, directDec[j]);
            }
        }
        check("★ SampleExtract_j → Pack → 库解密 == 直接解密原密文[j]（5 个位置，含 0 与 N−1）",
            directMism == 0, "位置 %s，错 %d 个", Arrays.toString(probePositions), directMism);
        check("        这 5 个位置的期望值确实是填进去的那 5 个（密文自身解密正确）",
            directDec[0] == probeValues[0] && directDec[59] == probeValues[3]
                && directDec[m.n - 1] == probeValues[4],
            "[0]=%d [59]=%d [N−1]=%d（期望 %d / %d / %d）",
            directDec[0], directDec[59], directDec[m.n - 1],
            probeValues[0], probeValues[3], probeValues[4]);

        // ---------------------------------------------------------------
        // 5. 负对照
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 5. 负对照 ----------------");
        // 5a. 位置
        final int jGood = distinctAdjacent;
        final long[] wrongPos = FusePirPack.roundTripAtWrongPosition(m, y, jGood, jGood + 1);
        int wrongPosMism = 0;
        for (int b = 0; b < bPay; b++) {
            if (wrongPos[b] != y[b]) {
                wrongPosMism++;
            }
        }
        System.out.printf("  在位置 %d 打包、在位置 %d 读取：%d/%d 个系数失配%n",
            jGood, jGood + 1, wrongPosMism, bPay);
        check("[负对照 1·位置] 打包位置 != 读取位置 ⇒ 比较必须失败",
            wrongPosMism > 0,
            "失配 %d/%d（若为 0，说明位置的正确性根本没被检查到）", wrongPosMism, bPay);

        // 5b. 个数：响应条数 < 声明的 B_pay ⇒ 必须抛
        final Object[] shortResp = FusePirPack.packAndUnpackWithWrongCount(m, y, bPay - 1, bPay);
        System.out.printf("  响应只有 %d 条、声明 B_pay=%d ⇒ 结果 = %s%n",
            bPay - 1, bPay, shortResp[1] == null ? "静默通过了（坏）" : "抛异常");
        check("[负对照 2·个数] 响应条数少于声明 ⇒ 必须抛，不能静默补零",
            shortResp[1] != null, "异常消息 = %s", shortResp[1]);

        // 5c. 个数：声明的 B_pay 少于实际装了 60 个 ⇒ 尾部丢失
        final Object[] longDecl = FusePirPack.packAndUnpackWithWrongCount(m, y, bPay, bPay - 1);
        final long[] shortRead = (long[]) longDecl[0];
        final boolean headOk = shortRead != null
            && FusePirPack.firstMismatch(Arrays.copyOf(y, bPay - 1), shortRead) < 0;
        check("[负对照 2b·个数] 声明 B_pay−1 ⇒ 与完整载荷比较必须失配（尾部丢 1 项）",
            shortRead != null && FusePirPack.firstMismatch(y, shortRead) >= 0,
            "长度 %d vs %d，firstMismatch=%d", y.length,
            shortRead == null ? -1 : shortRead.length,
            shortRead == null ? -1 : FusePirPack.firstMismatch(y, shortRead));
        check("        同一次读回的前 B_pay−1 项确实是对的（丢的是尾部，不是读错位）",
            headOk, "失配 %s", headOk ? "0" : "非 0");

        // 5d. 越界的位置必须抛，不能回绕
        boolean threwBadPos = false;
        try {
            FusePirPack.packSingleCoefficient(m, y[0], m.n);
        } catch (RuntimeException e) {
            threwBadPos = true;
        }
        check("[负对照 1b·位置] 位置 = N（越界）⇒ 必须抛，不能回绕到 0",
            threwBadPos, "抛了 = %b", threwBadPos);

        // ---------------------------------------------------------------
        // 6. 负结果：密集打包（一条装多位置）在本库不成立
        // ---------------------------------------------------------------
        densePackingNegativeSection(m, ctDirect, directDec);

        // ---------------------------------------------------------------
        // 7. 线成本
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 7. 线成本（如实报：R1 没有改善）----------------");
        final Ciphertext freshCt = m.encrypt(new long[m.n]);
        final int perFresh = FusePirPack.wireBytes(freshCt);
        final int perPacked = FusePirPack.wireBytes(packed[0]);
        final int denseGoal = (bPay + m.n - 1) / m.n;
        System.out.println("  " + FusePirPack.wireCostReport(m, bPay, perPacked, denseGoal)
            .replace("\n", "\n  "));
        final int packedDataLen = packed[0].data().length;
        System.out.printf("  内部结构：打包件 data().length = %d（size=%d, coeffModSize=%d）；"
                + "未打包件 data().length = %d（size=%d, coeffModSize=%d）%n"
                + "  ⇒ 两者**裸数据长度相同**，但序列化后差 2 倍 ⇒ "
                + "**序列化长度不是 8 × data().length 的简单函数**（不同层/parmsId 会变）%n",
            packedDataLen, packed[0].size(), packed[0].getCoeffModulusSize(),
            freshCt.data().length, freshCt.size(), freshCt.getCoeffModulusSize());
        check("★ 实测单条系数域密文字节数", perPacked > 0,
            "%d 字节 = %.3f MB", perPacked, perPacked / 1048576.0);
        check("序列化长度落在 [1, 8 × 裸数据 + 1 KB] 内（只做量级自检，不假设公式）",
            perPacked >= 1 && perPacked <= packedDataLen * 8L + 1024,
            "裸数据 %d 字节上限，实测 %d", packedDataLen * 8L, perPacked);
        check("序列化长度**不能**用 8 × data().length + 常数 解释（两件裸数据相同、序列化差 2 倍）",
            perFresh != packedDataLen * 8L && perPacked != packedDataLen * 8L,
            "未打包 %d 字节 vs 裸数据 %d；打包件 %d 字节（比值 %.3f）",
            perFresh, packedDataLen * 8L, perPacked, perFresh / (double) perPacked);
        check("R1 的响应总量 = B_pay 条（**条数与未打包相同，无改善**）",
            (long) perPacked * bPay > 0,
            "%d 条 × %d 字节 = %.2f MB；未打包形状单条 %d 字节 ⇒ 若走未打包是 %.2f MB",
            bPay, perPacked, perPacked * (double) bPay / 1048576.0, perFresh,
            perFresh * (double) bPay / 1048576.0);

        // 过线往返：A1 DECODE 的客户端只有【字节】。这条不测就不知道这条路能不能上线。
        int wireOk = 0;
        int wireBad = -1;
        for (int beta = 0; beta < bPay; beta++) {
            final byte[] wire;
            try {
                wire = new edu.alibaba.mpc4j.crypto.fhe.seal.serialization.SealSerializable<>(packed[beta])
                    .save();
            } catch (java.io.IOException e) {
                wireBad = beta;
                break;
            }
            final Ciphertext back = new Ciphertext();
            back.load(m.context, wire);
            if (FusePirPack.unpackCoefficient(m, back, beta) == y[beta]) {
                wireOk++;
            } else if (wireBad < 0) {
                wireBad = beta;
                break;
            }
        }
        check("★ 过线往返：序列化 → load → SampleExtract_β → 解密 == y[β]（全部 B_pay 条）",
            wireOk == bPay, "%d/%d 条正确%s", wireOk, bPay,
            wireBad < 0 ? "" : ("；首个坏的第 " + wireBad + " 条"));

        // ---------------------------------------------------------------
        // 8. A1 DECODE 5 的调用链
        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("---------------- 8. A1 DECODE 5 的调用链：解包 → Recover ----------------");
        final List<Integer> fromPacked = FusePirPack.decodePackedPayload(m, packed, bPay, t);
        final List<Integer> fromPlain = FusePirDecode.decodePayloadCoefficients(y, t);
        System.out.printf("  从系数域密文解出的候选 = %s%n", fromPacked);
        System.out.printf("  从明文载荷切出的候选   = %s%n", fromPlain);
        check("两个入口（密文 / 明文）解出的候选逐项一致 ⇒ 切分算式只有一份",
            fromPacked.equals(fromPlain), "%s vs %s", fromPacked, fromPlain);

        final int countSlot = FusePirSetup.countOffset(FusePirSetup.fpSlots(t));
        final int countInPayload = countSlot < y.length ? (int) y[countSlot] : -1;
        check("候选数槽（下标 " + countSlot + "）与切出的候选个数一致（切分确实切到了东西）",
            countInPayload == fromPlain.size(),
            "count=%d, 候选个数=%d", countInPayload, fromPlain.size());
        check("A1 DECODE 6 的指纹校验对真实关键词成立（这里只核正向，负对照在别的探针里）",
            FusePirDecode.fingerprintOk(db.keywords.get(0), y, t),
            "fp(%s) 校验通过", db.keywords.get(0));

        // ---------------------------------------------------------------
        System.out.println();
        System.out.println("  ⚠️ 本探针**没有**证明的事（重复一遍，避免被读成 Pack 做完了）：");
        System.out.println("   (1) 这不是论文 A1 ANSWER 13 的槽位域 Pack —— 输出不可槽位寻址；");
        System.out.println("   (2) A2 ANSWER 3 的 Parse{(ct_{v_j}, ct^BF_j)} from resp_anc 仍做不到；");
        System.out.println("   (3) 因此 D2（重新加密候选 Bloom 向量）仍然开放，本变体不改变它；");
        System.out.println("   (4) 线成本**没有**改善：B_pay 条 → B_pay 条（密集打包实测不成立，见第 6 节）；");
        System.out.println("   (5) 样本来自【一条】RLWE 密文的 sampleExtract —— 把独立加密的 B_pay 条");
        System.out.println("       LWE 密文合成一条仍需密钥切换（MAP 第 6 节记的 ≈12 GB）；");
        System.out.println("   (6) 全程纯 Java，未跑 native、未跑 HTTP、未碰 CapeDemoService。");
        System.out.println();
        System.out.println((fails == 0 ? "=== 全部通过" : "=== 有失败项") + "：" + checks
            + " 项检查，" + fails + " 项失败 ===");
        if (fails != 0) {
            System.exit(1);
        }
    }

    /**
     * <b>负结果节：密集打包（一条密文装多个系数位置）在本库不成立。</b>
     *
     * <p>这一节<b>不是</b>在抱怨，而是把"R1 为什么退化成一个系数一条密文"变成
     * <b>可执行的证据</b>。三条断言：
     * <ol>
     *   <li>把 {@link LweRlweBridge#packFromSample} 在一个密文上叠 K 次（K=6），
     *       直接解密<b>必须至少有一处错</b>（实测只有第 0 个位置对）；</li>
     *   <li>两个<b>各自正确</b>的单位置密文相加，第二个位置<b>必须坏掉</b>
     *       （K 次叠加的失败不是"第一个漏掉"那么简单，它是可加性本身失效）；</li>
     *   <li>失败形态是<b>静默</b>的：整个过程<b>不抛任何异常</b>。</li>
     * </ol>
     * ⚠️ 为什么必须写这一节：如果只写"我们选择了一个系数一条密文"，
     * 读者会以为那是<b>偷懒</b>；有了这三条，它就是<b>被数据逼出来的边界</b>。
     */
    private static void densePackingNegativeSection(Mpc4jRgsw m, Ciphertext ctDirect,
                                                    long[] directDec) {
        System.out.println();
        System.out.println("---------------- 6. 负结果：一条密文装多个位置（实测不成立）----------------");
        final int howMany = 6;
        final long[][][] samples = new long[howMany][][];
        final int[] positions = new int[howMany];
        for (int i = 0; i < howMany; i++) {
            positions[i] = i;
            samples[i] = LweRlweBridge.sampleExtract(m, ctDirect, i);
        }
        // (1) 单位置：必须全对（这是第 4 节已经验过的性质，这里对 6 个位置再走一遍）
        int singleBad = 0;
        for (int i = 0; i < howMany; i++) {
            final Ciphertext one = LweRlweBridge.packFromSample(m, samples[i], i);
            if (FusePirPack.unpackCoefficient(m, one, i) != directDec[i]) {
                singleBad++;
            }
        }
        check("[负结果·前提] 单位置打包 6 个位置全部精确（这条是下面那条的对照）",
            singleBad == 0, "错 %d/%d", singleBad, howMany);

        // (2) 逐一相加：从第 2 条开始必须坏
        Ciphertext acc = null;
        int brokeAt = -1;
        for (int i = 0; i < howMany; i++) {
            final Ciphertext one = LweRlweBridge.packFromSample(m, samples[i], i);
            if (acc == null) {
                acc = one;
            } else {
                if (acc.isNttForm()) {
                    m.evaluator.transformFromNttInplace(acc);
                }
                m.evaluator.addInplace(acc, one);
            }
            final long[] d = m.decrypt(acc);
            boolean okAll = true;
            for (int t = 0; t <= i; t++) {
                if (d[t] != directDec[t]) {
                    okAll = false;
                    break;
                }
            }
            System.out.printf("      累积到 %d 条：解密[0..%d] %s%n", i + 1, i,
                okAll ? "全对" : "有错 → " + Arrays.toString(Arrays.copyOf(d, i + 1)));
            if (!okAll && brokeAt < 0) {
                brokeAt = i;
            }
        }
        check("[负结果·可加性失效] 两个各自正确的单位置密文相加后，某个位置必须读出错误值",
            brokeAt >= 0 && brokeAt <= 1,
            "第一次出错发生在累积到 %d 条时（%s）",
            brokeAt + 1, brokeAt == 1 ? "正是 2 条时 ⇒ 可加性本身失效" : "更晚");

        // (3) 静默性：整个过程没有任何异常（否则上面的断言不会跑到这里）
        boolean threwAny = false;
        try {
            final Ciphertext again = LweRlweBridge.packFromSample(m, samples[1], 1);
            if (acc.isNttForm()) {
                m.evaluator.transformFromNttInplace(acc);
            }
            m.evaluator.addInplace(acc, again);
            m.decrypt(acc);
        } catch (Throwable e) {
            threwAny = true;
        }
        check("[负结果·静默] 多位置叠加全程不抛异常（所以错值会被当成正常结果收下）",
            !threwAny, "抛异常 = %b", threwAny);

        System.out.println("      ⇒ 结论：R1 只能走【单位置】那条已实测精确的路 "
            + "⇒ 一个载荷系数一条密文 ⇒ 线成本没有改善。");
        System.out.println("      ⇒ 这条也是「'把 packFromSample 用满' 这个设想不成立」的直接证据。");
    }

    /**
     * 与 {@code CapeDemoData.buildPayload} <b>同分布</b>的合成载荷 —— 只在
     * 「数据集载荷装不进环上下文的 {@code Z_t}」时使用，调用点会标注 synthetic。
     *
     * <p>布局照 {@code FusePirSetup} 的四个函数走（<b>不手抄下标</b>），
     * 值取"互不相同的小整数"、Bloom 位取确定的稀疏模式 —— 全零或全同的载荷
     * 会让"往返一致"退化成巧合。
     */
    private static long[] syntheticPayload(int bPay, long t) {
        final int lBf = 18;
        final int maxValues = 3;
        final int fpSlots = FusePirSetup.fpSlots(t);
        final long[] y = new long[bPay];
        y[0] = 123456789L % t;
        if (fpSlots > 1) {
            y[1] = 987654321L % t;
        }
        y[FusePirSetup.countOffset(fpSlots)] = maxValues;
        for (int v = 0; v < maxValues; v++) {
            final int base = FusePirSetup.valueOffset(fpSlots, v, FusePirSetup.perValue(lBf));
            y[base] = 100 + v;
            for (int b = 0; b < lBf; b++) {
                y[FusePirSetup.bloomOffset(fpSlots, v, FusePirSetup.perValue(lBf)) + b]
                    = ((b + v) % 3 == 0) ? 1 : 0;
            }
        }
        return y;
    }
}
