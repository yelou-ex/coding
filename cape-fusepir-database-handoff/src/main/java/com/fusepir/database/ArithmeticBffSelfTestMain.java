package com.fusepir.database;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * BFF 端到端自检（不依赖 JUnit）——Setup → Encode → Check → Reconstruct → 指纹校验。
 *
 * <p>背景：本模块原先只有 JUnit 5 测试，而本机没有 Maven、`.m2repo` 里也只有 JUnit 4，
 * 所以这些测试**跑不起来**。本类用项目一贯的 {@code main()} 自检风格补上一个可直接运行的验证。
 *
 * <p>跑法：
 * <pre>
 * javac -encoding UTF-8 -d _out (src\main\java 下所有 .java)
 * java -cp _out com.fusepir.database.ArithmeticBffSelfTestMain [tags.csv 路径]
 * </pre>
 */
public final class ArithmeticBffSelfTestMain {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        CapeParameters params = CapeParameters.defaults();

        // ================= T1 合成小库：重建 + 指纹 + 不存在关键词 =================
        CanonicalDatabase small = new CanonicalDatabase(
            List.of(new KeywordRecord("a", new int[]{1, 2}),
                    new KeywordRecord("b", new int[]{2, 3}),
                    new KeywordRecord("c", new int[]{2})),
            Map.of(1, Set.of("a"), 2, Set.of("a", "b", "c"), 3, Set.of("b")), 2, 32);
        PreparedDatabase prepared = new DatabasePreprocessor().prepare(small, params, 42L);
        ArithmeticBff bff = new ArithmeticBffEncoder().encode(prepared, params,
            new BffOptions(7L, 42L, 32, 1_000_000L));

        int wrong = 0;
        int checked = 0;
        for (Map.Entry<String, PlaintextPayload> entry : prepared.payloads().entrySet()) {
            int[] got = bff.reconstruct(entry.getKey());
            short[] want = entry.getValue().coefficients();
            checked++;
            for (int i = 0; i < want.length; i++) {
                if (got[i] != (want[i] & 0xffff)) wrong++;
            }
            if (!bff.matchesFingerprint(entry.getKey(), got)) wrong++;
        }
        boolean missingRejected = !bff.matchesFingerprint("zzz-not-in-db", bff.reconstruct("zzz-not-in-db"));
        report("T1 合成小库：3 个关键词全重建 + 指纹 + 不存在关键词回 ⊥",
            wrong == 0 && missingRejected,
            String.format("检查 %d 个关键词、%d 个系数块，错 %d；不存在关键词被拒 = %b；表长 %d、段长 %d",
                checked, prepared.payloadLength(), wrong, missingRejected, bff.tableLength(), bff.segmentSize()));

        // ================= T2 布局公式（Algorithm 3 k=3）=================
        System.out.println();
        System.out.println("T2 布局公式：段长 = 2^⌊log₃.₃₃(n)+2.11⌋，尺寸因子 = max(1.125, 0.875+0.25·log_n(10⁶))");
        System.out.printf("     %-10s %-10s %-12s %-12s%n", "n", "段长", "表长", "表长/n");
        boolean layoutOk = true;
        for (int n : new int[]{3, 10, 100, 1000, 1475, 10000, 1000000}) {
            BffHashGen.Layout l = BffHashGen.layout(n);
            System.out.printf("     %-10d %-10d %-12d %-12.3f%n", n, l.segmentLength(), l.tableLength(),
                l.tableLength() / (double) n);
            if (l.tableLength() < n) layoutOk = false;              // 表至少要装得下所有关键词
            if (Integer.bitCount(l.segmentLength()) != 1) layoutOk = false;   // 段长必须是 2 的幂
        }
        // 手工按公式复算一遍，确认不是"随便一个能跑的数"
        boolean formulaOk = true;
        for (int n : new int[]{3, 100, 1475, 10000}) {
            int expectSeg = 1 << (int) Math.floor(Math.log(n) / Math.log(3.33) + 2.11);
            expectSeg = Math.min(expectSeg, 1 << 18);
            formulaOk &= BffHashGen.layout(n).segmentLength() == expectSeg;
        }
        report("T2 布局符合 Algorithm 3 的段长公式，且表长 ≥ n、段长为 2 的幂",
            layoutOk && formulaOk, "段长逐点与公式一致 = " + formulaOk);

        // ================= T3 MovieLens 真数据 =================
        Path tags = args.length > 0 ? Path.of(args[0])
            : Path.of("..", "ml-latest-small", "ml-latest-small", "tags.csv");
        System.out.println();
        if (!Files.exists(tags)) {
            System.out.println("T3 跳过：找不到 " + tags.toAbsolutePath());
        } else {
            // 说明：内存版 encoder 装不下全量 MovieLens small
            //   载荷长 = 5 + maxValues·(2 + ℓ_BF)；实测 ℓ_BF ≈ 5075、maxValues = 131 ⇒ 载荷长 ≈ 665,092
            //   表长 2048 ⇒ 需 13.6 亿系数（约 5.4 GB）> 默认上限 1e8
            // 这正是 DiskBffEncoder（分块落盘）存在的原因。此处按行数截断到内存可行的规模，
            // 仍然走完整的真实预处理 + 真实哈希 + 真实载荷布局。
            List<String> all = Files.readAllLines(tags);
            String header = all.isEmpty() ? "" : all.get(0);
            long limit = 90_000_000L;
            CanonicalDatabase ml = null;
            PreparedDatabase p3 = null;
            long needed = -1;
            int usedRows = -1;
            for (int cap : new int[]{2000, 1200, 800, 500, 300, 150}) {
                int rows = Math.min(cap, Math.max(0, all.size() - 1));
                Path temp = Files.createTempFile("bff-selftest-", ".csv");
                List<String> sub = new java.util.ArrayList<>();
                sub.add(header);
                sub.addAll(all.subList(1, 1 + rows));
                Files.write(temp, sub);
                CanonicalDatabase candidateDb = MovieLensTagLoader.load(temp);
                Files.deleteIfExists(temp);
                if (candidateDb.records().isEmpty()) continue;
                PreparedDatabase candidate = new DatabasePreprocessor().prepare(candidateDb, params,
                    DatabasePreprocessor.DEFAULT_FINGERPRINT_SEED);
                long need = (long) ArithmeticBffEncoder.tableLength(candidateDb.records().size())
                    * candidate.payloadLength();
                if (need <= limit) {
                    ml = candidateDb;
                    p3 = candidate;
                    needed = need;
                    usedRows = rows;
                    break;
                }
            }
            if (ml == null) {
                System.out.println("T3 跳过：截断后仍超过内存上限");
            } else {
                System.out.printf("     真实数据子集：tags.csv 前 %d 行 → %d 个关键词、maxValues=%d、载荷长=%d、Bloom 长=%d、表长=%d、需 %.2e 系数%n",
                    usedRows, ml.records().size(), ml.maxValues(), p3.payloadLength(),
                    p3.bloom().length(), ArithmeticBffEncoder.tableLength(ml.records().size()), (double) needed);

                long t0 = System.nanoTime();
                ArithmeticBff b3 = new ArithmeticBffEncoder().encode(p3, params, BffOptions.defaults());
                long encMs = (System.nanoTime() - t0) / 1_000_000;

                int bad = 0;
                int badFp = 0;
                int count = 0;
                for (Map.Entry<String, PlaintextPayload> entry : p3.payloads().entrySet()) {
                    int[] got = b3.reconstruct(entry.getKey());
                    short[] want = entry.getValue().coefficients();
                    count++;
                    boolean thisBad = false;
                    for (int i = 0; i < want.length; i++) {
                        if (got[i] != (want[i] & 0xffff)) {
                            thisBad = true;
                            break;
                        }
                    }
                    if (thisBad) bad++;
                    if (!b3.matchesFingerprint(entry.getKey(), got)) badFp++;
                }
                report("T3 真实数据：每个关键词都重建正确、且指纹全部通过",
                    bad == 0 && badFp == 0,
                    String.format("%d 个关键词：系数错 %d 个，指纹失败 %d 个；编码 %.0f ms",
                        count, bad, badFp, (double) encMs));

                // ---- T4 二维矩阵视图（论文 SETUP 第 14 行 P_{c,b}(X) = Σ_r D[r+cR][b]·X^r）----
                BffMatrixLayout matrix = BffMatrixLayout.of(b3, params);
                int mismatch = 0;
                for (int slot = 0; slot < b3.tableLength(); slot++) {
                    int[] a = b3.entryAt(slot);
                    int[] b = matrix.reconstructSlot(slot);
                    for (int i = 0; i < a.length; i++) {
                        if (a[i] != b[i]) {
                            mismatch++;
                            break;
                        }
                    }
                }
                report("T4 二维列打包视图：D[r+cR] ↔ P_{c,b}(X) 逐槽一致",
                    mismatch == 0,
                    String.format("%d 行 × %d 列（RC = %d ≥ 表长 %d），不一致槽位 %d",
                        matrix.rows(), matrix.columns(), (long) matrix.rows() * matrix.columns(),
                        b3.tableLength(), mismatch));

                // ---- T5 不存在的关键词必须被指纹拒掉 ----
                String fake = "zzz-not-a-real-tag-9f3a";
                boolean rejected = !b3.matchesFingerprint(fake, b3.reconstruct(fake));
                report("T5 不存在的关键词被指纹拒掉（返回 ⊥ 的依据）", rejected, "keyword = " + fake);
            }
        }

        System.out.println();
        System.out.println(failed == 0
            ? "=== BFF 自检全部通过：Setup / Encode / Check / Reconstruct 都可用 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
