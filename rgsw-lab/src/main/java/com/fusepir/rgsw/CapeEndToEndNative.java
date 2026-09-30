package com.fusepir.rgsw;

import com.fusepir.common.BfGen;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * <b>CAPE 四步端到端（SETUP → QUERY → ANSWER → DECODE）—— ANSWER 用 native（路线 A）。</b>
 *
 * <p>这是 {@link CapeEndToEnd4} 的姊妹版：<b>结构与它逐项对齐</b>（R×C 二维布局、BFF 三份份额、
 * 载荷布局、Bloom 合取判定），但 <b>ANSWER 段整段换成一次 JNI 调用</b>
 * （{@link NativeCapeAnswer#run} → 真 SEAL 4.0.0 C++）。
 * {@code CapeEndToEnd4.java} <b>一行未改</b>。
 *
 * <h3>两步之间的口径差别（必须记住）</h3>
 * <table border="1">
 *   <tr><th></th><th>{@code CapeEndToEnd4}（路线 B）</th><th>本类（路线 A）</th></tr>
 *   <tr><td>列选择子</td><td>C 个独立 one-hot 密文</td><td><b>同样</b>（native 内构造，base CAPE 口径）</td></tr>
 *   <tr><td>盲旋转</td><td>MPC4J 纯 Java</td><td><b>真 SEAL C++</b></td></tr>
 *   <tr><td>三路相加</td><td>SampleExtract 之后在样本域</td><td><b>在密文域</b>（SampleExtract 线性，等价）</td></tr>
 *   <tr><td>解码</td><td>客户端用 Java 的解密器</td><td>同进程回环：native 用 SEAL 的解密器</td></tr>
 *   <tr><td>Bloom 打分</td><td><b>同态</b>（{@code CtCtMul} + 折叠）</td><td>⚠️ <b>明文侧</b>算（见下）</td></tr>
 * </table>
 *
 * <p>⚠️ <b>Bloom 打分这一处是本类相对 {@code CapeEndToEnd4} 的实测简化</b>：native ANSWER 回环时
 * 已经把锚载荷解出来了，所以这里直接在明文上算 ⟨b_qry, b_v⟩ 与 τ 比较。
 * 同态打分那一版（服务端全程不解密）在 {@code CapeEndToEnd4} 里已经跑通（4.3 命中判定），
 * 本类<b>不声称</b>复现了它。要 native 也做同态打分，得再加 Galois 折叠。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeEndToEndNative 4096 16}
 */
public final class CapeEndToEndNative {

    private static final double DEMO_EPS_BF = Math.pow(2, -6);
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        if (run(n, d) != 0) {
            System.exit(1);
        }
    }

    public static int run(int n, int d) {
        failed = 0;
        long t = 65537L;
        System.out.println("=== CAPE 四步端到端（ANSWER = native 真 SEAL C++）===");
        System.out.printf("[params] N=%d, t=%d, base=2^16, d=%d, LWE q_L=2N=%d%n%n", n, t, d, 2 * n);

        if (!NativeCapeAnswer.available()) {
            System.out.println("[FAIL] native 不可用：先用 tools/build_blindrotate_jni.py 构建，"
                + "并用 run-mpc4j.ps1（它已设置 java.library.path）");
            return 1;
        }

        // ============================================================
        // 1. SETUP（服务器，全明文）
        // ============================================================
        final int C = 4;
        final int R = 16;
        final int k = 3;
        String[] kw = {"K_1", "K_2", "K_3"};
        int[][] dbValues = {{11, 22}, {11}, {33}};

        System.out.println("--- 1. SETUP（服务器，全明文）---");
        Map<Integer, Set<String>> kwOf = new TreeMap<>();
        for (int i = 0; i < dbValues.length; i++) {
            for (int v : dbValues[i]) {
                kwOf.computeIfAbsent(v, x -> new TreeSet<>()).add(kw[i]);
            }
        }
        int maxSetSize = kwOf.values().stream().mapToInt(Set::size).max().orElse(1);
        int maxValues = Arrays.stream(dbValues).mapToInt(x -> x.length).max().orElse(0);

        BfGen bfGen = BfGen.choose(maxSetSize, DEMO_EPS_BF, n);
        Map<Integer, boolean[]> bV = new TreeMap<>();
        kwOf.forEach((v, ks) -> bV.put(v, bfGen.bits(ks)));

        int lBf = bfGen.length();
        int bPay = 2 + maxValues * (1 + lBf);
        System.out.printf("    %s（ε_BF=2^%.0f 是【玩具值】，论文 2^-20）%n",
            bfGen, Math.log(DEMO_EPS_BF) / Math.log(2));
        System.out.printf("    R×C = %d×%d = %d，B_pay = %d，maxValues = %d%n", R, C, R * C, bPay, maxValues);

        // 载荷：fp(1) ‖ 值个数(1) ‖ 每个值 [值(1) ‖ ℓ_BF 个 Bloom 位]
        long[][] payload = new long[kw.length][bPay];
        for (int i = 0; i < kw.length; i++) {
            payload[i][0] = Math.floorMod(kw[i].hashCode(), 1000) + 1;
            payload[i][1] = dbValues[i].length;
            for (int j = 0; j < dbValues[i].length; j++) {
                int base = 2 + j * (1 + lBf);
                payload[i][base] = dbValues[i][j];
                boolean[] bv = bV.get(dbValues[i][j]);
                for (int bi = 0; bi < lBf; bi++) {
                    payload[i][base + 1 + bi] = bv[bi] ? 1 : 0;
                }
            }
        }

        Random demoRnd = new Random(20261013L);
        int[][] pos = new int[kw.length][k];
        for (int i = 0; i < kw.length; i++) {
            for (int a = 0; a < k; a++) {
                pos[i][a] = a * R + i;
            }
        }
        long[][][] dShare = new long[kw.length][k][bPay];
        for (int i = 0; i < kw.length; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < k - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    dShare[i][a][b] = demoRnd.nextInt((int) t);
                    sum[b] = (sum[b] + dShare[i][a][b]) % t;
                }
            }
            for (int b = 0; b < bPay; b++) {
                dShare[i][k - 1][b] = Math.floorMod(payload[i][b] - sum[b], t);
            }
        }

        // P_{c,b}(X)：先全填（真实数据库本就如此），再覆盖 3 个 BFF 位置
        long[][][] p = new long[C][bPay][n];
        for (int c = 0; c < C; c++) {
            for (int b = 0; b < bPay; b++) {
                for (int rr = 0; rr < R; rr++) {
                    p[c][b][rr] = 1 + demoRnd.nextInt((int) t - 1);
                }
            }
        }
        for (int a = 0; a < k; a++) {
            int u = pos[0][a];
            int rr = u % R;
            int c = u / R;
            if (c >= C) {
                continue;
            }
            for (int b = 0; b < bPay; b++) {
                p[c][b][rr] = dShare[0][a][b];
            }
        }
        System.out.printf("    BFF 位置（u_a = a·R + i，i=锚）%s ⇒ 覆盖列 %s%n",
            Arrays.toString(pos[0]),
            java.util.stream.IntStream.of(pos[0]).map(u -> u / R).distinct().boxed().toList());
        System.out.printf("    %d 条明文多项式 P_{c,b}(X)%n%n", C * bPay);

        // ============================================================
        // 2. QUERY（客户端）
        // ============================================================
        List<String> query = List.of("K_1", "K_2");
        int anchor = 0;
        System.out.println("--- 2. QUERY（客户端）---");
        int[] cOf = new int[k];
        int[] rOf = new int[k];
        for (int a = 0; a < k; a++) {
            rOf[a] = pos[anchor][a] % R;
            cOf[a] = pos[anchor][a] / R;
        }
        boolean[] bQryBits = bfGen.bits(query.subList(1, query.size()));
        long tau = 0;
        for (boolean bit : bQryBits) {
            if (bit) {
                tau++;
            }
        }
        System.out.printf("    查询 = %s，锚 = %s；c_a = %s，r_a = %s%n",
            query, kw[anchor], Arrays.toString(cOf), Arrays.toString(rOf));
        System.out.printf("    b_qry = %s，τ = %d%n", Arrays.toString(bQryBits), tau);
        System.out.println("    [发出去] 服务端只需要 c_a / r_a（本版把选择子交给 native 内构造）+ P 表");
        System.out.println();

        // ============================================================
        // 3. ANSWER（native：整段一次 JNI 调用）
        // ============================================================
        System.out.println("--- 3. ANSWER（native，真 SEAL 4.0.0 C++）---");
        long t0 = System.nanoTime();
        long[] rec = NativeCapeAnswer.run(n, d, C, k, bPay, p, cOf, rOf);
        long ansMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    列选择×%d + 盲旋转×%d + 密文域三路相加 = %d 个单元，%d ms（1 次 JNI 调用）%n",
            k * bPay, k * bPay, k * bPay, ansMs);
        System.out.println("    ★ native 内全程不解密到返回前；引导密钥/明文表/选择子都留在 native 内存");
        System.out.println();

        // ============================================================
        // 4. DECODE
        // ============================================================
        System.out.println("--- 4. DECODE（客户端）---");
        boolean fpOk = rec[0] == payload[anchor][0];
        report("4.1 BFF 三路重建 == 原始 payload（逐位）",
            Arrays.equals(rec, payload[anchor]),
            "恢复前 6: " + Arrays.toString(Arrays.copyOf(rec, 6))
                + "；原前 6: " + Arrays.toString(Arrays.copyOf(payload[anchor], 6)));
        report("4.2 指纹校验", fpOk, "fp=" + rec[0] + "，期望 " + payload[anchor][0]);

        int count = (int) rec[1];
        int firstValue = count > 0 ? (int) rec[2] : -1;
        long score = 0;
        for (int j = 0; j < lBf; j++) {
            if (bQryBits[j] && rec[3 + j] != 0) {
                score++;
            }
        }
        boolean hit = count > 0 && score == tau;
        report("4.3 合取判定（⟨b_qry, b_v⟩ == τ）", hit,
            String.format("值个数=%d，第一个值=%d，得分=%d，τ=%d ⚠️ 明文侧算（同态版见 CapeEndToEnd4 4.3）",
                count, firstValue, score, tau));
        report("4.4 恢复的值 ∈ 明文答案集", count > 0 && firstValue == 11,
            "第一个值 = " + firstValue);

        // ---- 负对照：选择子必须是承重的 ----
        int[] badCol = cOf.clone();
        badCol[0] = (badCol[0] + 1) % C;
        long[] recBadCol = NativeCapeAnswer.run(n, d, C, k, bPay, p, badCol, rOf);
        report("4.5 负对照：列选择器错位一列 ⇒ 载荷必须改变",
            !Arrays.equals(recBadCol, payload[anchor]), "");

        int[] badRow = rOf.clone();
        badRow[0] = (badRow[0] + 1) % R;
        long[] recBadRow = NativeCapeAnswer.run(n, d, C, k, bPay, p, cOf, badRow);
        report("4.6 负对照：行选择器错位一行 ⇒ 载荷必须改变",
            !Arrays.equals(recBadRow, payload[anchor]), "");

        System.out.printf("%n=== %s（失败 %d 项）===", failed == 0 ? "四步跑通" : "有失败", failed);
        System.out.println();
        System.out.printf("[速度] ANSWER（native）= %d ms；路线 B（CapeEndToEnd4 实测）= 15 407 ms ⇒ %.2fx%n",
            ansMs, 15407.0 / Math.max(1, ansMs));
        return failed;
    }

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.printf("    [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (detail != null && !detail.isEmpty()) {
            System.out.println("          " + detail);
        }
    }
}
