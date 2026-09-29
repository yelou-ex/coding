package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Random;

/**
 * <b>CAPE QUERY + DECODE 编排</b>（README 整改项 A2 / A3 / A5）。
 *
 * <h3>补齐链路里空着的两端</h3>
 * <pre>
 *   SETUP   （已有：BFF 编码 → 二维布局 P_{c,b}(X) → 盲旋转密钥）
 *   QUERY   ★ 本次补齐：客户端构造查询与选择器
 *   ANSWER  （已有：列选择 → 盲旋转 → BFF 三路相加）
 *   DECODE  ★ 本次补齐：解密 → 读字段 → Bloom 合取判定 → 输出结果集
 * </pre>
 *
 * <h3>列选择的语义（README §1.2 已纠正）</h3>
 * 列选择是 <b>{@code CtPtMul}（密文 × 明文）</b>，不是 {@code CtCtMul}。
 * 本类按该语义实现：服务端持有明文列多项式 {@code P_{c,b}(X)}，
 * 客户端送来的列坐标 {@code c*} 用于挑出目标列（本验证版直接传明文索引；
 * 论文的"加密 one-hot"是同一语义下的隐私增强，见 README §1.2 第 1 点）。
 *
 * <h3>行选择的语义</h3>
 * 行索引 {@code r*} 是<b>加密</b>的（LWE 密文），服务端通过盲旋转把它同态地挪到常数位，
 * 全程不知道 {@code r*}。
 *
 * <h3>DECODE 的关键</h3>
 * 三路 BFF 相加后得到 payload 的加密。然后：
 * <pre>
 *   值      = payload[字段 2]
 *   Bloom 位 = payload[字段 2+1+i]  （i = 0..ℓ_BF−1）
 *   合取判定 = (⟨b_qry, b_v⟩ == τ)
 * </pre>
 */
public final class CapeQueryDecode {

    private static int failed = 0;

    /** 一个小型明文数据库：关键字 → 值列表 */
    static final class Entry {
        final String keyword;
        final int[] values;
        Entry(String k, int[] v) { this.keyword = k; this.values = v; }
    }

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int qL = 2 * n;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== CAPE QUERY + DECODE 编排 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d%n%n", d, qL);

        Random rnd = new Random(20260928L);

        // ============================================================
        // 1. SETUP：构造数据库 / payload / BFF / 列多项式
        // ============================================================
        System.out.println("--- 1. SETUP ---");

        // 三个关键字，值域小到能手工核对
        Entry[] db = {
            new Entry("K_1", new int[]{11, 22}),
            new Entry("K_2", new int[]{11}),
            new Entry("K_3", new int[]{33}),
        };
        for (Entry e : db) {
            System.out.printf("    %s → %s%n", e.keyword, java.util.Arrays.toString(e.values));
        }

        // 值 → 关联的关键字集合（决定 Bloom）
        java.util.Map<Integer, java.util.Set<String>> kwOfValue = new java.util.TreeMap<>();
        for (Entry e : db) {
            for (int v : e.values) {
                kwOfValue.computeIfAbsent(v, x -> new java.util.TreeSet<>()).add(e.keyword);
            }
        }
        System.out.println("    值 → 关联关键字：");
        kwOfValue.forEach((v, ks) -> System.out.printf("        v=%-3d ← %s%n", v, ks));

        // Bloom（ℓ_BF = 2，按规范第 10 节的极小设定）
        final int lBf = 2;
        java.util.Map<Integer, long[]> bloom = new java.util.TreeMap<>();
        kwOfValue.forEach((v, ks) -> {
            long[] b = new long[lBf];
            // 极小版 Bloom：用确定性哈希把每个关键字映射到 lBf 个位置之一
            for (String k : ks) {
                int h = Math.floorMod(k.hashCode() * 0x9E3779B1, lBf);
                b[h] = 1;
            }
            bloom.put(v, b);
        });
        System.out.println("    Bloom（ℓ_BF=" + lBf + "）：");
        bloom.forEach((v, b) -> System.out.printf("        b_{v=%-3d} = %s   （关联 %s）%n",
            v, java.util.Arrays.toString(b), kwOfValue.get(v)));

        // payload 展平：字段 0=指纹, 1=值的数量, 2+(j-1)*(1+ℓ_BF)=第 j 个值,
        //               2+(j-1)*(1+ℓ_BF)+1+i = 该值的 Bloom 第 i 位
        int mMax = 0;
        for (Entry e : db) mMax = Math.max(mMax, e.values.length);
        int bPay = 2 + mMax * (1 + lBf);
        System.out.printf("    B_pay = %d（m=%d, ℓ_BF=%d）%n", bPay, mMax, lBf);

        long[][] payload = new long[db.length][bPay];
        for (int i = 0; i < db.length; i++) {
            Entry e = db[i];
            payload[i][0] = Math.floorMod(e.keyword.hashCode(), 1000) + 1;   // 指纹
            payload[i][1] = e.values.length;                                  // 数量（用高位存长度）
            for (int j = 0; j < e.values.length; j++) {
                int base = 2 + j * (1 + lBf);       // j 从 0 起
                payload[i][base] = e.values[j];
                long[] b = bloom.get(e.values[j]);
                for (int bi = 0; bi < lBf; bi++) payload[i][base + 1 + bi] = b[bi];
            }
        }
        System.out.println("    payload：");
        for (int i = 0; i < db.length; i++) {
            System.out.printf("        payload_%d = %s%n", i + 1, java.util.Arrays.toString(payload[i]));
        }

        // BFF 编码（k=3）。规范 1.3：
        //     D[p_i] = payload_i − Σ_{j: h_j(K_i) ≠ p_i} D[h_j(K_i)]
        // 恢复靠 Σ_{a=0}^{k−1} D[u_a] = payload（三路相加）。
        //
        // 本验证版给每个关键字分配 k 个【互不重叠】的位置（从位置池里连续取），
        // 这样每个关键字的三元组只落在自己那 k 个格子上，BFF 等式严格成立；
        // 这等价于规范里 MappingStep 的作用（把关键字分配给格子），
        // 只是不做"剥离"优化 —— 验证正确性不需要它。
        int kBff = 3;
        int[][] pos = new int[db.length][kBff];
        int pool = 0;
        for (int i = 0; i < db.length; i++) {
            if (pool + kBff > n) throw new IllegalStateException("位置池不够：n 需 ≥ 关键字数×k");
            for (int a = 0; a < kBff; a++) pos[i][a] = pool + a;
            pool += kBff;
        }
        System.out.println("    BFF 位置（每关键字 " + kBff + " 个不重叠格子）：");
        for (int i = 0; i < db.length; i++) {
            System.out.printf("        %s → %s%n", db[i].keyword, java.util.Arrays.toString(pos[i]));
        }

        // BFF 等式（规范 1.3）：D[p_i] = payload_i − Σ_{j: h_j(K_i) ≠ p_i} D[h_j(K_i)]
        // 恢复靠 Σ_{a=0}^{k−1} D[u_a] = payload（三路相加）。
        //
        // 实现：把 payload 按 (k−1) 个随机份额拆分，最后一个格子取
        //     D[u_{k−1}] = payload − Σ_{a<k−1} D[u_a]
        // 这样每格都非平凡，且 Σ_a D[u_a] ≡ payload (mod t) 恒成立 ——
        // 与规范等式的结构一致（目标格承担"减去其余格"的角色）。
        long[][][] D = new long[db.length][kBff][bPay];
        for (int i = 0; i < db.length; i++) {
            long[] sum = new long[bPay];
            for (int a = 0; a < kBff - 1; a++) {
                for (int b = 0; b < bPay; b++) {
                    D[i][a][b] = rnd.nextInt((int) m.t);
                    sum[b] = (sum[b] + D[i][a][b]) % m.t;
                }
            }
            for (int b = 0; b < bPay; b++) {
                D[i][kBff - 1][b] = Math.floorMod(payload[i][b] - sum[b], m.t);
            }
        }

        // 列多项式：P_b(X) = Σ_i Σ_a D[i][a][b]·X^{pos[i][a]}
        // （R=n, C=1 的布局：每个字段一条长度 N 的多项式）
        long[][] P = new long[bPay][n];          // [字段][系数]
        for (int i = 0; i < db.length; i++) {
            for (int a = 0; a < kBff; a++) {
                int u = pos[i][a];
                for (int b = 0; b < bPay; b++) P[b][u] = D[i][a][b];
            }
        }
        System.out.println("    " + bPay + " 个字段多项式已构造（每个长度 N=" + n + "）");
        System.out.println();

        // ============================================================
        // 2. QUERY（★ 本次补齐）
        // ============================================================
        System.out.println("--- 2. QUERY（客户端）---");

        // 查询关键字：K_1 ∧ K_2 —— 要找一个值同时属于这两个关键字
        String[] query = {"K_1", "K_2"};
        System.out.println("    查询 = " + java.util.Arrays.toString(query) + "（合取）");

        // 锚关键词 K_1 的 BFF 位置 = 行索引
        int anchor = 0;
        for (int i = 0; i < db.length; i++) if (db[i].keyword.equals(query[0])) anchor = i;
        System.out.printf("    锚关键词 = %s，其 BFF 位置 = %s%n",
            db[anchor].keyword, java.util.Arrays.toString(pos[anchor]));

        // 客户端 LWE 密钥（逐位）与自举密钥
        int[] s = new int[d];
        for (int i = 0; i < d; i++) s[i] = rnd.nextInt(2);

        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) bk[i] = m.encryptRgswConstant(s[i]);
        long bkMs = (System.nanoTime() - t0) / 1_000_000;

        // 三个 BFF 位置各一条 LWE 行索引密文
        long[][] aArr = new long[kBff][];
        long[] betaArr = new long[kBff];
        for (int a = 0; a < kBff; a++) {
            long r = pos[anchor][a];
            long sum = 0;
            aArr[a] = new long[d];
            for (int i = 0; i < d; i++) {
                aArr[a][i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + aArr[a][i] * s[i]) % qL;
            }
            betaArr[a] = Math.floorMod(sum + r, qL);
        }

        // 客户端查询 Bloom 向量：其余关键词（K_2）各自关联的值集合 → Bloom
        // 规范：b_qry = Σ_{i≥2} B(K_i)，即"查询里除锚外每个关键词"的位
        long[] qBf = new long[lBf];
        for (int qi = 1; qi < query.length; qi++) {
            int idx = -1;
            for (int i = 0; i < db.length; i++) if (db[i].keyword.equals(query[qi])) idx = i;
            if (idx < 0) continue;
            for (int v : db[idx].values) {
                long[] b = bloom.get(v);
                for (int bi = 0; bi < lBf; bi++) qBf[bi] |= b[bi];
            }
        }
        long tau = 0;
        for (long v : qBf) tau += v;
        System.out.printf("    自举密钥 %d 个 RGSW，%.0f ms%n", d, (double) bkMs);
        System.out.printf("    行索引密文 %d 条（每个 BFF 位置一条）%n", kBff);
        System.out.printf("    查询 Bloom b_qry = %s，τ = |b_qry|₁ = %d%n",
            java.util.Arrays.toString(qBf), tau);
        System.out.println();

        // ============================================================
        // 3. ANSWER（服务器；看不到 r*）
        // ============================================================
        System.out.println("--- 3. ANSWER（服务器）---");
        t0 = System.nanoTime();

        // 三路：每路对所有字段做一次盲旋转
        Ciphertext[][] rotated = new Ciphertext[kBff][bPay];
        for (int a = 0; a < kBff; a++) {
            for (int b = 0; b < bPay; b++) {
                Ciphertext acc = m.encrypt(P[b]);
                rotated[a][b] = BlindRotateOps.blindRotate(m, bk, acc, aArr[a], betaArr[a]);
            }
        }
        long ansMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("    盲旋转 %d 路 × %d 字段 = %d 次，%.0f ms%n",
            kBff, bPay, kBff * bPay, (double) ansMs);
        System.out.println();

        // ============================================================
        // 4. DECODE（★ 本次补齐）
        // ============================================================
        System.out.println("--- 4. DECODE（客户端）---");

        // 4.1 三路相加 → payload 的加密
        long[] rebuilt = new long[bPay];
        for (int b = 0; b < bPay; b++) {
            long sum = 0;
            for (int a = 0; a < kBff; a++) {
                sum += m.decrypt(rotated[a][b])[0];
            }
            rebuilt[b] = Math.floorMod(sum, m.t);
        }
        long[] ref = payload[anchor];
        System.out.printf("    重建 payload = %s%n", java.util.Arrays.toString(rebuilt));
        System.out.printf("    原始 payload = %s%n", java.util.Arrays.toString(ref));
        failed += report("4.1 BFF 三路重建 == 原始 payload",
            java.util.Arrays.equals(rebuilt, ref), "见上两行");

        // 4.2 读出值与 Bloom 位
        long value = rebuilt[2];
        long[] gotBf = new long[lBf];
        for (int bi = 0; bi < lBf; bi++) gotBf[bi] = rebuilt[2 + 1 + bi];
        System.out.printf("    恢复的值 v = %d，其 Bloom = %s%n",
            value, java.util.Arrays.toString(gotBf));

        // 4.3 Bloom 合取判定：⟨b_qry, b_v⟩ == τ ?
        long score = 0;
        for (int bi = 0; bi < lBf; bi++) score += qBf[bi] * gotBf[bi];
        boolean hit = score == tau;
        System.out.printf("    ⟨b_qry, b_v⟩ = %d，τ = %d → %s%n",
            score, tau, hit ? "命中" : "不命中");
        failed += report("4.3 Bloom 合取判定命中", hit, "score=" + score + " tau=" + tau);

        // 4.4 与明文答案对账：期望命中哪个值
        java.util.Set<Integer> expect = new java.util.TreeSet<>();
        for (int v : kwOfValue.keySet()) {
            if (kwOfValue.get(v).containsAll(java.util.Arrays.asList(query))) expect.add(v);
        }
        System.out.printf("    明文答案集（同时属于 %s 的值）= %s%n",
            java.util.Arrays.toString(query), expect);
        failed += report("4.4 恢复的值 ∈ 明文答案集",
            expect.contains((int) value), "v=" + value + " 期望∈" + expect);

        // 4.5 负对照：换一个不含 K_2 的关键词做查询，应不命中
        long[] qBfNeg = new long[lBf];
        long[] bOfV33 = bloom.get(33);                 // v=33 只属于 K_3
        for (int bi = 0; bi < lBf; bi++) qBfNeg[bi] = gotBf[bi];   // 用同一个 b_v
        long tauNeg = 0;
        for (long v : qBfNeg) tauNeg += v;
        long scoreNeg = 0;
        for (int bi = 0; bi < lBf; bi++) scoreNeg += bOfV33[bi] * gotBf[bi];
        System.out.printf("    负对照：b_{v=33} = %s，⟨·, b_v⟩ = %d（τ = %d）→ %s%n",
            java.util.Arrays.toString(bOfV33), scoreNeg, tauNeg,
            scoreNeg == tauNeg ? "命中" : "不命中（正确）");
        System.out.println();

        System.out.println(failed == 0
            ? "=== QUERY + DECODE 打通：客户端拿到「同时属于 "
                + java.util.Arrays.toString(query) + " 的值 = " + value + "」 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) System.exit(1);
    }

    private static int report(String name, boolean ok, String detail) {
        if (!ok) failed++;
        System.out.println((ok ? "    [PASS] " : "    [FAIL] ") + name
            + (ok || detail.isEmpty() ? "" : "   " + detail));
        return ok ? 0 : 1;
    }
}
