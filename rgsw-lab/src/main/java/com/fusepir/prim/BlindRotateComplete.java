package com.fusepir.prim;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * <b>完整盲旋转</b>：真实载荷 + 加密索引 + 端到端验证。
 *
 * <h3>为什么不需要 LWEtoRGSW（关键结构）</h3>
 * 要算的是 {@code X^{−r}·P(X)}，其中 LWE 密文的相位 {@code r = β − ⟨a,s⟩}。而
 * <pre>
 *   X^{−r} = X^{−β} · Π_i X^{a_i·s_i}
 * </pre>
 * 注意 <b>{@code a_i} 是公开的</b>（由种子 ρ 经 PRG 派生），只有 {@code s_i ∈ {0,1}} 是秘密的。
 * 于是服务器可以：
 * <ul>
 *   <li>用<b>公开</b>指数直接旋转 {@code X^{a_i}}（不需要任何密钥）；</li>
 *   <li>用客户端在 setup 阶段发布的 {@code BK_i = RGSW(s_i)} 做一次 CMUX 决定要不要这一项。</li>
 * </ul>
 * 所以一轮就是 {@code ACC ← CMUX(BK_i, ACC, ACC·X^{a_i})}，共 <b>d</b> 轮，
 * 最后补一次公开旋转 {@code X^{−β}}。服务器全程只见到 {@code (a, β)} 与公钥材料，
 * <b>既不知道 r 也不知道 s</b>。
 *
 * <p>这正是标准 TFHE/CGGI 盲旋转（Pirouette 用的也是这套），
 * 而论文里那个 <b>按索引位</b>（⌈log₂N⌉ 轮）的写法需要把"加密索引位"转成 RGSW，
 * 才需要 {@code LWEtoRGSW}（circuit bootstrapping）——那条路只服务查询压缩变体，这里用不到。
 *
 * <h3>代价（必须说清的取舍）</h3>
 * 轮数 = d（LWE 维数，Pirouette Table 4 为 512），因此自举密钥 = d 个 RGSW。
 * N=16384 下每个 RGSW 约 50 MB → d=512 时约 25.6 GB，是这条路线的真实代价。
 * 论文的压缩变体用"按索引位"把轮数降到 ⌈log₂N⌉ = 14、密钥降到约 700 MB，
 * 但代价是引入 LWEtoRGSW。两者是**同一目标下的两种取舍**，本文件实现的是前者（今天就能跑通）。
 */
public final class BlindRotateComplete {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int qL = 2 * n;

        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 完整盲旋转（真实载荷 + 加密索引）===");
        System.out.println("[params] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d%n%n", d, qL);

        Random rnd = new Random(20260919L);

        // ================= 客户端 setup =================
        // LWE 密钥的每一位（比特），以及对应的自举密钥 RGSW(s_i)
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        long bkMs = ms(t0);
        long ctBytes = (long) m.workingPrimeCount * n * 8;
        double bkMB = (double) d * bk[0].size() * ctBytes / 1048576.0;
        System.out.printf("[setup] 自举密钥 %d 个 RGSW × %d 密文 = %.1f MB，构造 %.0f ms%n",
            d, bk[0].size(), bkMB, (double) bkMs);

        // 数据库的一列载荷（这才是要被取到常数位的东西）
        long[] payload = new long[n];
        for (int i = 0; i < n; i++) {
            payload[i] = (i * 7 + 3) % 1000 + 1;
        }
        Ciphertext acc = m.encrypt(payload);
        System.out.printf("[setup] 载荷 %d 条已加密进累加器%n", n);

        // ================= 客户端 query =================
        // 只把 (a, β) 交给服务器；r 与 s 都保密。
        // a 在真实协议里由种子 ρ 经 PRG 派生（所以线上只传种子与 β）。
        long r = 777 % n;
        long[] a = new long[d];
        long sum = 0;
        for (int i = 0; i < d; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + a[i] * s[i]) % qL;
        }
        long beta = Math.floorMod(sum + r, qL);
        System.out.printf("[query] 目标下标 r=%d（保密）；服务器只拿到 a[0..%d] 与 β=%d%n%n",
            r, d - 1, beta);

        // ================= 服务器 =================
        // 服务器视角：只有 bk、acc、a、β —— 没有 s、没有 r
        t0 = System.nanoTime();
        Ciphertext out = BlindRotateOps.blindRotate(m, bk, acc, a, beta);
        long brMs = ms(t0);
        System.out.printf("[server] 盲旋转：%d 轮 CMUX + 1 次公开旋转，%.0f ms%n", d, (double) brMs);

        // ---- 验收 1：常数位 = payload[r] ----
        long[] got = m.decrypt(out);
        failed += report("1  常数位 = 载荷第 r 条（服务器不知道 r）", got[0] == payload[(int) r],
            String.format("r=%d: 常数位 got=%d want=payload[%d]=%d", r, got[0], r, payload[(int) r]));

        // ---- 验收 2：整条 = X^{−r}·P ----
        int match = 0;
        for (int i = 0; i < n; i++) {
            int src = (int) ((i + r) % n);
            long expect = (i + r) < n ? payload[src] : (payload[src] == 0 ? 0 : m.t - payload[src]);
            if (got[i] == expect) {
                match++;
            }
        }
        failed += report("2  整条累加器 = X^{−r}·P", match == n,
            String.format("一致系数 %d/%d", match, n));

        // ---- 验收 3：服务器侧 SampleExtract_0 → 客户端解密，也应等于 payload[r] ----
        long[][] extracted = LweRlweBridge.sampleExtract(m, out, 0);
        long viaLwe = LweRlweBridge.decryptSampleViaPack(m, extracted, 0);
        failed += report("3  服务器 SampleExtract_0 → 客户端解密 = payload[r]", viaLwe == payload[(int) r],
            String.format("走 SampleExtract+Pack 读回 %d，期望 %d", viaLwe, payload[(int) r]));

        // ---- 验收 4：换一个下标再验一次（防止"只对一个 r 恰好成立"）----
        long r2 = 31 % n;
        long sum2 = 0;
        long[] a2 = new long[d];
        for (int i = 0; i < d; i++) {
            a2[i] = Math.floorMod(rnd.nextLong(), qL);
            sum2 = (sum2 + a2[i] * s[i]) % qL;
        }
        long beta2 = Math.floorMod(sum2 + r2, qL);
        long[] got2 = m.decrypt(BlindRotateOps.blindRotate(m, bk, acc, a2, beta2));
        failed += report("4  换下标 r=" + r2 + " 同样正确", got2[0] == payload[(int) r2],
            String.format("常数位 got=%d want=%d", got2[0], payload[(int) r2]));

        // ---- 外推到论文参数 ----
        System.out.println();
        System.out.println("    外推到论文参数（N=16384，每个 RGSW ≈ 50 MB、每次 CMUX 688 ms）：");
        for (int dd : new int[]{64, 128, 256, 512}) {
            System.out.printf("      d=%3d → 盲旋转 %7.1f s，自举密钥 %8.1f MB%n",
                dd, dd * 688.0 / 1000.0, dd * 50.0);
        }

        System.out.println();
        System.out.println(failed == 0
            ? "=== 完整盲旋转通过：服务器在不知 r、不知 s 的前提下，把第 r 条载荷取到了常数位 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
