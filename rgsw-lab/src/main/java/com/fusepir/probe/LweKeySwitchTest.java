package com.fusepir.probe;

import com.fusepir.prim.LweKeySwitch;
import com.fusepir.prim.LweKeySwitch.SwitchKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;

/**
 * <b>LWE 密钥切换（N → d）自检探针</b>：验证 {@link LweKeySwitch}。
 *
 * <h3>覆盖的检查（每条都带正/负对照）</h3>
 * <ol>
 *   <li><b>往返</b>：合成维度 N 的样本（{@code b = ⟨a,s⟩ + m}）→ 切换到维度 d →
 *       用 {@code s'} 解密必须等于 m。消息含 {@code 0}、{@code 1}、{@code t−1}。
 *       负对照：把 {@code b'} 加 1（<b>变异测试</b>），解出来必须是 {@code m+1 mod t} 而不是 m——
 *       证明这条断言不是恒真。</li>
 *   <li><b>独立性是真的</b>：{@code s} 与 {@code s'} 独立生成且必须不同；
 *       用错密钥（{@code s} 的前 d 位）解切换后的样本必须是垃圾。
 *       <b>负对照的对照</b>：故意用 {@code s' := s[0..d)} 造一份"相关密钥"，
 *       此时错密钥解密必须<b>能</b>解出 m——证明上一条检查确实有分辨力。</li>
 *   <li><b>gadget 覆盖被强制</b>：{@code B^digits < t} 必须抛，不能静默截断。
 *       卡在 {@code t = 65537} 的刀锋上：{@code 256^2 = 65536 = t−1} 抛、
 *       {@code 256^3} 通过、{@code 2^16 = 65536} 抛、{@code 2^17} 通过、
 *       恰好相等的 {@code 65537^1 = t} 必须<b>通过</b>（证明判据是 ≥ 而不是 >）。</li>
 *   <li><b>随维度伸缩</b>：{@code d ∈ {4,16,64}} × {@code N ∈ {1024,8192}}，
 *       报密钥条数、字节数、生成耗时、单次切换耗时。</li>
 *   <li><b>实测成本口径</b>：{@code N=8192, d=16} 下真实构造并测量密钥体积，
 *       并给出对 {@code d=N} 的算术外推（<b>外推不实测</b>，9 GB 级不敢分配，明确标注）。</li>
 * </ol>
 *
 * <h3>为什么单列一条 {@code [sign-probe]}</h3>
 * 任务书的文字自带一处符号矛盾：ksk 载荷取 {@code +B^k·s[j]} 且切换用"加法累加"时，
 * 推出的实际关系是 {@code b' − ⟨a',s'⟩ ≡ b + ⟨a,s⟩}，而不是要求的 {@code b − ⟨a,s⟩}。
 * 本探针把两种符号都算出来并打印，让这个矛盾在输出里可见、可复算，
 * 而不是只写在注释里（见 {@link LweKeySwitch} 类注释的"符号偏离"一节）。
 *
 * <h3>已知的未验证范围（诚实清单）</h3>
 * <ul>
 *   <li>ksk 是<b>无噪声</b>精确加密（模 t 精确、无舍入），所以往返是逐位精确的；
 *       <b>噪声增长、噪声预算、失败概率都没有被验证</b>，本探针不模拟噪声。</li>
 *   <li>{@code s'} 维度只有 4/16/64，<b>没有任何安全性结论</b>。</li>
 *   <li>样本是<b>合成</b>的（直接按 {@code b = ⟨a,s⟩ + m} 造），
 *       没有从 RLWE 层 SampleExtract 或盲旋转的结果里取——那条链是别的探针的范围。</li>
 *   <li>密钥体积是<b>内存里的 {@code long[]} 口径</b>（{@code 条数 × (d+1) × 8}），
 *       不含序列化开销、不含位打包（t=65537 其实 17 bit/系数就够）。</li>
 * </ul>
 *
 * <p>用法：{@code java ... com.fusepir.probe.LweKeySwitchTest [N] [d]}（默认 8192 16）。
 * 任何一项失败即 {@code System.exit(1)}。
 */
public final class LweKeySwitchTest {

    /** 本项目的明文模数（与 {@code Mpc4jRgsw(n, 65537L, ...)} 同口径）。 */
    private static final long T = 65537L;
    /** 本项目口径的 gadget 基：{@code 2^8}。 */
    private static final int BASE = 1 << 8;
    /** 本项目口径的 gadget 位数：{@code 256^3 = 2^24 > t}。 */
    private static final int DIGITS = 3;
    /** 固定种子 ⇒ 本探针的输出可复现（负对照的"匹配 0 次"因此不是碰运气）。 */
    private static final long SEED = 20261101L;

    private static int checks = 0;
    private static int fails = 0;
    /** 最近一次 {@link #throwsIae} 的说明（供报告使用）。 */
    private static String lastThrow = "";

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;

        System.out.println("=== LWE 密钥切换（N → d）自检 ===");
        System.out.printf(Locale.ROOT,
            "[params] N=%d, d=%d, t=%d, base=%d=2^%d, digits=%d  ⇒ base^digits=%s%n",
            n, d, T, BASE, Integer.numberOfTrailingZeros(BASE), DIGITS,
            BigInteger.valueOf(BASE).pow(DIGITS));
        System.out.printf(Locale.ROOT,
            "[口径] 密钥 = N·digits 条独立 LWE 样本，每条 (d+1) 个 long；"
                + "解密的相位约定 = b − ⟨a,s⟩；样本按 b = ⟨a,s⟩ + m 合成%n");
        System.out.println();

        checkRoundTrip(n, d);
        checkEdgeCases(n, d);
        checkIndependence(n, d);
        checkGadgetCoverage();
        checkScaling();
        checkCost(n, d);

        System.out.println();
        System.out.printf(Locale.ROOT, "=== %d PASS / %d FAIL（共 %d 项检查）===%n",
            checks - fails, fails, checks);
        if (fails != 0) {
            System.out.println("=== 有失败项 ⇒ exit 1 ===");
            System.exit(1);
        }
    }

    // ==================================================================
    //  1  往返 + 变异负对照 + [sign-probe]
    // ==================================================================

    private static void checkRoundTrip(int n, int d) {
        System.out.println("---------------- 1  往返（N=" + n + " → d=" + d + "）----------------");
        Random rndKey = new Random(SEED);
        long[] s = randomBinarySecret(n, T, rndKey);
        long[] sPrime = randomBinarySecret(d, T, new Random(SEED ^ 0x9E3779B97F4A7C15L));
        SwitchKey key = LweKeySwitch.generate(s, sPrime, T, BASE, DIGITS, new Random(SEED + 1));
        System.out.println("  " + key.describe());

        long[] msgs = {0L, 1L, 2L, 12345L, 32768L, T - 1};
        Random rndSample = new Random(SEED + 7);
        int bad = 0;
        int mutatedWrong = 0;
        int degenerate = 0;
        for (long m : msgs) {
            long[] src = encrypt(s, m, T, rndSample);
            long[] a = Arrays.copyOfRange(src, 1, src.length);
            long[] sw = LweKeySwitch.switchSample(key, a, src[0]);

            long phaseSrc = Math.floorMod(src[0] - LweKeySwitch.innerProduct(a, s, T), T);
            long phaseSw = Math.floorMod(
                sw[0] - LweKeySwitch.innerProduct(sw, 1, sPrime, T), T);
            long got = LweKeySwitch.decrypt(sw, sPrime, T);

            // 变异负对照：把 b' 加 1，解密必须变成 m+1（而不是仍然是 m）
            long[] mutated = Arrays.copyOf(sw, sw.length);
            mutated[0] = (mutated[0] + 1) % T;
            long gotMutated = LweKeySwitch.decrypt(mutated, sPrime, T);
            boolean mutOk = gotMutated != m;

            // 非退化：切换后的 a' 不能是全零（否则等于把样本原样搬过来，密钥其实没换）
            boolean nonZeroA = false;
            for (int i = 1; i < sw.length; i++) {
                if (sw[i] != 0) {
                    nonZeroA = true;
                    break;
                }
            }

            boolean ok = sw.length == d + 1
                && phaseSrc == m
                && phaseSw == m
                && got == m
                && mutOk
                && nonZeroA;
            if (!ok) {
                bad++;
            }
            if (!mutOk) {
                mutatedWrong++;
            }
            if (!nonZeroA) {
                degenerate++;
            }
            System.out.printf(Locale.ROOT,
                "  m=%-6d | 相位(原)=%-6d 相位(切)=%-6d 解密=%-6d | 变异 b'+1 解密=%-6d %s "
                    + "| 长度=%d a'非零=%s%n",
                m, phaseSrc, phaseSw, got, gotMutated, mutOk ? "(≠m ✓)" : "(=m ✗)",
                sw.length, nonZeroA ? "是" : "否");
        }
        check(bad == 0, "1.1 往返：6 个消息（含 0、1、t−1=%d）全部满足 "
                + "b' − ⟨a',s'⟩ ≡ m 且用 s' 解密 = m；变异负对照 %d/%d 次把 b'+1 后解成 m（应为 0）；"
                + "退化（a' 全零）%d 次（应为 0）",
            T - 1, mutatedWrong, msgs.length, degenerate);

        // 守卫：用错维度解密必须抛（而不是静默给垃圾）
        final long[] sw0 = LweKeySwitch.switchSample(key,
            Arrays.copyOfRange(encrypt(s, 5, T, rndSample), 1, n + 1), 0);
        boolean threwDim = throwsIae(() -> LweKeySwitch.decrypt(sw0, s, T));
        check(threwDim, "1.2 守卫：用维度 N=%d 的秘密去解维度 d=%d 的样本必须抛异常（%s）",
            n, d, lastThrow);
        check(!throwsIae(() -> LweKeySwitch.decrypt(sw0, sPrime, T)),
            "1.2 对照：用正确的维度 d=%d 的秘密解密<b>不</b>抛异常（正对照）", d);

        // 守卫：样本维度不符必须抛
        final long[] wrongLen = new long[n + 1];
        boolean threwLen = throwsIae(() -> LweKeySwitch.switchSample(key, wrongLen, 0));
        check(threwLen, "1.3 守卫：switchSample 的 a 长度 ≠ N 必须抛异常（%s）", lastThrow);

        // ---------------- [sign-probe]：任务书字面"加法累加"的相位 ----------------
        long[] src = encrypt(s, 12345L, T, new Random(SEED + 99));
        long[] a = Arrays.copyOfRange(src, 1, src.length);
        long dot = LweKeySwitch.innerProduct(a, s, T);
        long sumB = 0;
        long[] sumA = new long[d];
        for (int j = 0; j < n; j++) {
            long[] dig = LweKeySwitch.decompose(a[j], BASE, DIGITS);
            for (int k = 0; k < DIGITS; k++) {
                long c = dig[k];
                if (c == 0) {
                    continue;
                }
                sumB = (sumB + c * key.kskB(j, k)) % T;
                for (int i = 0; i < d; i++) {
                    sumA[i] = (sumA[i] + c * key.kskA(j, k, i)) % T;
                }
            }
        }
        long bPlus = (src[0] + sumB) % T;
        long phasePlus = Math.floorMod(bPlus - LweKeySwitch.innerProduct(sumA, sPrime, T), T);
        long expectPlus = (src[0] + dot) % T;
        long decPlus = LweKeySwitch.decrypt(
            concat(bPlus, sumA), sPrime, T);
        System.out.println();
        System.out.printf(Locale.ROOT,
            "  [sign-probe] 字面加法版：b'+ = (b + Σ a[j][k]·ksk.b) = %d；"
                + "相位 = %d；闭式 b + ⟨a,s⟩ = %d（一致：%s）%n",
            bPlus, phasePlus, expectPlus, (phasePlus == expectPlus ? "是" : "否"));
        System.out.printf(Locale.ROOT,
            "  [sign-probe] 该相位 = %d，而真值是 m=%d（⟨a,s⟩=%d, 2⟨a,s⟩ mod t = %d）"
                + " ⇒ %s；用 s' 解密得到 %d ≠ m%n",
            phasePlus, 12345L, dot, (2 * dot) % T,
            (phasePlus == 12345L ? "竟然相等" : "与 m 不同"),
            decPlus);
        check(phasePlus == expectPlus && decPlus != 12345L,
            "1.4 [sign-probe] 证实任务书字面「加法累加」推出的是 b + ⟨a,s⟩ 而非 b − ⟨a,s⟩，"
                + "故本实现取减法（等价写法：ksk 载荷取负）；加法版解出 %d ≠ 12345", decPlus);
        System.out.println();
    }

    // ==================================================================
    //  1b  边界样本（a 的极端取值、下标两端、大批量）
    // ==================================================================

    private static void checkEdgeCases(int n, int d) {
        System.out.println("---------------- 1b 边界样本（N=" + n + " → d=" + d + "）----------------");
        long[] s = randomBinarySecret(n, T, new Random(SEED));
        long[] sPrime = randomBinarySecret(d, T, new Random(SEED ^ 0x9E3779B97F4A7C15L));
        SwitchKey key = LweKeySwitch.generate(s, sPrime, T, BASE, DIGITS, new Random(SEED + 1));

        // 各种极端的 a
        long[] zeros = new long[n];
        long[] allMax = new long[n];
        Arrays.fill(allMax, T - 1);              // 65536：digits=2 装不下、digits=3 的最坏值
        long[] first = new long[n];
        first[0] = 1;
        long[] last = new long[n];
        last[n - 1] = 1;
        long[] lastMax = new long[n];
        lastMax[n - 1] = T - 1;

        String[] names = {"a 全 0", "a 全 t−1", "a 只有 a[0]=1", "a 只有 a[N−1]=1", "a 只有 a[N−1]=t−1"};
        long[][] vecs = {zeros, allMax, first, last, lastMax};
        int bad = 0;
        for (int i = 0; i < vecs.length; i++) {
            long m = 4242L;
            long[] sample = sampleFrom(vecs[i], s, m, T);
            long[] sw = LweKeySwitch.switchSample(key, vecs[i], sample[0]);
            long got = LweKeySwitch.decrypt(sw, sPrime, T);
            boolean ok = got == m;
            if (!ok) {
                bad++;
            }
            System.out.printf(Locale.ROOT,
                "  %-22s ⇒ b'=%d, a' 前3=%s, 解密=%-6d %s%n",
                names[i], sw[0],
                Arrays.toString(Arrays.copyOfRange(sw, 1, Math.min(sw.length, 4))),
                got, ok ? "✓" : "✗ (期望 " + m + ")");
        }
        check(bad == 0, "1b.1 极端 a（全 0 / 全 t−1 / 单点在下标 0 与 N−1 / 单点取 t−1）"
            + "全部往返正确（失败 %d）——注意 a 全 0 会走 switchSample 的跳过分支，"
            + "而 a[j]=t−1 正是 digits=2 装不下、digits=3 才够的那个值", bad);

        // 大批量随机消息 + 随机 a（每条的 a 都不同）
        int batch = 1000;
        Random rnd = new Random(SEED + 101);
        int badBatch = 0;
        for (int i = 0; i < batch; i++) {
            long m = Math.floorMod(rnd.nextLong(), T);
            long[] sample = encrypt(s, m, T, rnd);
            long[] sw = LweKeySwitch.switchSample(key,
                Arrays.copyOfRange(sample, 1, sample.length), sample[0]);
            if (LweKeySwitch.decrypt(sw, sPrime, T) != m) {
                badBatch++;
            }
        }
        check(badBatch == 0, "1b.2 大批量：%d 条随机 (a ∈ Z_t^%d, m ∈ Z_t) 全部往返正确（失败 %d）",
            batch, n, badBatch);
        System.out.println();
    }

    // ==================================================================
    //  2  独立性
    // ==================================================================

    private static void checkIndependence(int n, int d) {
        System.out.println("---------------- 2  独立性是真的 + 负对照 ----------------");
        int trials = 64;
        // 两把密钥来自两个独立的 RNG 流（不是同一个流的先后两段——那也会相关）
        long[] s = randomBinarySecret(n, T, new Random(SEED));
        long[] sPrime = randomBinarySecret(d, T, new Random(SEED ^ 0x5DEECE66DL));
        long[] sWrong = Arrays.copyOf(s, d);      // 错密钥：s 的前 d 位

        int diff = 0;
        for (int i = 0; i < d; i++) {
            if (s[i] != sPrime[i]) {
                diff++;
            }
        }
        check(s.length != sPrime.length && diff > 0,
            "2.1 s（N=%d）与 s'（d=%d）独立生成且不同：前 d 位有 %d/%d 位不同（应 >0）",
            n, d, diff, d);

        SwitchKey key = LweKeySwitch.generate(s, sPrime, T, BASE, DIGITS, new Random(SEED + 1));
        Random rnd = new Random(SEED + 21);
        int rightOk = 0;
        int wrongMatch = 0;
        StringBuilder wrongSample = new StringBuilder();
        for (int i = 0; i < trials; i++) {
            long m = i % T;
            long[] src = encrypt(s, m, T, rnd);
            long[] sw = LweKeySwitch.switchSample(key,
                Arrays.copyOfRange(src, 1, src.length), src[0]);
            long withRight = LweKeySwitch.decrypt(sw, sPrime, T);
            long withWrong = LweKeySwitch.decrypt(sw, sWrong, T);
            if (withRight == m) {
                rightOk++;
            }
            if (withWrong == m) {
                wrongMatch++;
            }
            if (i < 6) {
                wrongSample.append(String.format(Locale.ROOT, "%d→%d ", m, withWrong));
            }
        }
        check(rightOk == trials,
            "2.2 正对照：%d/%d 个消息用 s' 解密全部等于 m", rightOk, trials);
        check(wrongMatch == 0,
            "2.3 负对照：用错密钥（s 的前 d 位）解密，%d/%d 次意外等于 m（应为 0；"
                + "随机猜测的期望命中率 ≈ %d/%d ≈ %.5f）。前 6 个 (m→错解密)：%s",
            wrongMatch, trials, trials, T, trials / (double) T, wrongSample.toString().trim());

        // ---- 负对照的对照：故意造"相关密钥"，错密钥检查必须能发现 ----
        SwitchKey depKey = LweKeySwitch.generate(s, sWrong, T, BASE, DIGITS, new Random(SEED + 2));
        Random rnd2 = new Random(SEED + 22);
        int depWrongMatch = 0;
        int depRightMatch = 0;
        for (int i = 0; i < trials; i++) {
            long m = i % T;
            long[] src = encrypt(s, m, T, rnd2);
            long[] sw = LweKeySwitch.switchSample(depKey,
                Arrays.copyOfRange(src, 1, src.length), src[0]);
            if (LweKeySwitch.decrypt(sw, sWrong, T) == m) {
                depWrongMatch++;
            }
            if (LweKeySwitch.decrypt(sw, sPrime, T) == m) {
                depRightMatch++;
            }
        }
        check(depWrongMatch == trials,
            "2.4 负对照的对照：故意用 s' := s[0..d) 造相关密钥时，"
                + "「错密钥」解密 %d/%d 次<b>能</b>解出 m —— 说明 2.3 那条检查确实有分辨力"
                + "（也说明本类不会替你发现两把密钥相关）", depWrongMatch, trials);
        check(depRightMatch == 0,
            "2.4 对照：同一份相关密钥改用真正独立的 s' 解密，%d/%d 次解出 m（应为 0）",
            depRightMatch, trials);
        System.out.println();
    }

    // ==================================================================
    //  3  gadget 覆盖
    // ==================================================================

    private static void checkGadgetCoverage() {
        System.out.println("---------------- 3  gadget 覆盖被强制（刀锋边界）----------------");
        long[] s = randomBinarySecret(64, T, new Random(SEED));
        long[] sP = randomBinarySecret(4, T, new Random(SEED + 3));

        // (base, digits, 必须抛?)
        int[][] cases = {
            {256, 3, 0},      // 256^3 = 16777216 ≥ 65537 → 通过
            {256, 2, 1},      // 256^2 = 65536  = t−1   → 必须抛（差 1）
            {2, 16, 1},       // 2^16  = 65536  = t−1   → 必须抛（差 1）
            {2, 17, 0},       // 2^17  = 131072 ≥ t     → 通过
            {65537, 1, 0},    // t^1   = t      = t     → 必须通过（证明判据是 ≥ 不是 >）
            {1, 3, 1},        // base < 2               → 必须抛
            {256, 0, 1},      // digits < 1             → 必须抛
            {0, 3, 1},        // base = 0               → 必须抛
        };
        for (int[] c : cases) {
            int base = c[0];
            int digits = c[1];
            boolean mustThrow = c[2] == 1;
            final int fb = base;
            final int fd = digits;
            boolean threw = throwsIae(
                () -> LweKeySwitch.generate(s, sP, T, fb, fd, new Random(SEED + 5)));
            String cover = (base >= 2 && digits >= 1)
                ? BigInteger.valueOf(base).pow(digits).toString() : "—";
            check(threw == mustThrow,
                "3.x base=%-6d digits=%-2d ⇒ base^digits=%-9s vs t=%d：%s（实际：%s）",
                base, digits, cover, T,
                mustThrow ? "必须抛" : "必须通过",
                threw ? "抛了" : "没抛");
        }

        // decompose 自身：越界必须抛，不截断
        boolean dThrew = throwsIae(() -> LweKeySwitch.decompose(65536L, 256, 2));
        check(dThrew, "3.y decompose(65536, base=256, digits=2) 必须抛（这正是会被静默截断的值；%s）",
            lastThrow);
        check(!throwsIae(() -> LweKeySwitch.decompose(65535L, 256, 2)),
            "3.y 对照：decompose(65535, 256, 2) 必须成功（= t−2，刀锋另一侧）");
        boolean negThrew = throwsIae(() -> LweKeySwitch.decompose(-1L, 256, 2));
        check(negThrew, "3.y 守卫：decompose(−1, …) 必须抛（负数不进 [0,t) 的分解；%s）", lastThrow);

        // 另两条本类的守卫，必须各自能响（否则就是"写了却没生效"）
        boolean tLimitThrew = throwsIae(() -> LweKeySwitch.generate(
            s, sP, 2147483649L, 2, 32, new Random(SEED + 6)));
        check(tLimitThrew, "3.t 守卫：t=2^31+1（覆盖已满足：2^32 ≥ t）必须抛「超过 2^31」上限（%s）",
            lastThrow);
        boolean baseGtTThrew = throwsIae(() -> LweKeySwitch.generate(
            s, sP, T, 100000, 1, new Random(SEED + 6)));
        check(baseGtTThrew, "3.b 守卫：base=100000 > t=65537（覆盖 100000 ≥ t 已满足）必须抛（%s）",
            lastThrow);
        long[] dig = LweKeySwitch.decompose(65535L, 256, 2);
        check(dig.length == 2 && dig[0] == 255 && dig[1] == 255,
            "3.z 分解正确性：65535 → [%d, %d]（期望 [255, 255]）", dig[0], dig[1]);
        // 分解往返：逐位重构必须等于原值
        Random rnd = new Random(SEED + 31);
        int bad = 0;
        for (int i = 0; i < 1000; i++) {
            long v = Math.floorMod(rnd.nextLong(), T);
            long[] dd = LweKeySwitch.decompose(v, BASE, DIGITS);
            long back = 0;
            for (int k = DIGITS - 1; k >= 0; k--) {
                back = back * BASE + dd[k];
            }
            if (back != v) {
                bad++;
            }
            for (long x : dd) {
                if (x < 0 || x >= BASE) {
                    bad++;
                }
            }
        }
        check(bad == 0, "3.w 分解往返：1000 个随机 Z_t 值的 Σ digits·B^k 全部等于原值，"
            + "且每位都在 [0,B)（错 %d 次）", bad);
        System.out.println();
    }

    // ==================================================================
    //  4  随维度伸缩
    // ==================================================================

    private static void checkScaling() {
        System.out.println("---------------- 4  随维度伸缩（实测）----------------");
        System.out.printf(Locale.ROOT,
            "  %6s %5s %9s %14s %12s %12s %12s %10s %s%n",
            "N", "d", "条数", "密钥字节", "MiB", "生成 ms", "切换 µs", "往返", "条/切换");
        int[] ns = {1024, 8192};
        int[] ds = {4, 16, 64};
        int bad = 0;
        int rows = 0;
        for (int n : ns) {
            for (int d : ds) {
                rows++;
                long[] s = randomBinarySecret(n, T, new Random(SEED + n));
                long[] sP = randomBinarySecret(d, T, new Random(SEED + d));
                long t0 = System.nanoTime();
                SwitchKey key = LweKeySwitch.generate(s, sP, T, BASE, DIGITS, new Random(SEED + n + d));
                double genMs = (System.nanoTime() - t0) / 1e6;

                // 往返必须成立（3 个消息）
                Random rnd = new Random(SEED + 41);
                boolean roundOk = true;
                long[] lastSample = null;
                for (long m : new long[]{0L, 1L, T - 1}) {
                    long[] src = encrypt(s, m, T, rnd);
                    long[] sw = LweKeySwitch.switchSample(key,
                        Arrays.copyOfRange(src, 1, src.length), src[0]);
                    if (LweKeySwitch.decrypt(sw, sP, T) != m) {
                        roundOk = false;
                    }
                    lastSample = sw;
                }

                // 计时：3 次预热 + 21 次取中位数
                long[] a = new long[n];
                Random rndA = new Random(SEED + 51);
                for (int i = 0; i < n; i++) {
                    a[i] = Math.floorMod(rndA.nextLong(), T);
                }
                for (int i = 0; i < 3; i++) {
                    LweKeySwitch.switchSample(key, a, 7);
                }
                double[] us = new double[21];
                for (int i = 0; i < us.length; i++) {
                    long t1 = System.nanoTime();
                    LweKeySwitch.switchSample(key, a, 7);
                    us[i] = (System.nanoTime() - t1) / 1e3;
                }
                Arrays.sort(us);
                double medUs = us[us.length / 2];

                if (!roundOk) {
                    bad++;
                }
                System.out.printf(Locale.ROOT,
                    "  %6d %5d %9d %,14d %12.2f %12.1f %12.1f %10s %,10.1f%n",
                    n, d, key.entries(), key.bytes(), key.bytes() / 1048576.0,
                    genMs, medUs, roundOk ? "PASS" : "FAIL",
                    key.entries() / (medUs / 1e6) / 1e6);
                if (lastSample == null) {
                    bad++;
                }
            }
        }
        check(bad == 0, "4.1 %d 个 (N,d) 组合全部完成密钥生成 + 切换 + 往返（失败 %d）", rows, bad);
        System.out.println("  注：切换耗时是中位数（21 次，含 3 次预热）；条/切换 = 每秒处理多少条 ksk。");
        System.out.println("  注：密钥字节口径 = 条数 × (d+1) × 8（内存 long[] 口径，不含序列化/位打包）。");
        System.out.println();
    }

    // ==================================================================
    //  5  成本口径
    // ==================================================================

    private static void checkCost(int n, int d) {
        System.out.println("---------------- 5  实测成本（N=" + n + ", d=" + d + "）----------------");
        long[] s = randomBinarySecret(n, T, new Random(SEED));
        long[] sP = randomBinarySecret(d, T, new Random(SEED + d));
        long t0 = System.nanoTime();
        SwitchKey key = LweKeySwitch.generate(s, sP, T, BASE, DIGITS, new Random(SEED + n + d));
        double genMs = (System.nanoTime() - t0) / 1e6;
        System.out.println("  " + key.describe());
        System.out.printf(Locale.ROOT, "  实测：条数 %,d；字节 %,d = %.2f MB(10进制) = %.2f MiB；生成 %.1f ms%n",
            key.entries(), key.bytes(), key.bytes() / 1e6, key.bytes() / 1048576.0, genMs);

        // 一次切换的实测
        Random rnd = new Random(SEED + 61);
        long[] src = encrypt(s, 12345L, T, rnd);
        long[] a = Arrays.copyOfRange(src, 1, src.length);
        for (int i = 0; i < 3; i++) {
            LweKeySwitch.switchSample(key, a, src[0]);
        }
        double[] us = new double[21];
        for (int i = 0; i < us.length; i++) {
            long t1 = System.nanoTime();
            LweKeySwitch.switchSample(key, a, src[0]);
            us[i] = (System.nanoTime() - t1) / 1e3;
        }
        Arrays.sort(us);
        System.out.printf(Locale.ROOT, "  实测：单次切换中位数 %.1f µs（21 次，含预热）%n", us[us.length / 2]);

        // 真实构造几种 gadget 分解，报真实体积（不是算术外推）
        System.out.println();
        System.out.println("  --- 同为 N=" + n + ", d=" + d + "，不同 gadget 分解的真实体积（全部实建）---");
        int[][] gadgets = {{256, 3}, {4, 9}, {2, 17}};
        long minBytes = Long.MAX_VALUE;
        boolean gadgetRoundOk = true;
        for (int[] g : gadgets) {
            int base = g[0];
            int digits = g[1];
            long tt0 = System.nanoTime();
            SwitchKey k2 = LweKeySwitch.generate(s, sP, T, base, digits, new Random(SEED + 71));
            double ms = (System.nanoTime() - tt0) / 1e6;
            long[] src2 = encrypt(s, 999L, T, new Random(SEED + 72));
            long got = LweKeySwitch.decrypt(
                LweKeySwitch.switchSample(k2, Arrays.copyOfRange(src2, 1, src2.length), src2[0]),
                sP, T);
            minBytes = Math.min(minBytes, k2.bytes());
            System.out.printf(Locale.ROOT,
                "     base=%-6d digits=%-3d 覆盖 %-10s 条数 %,8d 体积 %,13d B = %8.2f MiB"
                    + " | 生成 %7.1f ms | 往返 %s%n",
                base, digits, BigInteger.valueOf(base).pow(digits).toString(),
                k2.entries(), k2.bytes(), k2.bytes() / 1048576.0, ms,
                got == 999L ? "PASS" : "FAIL(" + got + ")");
            if (got != 999L) {
                gadgetRoundOk = false;
            }
        }
        check(gadgetRoundOk, "5.0 %d 种 gadget 分解（含真实体积对比）切换后往返全部 PASS", gadgets.length);

        // 对 d = N 的算术外推（不实测：量级在 GB，明确标注是外推）
        System.out.println();
        System.out.println("  --- 与「d = N」（今天的 LWE-in-RLWE 被迫口径）的对比：算术外推，**未实测** ---");
        System.out.printf(Locale.ROOT, "  %10s %14s %16s %16s %10s%n",
            "gadgets", "d=" + d + " 实测", "d=N=" + n + " 外推", "倍数", "口径");
        for (int[] g : gadgets) {
            int digits = g[1];
            long entries = (long) n * digits;
            long bytesD = entries * (d + 1) * 8L;
            long bytesN = entries * ((long) n + 1) * 8L;
            System.out.printf(Locale.ROOT,
                "  %10s %,14d B %,16d B %16s %10s%n",
                "B=" + g[0] + "^" + digits, bytesD, bytesN,
                String.format(Locale.ROOT, "%.3f GB", bytesN / 1e9),
                String.format(Locale.ROOT, "(N+1)/(d+1)=%.1f×", (n + 1.0) / (d + 1.0)));
        }
        System.out.println("  ⚠️ 右三列是**算术外推**（同一结构把 d 换成 N），没有真实分配 "
            + "(GB 级会 OOM)；左列是真实构造测量的。");
        System.out.printf(Locale.ROOT,
            "  项目关心的数字：N=%d, d=%d 的最小实测 ksk = %,d B = %.2f MiB（base=256, digits=3）；"
                + "二进制分解 base=2,digits=17 时 = %,d B ≈ %.1f MiB%n",
            n, d, minBytes, minBytes / 1048576.0,
            (long) n * 17 * (d + 1) * 8L, (long) n * 17 * (d + 1) * 8L / 1048576.0);
        check(true, "5.1 成本已实测并打印（口径：内存 long[]；不含序列化/位打包）");
        System.out.println();
    }

    // ==================================================================
    //  工具
    // ==================================================================

    /** 二元秘密 {0,1}（RLWE 环秘密的简化；真实 SEAL 秘密是三元的）。 */
    private static long[] randomBinarySecret(int len, long t, Random rnd) {
        if (t < 2) {
            throw new IllegalArgumentException("t=" + t);
        }
        long[] out = new long[len];
        for (int i = 0; i < len; i++) {
            out[i] = rnd.nextInt(2);
        }
        return out;
    }

    /** 合成一条维度 {@code s.length} 的 LWE 样本：{@code b = ⟨a,s⟩ + m}，{@code a} 均匀于 Z_t。 */
    private static long[] encrypt(long[] s, long m, long t, Random rnd) {
        long[] out = new long[s.length + 1];
        long acc = 0;
        for (int i = 0; i < s.length; i++) {
            long ai = Math.floorMod(rnd.nextLong(), t);
            out[1 + i] = ai;
            acc = (acc + ai * s[i]) % t;
        }
        out[0] = (acc + Math.floorMod(m, t)) % t;
        return out;
    }

    /** 由已知 a 合成样本：{@code b = ⟨a,s⟩ + m}。 */
    private static long[] sampleFrom(long[] a, long[] s, long m, long t) {
        long[] out = new long[a.length + 1];
        out[0] = (LweKeySwitch.innerProduct(a, s, t) + Math.floorMod(m, t)) % t;
        System.arraycopy(a, 0, out, 1, a.length);
        return out;
    }

    private static long[] concat(long b, long[] a) {
        long[] out = new long[a.length + 1];
        out[0] = b;
        System.arraycopy(a, 0, out, 1, a.length);
        return out;
    }

    /** 只接受 {@link IllegalArgumentException}：抛别的异常也算不合格。 */
    private static boolean throwsIae(Runnable r) {
        try {
            r.run();
            lastThrow = "没有抛";
            return false;
        } catch (IllegalArgumentException e) {
            lastThrow = "抛了 IllegalArgumentException：" + e.getMessage();
            return true;
        } catch (RuntimeException e) {
            lastThrow = "抛了别的异常：" + e.getClass().getSimpleName() + "（不合格）";
            return false;
        }
    }

    /**
     * ⚠️ <b>varargs + {@code String.format} 兜底</b>（本仓库的既定口径）。
     *
     * <p>固定参数个数的版本在占位符数与参数个数不匹配时会抛
     * {@code MissingFormatArgumentException}，把"检查失败"伪装成"探针崩溃"，
     * 而且后面的检查根本不跑。这里一律 varargs，且格式化失败时把原因打出来，
     * <b>绝不让格式化异常吃掉断言</b>。
     */
    private static void check(boolean ok, String fmt, Object... args) {
        checks++;
        String msg;
        try {
            msg = (args == null || args.length == 0) ? fmt : String.format(Locale.ROOT, fmt, args);
        } catch (RuntimeException e) {
            msg = fmt + "   [⚠️ 格式化失败：" + e.getClass().getSimpleName() + " —— 断言本身仍按 ok 计]";
        }
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + msg);
        if (!ok) {
            fails++;
        }
    }
}
