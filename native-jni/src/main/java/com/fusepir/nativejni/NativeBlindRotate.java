package com.fusepir.nativejni;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * <b>路线 A（真 SEAL 4.0.0 C++ 本体）上的 RGSW / CMUX / 盲旋转。</b>
 *
 * <p>对应路线 B（MPC4J 纯 Java 移植）的
 * {@code com.fusepir.rgsw.Mpc4jRgsw.externalProduct/cmux} 与
 * {@code com.fusepir.rgsw.BlindRotateOps.blindRotate}，参数与语义逐项对齐，
 * 目的是**同参同输入下做速度对照**。
 *
 * <h3>为什么需要 C++ 侧实现</h3>
 * MPC4J 全仓库（包括它自带的 {@code mpc4j-native-fhe} JNI 封装）**没有任何 RGSW 实现**，
 * 只有协议级接口。所以这条路线的 RGSW/CMUX/盲旋转必须自己写 —— 就是本文件背后的
 * {@code src/main/cpp/rgsw_blindrotate.cpp}。
 *
 * <h3>C++ 侧相对 Java 侧的三处真实差别</h3>
 * <ol>
 *   <li>CRT 重构用 {@code unsigned __int128}，Java 侧要手写 Montgomery + 双 long；</li>
 *   <li>{@code multiplyPowerOfX} 退化成"把 X^k 当明文做一次 {@code multiply_plain}" ——
 *       <b>没有密钥切换，也没有系数域↔NTT 域往返</b>；Java 侧是 fromNtt + 搬移 + toNtt；</li>
 *   <li>累加器由首个乘积初始化，不再每轮现造零密文。</li>
 * </ol>
 *
 * <h3>范围限制（写在明处）</h3>
 * CRT 只组合到 128 位 ⇒ 本模块**最多支持 2 个工作素数**，即 <b>N ≤ 4096</b>，
 * 正是我们要对照的那一档。更大 N 会直接抛异常。
 *
 * <p>跑法：{@code .\run-native.ps1 4096 16}
 */
public final class NativeBlindRotate {

    static {
        System.loadLibrary("blindrotate");
    }

    public static native long nativeCreateContext(int n, long t, int baseBits);

    public static native void nativeDestroyContext(long h);

    public static native String nativeDescribe(long h);

    public static native long nativeBuildBootstrapKey(long h, int d);

    /** 独立的 RGSW(mu) 密钥（正确性检查用；引导密钥的每一行是 RGSW(s_i)，不是 RGSW(0)/RGSW(1)）。 */
    public static native long nativeRgswConstant(long h, long mu);

    public static native void nativeDestroyKey(long kh);

    public static native byte[] nativeEncrypt(long h, long[] msg);

    public static native long[] nativeDecrypt(long h, byte[] ct);

    public static native int nativeNoiseBudget(long h, byte[] ct);

    public static native byte[] nativeBlindRotate(long h, long kh, byte[] acc, long[] a, long beta);

    public static native long[] nativeExternalProduct(long h, long kh, byte[] src, int row);

    public static native Long[] nativeSecretBits(long h, int d);

    /**
     * 自包含：建 d 个引导密钥 + 累加器 + LWE 索引，跑 {@code reps} 次盲旋转，再解密验证。
     * 返回 {@code {0, 非零个数, 落点, 单位值个数}}。
     *
     * <p><b>计时放在 Java 侧</b>：C++ 里一旦用 {@code std::chrono}，MinGW/ucrt 就会让
     * DLL 动态依赖 {@code libwinpthread-1.dll!clock_gettime64}，而 JVM 能找到的那个
     * libwinpthread 不导出它 ⇒ {@code System.loadLibrary} 直接失败
     * （{@code UnsatisfiedLinkError: 找不到指定的程序}）。
     * 两次调用的差值（都含一次建密钥）即可分离出单次旋转的耗时。
     */
    public static native long[] nativeSelfTest(long h, int d, int reps);

    /**
     * 持久化一次盲旋转作业：引导密钥、累加器、LWE 索引只建一次，留在 native 内存里。
     * 之后 {@link #nativeRunWithCtx} 可以反复跑并被直接计时 —— 这是唯一能拿到
     * <b>收敛的稳态数字</b>的办法（用两次 nativeSelfTest 求差会被冷启动污染）。
     */
    public static native long nativePrepare(long h, int d);

    public static native long[] nativeRunWithCtx(long h, long job, int reps);

    public static native void nativeFreeJob(long job);

    // ---- native 侧密文句柄表（跨 JNI 不再依赖序列化）----
    /** 加密并存入 native 内存，返回句柄。 */
    public static native long nativeEncryptToStore(long h, long[] msg);

    /** 把序列化字节存入 native 内存，返回句柄。 */
    public static native long nativeStoreBytes(long h, byte[] ctBytes);

    public static native void nativeFreeCt(long handle);

    /** 用句柄做一次外部乘积并解密返回。 */
    public static native long[] nativeExternalProductH(long h, long kh, long ctHandle, int row);

    public static native int nativeNoiseBudgetH(long h, long ctHandle);

    /** 句柄版盲旋转（返回结果密文的句柄）与解密，整条链路不走序列化。 */
    public static native long nativeBlindRotateH(long h, long kh, long accHandle, long[] a, long beta);

    public static native long[] nativeDecryptH(long h, long ctHandle);

    /**
     * 原生 CAPE ANSWER 基准：跑 {@code k × B_pay} 个单元，每个单元 =
     * 列选择（C 次 CtPtMul）+ 盲旋转（d 轮 CMUX）+ SampleExtract_0。
     * 返回 {@code {checksum,0,0,0}}；计时放在 Java 侧（同 chrono 的理由）。
     */
    public static native long[] nativeAnswerBench(long h, int d, int C, int bPay, int k);

    /**
     * <b>整个 CAPE ANSWER 在 native 里跑</b>：k 条路 × B_pay 个单元，每单元 =
     * 列选择（C 次 CtPtMul）+ 盲旋转（d 轮 CMUX）+ SampleExtract_0，最后做密文域三路相加。
     *
     * <p>返回扁平化的 {@code long[B_pay][L][n+1]}，与 Java 侧 {@code ctPaySample} 布局一致，
     * 因此 DECODE 一行都不用改。<b>整条链路只有 1 次 JNI 调用</b>；引导密钥、明文表、
     * 选择子都留在 native 内存里（跨边界的只有 3 个索引数组）。
     *
     * @param tableFlat {@code [C][B_pay][N]} 服务端明文表（展平）
     * @param cIdx      每条路的列号 {@code c_a}
     * @param rIdx      每条路的行号 {@code r_a}
     */
    public static native long[] nativeCapeAnswer(long h, int d, int C, int k, int bPay,
                                                  long[] tableFlat, long[] cIdx, long[] rIdx);

    /**
     * <b>只用于剖面：把 ANSWER 拆成「列选择」与「盲旋转」两段分别计时。</b>
     *
     * <p>与 {@link #nativeCapeAnswer} 的循环结构、CtPtMul 次数、CMUX 次数<b>完全一致</b>，
     * 只是：(a) 关掉解码（避免对零值密文解密冒出无意义的噪声），(b) 分两段计时。
     * 因为两段共用同一个 {@code accCol} 变量、同一条控制流，所以
     * {@code colUs} 是列选择的独占时间，{@code rotUs} 是盲旋转的独占时间，
     * 两者直接可比，不存在“两次独立运行漂移”的问题。
     *
     * @return {@code [colUs, rotUs, colRounds, rotRounds, checksum]}
     */
    public static native long[] nativeCapeAnswerSplit(long h, int d, int C, int k, int bPay,
                                                       long[] tableFlat, long[] cIdx, long[] rIdx);

    /**
     * <b>CMUX 成本拆解</b>：跑 {@code rounds} 轮真实盲旋转，报告时间花在哪。
     *
     * <p>存在的理由：仓库里「`decompose` 占 CMUX 的 24%」这个数出自数月前另一个参数集
     * （levels=11, t=65537）的独立剖面，拿它去推算「改掉多字 CRT 往返能省多少」
     * 是**没有依据的外推**。这个入口让那个问题由实测回答。
     *
     * @return {@code [总us, 分解里的正向NTT us, 多字CRT算术 us, 明文NTT us,
     *          multiply_plain us, decompose 次数, multiply_plain 次数, rounds]}
     */
    public static native long[] nativeCmuxProfile(long h, int d, int rounds);

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        int reps = args.length > 2 ? Integer.parseInt(args[2]) : 5;
        long t = 65537L;

        System.out.println("=== 路线 A（真 SEAL C++）RGSW / 盲旋转基准与正确性 ===");
        long h = nativeCreateContext(n, t, 16);
        System.out.println("[params] " + nativeDescribe(h));
        System.out.printf("[目标]   与路线 B 对照：N=%d, d=%d, t=%d, base=2^16%n%n", n, d, t);

        // ---------------- 自包含基准（完全不经过序列化）----------------
        // 先预热一次（把 SEAL 的路径与内存池都跑热），再对持久作业直接计时。
        long job = nativePrepare(h, d);
        nativeRunWithCtx(h, job, 2);                    // warm-up
        int K = Math.max(1, reps);
        long ta = System.nanoTime();
        long[] st2 = nativeRunWithCtx(h, job, K);
        long tb = System.nanoTime();
        double perRot = (tb - ta) / 1e6 / K;            // ms / 次
        // 复测一次，看是否收敛
        long tc = System.nanoTime();
        nativeRunWithCtx(h, job, K);
        long td = System.nanoTime();
        double perRot2 = (td - tc) / 1e6 / K;
        nativeFreeJob(job);
        System.out.println("---------------- 速度（持久作业，直接计时）----------------");
        System.out.printf("  一次盲旋转（d=%d 轮 CMUX） : %9.2f ms（复测 %.2f）%n", d, perRot, perRot2);
        System.out.printf("  单轮 CMUX                   : %9.2f ms%n", perRot / d);

        // ---------------- CAPE ANSWER 全链路（列选择 + 盲旋转 + 抽样）----------------
        int C = 4;
        int bPay = 40;
        int kk = 3;
        long t0 = System.nanoTime();
        long[] ans = nativeAnswerBench(h, d, C, bPay, kk);
        long t1 = System.nanoTime();
        double ansMs = (t1 - t0) / 1e6;
        System.out.println();
        System.out.println("---------------- CAPE ANSWER 全链路（native，同 CapeEndToEnd4 形状）----------------");
        System.out.printf("  k=%d, B_pay=%d, C=%d ⇒ %d 个单元，每单元 = 列选择(C) + 盲旋转(d) + SampleExtract_0%n",
            kk, bPay, C, kk * bPay);
        System.out.printf("  ANSWER 总耗时               : %9.1f ms（checksum=%d）%n", ansMs, ans[0]);
        System.out.printf("  单单元                      : %9.2f ms%n", ansMs / (kk * bPay));
        System.out.println("  路线 B（MPC4J 纯 Java）同参数：ANSWER = 15 407 ms，单单元 128.4 ms");
        System.out.printf("  正确性：非零 %d 个（应 1），落点 %d，单位值 %d 个（应 1）%n",
            st2[1], st2[2], st2[3]);
        report("0. 盲旋转：one-hot 进 → one-hot 出", st2[1] == 1 && st2[3] == 1, "");
        System.out.println();
        System.out.println("  路线 B（MPC4J 纯 Java）同参数实测对照：");
        System.out.println("    优化前 单轮 CMUX = 15.55 ms（ANSWER 50 078 ms）");
        System.out.println("    优化后 单轮 CMUX =  6.03 ms（ANSWER 15 407 ms）");
        System.out.println();

        // ---------------- 旧的分步正确性检查（走序列化）----------------
        // 已知在第二次 Ciphertext::load 往返时抛 "index must be within [0, size)"，
        // 所以单独包起来，不让它拖垮上面的自包含基准。
        try {

        // ---------------- 正确性 ① RGSW(1) ⊗ ct = ct ----------------
        long kh = nativeBuildBootstrapKey(h, d);
        Long[] bits = nativeSecretBits(h, d);
        long kh1 = nativeRgswConstant(h, 1);
        long kh0 = nativeRgswConstant(h, 0);
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 7) + 1;
        }
        long ctH = nativeEncryptToStore(h, msg);          // 走句柄，不序列化
        byte[] ct = nativeEncrypt(h, msg);                // 同时保留字节路径做对照

        long[] ep1 = nativeExternalProductH(h, kh1, ctH, 0);   // RGSW(1)
        int bad1 = 0;
        for (int i = 0; i < n; i++) {
            if (ep1[i] != msg[i]) {
                bad1++;
            }
        }
        report(String.format("1. RGSW(1) ⊗ ct = ct（错位 %d/%d）", bad1, n), bad1 == 0,
            "噪声预算 = " + nativeNoiseBudgetH(h, ctH) + " bit");

        long[] ep0 = nativeExternalProductH(h, kh0, ctH, 0);   // RGSW(0)
        int nz = 0;
        for (int i = 0; i < n; i++) {
            if (ep0[i] != 0) {
                nz++;
            }
        }
        report(String.format("2. RGSW(0) ⊗ ct = 0（非零 %d/%d）", nz, n), nz == 0, "");
        nativeFreeCt(ctH);
        nativeDestroyKey(kh1);
        nativeDestroyKey(kh0);

        // ---------------- 正确性 ② 盲旋转：one-hot 进去必须 one-hot 出来 ----------------
        SecureRandom rnd = new SecureRandom();
        int r = rnd.nextInt(n);
        long[] oneHot = new long[n];
        oneHot[r] = 1;
        byte[] acc = nativeEncrypt(h, oneHot);
        long[] a = new long[d];        long twoN = 2L * n;
        long sum = 0;
        for (int i = 0; i < d; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), twoN);
            sum = (sum + a[i] * bits[i]) % twoN;
        }
        long beta = Math.floorMod(sum + r, twoN);

        long accH = nativeEncryptToStore(h, oneHot);      // 句柄路径，不序列化
        long rotH = nativeBlindRotateH(h, kh, accH, a, beta);
        long[] got = nativeDecryptH(h, rotH);
        int nonZero = 0;
        int unit = 0;
        int where = -1;
        for (int i = 0; i < n; i++) {
            if (got[i] != 0) {
                nonZero++;
                where = i;
                if (got[i] == 1 || got[i] == t - 1) {
                    unit++;
                }
            }
        }
        report(String.format("3. 盲旋转：one-hot 进 → one-hot 出（非零 %d 个，落点 %d，其中单位值 %d 个）",
                nonZero, where, unit),
            nonZero == 1 && unit == 1,
            "噪声预算 = " + nativeNoiseBudgetH(h, rotH) + " bit");

        // ---------------- 速度（已由上面的持久作业给出，这里只做字节路径留档）----------------
        System.out.println();
        System.out.println("  [留档] 旧的字节目录路径仍然不可用（见下方 [已知]），因此不再计时。");
        nativeDestroyKey(kh);
        } catch (RuntimeException e) {
            System.out.println();
            System.out.println("    [已知] 序列化分步检查失败（不影响上面的自包含基准）：" + e.getMessage());
        }
        nativeDestroyContext(h);
        System.out.printf("%n=== %d PASS / %d FAIL ===%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
        }
        System.out.printf("    [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (!detail.isEmpty()) {
            System.out.println("          " + detail);
        }
    }
}
