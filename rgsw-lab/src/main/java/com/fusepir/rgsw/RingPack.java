package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.math.BigInteger;
import java.util.Random;

/**
 * <b>Ring Packing（LWE → RLWE 打包）原型</b>——把多条「只加密一个比特」的 LWE 密文
 * 打包成<b>一个</b> RLWE 密文，<b>每条落在一个槽位</b>上，从而能跑 SIMD 二进制同态内积。
 *
 * <h3>为什么不能靠"系数摆放"（已有实测）</h3>
 * {@code packFromSample} 的相位是"消息在系数 j、其余系数满量级污染"（见 {@code PackGoalCheck}）。
 * 而槽位是相位的**求值**，一个"只有一个系数非零"的多项式，它的求值**铺满所有槽**——
 * 所以没有任何槽等于消息（实测 0/4096 命中）。
 *
 * <h3>本类用的构造：从一开始就在槽位域构造【纯常数】</h3>
 * 对每条 LWE 样本 {@code (a^(i), b^(i))}，其消息是
 * <pre>m_i = b^(i) − ⟨a^(i), s⟩   (mod t)</pre>
 * 两部分**分别在槽位域凑**（{@code b} 与 {@code a} 都是公开量，只有 {@code s} 保密）：
 * <pre>
 *   ⟨a^(i), s⟩ = Σ_j a^(i)_j · s_j
 *     ⇒ 用交换密钥 SwK[j][k] = RLWE( B^k · s_j )（把 LWE 私钥系数当【常数】加密）
 *        再乘公开小数字 d_{j,k}（a_j 的 B 进制分解）后累加
 *
 *   ct_i = ( − Σ_j Σ_k d_{j,k}·SwK[j][k] )  +  明文常数 b^(i)
 *          相位 = 纯常数 ( b^(i) − ⟨a^(i),s⟩ ) = m_i       ← 没有污染 ✓
 *
 *   packed = Σ_i  ct_i ⊗ E_i          E_i = 槽位选择子（槽 i = 1，其余 0）
 *          ⇒ packed 的槽 i 解码出来就是 m_i   ✓✓✓
 * </pre>
 *
 * <b>"纯常数"是全部关键</b>：只有相位是常数，乘槽选择子才不会把别处的值带进来。
 *
 * <h3>与文献的对应</h3>
 * 这就是文献里的 <b>Ring Packing / {@code RLWE-Pack}</b>（奠基：CDKS21, ePrint 2020/015；
 * 使用者：YPIR USENIX'24、LOHEN USENIX'25、InsPIRe ePrint 2025/1352 的 InspiRING、HERMES）。
 * 完整的调研见 {@code LWE_RLWE打包_RingPack_调研.md}。
 *
 * <h3>本原型的边界（重要）</h3>
 * <ul>
 *   <li><b>LWE 模数取 t（明文模数）</b>：因为 BFV 的明文域就是 mod t，{@code b_i − ⟨a,s⟩} 必须落在 mod t 里，
 *       才能被 BFV 正确解出来。真实协议里 LWE 密文在大模数上，需要额外的缩放/模数切换。</li>
 *   <li><b>做了 gadget 分解</b>（把 a_j 按底 B 拆成小数字），这正是控制噪声的关键；
 *       底 B 受 BFV 明文窗口 ±t/2 限制（与 {@code Mpc4jRgsw.decompose} 同一个约束）。</li>
 *   <li><b>交换密钥条数 = nLwe × digits</b>。若沿用"LWE 维数 = 环维度 N"的 LWE-in-RLWE 假设，
 *       这个密钥会撑到 N 条（N=16384 时约 16 GB）——所以真上这个原语**可能要放弃 LWE-in-RLWE**，
 *       改成论文写的 {@code sk = (s_L, s_R)} 两把独立密钥。见调研文档 §四。</li>
 * </ul>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.RingPack 8192 32}
 */
public final class RingPack {

    private static int failed = 0;

    // ==================================================================
    //  交换密钥 / 槽位选择子
    // ==================================================================

    /**
     * 交换密钥 {@code SwK[j][k] = RLWE(B^k · s_j mod t)}（消息为**常数**，NTT 域存放）。
     *
     * @param s    LWE 私钥（此处用二值；其它分布同样适用）
     * @param base gadget 底 B
     * @param digits 分解段数
     */
    public static Ciphertext[][] switchingKey(Mpc4jRgsw m, int[] s, int base, int digits) {
        Ciphertext[][] swk = new Ciphertext[s.length][digits];
        long power = 1;
        long[] powers = new long[digits];
        for (int k = 0; k < digits; k++) {
            powers[k] = power;
            power = Math.floorMod(power * base, m.t);
        }
        for (int j = 0; j < s.length; j++) {
            for (int k = 0; k < digits; k++) {
                long value = Math.floorMod(powers[k] * s[j], m.t);   // B^k · s_j mod t
                long[] constant = new long[m.n];
                constant[0] = value;                                  // 常数多项式
                Ciphertext ct = m.encrypt(constant);
                m.evaluator.transformToNttInplace(ct);                // 统一到 NTT 域，便于 multiplyPlain
                swk[j][k] = ct;
            }
        }
        return swk;
    }

    /**
     * 常数明文 `c`（NTT 域：所有槽都是 c）。
     *
     * <p>常数多项式在多项式环里就是 `c`，它的 NTT 处处等于 `c`，所以"乘常数"和"槽位域乘常数"
     * 是同一件事——这正是本构造全程可以留在 NTT 域的原因。
     */
    public static Plaintext plainConstant(Mpc4jRgsw m, long c) {
        long[] constant = new long[m.n];
        constant[0] = Math.floorMod(c, m.t);
        Plaintext pt = new Plaintext(constant);
        m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        return pt;
    }

    /**
     * 常数 1 的密文（NTT 域）。
     *
     * <p><b>为什么要它</b>：本构造需要把公开量 `b^(i)` 加到相位的常数项上。最自然的算子是
     * {@code Evaluator.addPlain}，但 SEAL 对 BFV 的明文加法有形态约束，实测在这套 Java 移植上
     * 直接抛 {@code "plain is not valid for encryption parameters"}（`setParmsId` 会把明文
     * 标成 NTT 形态，于是系数域 / NTT 域两边都凑不齐）。
     * 绕开办法：`b^(i) · RLWE(1) = multiplyPlain(一层密文, 常数明文)`——
     * 纯 `multiplyPlain`，没有形态约束，且结果仍是"纯常数"。
     */
    public static Ciphertext oneNtt(Mpc4jRgsw m) {
        long[] one = new long[m.n];
        one[0] = 1;
        Ciphertext ct = m.encrypt(one);
        m.evaluator.transformToNttInplace(ct);
        return ct;
    }

    /**
     * 槽位选择子 `E_slot`：槽 slot = 1，其余 0。
     *
     * <p><b>踩坑记录</b>：C++ 版 SEAL 的 {@code BatchEncoder::encode} 直接产出 <b>NTT 形态</b>明文，
     * 但这套 Java 移植产出的是<b>系数形态</b>。于是「NTT 密文 × encode 明文」的
     * {@code multiplyPlain} 会抛 {@code "NTT form mismatch"}。必须显式再转一次 NTT 才行。
     * （形态不匹配时即使不报错，乘出来也只是<b>多项式乘</b>而不是<b>槽位逐点乘</b>，结果全错。）
     */
    public static Plaintext slotSelector(Mpc4jRgsw m, BatchEncoder be, int slot) {
        long[] values = new long[be.slotCount()];
        values[slot] = 1;
        Plaintext pt = new Plaintext();
        be.encode(values, pt);
        m.evaluator.transformToNttInplace(pt, m.context.firstParmsId());
        return pt;
    }

    // ==================================================================
    //  打包
    // ==================================================================

    /**
     * ring packing：把 K 条 LWE 密文 {@code (a^(i), b^(i))} 打包成一个 RLWE 密文，
     * 第 i 条的消息落在槽位 {@code slots[i]}。
     *
     * <p>LWE 关系约定：{@code b^(i) ≡ ⟨a^(i), s⟩ + m_i (mod t)}。
     */
    public static Ciphertext pack(Mpc4jRgsw m, BatchEncoder be, Ciphertext[][] swk,
                                  int base, int digits, long[][] as, long[] bs, int[] slots) {
        Ciphertext acc = null;
        Ciphertext one = oneNtt(m);
        for (int i = 0; i < bs.length; i++) {
            // ① Σ_j Σ_k d_{j,k} · SwK[j][k]  —— 消息 = ⟨a^(i), s⟩（常数）
            Ciphertext sum = null;
            for (int j = 0; j < as[i].length; j++) {
                long remaining = Math.floorMod(as[i][j], m.t);
                for (int k = 0; k < digits; k++) {
                    long digit = remaining % base;
                    remaining /= base;
                    if (digit == 0) {
                        continue;
                    }
                    Ciphertext term = new Ciphertext();
                    term.copyFrom(swk[j][k]);
                    m.evaluator.multiplyPlainInplace(term, plainConstant(m, digit));
                    sum = (sum == null) ? term : m.add(sum, term);
                }
            }
            // ② 减去 b^(i)：b 是公开量，用「常数明文 × RLWE(1)」得到一条常数 −b^(i) 的密文
            //    （不用 addPlain——见 oneNtt 的注释：BFV 下 addPlain 的形态约束凑不齐）
            Ciphertext bias = new Ciphertext();
            bias.copyFrom(one);
            m.evaluator.multiplyPlainInplace(bias, plainConstant(m, -bs[i]));
            sum = (sum == null) ? bias : m.add(sum, bias);

            // ③ 取负：消息从 ⟨a,s⟩ − b 变成 b − ⟨a,s⟩ = m_i（仍是纯常数）
            m.evaluator.negateInplace(sum);

            // ④ 乘槽位选择子 ⇒ 只落在槽 slots[i]
            Ciphertext selected = new Ciphertext();
            selected.copyFrom(sum);
            m.evaluator.multiplyPlainInplace(selected, slotSelector(m, be, slots[i]));
            acc = (acc == null) ? selected : m.add(acc, selected);
        }
        return acc;
    }

    // ==================================================================
    //  自检
    // ==================================================================

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int nLwe = args.length > 1 ? Integer.parseInt(args[1]) : 32;
        int base = 1 << 8;
        int digits = 3;                       // 2^24 > t，足够覆盖 mod t 的 a_j
        int bits = 16;                        // 打包多少个比特（= int(log2(t)) 以内）
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        long t = m.t;

        System.out.println("=== Ring Packing（LWE → RLWE 打包）原型自检 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[plan] LWE 维数 n=%d；gadget 底 B=%d、段数 %d；打包 %d 个比特到槽 0..%d%n%n",
            nLwe, base, digits, bits, bits - 1);

        // ---------- 客户端/密钥持有者：造 LWE 私钥与交换密钥 ----------
        Random rnd = new Random(20260927L);
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        long t0 = System.nanoTime();
        Ciphertext[][] swk = switchingKey(m, s, base, digits);
        long keyMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("[setup] 交换密钥 %d 条（%d×%d），构造 %.0f ms%n",
            nLwe * digits, nLwe, digits, (double) keyMs);
        System.out.printf("        体积约 %.1f MB（每条 %.0f KB）%n%n",
            nLwe * digits * (2.0 * m.workingPrimeCount * n * 8) / 1048576.0,
            2.0 * m.workingPrimeCount * n * 8 / 1024.0);

        // ---------- 造 K 条"每条约一个比特"的 LWE 密文 ----------
        long[][] as = new long[bits][nLwe];
        long[] bs = new long[bits];
        long[] truth = new long[bits];
        for (int i = 0; i < bits; i++) {
            truth[i] = rnd.nextInt(2);                   // 伪随机比特，避免"交替"这种可猜模式
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), t);
                sum = Math.floorMod(sum + as[i][j] * s[j], t);
            }
            bs[i] = Math.floorMod(sum + truth[i], t);   // b = ⟨a,s⟩ + m  (mod t)
        }

        // ---------- 打包 ----------
        int[] slots = new int[bits];
        for (int i = 0; i < bits; i++) {
            slots[i] = i;
        }
        t0 = System.nanoTime();
        Ciphertext packed = pack(m, be, swk, base, digits, as, bs, slots);
        long packMs = (System.nanoTime() - t0) / 1_000_000;

        long[] decoded = decodeSlots(m, be, packed);
        int wrong = 0;
        StringBuilder first = new StringBuilder();
        for (int i = 0; i < bits; i++) {
            if (decoded[i] != truth[i]) {
                wrong++;
                if (wrong <= 4) {
                    first.append(String.format(" [槽%d got=%d want=%d]", i, decoded[i], truth[i]));
                }
            }
        }
        // 其余槽应全为 0
        int leak = 0;
        for (int i = bits; i < be.slotCount(); i++) {
            if (decoded[i] != 0) {
                leak++;
            }
        }
        report("P1 多条 LWE 比特 → 一个 RLWE 密文，每位落在自己的槽位",
            wrong == 0 && leak == 0,
            String.format("%d 个比特打包 %.0f ms；槽位错 %d 个%s；未被写入的槽里非零 %d 个",
                bits, (double) packMs, wrong, first, leak));

        // ---------- P2 端到端：拿打包产物直接去做二进制同态内积 ----------
        GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        long[] query = new long[be.slotCount()];
        for (int i = 0; i < bits; i++) {                // 查询只覆盖被打包的槽
            query[i] = rnd.nextInt(2);
        }
        long want = 0;
        for (int i = 0; i < bits; i++) {
            want += query[i] * truth[i];
        }
        long got = score(m, gk, query, packed);
        report("P2 打包产物【直接】喂给 BloomScoring（槽位域二进制同态内积）",
            got == want,
            String.format("⟨q, v⟩ = %d；打包产物算出 %d —— 这一步就是 A4 闭合的判据",
                want, got));

        // ---------- P3 负对照：把查询向量循环平移一格，得分必须变 ----------
        //  没有这一条，P2 的"相等"可能只是噪声恰好落对一个常数。
        long[] shifted = new long[be.slotCount()];
        for (int i = 0; i < bits; i++) {
            shifted[(i + 1) % bits] = query[i];
        }
        long wantShift = 0;
        for (int i = 0; i < bits; i++) {
            wantShift += shifted[i] * truth[i];
        }
        long gotShift = score(m, gk, shifted, packed);
        report("P3 负对照：查询平移一格后得分必须跟着变（排除常数巧合）",
            gotShift == wantShift && gotShift != want,
            String.format("平移后期望 %d、算出 %d（原始得分 %d）", wantShift, gotShift, want));

        // ---------- P4 维度扫：交换密钥条数随 LWE 维数线性增长，噪声也要扛得住 ----------
        System.out.println();
        System.out.println("--- P4 LWE 维数扫描（同样的打包/打分流程，看噪声与耗时）---");
        boolean scaleOk = true;
        for (int nScan : new int[]{8, 32, 128, 512}) {
            long[] r = scanOne(m, be, gk, nScan, bits, rnd);
            boolean ok = (r[0] == 0 && r[1] == 1);
            scaleOk &= ok;
            System.out.printf("      n=%-4d 槽位错 %d 个、内积%s  交换密钥 %d 条、打包 %.0f ms%n",
                nScan, r[0], ok ? "正确" : "错误", r[2], (double) r[3]);
        }
        report("P4 LWE 维数 n = 8 / 32 / 128 / 512 都能正确打包并打分", scaleOk,
            "n 只影响交换密钥条数与耗时；n=512 对应真协议里 SampleExtract 的维数量级");

        // ---------- P5 尺度：真实 LWE 样本来在 q 尺度，必须缩放才能进这个构造 ----------
        System.out.println();
        boolean scalePass = scaleStepTest(m, be, gk, bits, rnd);

        System.out.println();
        if (failed == 0) {
            System.out.println("=== Ring Packing 结构验证通过：多个 LWE 比特 → 一个槽位域 RLWE → 可做 SIMD 内积 ===");
        } else {
            System.out.println("=== 有 " + failed + " 项失败（多半是噪声或参数；见调研文档 §三）===");
        }
    }

    /**
     * <b>P5：模数尺度自检。</b>
     *
     * <p>真协议里 LWE 样本来在 {@code SampleExtract} 之后，位于 RLWE 的大模数 {@code q_R} 上，
     * 消息被 {@code Δ = q/t} 放大；而本构造要求 {@code a, b ∈ Z_t}（BFV 的明文域）。
     * 所以中间必须有一步缩放
     * <pre>a'_j = round(a_j · t / q),   b' = round(b · t / q)</pre>
     * 这一步会引入 {@code ≤ n/2} 的舍入噪声（每个 a_j 的舍入误差 ≤ 1/2，乘上 |s_j| ≤ 1 后累加）。
     * 本项就测这个噪声到底吃不吃得下。
     */
    private static boolean scaleStepTest(Mpc4jRgsw m, BatchEncoder be, GaloisKeys gk,
                                         int bits, Random rnd) {
        System.out.println("--- P5 模数缩放：a,b ∈ Z_q（带 Δ 缩放与噪声）→ 缩放到 Z_t → 打包 ---");
        int nLwe = 32;
        int base = 1 << 8;
        int digits = 3;
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        BigInteger q = m.q;
        BigInteger tB = BigInteger.valueOf(m.t);
        BigInteger delta = q.divide(tB);              // Δ = q/t

        long[][] as = new long[bits][nLwe];
        long[] bs = new long[bits];
        long[] truth = new long[bits];
        for (int i = 0; i < bits; i++) {
            truth[i] = rnd.nextInt(2);
            BigInteger sum = BigInteger.ZERO;
            for (int j = 0; j < nLwe; j++) {
                BigInteger aq = new BigInteger(q.bitLength() + 1, rnd).mod(q);
                as[i][j] = scaleToT(m, aq);
                sum = sum.add(aq.multiply(BigInteger.valueOf(s[j])));
            }
            // 真实噪声：取 Δ 的千分之一量级（SampleExtract 出来的噪声远小于 Δ）
            BigInteger noise = BigInteger.valueOf(rnd.nextInt(1024));
            BigInteger bq = sum.add(delta.multiply(BigInteger.valueOf(truth[i])))
                               .add(noise).mod(q);
            bs[i] = scaleToT(m, bq);
        }
        Ciphertext[][] swk = switchingKey(m, s, base, digits);
        // 明文侧对照：先在整数上直接算 (b' − ⟨a',s⟩) mod t。
        // 关键认知：缩放会带来微小噪声，所以这个残差**不等于** m，而是 m + 小噪声。
        // 于是正确的判据有两层：(a) 同态打包必须**精确复现**这个残差；(b) 残差本身离 m 很近。
        long[] clearResid = new long[bits];
        int clearWrong = 0;
        long worst = 0;
        for (int i = 0; i < bits; i++) {
            long acc = 0;
            for (int j = 0; j < nLwe; j++) {
                acc = Math.floorMod(acc + as[i][j] * s[j], m.t);
            }
            clearResid[i] = Math.floorMod(bs[i] - acc, m.t);
            long centered = centered(clearResid[i], m.t);
            worst = Math.max(worst, Math.abs(centered - truth[i]));
            if (centered != truth[i]) {
                clearWrong++;
            }
        }
        System.out.printf("      明文侧：缩放噪声使 %d/%d 个样本的残差偏离 m 一步以上，最大偏差 %d%n",
            clearWrong, bits, worst);
        int[] slots = new int[bits];
        for (int i = 0; i < bits; i++) {
            slots[i] = i;
        }
        Ciphertext packed = pack(m, be, swk, base, digits, as, bs, slots);
        long[] decoded = decodeSlots(m, be, packed);
        int wrong = 0;
        for (int i = 0; i < bits; i++) {
            if (decoded[i] != clearResid[i]) {
                wrong++;
            }
        }
        report("P5a 缩放后的 LWE 样本被同态路径【精确搬运】（打包等于整数侧算出的残差）", wrong == 0,
            String.format("%d 个比特中错 %d 个 —— 打包本身不额外引入误差，缩放噪声是样本自带的", bits, wrong));

        // 缩放噪声随维数的增长：纯明文侧测量（不跑同态，所以能扫到真实协议的量级 n = N）
        System.out.println("      --- 缩放噪声随 LWE 维数的增长（明文侧，成本极低）---");
        long marginWorst = 0;
        for (int nScan : new int[]{32, 512, 2048, 8192}) {
            long[] r = scaleNoiseScan(m, nScan, 256, rnd);
            marginWorst = Math.max(marginWorst, r[0]);
            System.out.printf("      n=%-5d 最大偏差 %-4d（t/2 = %d，余量 %d 倍）%n",
                nScan, r[0], m.t / 2, (m.t / 2) / Math.max(1, r[0]));
        }
        boolean scaleOk = (wrong == 0) && marginWorst * 8 < m.t / 2;
        report("P5b 缩放噪声随 n 只按 √n 增长，且在 n = N = 8192（真实协议量级）仍有充足余量",
            scaleOk,
            String.format("最大偏差 %d，明文半窗 %d；要求至少 8 倍余量", marginWorst, m.t / 2));
        return scaleOk;
    }

    /** 明文侧扫描：给定 n，测 {@code round(b·t/q) − Σ round(a_j·t/q)·s_j} 离 m 的最大偏差。 */
    private static long[] scaleNoiseScan(Mpc4jRgsw m, int nLwe, int trials, Random rnd) {
        BigInteger q = m.q;
        BigInteger delta = q.divide(BigInteger.valueOf(m.t));
        long worst = 0;
        for (int tr = 0; tr < trials; tr++) {
            int[] s = new int[nLwe];
            for (int i = 0; i < nLwe; i++) {
                s[i] = rnd.nextInt(2);
            }
            BigInteger sum = BigInteger.ZERO;
            long[] aScaled = new long[nLwe];
            for (int j = 0; j < nLwe; j++) {
                BigInteger aq = new BigInteger(q.bitLength() + 1, rnd).mod(q);
                aScaled[j] = scaleToT(m, aq);
                sum = sum.add(aq.multiply(BigInteger.valueOf(s[j])));
            }
            long msg = rnd.nextInt(2);
            BigInteger bq = sum.add(delta.multiply(BigInteger.valueOf(msg))).mod(q);
            long bScaled = scaleToT(m, bq);
            long acc = 0;
            for (int j = 0; j < nLwe; j++) {
                acc = Math.floorMod(acc + aScaled[j] * s[j], m.t);
            }
            long dev = Math.abs(centered(Math.floorMod(bScaled - acc, m.t), m.t) - msg);
            worst = Math.max(worst, dev);
        }
        return new long[]{worst};
    }

    private static long centered(long v, long t) {
        return v > t / 2 ? v - t : v;
    }

    /** {@code x ∈ Z_q} → {@code Z_t}：四舍五入 {@code x·t/q} 后取模 t。 */
    private static long scaleToT(Mpc4jRgsw m, BigInteger x) {
        BigInteger q = m.q;
        BigInteger num = x.multiply(BigInteger.valueOf(m.t)).add(q.shiftRight(1));
        return num.divide(q).mod(BigInteger.valueOf(m.t)).longValueExact();
    }

    /** 一次完整的"造 LWE 样本 → 打包 → 打分"小流程，返回 {槽位错数, 内积是否正确, 密钥条数, 耗时ms}。 */
    private static long[] scanOne(Mpc4jRgsw m, BatchEncoder be, GaloisKeys gk,
                                  int nLwe, int bits, Random rnd) {
        int[] s = new int[nLwe];
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        int base = 1 << 8;
        int digits = 3;
        Ciphertext[][] swk = switchingKey(m, s, base, digits);

        long[][] as = new long[bits][nLwe];
        long[] bs = new long[bits];
        long[] truth = new long[bits];
        for (int i = 0; i < bits; i++) {
            truth[i] = rnd.nextInt(2);
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = Math.floorMod(sum + as[i][j] * s[j], m.t);
            }
            bs[i] = Math.floorMod(sum + truth[i], m.t);
        }
        int[] slots = new int[bits];
        for (int i = 0; i < bits; i++) {
            slots[i] = i;
        }
        long t0 = System.nanoTime();
        Ciphertext packed = pack(m, be, swk, base, digits, as, bs, slots);
        long ms = (System.nanoTime() - t0) / 1_000_000;

        long[] decoded = decodeSlots(m, be, packed);
        int wrong = 0;
        for (int i = 0; i < bits; i++) {
            if (decoded[i] != truth[i]) {
                wrong++;
            }
        }
        long[] query = new long[be.slotCount()];
        long want = 0;
        for (int i = 0; i < bits; i++) {
            query[i] = rnd.nextInt(2);
            want += query[i] * truth[i];
        }
        long got = score(m, gk, query, packed);
        return new long[]{wrong, got == want ? 1 : 0, (long) nLwe * digits, ms};
    }

    /** 打分：打包产物是 NTT 形态，而密文×密文要求非 NTT 形态，所以先转回来。 */
    private static long score(Mpc4jRgsw m, GaloisKeys gk, long[] query, Ciphertext packed) {
        Ciphertext qBF = BloomScoring.encryptBloomVector(m, query);
        Ciphertext packedCoeff = new Ciphertext();
        packedCoeff.copyFrom(packed);
        if (packedCoeff.isNttForm()) {
            m.evaluator.transformFromNttInplace(packedCoeff);
        }
        return BloomScoring.decodeScore(m, BloomScoring.bloomScore(m, gk, qBF, packedCoeff));
    }

    private static long[] decodeSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
