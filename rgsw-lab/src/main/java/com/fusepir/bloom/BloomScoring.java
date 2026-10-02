package com.fusepir.bloom;


import com.fusepir.prim.*;
import com.fusepir.probe.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Evaluator;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

/**
 * <b>Bloom 打分的槽位域实现</b>——即 CAPE 的"加密 Bloom 得分"，也就是那个<b>二进制同态内积</b>。
 *
 * <h3>论文对应</h3>
 * 算法 2 ANSWER 第 4~7 行：
 * <pre>
 *   ct_score,j ← CtCtMul(q_BF, ct_j^BF)
 *   for r = 0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
 * </pre>
 * 结果是 {@code s_j = ⟨b_qry, b_vj⟩}（论文 Theorem 3 的证明里明确写了这个式子）。
 *
 * <h3>为什么必须在槽位域（实测裁决，见 {@link BloomInnerProductProbe}）</h3>
 * <table border="1">
 *   <tr><th>域</th><th>CtCtMul 是</th><th>折叠后得到</th><th>可用？</th></tr>
 *   <tr><td><b>槽位</b>（BatchEncoder）</td><td>逐槽相乘 = 按位 AND</td><td><b>每个槽 = ⟨a,b⟩</b></td><td>✅</td></tr>
 *   <tr><td>系数</td><td>多项式乘法 = 卷积</td><td>一个无意义的数（既非内积也非重量之积）</td><td>❌</td></tr>
 * </table>
 * N=4096 实测：槽位域折叠后每槽 = 内积；系数域四组向量全部得不到内积。
 *
 * <h3>⚠️ 两个硬约束</h3>
 * <ol>
 *   <li><b>N ≥ 4096</b>。{@code CtCtMul} 之后要重线性化，而重线性化需要上下文支持密钥切换，
 *       也就是至少 <b>2 个工作素数</b>。N=2048 时 {@code bfvDefault} 只给 1 个素数，
 *       直接抛 {@code keyswitching is not supported by the context}。</li>
 *   <li><b>ℓ_BF ≤ N</b>：一条密文的槽数就是 N，Bloom 向量要能整条放进去。</li>
 * </ol>
 *
 * <h3>调用（两步）</h3>
 * <pre>
 *   // 客户端：把 Bloom 向量编成槽位密文
 *   Ciphertext qBF = BloomScoring.encryptBloomVector(m, m.encryptor, b_qry);
 *   // 服务端：对每个候选算得分（每个槽都是 s_j）
 *   Ciphertext score = BloomScoring.bloomScore(m, m.evaluator, gk, qBF, ct_j_BF);
 * </pre>
 *
 * <h3>尚未接通的一环（重要）</h3>
 * 本类要求 <b>{@code ct_j^BF} 本身已经处于槽位域</b>。而候选的 Bloom 向量是从载荷里检索出来的：
 * 载荷按<b>行号 = 系数下标</b>摆放（{@code P_{c,b}(X) = Σ_r D[r+cR][b]·X^r}），
 * {@code BlindRotate} + {@code SampleExtract} 出来的是一条条 <b>LWE 密文</b>。
 * <b>把 LWE 密文变成"槽位密文"这一步（即论文的 {@code Pack}）本类不做</b>——
 * 它需要专门的 packing 材料（技术出处：YPIR, USENIX Security'24；见 {@code OXTPIR.pptx} slide 30
 * "使用 YPIR 的技术打包成一个 RLWE 密文"），属独立原语。
 */
public final class BloomScoring {

    private BloomScoring() {
    }

    /**
     * 客户端：把 Bloom 向量编成槽位密文。
     *
     * @param bits 长度必须等于槽数（= N）；元素取 0/1
     */
    public static Ciphertext encryptBloomVector(Mpc4jRgsw m, long[] bits) {
        BatchEncoder encoder = new BatchEncoder(m.context);
        if (bits.length != encoder.slotCount()) {
            throw new IllegalArgumentException(
                "Bloom 向量长度必须等于槽数：" + bits.length + " != " + encoder.slotCount()
                    + "（ℓ_BF ≤ N 是硬约束）");
        }
        for (long b : bits) {
            if (b != 0 && b != 1) {
                throw new IllegalArgumentException("Bloom 向量必须是二进制，遇到 " + b);
            }
        }
        Plaintext pt = new Plaintext();
        encoder.encode(bits, pt);
        Ciphertext ct = new Ciphertext();
        m.encryptor.encryptSymmetric(pt, ct);
        return ct;
    }

    /**
     * 服务端：{@code ct_score ← CtCtMul(q_BF, ct_BF)} 再折叠求和。
     *
     * <p>输出密文的<b>每一个槽</b>都等于 {@code ⟨b_qry, b_v⟩}（证明：逐槽相乘得到 qᵢvᵢ，
     * 再把全部 N 个槽平移相加，每个槽就都变成总和）。
     *
     * @param galoisKeys 需要包含步长 {@code {1,2,4,…,N/2}}；见 {@link #galoisKeysFor}
     */
    public static Ciphertext bloomScore(Mpc4jRgsw m, GaloisKeys galoisKeys,
                                        Ciphertext queryBloom, Ciphertext candidateBloom) {
        Evaluator ev = m.evaluator;
        Ciphertext prod = new Ciphertext();
        ev.multiply(queryBloom, candidateBloom, prod);
        ev.relinearizeInplace(prod, m.relinKeys());
        return foldAllSlots(m, galoisKeys, prod);
    }

    /** 折叠：行内按 {@code 2^r} 平移相加，最后做一次列旋转把两行合并。 */
    public static Ciphertext foldAllSlots(Mpc4jRgsw m, GaloisKeys galoisKeys, Ciphertext ct) {
        Evaluator ev = m.evaluator;
        Ciphertext acc = new Ciphertext();
        acc.copyFrom(ct);
        // ① 行内折叠：seal 的两行布局，每行 N/2 个槽；平移步长上限是 N/2−1，所以只到 N/4
        for (int r = 1; r < m.n / 2; r *= 2) {
            Ciphertext shifted = new Ciphertext();
            shifted.copyFrom(acc);
            ev.rotateRowsInplace(shifted, r, galoisKeys);
            ev.addInplace(acc, shifted);
        }
        // ② 合并两行：一次列旋转
        Ciphertext other = new Ciphertext();
        other.copyFrom(acc);
        ev.rotateColumnsInplace(other, galoisKeys);
        ev.addInplace(acc, other);
        return acc;
    }

    /**
     * 造出折叠所需的 Galois 密钥。
     *
     * <p>步长集 = <b>{0} ∪ {1,2,4,…,N/4}</b>：
     * <ul>
     *   <li>步长 0 → 列旋转的元素（把两行合并）；</li>
     *   <li>1,2,4,…,N/4 → 行内平移。
     *   <b>不能取到 N/2</b>：seal 的 {@code getEltFromStep} 在 {@code |step| ≥ N/2} 时抛
     *   {@code step count too large}（实测踩到过）。</li>
     * </ul>
     * 一共 {@code log₂N} 个——与论文的 {@code for r = 0..log₂ℓ_BF−1} 轮数一致 ✓
     */
    public static GaloisKeys galoisKeysFor(Mpc4jRgsw m) {
        java.util.List<Integer> steps = new java.util.ArrayList<>();
        steps.add(0);                                   // 列旋转（合并两行）
        for (int r = 1; r < m.n / 2; r *= 2) {
            steps.add(r);                               // 行内平移
        }
        int[] arr = new int[steps.size()];
        for (int i = 0; i < arr.length; i++) {
            arr[i] = steps.get(i);
        }
        GaloisKeys gk = new GaloisKeys();
        m.keyGen.createStepGaloisKeys(arr, gk);
        return gk;
    }

    /** 读回得分（客户端侧，仅用于验证/自检）。任取一个槽即可，因为折叠后每个槽都相同。 */
    public static long decodeScore(Mpc4jRgsw m, Ciphertext score) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(score);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] slots = new long[new BatchEncoder(m.context).slotCount()];
        new BatchEncoder(m.context).decode(pt, slots);
        return slots[0];
    }

    // ==================================================================
    //  自检：用一组"命中 / 不命中"的候选验证打分的判定能力
    // ==================================================================

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();
        long t = m.t;

        System.out.println("=== Bloom 打分（槽位域二进制同态内积）自检 ===");
        System.out.println("[params] " + m.describe());
        System.out.printf("[slots] 槽数 = %d（一条密文装 %d 位 Bloom）%n%n", slots, slots);

        // ---- 查询侧：b_qry，令 τ = ‖b_qry‖₁ ----
        long[] query = new long[slots];
        for (int i = 0; i < slots; i += 7) {
            query[i] = 1;
        }
        long tau = 0;
        for (long v : query) {
            tau += v;
        }
        System.out.printf("[query] b_qry 的汉明重量 τ = %d%n", tau);

        long t0 = System.nanoTime();
        GaloisKeys gk = galoisKeysFor(m);
        long keyMs = (System.nanoTime() - t0) / 1_000_000;
        Ciphertext qBF = encryptBloomVector(m, query);
        System.out.printf("[setup] Galois 密钥（%d 个步长）%.0f ms%n%n", Integer.numberOfTrailingZeros(n), (double) keyMs);

        // ---- 候选 1：完全命中（b_qry 的每一位都被置 1，额外还有别的位）----
        long[] hit = new long[slots];
        System.arraycopy(query, 0, hit, 0, slots);
        for (int i = 3; i < slots; i += 11) {
            hit[i] = 1;                      // 额外位（模拟该值还关联了别的关键词）
        }
        check(m, be, gk, qBF, hit, tau, "C1 命中候选（包含 b_qry 全部位）应得 s = τ");

        // ---- 候选 2：恰好是 b_qry 本身（多值都不能少）----
        check(m, be, gk, qBF, query, tau, "C2 候选 = b_qry 本身，应得 s = τ");

        // ---- 候选 3：漏了 1 位 → 应得 τ−1，被拒 ----
        long[] miss1 = new long[slots];
        System.arraycopy(query, 0, miss1, 0, slots);
        miss1[14] = 0;                       // 第 14 位本该是 1
        check(m, be, gk, qBF, miss1, tau - 1, "C3 漏 1 位 → s = τ−1，应当被拒");

        // ---- 候选 4：漏 5 位 ----
        long[] miss5 = new long[slots];
        System.arraycopy(query, 0, miss5, 0, slots);
        int removed = 0;
        for (int i = 0; i < slots && removed < 5; i += 7) {
            miss5[i] = 0;
            removed++;
        }
        check(m, be, gk, qBF, miss5, tau - 5, "C4 漏 5 位 → s = τ−5，应当被拒");

        // ---- 候选 5：全 0 → 应得 0 ----
        check(m, be, gk, qBF, new long[slots], 0, "C5 空候选 → s = 0");

        System.out.println();
        System.out.printf("[判定] 阈值 τ = %d：s = τ 接受，s < τ 拒绝。"
            + "C1/C2 应接受，C3/C4/C5 应拒绝。%n", tau);

        System.out.println();
        System.out.println(failed == 0
            ? "=== Bloom 槽位域打分全部通过：CtCtMul + 折叠 = 二进制同态内积 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static void check(Mpc4jRgsw m, BatchEncoder be, GaloisKeys gk,
                              Ciphertext qBF, long[] candidate, long expected, String name) {
        Ciphertext ctBF = encryptBloomVector(m, candidate);
        long t0 = System.nanoTime();
        Ciphertext score = bloomScore(m, gk, qBF, ctBF);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        long got = decodeScore(m, score);
        // 顺带确认"每个槽都相同"
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(score);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] slots = new long[be.slotCount()];
        be.decode(pt, slots);
        int distinct = 0;
        for (int i = 1; i < slots.length; i++) {
            if (slots[i] != slots[0]) {
                distinct++;
            }
        }
        boolean ok = got == expected && distinct == 0;
        System.out.printf("%s %s%n", ok ? "[PASS]" : "[FAIL]", name);
        System.out.printf("       s = %d（期望 %d）；%d ms；不一致的槽 %d/%d%n",
            got, expected, ms, distinct, slots.length);
        if (!ok) {
            failed++;
        }
    }
}
