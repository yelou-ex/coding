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

    /** 第 6 段自检用的 {@code ℓ_BF}：远小于 N，专门覆盖"补齐 + 只折 ℓ_BF 项"这条路径。 */
    private static final int SMALL_LBF = 18;

    private BloomScoring() {
    }

    /**
     * 客户端：把 Bloom 向量编成槽位密文。
     *
     * <p>⚠️ {@code bits} 的长度必须**恰好等于槽数 N**，不是"≤ N"。
     * 调用方负责补齐（{@code BloomChannel.padToSlots}），
     * 而"下标 {@code ≥ ℓ_BF} 的槽为 0"正是折叠只折 {@code ℓ_BF} 项就等于折满 N 项的前提
     * —— 所以这里同时校验二进制性与长度。
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
     * 服务端：{@code ct_score ← CtCtMul(q_BF, ct_BF)} 再折叠求和（<b>折全部 N 个槽</b>）。
     *
     * <p>输出密文的<b>每一个槽</b>都等于 {@code ⟨b_qry, b_v⟩}（证明：逐槽相乘得到 qᵢvᵢ，
     * 再把全部 N 个槽平移相加，每个槽就都变成总和）。
     *
     * <p>⚠️ 只有在**不知道 {@code ℓ_BF}** 时才该用这个版本。知道 {@code ℓ_BF} 时请用
     * {@link #bloomScore(Mpc4jRgsw, GaloisKeys, Ciphertext, Ciphertext, int)} ——
     * 它按论文折 {@code ⌈log2 ℓ_BF⌉} 轮，**噪声增长比这里小 2^(log2N − log2ℓ_BF) 倍**
     * （本组参数：2^13 vs 2^5 = 256 倍）。
     *
     * @param galoisKeys 需要包含步长 {@code {0} ∪ {1,2,4,…,N/4}}；见 {@link #galoisKeysFor}
     */
    public static Ciphertext bloomScore(Mpc4jRgsw m, GaloisKeys galoisKeys,
                                        Ciphertext queryBloom, Ciphertext candidateBloom) {
        // A2 ANSWER 4 的 `CtCtMul`（含 relinearize —— 收进 CtOps，免得漏）
        Ciphertext prod = CtOps.ctCtMul(m, queryBloom, candidateBloom);
        return foldAllSlots(m, galoisKeys, prod);
    }

    /**
     * 服务端：{@code CtCtMul} + <b>论文形状的折叠</b>（A2 ANSWER 5-6）。
     *
     * <p>与 4 参数版的差别只有折叠深度：这里折 {@code ⌈log2 ℓ_BF⌉} 轮，
     * 而不是折满 {@code N/2} 个槽。
     *
     * @param lBf {@code ℓ_BF}，**必须与建表、建查询时用的一致**
     */
    public static Ciphertext bloomScore(Mpc4jRgsw m, GaloisKeys galoisKeys,
                                        Ciphertext queryBloom, Ciphertext candidateBloom,
                                        int lBf) {
        // A2 ANSWER 4 的 `CtCtMul`（含 relinearize）
        Ciphertext prod = CtOps.ctCtMul(m, queryBloom, candidateBloom);
        return foldSlots(m, galoisKeys, prod, lBf);
    }

    /**
     * <b>论文 A2 ANSWER 5-6 的折叠</b>：
     * <pre>
     *   for r = 0 to log2 ℓ_BF − 1 do
     *       ct_score ← CtCtAdd(ct_score, CtRotate(ct_score, 2^r))
     * </pre>
     *
     * <h3>⚠️ 轮数用 ⌈log2 ℓ_BF⌉，不是论文字面的 ⌊log2 ℓ_BF⌋</h3>
     * 论文那一行写成 {@code log2 ℓ_BF}，而 {@code ℓ_BF} 不是 2 的幂时会**少折一轮**：
     * {@code ℓ_BF = 18} 时 {@code log2(18) = 4.17} ⇒ 只折 4 轮 ⇒
     * 只覆盖槽 {@code [0,16)}，**漏掉槽 16、17** ⇒ {@code s_j} 偏小 2 ⇒
     * 本该接受的候选被拒。⇒ <b>照抄那一行会算错</b>，必须取 ⌈·⌉
     * （或者约束 {@code ℓ_BF} 是 2 的幂）。
     *
     * <h3>为什么可以不做列旋转</h3>
     * 两侧的向量都经 {@code padToSlots} 补齐 ⇒ 槽 {@code ≥ ℓ_BF} 全为 0
     * ⇒ 乘积的支撑也全在 {@code [0, ℓ_BF)} 内。当 {@code ℓ_BF ≤ N/2} 时支撑完全落在
     * <b>第 0 行</b>，所以只需行内平移，<b>列旋转纯属白做</b>（加的是 0，还多一份噪声）。
     * {@code ℓ_BF > N/2} 时支撑跨两行，退回 {@link #foldAllSlots}。
     *
     * <p>正确性前提（由调用方保证，见 {@code BloomChannel.padToSlots}）：
     * {@code ℓ_BF ≤ N/2} 且两侧向量的 {@code [ℓ_BF, N)} 段为 0。
     *
     * <p>⚠️ <b>候选是 {@code Pack} 的产物时不满足这条前提</b>（Bloom 位散布在整个
     * {@code [0, B_pay)} 上，{@code B_pay = 61} 时最高到槽 60）⇒ 用本方法会<b>静默漏算</b>。
     * 那种情况下请用 {@link #foldSlotsReaching}（它按最高参与槽取轮数）。
     * 实测证据与判据见 {@code probe/PackLimbPayloadTest} 的 P4/P6。
     */
    public static Ciphertext foldSlots(Mpc4jRgsw m, GaloisKeys galoisKeys, Ciphertext ct, int lBf) {
        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();
        if (lBf <= 0 || lBf > slots) {
            throw new IllegalArgumentException("ℓ_BF = " + lBf + " 不在 (0, " + slots + "] 内");
        }
        if (lBf > slots / 2) {
            // 支撑跨两行 ⇒ 列旋转是必要的，退回"折满"的那一版
            return foldAllSlots(m, galoisKeys, ct);
        }
        Evaluator ev = m.evaluator;
        Ciphertext acc = new Ciphertext();
        acc.copyFrom(ct);
        // ⌈log2 ℓ_BF⌉ 轮：折完覆盖槽 [0, 2^rounds) ⊇ [0, ℓ_BF)
        int rounds = 0;
        for (int step = 1; step < lBf; step *= 2) {
            ++rounds;
        }
        for (int i = 0; i < rounds; i++) {
            int step = 1 << i;                 // ≤ N/4 < N/2 ⇒ rotateRows 的步长上限内
            // A2 ANSWER 5 的 `CtRotate(ct, 2^r)`
            Ciphertext shifted = CtOps.ctRotateRows(m, acc, step, galoisKeys);
            CtOps.ctCtAddInplace(m, acc, shifted);   // A2 ANSWER 5 的 CtCtAdd
        }
        return acc;
    }

    /**
     * <b>按"参与槽的最高下标"取折叠轮数</b> —— 当候选是 <b>{@code Pack} 的产物</b>时，
     * 论文形状的 {@code ⌈log2 ℓ_BF⌉} 轮<b>不够</b>。
     *
     * <h3>为什么必须补这个入口（2026-10-15 实测，见 {@code probe/PackLimbPayloadTest}）</h3>
     * {@link #foldSlots} 的正确性前提写得很清楚：支撑要落在 {@code [0, ℓ_BF)}。
     * {@code BloomChannel.padToSlots} 造的候选满足它。但 <b>{@code Pack} 的产物不满足</b>——
     * {@code Pack} 把 {@code B_pay} 个 limb 摆进槽 {@code 0..B_pay−1}，其中
     * <b>Bloom 位就散布在整个 {@code [0, B_pay)} 上</b>，例如
     * {@code t=65537}、{@code ℓ_BF=18}、{@code B_pay=61} 时三段 Bloom 位分别起于
     * <b>槽 5 / 24 / 43</b>。
     *
     * <p>而 {@code ⌈log2 18⌉ = 5} 轮只够到 {@code [0,32)} ⇒ <b>槽 32 以上的命中位被静默漏掉</b>：
     * 实测段 1（命中位在槽 39..41）与段 2（槽 58..60）都算出 <b>0 而不是 3</b>。
     * 这是"漏算"而不是"算错"—— 分值偏小 ⇒ 本该接受的候选被拒，
     * 也就是 {@code foldSlots} 注释里已经登记过的那种静默失败。
     *
     * <h3>正确的轮数</h3>
     * {@code ⌈log2(最高参与槽 + 1)⌉}：{@code B_pay = 61} ⇒ 最高参与槽 60 ⇒ <b>6 轮</b>
     * （够到 {@code [0,64)}）。它严格介于论文形状的 5 轮与 {@link #foldAllSlots} 的 13 轮之间
     * —— 比论文多 1 轮，比折满少 7 轮。
     *
     * <p><b>本方法没有跑在 {@code CapeBloomScore} 那条现行路径上</b>（那里的候选是
     * {@code BloomChannel} 造的 BF 向量、支撑在 {@code [0, ℓ_BF)}，5 轮是对的）。
     * 它是为 A1 ANSWER 13 的 {@code Pack} 接线准备的 —— 一旦打包产物成为候选，
     * 就必须走这一条，否则上面那个漏算会静默上线。
     *
     * @param highestSlotInclusive 参与内积的<b>最高槽下标</b>（含）。
     *                             拿不准就传 {@code B_pay − 1}（载荷摆满时即最大）。
     *                             传太小会静默漏算，传太大只是多付噪声。
     */
    public static Ciphertext bloomScoreReaching(Mpc4jRgsw m, GaloisKeys galoisKeys,
                                                Ciphertext queryBloom, Ciphertext candidateBloom,
                                                int highestSlotInclusive) {
        Ciphertext prod = CtOps.ctCtMul(m, queryBloom, candidateBloom);
        return foldSlotsReaching(m, galoisKeys, prod, highestSlotInclusive);
    }

    /**
     * {@link #bloomScoreReaching} 的折叠那一半；见那里的说明。
     *
     * <p>实现在 {@link #foldSlots} 之上：{@code foldSlots} 的轮数算法是
     * "最小的 {@code r} 使 {@code 2^r ≥ 入参}"，所以传 {@code 最高参与槽 + 1}
     * 恰好等价于"够到该槽"。支撑跨行（{@code > 槽数/2}）时 {@code foldSlots} 自己会退回折满。
     */
    public static Ciphertext foldSlotsReaching(Mpc4jRgsw m, GaloisKeys galoisKeys, Ciphertext ct,
                                               int highestSlotInclusive) {
        if (highestSlotInclusive < 0) {
            throw new IllegalArgumentException("参与槽的最高下标不能为负：" + highestSlotInclusive);
        }
        return foldSlots(m, galoisKeys, ct, highestSlotInclusive + 1);
    }

    /**
     * <b>折满</b>折叠：行内按 {@code 2^r} 平移相加（{@code r = 1,2,…,N/4}，共 log2(N/2) 轮），
     * 最后做一次列旋转把两行合并。
     *
     * <p>⚠️ 它的轮数是 <b>log2(N/2)+1</b>（N=8192 时 13 轮），而论文只折
     * {@code ⌈log2 ℓ_BF⌉} 轮。两者在"两侧向量已补齐 0"时**结果相同**，
     * 但本方法的**噪声增长大 256 倍**（2^13 vs 2^5）。
     * ⇒ 知道 {@code ℓ_BF} 时请用 {@link #foldSlots}。
     */
    public static Ciphertext foldAllSlots(Mpc4jRgsw m, GaloisKeys galoisKeys, Ciphertext ct) {
        Evaluator ev = m.evaluator;
        Ciphertext acc = new Ciphertext();
        acc.copyFrom(ct);
        // ① 行内折叠：seal 的两行布局，每行 N/2 个槽；平移步长上限是 N/2−1，所以只到 N/4
        for (int r = 1; r < m.n / 2; r *= 2) {
            Ciphertext shifted = CtOps.ctRotateRows(m, acc, r, galoisKeys);
            CtOps.ctCtAddInplace(m, acc, shifted);   // A2 ANSWER 5 的 CtCtAdd
        }
        // ② 合并两行：一次列旋转
        Ciphertext other = new Ciphertext();
        other.copyFrom(acc);
        ev.rotateColumnsInplace(other, galoisKeys);
        CtOps.ctCtAddInplace(m, acc, other);   // A2 ANSWER 5 的 CtCtAdd
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
     * 一共 {@code 1 + log₂(N/2)} 个步长（N=8192 时 13 个）。
     *
     * <p>⚠️ <b>2026-10-14 深夜更正一句自欺的注释</b>：这里原先写着
     * 「一共 {@code log₂N} 个 —— 与论文的 {@code for r = 0..log₂ℓ_BF−1} 轮数一致 ✓」。
     * <b>13 ≠ 5，不一致。</b> 那个 ✓ 把"密钥里的步长个数"与"折叠的轮数"当成了同一件事，
     * 结果是给"多折了 8 轮、噪声多 256 倍"盖了个章。折叠轮数现在由
     * {@link #foldSlots} 显式取 {@code ⌈log2 ℓ_BF⌉}。
     *
     * <p>步长集合本身仍然按 {@code log2(N/2)} 生成 —— 因为
     * {@link #foldAllSlots}（不知道 ℓ_BF 时的兜底）需要全套。
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

        // ---- 6. ℓ_BF ≪ N：论文形状的折叠（foldSlots）必须与"折满"等价 ----
        //
        // ⚠️ 这一段是 2026-10-14 深夜补的。上面 C1..C5 全把 query 铺满**全部** N 个槽
        //    （ℓ_BF = N），所以它们**测不到 ℓ_BF < N 的情形** —— 而那恰恰是折叠最容易错的一档：
        //    折少了会漏掉高位（论文那一行的 log2 ℓ_BF 就有这个毛病），
        //    折多了则纯粹涨噪声。这里用 ℓ_BF = 18 把两边钉在一起。
        System.out.println();
        System.out.println("---------------- 6. ℓ_BF = " + SMALL_LBF + " ≪ N：两种折叠必须等价 ----------------");
        {
            int lBf = SMALL_LBF;
            long[] qSmall = new long[slots];
            long[] cSmall = new long[slots];
            for (int i = 0; i < lBf; i += 3) {
                qSmall[i] = 1;                       // b_qry：置位 i = 0,3,6,…
            }
            long tauSmall = 0;
            for (int i = 0; i < lBf; i++) {
                cSmall[i] = (i % 3 == 0 || i % 5 == 0) ? 1 : 0;   // 候选：包含全部置位 + 额外位
                tauSmall += qSmall[i];
            }
            long naive = 0;
            for (int i = 0; i < lBf; i++) {
                naive += qSmall[i] * cSmall[i];
            }
            Ciphertext q = encryptBloomVector(m, qSmall);
            Ciphertext c = encryptBloomVector(m, cSmall);
            long folded = decodeScore(m, bloomScore(m, gk, q, c, lBf));      // ⌈log2 ℓ_BF⌉ 轮
            long allSlots = decodeScore(m, bloomScore(m, gk, q, c));         // 折满 N/2 槽
            check("折叠值 == 朴素内积（ℓ_BF = " + lBf + "）", folded == naive,
                "folded=" + folded + " naive=" + naive + " τ=" + tauSmall);
            check("foldSlots(lBf) 与 foldAllSlots 结果相同（等价性）", folded == allSlots,
                "foldSlots=" + folded + " foldAllSlots=" + allSlots);

            // 负对照：把 ℓ_BF 报小（少折两轮）⇒ **必须算错**，否则说明这一段没有证明力
            int tooSmall = lBf / 4;              // 4 < 18 ⇒ 只覆盖槽 [0,8)
            long underFolded = decodeScore(m, bloomScore(m, gk, q, c, tooSmall));
            check("[负对照] 把 ℓ_BF 报成 " + tooSmall + "（少折）⇒ 分数必须变小",
                underFolded < folded, "underFolded=" + underFolded + " folded=" + folded);
        }

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

    /** 断言（与 {@link #check(Mpc4jRgsw, BatchEncoder, GaloisKeys, Ciphertext, long[], long, String)} 并列）。 */
    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    /** Bloom 打分专项断言：既比分数，也确认"每个槽都相同"。 */
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
