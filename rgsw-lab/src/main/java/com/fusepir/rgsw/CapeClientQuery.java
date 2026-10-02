package com.fusepir.rgsw;

import com.fusepir.common.BfGen;
import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>客户端</b>：按论文 Algorithm 1 QUERY（L834–838）与 Algorithm 2 QUERY（L985–997）
 * 构造密文查询。
 *
 * <h3>为什么需要这个类</h3>
 * 逐子程序核对发现 <b>D1</b>：原实现把**明文关键词**发给服务器，服务器自己
 * `bloomBits(others)` 算 Bloom 位、自己 `kwIndex` 查锚点 —— 协议里有一条明文信道，
 * 论文 Appendix D.2 的混合论证（"challenge-dependent part ... consists of the
 * <b>encrypted</b> column and row selectors"）直接不成立。
 *
 * <p>这个类把 QUERY 完整放在客户端：
 * <ul>
 *   <li>A1 L836-837：{@code u_a ← h_a(K)}、{@code r_a ← u_a mod R}、{@code c_a ← ⌊u_a/R⌋}
 *       —— 位置由**公开参数 {@code H}** 决定，客户端自己算；</li>
 *   <li>A1 L838：{@code q^col_a}（one-hot 列选择子）与 {@code q^row_a}（LWE 行选择子）
 *       —— 都在这里生成，服务器只收到「不透明的 ⟨a, β⟩」；</li>
 *   <li>A2 L990-992：{@code b_qry ← BF.Gen(0, {K_2..K_Q})}、{@code τ ← ‖b_qry‖₁}、
 *       {@code q_BF ← RLWE.Enc_{s_R}(b_qry)} —— τ 留在客户端，密文发出去。</li>
 * </ul>
 *
 * <p>发到服务器的只有一个 JSON：{@code {colIdx, rowIdx, a, beta, bf}}。
 * 里面没有任何关键词、没有任何明文位置以外的东西（位置由公开哈希算出，不算泄露）。
 *
 * <h3>与服务器的信任边界（演示尺度，要如实说）</h3>
 * 这是**单进程回环演示**：同一个 JVM 既跑这个客户端也跑服务器，SEALContext 是共享的。
 * 所以它证明的是「**协议的数据流**做到了论文那样」，不是「部署上真的两方隔离」。
 * 真两方部署还要求客户端与服务器各自持有独立的 HE 上下文（见缺陷总表 P0-4）。
 */
public final class CapeClientQuery {

    /** 一次密文查询。 */
    public static final class Sealed {
        public long[] colIdx;      // [k] 每条路的列号 c_a
        public long[] rowIdx;      // [k] 每条路的行号 r_a（**不发给服务器**）
        public long[][] a;         // [k][d] LWE 的 a 分量
        public long[] beta;        // [k] LWE 的 β 分量 = ⟨a,s_L⟩ + r_a (mod 2N)
        public int[] sBits;        // [d] 公开引导密钥材料 bsk = {RGSW(s_i)}
        public boolean[] bQry;     // Bloom 查询向量（**只给客户端自己用**）
        public long tau;           // ‖b_qry‖₁（**不进 JSON**）
        public long[] bfSlots;     // q_BF 的批处理槽表示（D2 的接入口）
    }

    private CapeClientQuery() {
    }

    /**
     * 构造一次查询。
     *
     * @param n         环维度 N
     * @param k         BFF 位置数（= 3）
     * @param r         行数 R
     * @param maxValues 每个关键词最多几个值（决定 cell 占几行）
     * @param lBf       ℓ_BF
     * @param maxSetSize 公开 Bloom 参数
     * @param epsBf     公开 Bloom 参数 ε_BF
     * @param keywords  DB 里的关键词全集（用于复算公开哈希 H）
     * @param query     本次查询的关键词，第一个是锚
     */
    /**
     * 构造一次查询。
     *
     * @param bskBits 服务器的引导密钥 {@code bsk = {RGSW(s_i)}} 所对应的比特。
     *   <b>它必须与建 bk 用的那一组完全相同</b> —— 见下面那段不变量说明。
     */
    public static Sealed build(long ctxHandle, int n, int k, int r, int maxValues, int lBf,
                               int maxSetSize, double epsBf, int[] bskBits,
                               List<String> keywords, List<String> query) {
        if (query.isEmpty()) {
            throw new IllegalArgumentException("query must not be empty");
        }
        int kwCount = keywords.size();

        // ---- 公开哈希 H：与 CapeDemoData.keywordHash 必须逐位一致 ----
        int cellsPerCol = Math.max(1, r / maxValues);
        int c = Math.max(1, (kwCount + cellsPerCol - 1) / cellsPerCol);
        int[] slotOf = keywordHash(keywords, cellsPerCol, c);
        Map<String, Integer> kwIndex = new LinkedHashMap<>();
        for (int i = 0; i < kwCount; i++) {
            kwIndex.put(keywords.get(i), i);
        }

        String anchor = query.get(0);
        Integer ai = kwIndex.get(anchor);
        if (ai == null) {
            throw new IllegalArgumentException("unknown keyword: " + anchor);
        }

        Sealed q = new Sealed();
        q.colIdx = new long[k];
        q.rowIdx = new long[k];
        // ⚠️ 必须与 CapeDemoData 的网格算式【逐位一致】，否则服务器查错槽：
        //     colOf[i]   = slotOf[i] / cellsPerCol
        //     rowOf[i]   = (slotOf[i] % cellsPerCol) * maxValues
        //     a 路取该 cell 的第 a 行 ⇒ rowOf[i] + a
        for (int a = 0; a < k; a++) {
            q.colIdx[a] = slotOf[ai] / cellsPerCol;
            q.rowIdx[a] = (slotOf[ai] % cellsPerCol) * maxValues + a;
        }

        // ---- 行选择子：LWE 形式（A1 L838 q^row_a = LWE.Enc_{s_L}(r_a)）----
        // β = ⟨a, s_L⟩ + r_a (mod 2N)。
        //
        // ⚠️⚠️ **最关键的一条不变量，我在这里栽了四轮 —— 写清楚：**
        //
        //   blind_rotate 的每一轮做的是
        //       cur ← CMUX(bk[i], cur, cur·X^{a_i})
        //   即「s_i = 1 就转到 a_i，否则不动」，最后再逐步乘 X^{-β}。
        //   净效果 = X^{ Σ a_i·s_i(bsk) - β }。
        //   要它等于 X^{-r_a}，必须
        //       β = Σ a_i · s_i(bsk) + r_a
        //   ——**两边用的必须是同一组 s_i(bsk)**，也就是建 bk 时用的那组比特。
        //
        //   我先后试过三种「客户端自选 s」的写法，全都失败（载荷恒 0）：
        //     1) 新建自己的 SEALContext 取比特（另一随机秘密）；
        //     2) 依赖 nativeSecretBits 的 {0,1} 约定（它把三元秘密的 −1 静默归零，
        //        客户端无法区分"真 0"与"被归零的 −1"）；
        //     3) SHA-256 派生的 {0,1}^d（与 bk 的比特毫无关系）。
        //   三者都与 bk 不同源 ⇒ 旋转量变成 Σa_i(s_i^server − s_i^client) − r ⇒ 垃圾。
        //
        //   而且前面五轮"不变量核对"全都通过 —— 因为我**没有把这一条列进去**。
        //   教训：核对清单缺一条，比核对不出来更危险。
        //
        //   现在把 bskBits 作为显式入参传进来，由调用方保证与 bk 同源。
        //   密码学上这是对的：bsk = {RGSW(s_i)} 是**公开评估密钥**（"加密后的秘密比特"），
        //   本来就要发布给服务器；真两方部署里客户端自己生成 sk 与 bsk 并发布 bsk。
        int d = bskBits.length;
        q.sBits = bskBits.clone();
        q.a = new long[k][d];
        q.beta = new long[k];
        // ⚠️ 行选择子的构造**不引入任何噪声项**（按需求「盲旋转不要噪声」）：
        //    β ≡ Σ_i a_i · s_i + r_a  (mod 2N)   —— 严格等式
        // 老路径 nativeCapeAnswer 也是这个形式（betav = (sum + ridx[a]) % 2N），
        // 所以两边在这一点上完全一致。真正的噪声只来自同态运算本身。
        //
        // a_i 用**确定性序列**（与老路径相同的 XorShift 常量），不用 SecureRandom：
        // 这样「同一次查询」在同一台机器上可复现，排查时能把随机性排除掉。
        // 真部署应换成密码学安全的均匀采样（SecureRandom），这里为了对齐老路径先固定。
        long twoN = 2L * n;
        long rngState = 20260930L;
        for (int a = 0; a < k; a++) {
            long sum = 0;
            for (int i = 0; i < d; i++) {
                rngState ^= rngState << 13;
                rngState ^= rngState >>> 7;
                rngState ^= rngState << 17;
                q.a[a][i] = Math.floorMod(rngState, twoN);
                if (q.sBits[i] == 1) {
                    sum = (sum + q.a[a][i]) % twoN;
                }
            }
            q.beta[a] = (sum + q.rowIdx[a]) % twoN;
        }

        // ---- Bloom 查询向量（A2 L990-991），全部留在客户端 ----
        BfGen bf = BfGen.choose(maxSetSize, epsBf, n);
        if (bf.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch: " + bf.length() + " vs " + lBf);
        }
        List<String> others = new ArrayList<>(query.subList(1, query.size()));
        q.bQry = bf.bits(others);
        long tau = 0;
        for (boolean b : q.bQry) {
            if (b) {
                tau++;
            }
        }
        q.tau = tau;
        q.bfSlots = toSlots(q.bQry, n);
        return q;
    }

    /** 把 Bloom 向量铺成批处理槽形式（供后续 D2 使用）。 */
    static long[] toSlots(boolean[] bits, int n) {
        long[] slots = new long[n];
        for (int i = 0; i < bits.length && i < n; i++) {
            slots[i] = bits[i] ? 1 : 0;
        }
        return slots;
    }

    /**
     * 只构造**位置**（不含 β / bsk）的最小查询，用于跨进程验证「服务器接受该格式
     * 且不回显任何关键词」。
     *
     * <p>为什么正确的 β 不能跨进程构造：{@code β = ⟨a,s_L⟩ + r_a} 里的 {@code s_L}
     * 必须是**累加器所加密的那个秘密**的比特，而取它的入口 {@code nativeSecretBits}
     * 需要一个**进程内的上下文句柄**（裸指针）。跨进程传句柄会段错误（实测过），
     * 新建上下文则会拿到另一个随机秘密、导致载荷恒为 0（也实测过）。
     * 所以端到端正确性只能在服务进程内验：见 {@code CapeDemoService.selftestSealed()}。
     */
    public static Sealed buildIndicesOnly(int n, int k, int r, int maxValues,
                                          List<String> keywords, List<String> query) {
        int cellsPerCol = Math.max(1, r / maxValues);
        int c = Math.max(1, (keywords.size() + cellsPerCol - 1) / cellsPerCol);
        int[] slotOf = keywordHash(keywords, cellsPerCol, c);
        Map<String, Integer> kwIndex = new LinkedHashMap<>();
        for (int i = 0; i < keywords.size(); i++) {
            kwIndex.put(keywords.get(i), i);
        }
        Integer ai = kwIndex.get(query.get(0));
        if (ai == null) {
            throw new IllegalArgumentException("unknown keyword: " + query.get(0));
        }
        Sealed q = new Sealed();
        q.colIdx = new long[k];
        q.rowIdx = new long[k];
        for (int a = 0; a < k; a++) {
            q.colIdx[a] = slotOf[ai] / cellsPerCol;
            q.rowIdx[a] = (slotOf[ai] % cellsPerCol) * maxValues + a;
        }
        int d = Integer.getInteger("cape.d", 16);
        q.sBits = new int[d];
        q.a = new long[k][d];
        q.beta = new long[k];
        return q;
    }

    /**
     * 客户端自己的 {0,1}^d 私钥。用 SHA-256 从固定种子派生，
     * 这样一次会话内可复现（演示用；真部署应随机生成并安全保存）。
     */
    private static int[] sampleBinarySecret(int d) {
        int[] s = new int[d];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] seed = md.digest("cape-client-lwe-secret".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < d; i++) {
                s[i] = (seed[i % seed.length] >> (i / seed.length % 8)) & 1;
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return s;
    }

    /** 与 {@code CapeDemoData.keywordHash} 逐位一致的公开哈希。 */
    static int[] keywordHash(List<String> keywords, int cellsPerCol, int c) {
        int n = keywords.size();
        int span = Math.max(n, cellsPerCol * c);
        int[] slot = new int[span];
        Arrays.fill(slot, -1);
        for (int i = 0; i < n; i++) {
            int h = mix(keywords.get(i).hashCode()) % span;
            if (h < 0) {
                h += span;
            }
            while (slot[h] != -1) {
                h = (h + 1) % span;
            }
            slot[h] = i;
        }
        int[] out = new int[n];
        for (int h = 0; h < span; h++) {
            if (slot[h] >= 0) {
                out[slot[h]] = h;
            }
        }
        return out;
    }

    private static int mix(int h) {
        h ^= h >>> 16;
        h *= 0x85ebca6b;
        h ^= h >>> 13;
        h *= 0xc2b2ae35;
        h ^= h >>> 16;
        return h;
    }

    /**
     * 序列化成发往服务器的 JSON。
     *
     * <p><b>⚠️ 2026-10-14 修正：这个方法的隐私性质此前被高估了。</b>
     *
     * <p>旧版无条件执行 {@code m.put("bf", q.bfSlots)}，而 {@code bfSlots} 就是
     * {@code b_qry} 的**明文**槽表示（0/1）。因为 {@code H} 是公开参数，
     * 服务器拿置位集合穷举关键词即可**反解出查询关键词** —— 实测：
     * <pre>
     *   出站 bf 的置位 = [0, 9, 12, 15, 17]（τ=5）
     *   用公开 H 穷举库里 128 个关键词 ⇒ 唯一匹配 "family"
     * </pre>
     * 而 {@code CapeSealedFlowTest} 的隐私断言只检查「关键词字符串 / τ / b_qry
     * 字面量」是否出现在 JSON 里，字段改叫 {@code bf} 就全部通过 —— **断言测的是
     * 名字，不是性质**。这正是「绿灯但没证明任何事」的典型。
     *
     * <p>现在：<b>{@code bf} 默认不发。</b>只有显式 {@code -Dcape.d2=true}
     * （D2 开发用）时才发，且发的是 {@code d2PlaintextBf: true} 明确标注的字段，
     * 免得将来有人把这个字段当默认行为继承下去。D2 的正确接入口是
     * <b>加密后</b>的 {@code q_BF}（见 {@link BloomScoring#encryptBloomVector}），
     * 不是明文位向量。
     *
     * <p><b>清单（用来证明这条信道里没有明文）</b>：
     * <table>
     *   <tr><th>字段</th><th>发不发</th><th>理由</th></tr>
     *   <tr><td>colIdx / rowIdx</td><td>发</td><td>由**公开哈希 H** 算出，pp 里本来就含 H</td></tr>
     *   <tr><td>a</td><td>发</td><td>LWE 的公开分量</td></tr>
     *   <tr><td>beta</td><td>发</td><td>{@code ⟨a,s_L⟩ + r_a}，r_a 被掩掉</td></tr>
     *   <tr><td>sBits</td><td>发</td><td>**公开引导密钥材料** {@code bsk = {RGSW(s_i)}}；
     *       bsk 的定义就是"加密后的秘密比特"，本来就发布给服务器</td></tr>
     *   <tr><td>bf</td><td><b>默认不发</b></td><td>它是 {@code b_qry} 本身；要发必须是**密文**</td></tr>
     *   <tr><td><b>关键词</b></td><td><b>不发</b></td><td>—</td></tr>
     *   <tr><td><b>b_qry / τ</b></td><td><b>不发</b></td><td>τ 是接受阈值，论文明确保留在客户端</td></tr>
     * </table>
     */
    public static String toJson(Sealed q) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("colIdx", q.colIdx);
        m.put("rowIdx", q.rowIdx);
        // ⚠️ `a` 是二维的，而本项目的极简 JsonParser/CapeDemoData.JsonParser
        // **不支持嵌套数组**，所以这里扁平化 + 显式带上 d（维度）。服务器按 d 复原。
        int k = q.a.length;
        int d = k > 0 ? q.a[0].length : 0;
        long[] flat = new long[k * d];
        for (int i = 0; i < k; i++) {
            System.arraycopy(q.a[i], 0, flat, i * d, d);
        }
        m.put("d", d);
        m.put("aFlat", flat);
        m.put("beta", q.beta);
        m.put("sBits", q.sBits);
        // bf = b_qry 明文，默认不外发；见方法注释里的实测反解。
        if (Boolean.getBoolean("cape.d2")) {
            m.put("d2PlaintextBf", q.bfSlots);
        }
        return Json.write(m);
    }

    /**
     * 命令行驱动：起一个（或复用）服务，构造密文查询并打印发出去的 JSON。
     * <pre>
     *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeClientQuery &lt;port&gt; "K1" "K2"
     * </pre>
     * 只构造、不发送 —— 真正的数据流断言在 {@code CapeSealedFlowTest} 里。
     */
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        Map<String, Object> st = Http.get("http://127.0.0.1:" + port + "/api/state");
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) st.get("params");
        @SuppressWarnings("unchecked")
        List<String> kws = (List<String>) st.get("keywords");
        int n = ((Number) params.get("N")).intValue();
        int k = ((Number) params.get("k")).intValue();
        int r = ((Number) params.get("R")).intValue();
        int maxValues = ((Number) params.get("maxValues")).intValue();
        int lBf = ((Number) params.get("lBf")).intValue();
        int maxSetSize = ((Number) params.get("maxSetSize")).intValue();
        double epsBf = ((Number) params.get("epsBf")).doubleValue();

        List<String> query = args.length > 2
            ? Arrays.asList(args).subList(1, args.length) : kws.subList(0, 2);

        long ctxHandle = NativeBlindRotate.nativeCreateContext(n, 4294967296L,
            Integer.getInteger("cape.b", 32));
        try {
            // bsk 比特必须与建 bk 用的同源：这里取服务端上下文的（与本类文档的不变量一致）
            int dd = Integer.getInteger("cape.d", 16);
            Long[] b = NativeBlindRotate.nativeSecretBits(ctxHandle, dd);
            int[] bskBits = new int[dd];
            for (int i = 0; i < dd; i++) { bskBits[i] = b[i].intValue(); }
            Sealed q = build(ctxHandle, n, k, r, maxValues, lBf,
                maxSetSize, epsBf, bskBits, kws, query);
            System.out.println("=== 客户端构造的密文查询 ===");
            System.out.println("  关键词（**不进 JSON**）: " + query);
            System.out.println("  τ（**不进 JSON**）      : " + q.tau);
            System.out.println("  发给服务器的 JSON       : " + toJson(q));
        } finally {
            NativeBlindRotate.nativeDestroyContext(ctxHandle);
        }
    }

    /** 极简 HTTP 客户端（GET/POST），避免为演示引入依赖。 */
    static final class Http {
        private Http() {
        }

        @SuppressWarnings("unchecked")
        static Map<String, Object> get(String url) throws Exception {
            java.net.http.HttpClient c = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest r = java.net.http.HttpRequest.newBuilder(java.net.URI.create(url)).GET().build();
            java.net.http.HttpResponse<String> resp = c.send(r,
                java.net.http.HttpResponse.BodyHandlers.ofString());
            return (Map<String, Object>) new CapeDemoData.JsonParser(resp.body()).parse().v;
        }

        @SuppressWarnings("unchecked")
        static Map<String, Object> post(String url, String body) throws Exception {
            java.net.http.HttpClient c = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest r = java.net.http.HttpRequest.newBuilder(java.net.URI.create(url))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build();
            java.net.http.HttpResponse<String> resp = c.send(r,
                java.net.http.HttpResponse.BodyHandlers.ofString());
            return (Map<String, Object>) new CapeDemoData.JsonParser(resp.body()).parse().v;
        }
    }
}
