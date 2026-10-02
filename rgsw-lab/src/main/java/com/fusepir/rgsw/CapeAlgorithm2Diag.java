package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>CAPE Algorithm 2 的跨进程验收探针</b>：出站隐私 + 响应结构 + 坐标泄露，
 * 外加（在拿到打分密钥时）整条密文判定的正确性断言。
 *
 * <h3>论文依据（逐行）</h3>
 * <pre>
 *   A2 QUERY 2-3 : b_qry <- BF.Gen(0, {K_2..K_Q}) ;  tau <- ||b_qry||_1
 *   A2 ANSWER 2  : resp_anc <- FusePIR.Answer(st_S^F, q_anc)
 *   A2 ANSWER 4  : ct_score,j <- CtCtMul(q_BF, ct_{B^F_j})
 *   A2 ANSWER 6-7: for r = 0..log2(l_BF)-1: ct_score,j <- CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
 *   A2 ANSWER 8  : resp <- ({ct_{v_j}, ct_score,j})_j
 *   A2 DECODE 3-4: if f != fp(K) then return bot
 *   A2 DECODE 8-9: s_j <- Dec(ct_score,j) ; if s_j = tau then R <- R union {v_j}
 * </pre>
 *
 * <h3>本类与另外两个测试的分工（别互相替代）</h3>
 * <table border="1">
 *   <tr><th>测试</th><th>验什么</th><th>为什么只能在那个位置验</th></tr>
 *   <tr><td>{@code CapeDefaultPathTest}</td>
 *       <td>默认路径 <b>跨进程</b>：出站白名单 + 字节往返 + 判定 + 5 条负对照</td>
 *       <td>需要客户端持有<b>与服务端同一把</b>打分 sk（{@code -Dcape.insecure.keyecho=true}）</td></tr>
 *   <tr><td>{@code CapeDemoService.selftestCape()}</td>
 *       <td>同上，但<b>在服务进程内</b>跑，<b>不需要</b>任何后门</td>
 *       <td>打分 sk 与 native ctxHandle 都在进程内 —— 这是<b>推荐的正确性验收入口</b></td></tr>
 *   <tr><td><b>本类</b></td>
 *       <td>不需要密钥就能验的那些：出站隐私、响应结构自述、<b>N5 坐标泄露</b></td>
 *       <td>这些是纯数据流/数学事实，跨进程与进程内结论相同</td></tr>
 * </table>
 *
 * <h3>⚠️ 四个必须一起说的口径差（不要省略）</h3>
 * <ol>
 *   <li><b>打分信道的 {@code t} 与 native 信道不同</b>：{@code 2³²} 下
 *       {@code BatchEncoder} 根本构造不出来（实测 {@link CapeScoreChannelProbe}），
 *       所以打分跑在 {@code t = 65537}。两条信道各持一把独立密钥。</li>
 *   <li><b>D2 仍在</b>：{@code ct_{B^F_j}} 不是"检索出来的那条密文"，而是服务端
 *       把解出来的 Bloom 位重新编成的槽位密文。真障碍见 {@link CapeBloomScore} 的类注释。</li>
 *   <li><b>N5 未修</b>：sealed 路径的 {@code (c_a, r_a)} 对服务器可还原（见下）。</li>
 *   <li><b>行索引噪声按项目决定不引入</b>（偏差 D1）—— 本轮特意没碰。</li>
 * </ol>
 *
 * <p>跑法（需先起服务）：
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeAlgorithm2Diag 8756
 *   # 想连正确性一起验，服务端加 -Dcape.selftest=true 看 selftestCape；
 *   # 或本类加 -Dcape.insecure.keyecho=true + CapeDefaultPathTest
 * </pre>
 */
public final class CapeAlgorithm2Diag {

    private CapeAlgorithm2Diag() {
    }

    /** 一条候选的应答：论文 A2 ANSWER 8 的 {@code (ct_{v_j}, ct_score,j)}（服务端侧）。 */
    public static final class Cand {
        public final int valueId;
        public final long[] bloomBits;
        public final edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext ctBloom;
        public final edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext ctScore;

        Cand(int valueId, long[] bloomBits,
             edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext ctBloom,
             edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext ctScore) {
            this.valueId = valueId;
            this.bloomBits = bloomBits;
            this.ctBloom = ctBloom;
            this.ctScore = ctScore;
        }
    }

    /** 服务器侧 ANSWER 的产物（论文 A2 的 {@code resp}）。 */
    public static final class Answer {
        public final long fingerprint;
        public final int valueCount;
        /** **每候选一组**（P0-2 的落点）。 */
        public final List<Cand> candidates;
        /** 服务端为对照顺手解出来的槽值。**判定不读它**，只用来对拍。 */
        public final long[] serverPlainScore;
        public final long scoreMs;

        Answer(long fingerprint, int valueCount, List<Cand> candidates,
               long[] serverPlainScore, long scoreMs) {
            this.fingerprint = fingerprint;
            this.valueCount = valueCount;
            this.candidates = candidates;
            this.serverPlainScore = serverPlainScore;
            this.scoreMs = scoreMs;
        }
    }

    /**
     * 服务端 ANSWER：native 锚检索 -> 按候选分组 -> 打包成一条槽位密文 -> 同态打分。
     *
     * <p>生产路径在 {@code CapeDemoService.answerCape}（它持有打分信道与 native 上下文）；
     * 这个方法保留给进程内自检用。
     */
    public static Answer answer(CapeBloomScore.Scorer sc,
                                edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext qBF,
                                long[] payload, int maxCandidates, int lBf) {
        CapeBloomScore.Result r = CapeBloomScore.score(sc, qBF, payload, maxCandidates, lBf);
        List<Cand> cands = new ArrayList<>();
        for (CapeBloomScore.Candidate c : r.candidates) {
            cands.add(new Cand(c.valueId, c.bloomBits, c.ctBloom, c.ctScore));
        }
        return new Answer(CapeBloomScore.fingerprintOf(payload), (int) payload[1],
            cands, r.plainScoreSlots, r.scoreMs);
    }

    // ------------------------------------------------------------------
    //  客户端 DECODE
    // ------------------------------------------------------------------

    /** 解密一条 {@code ct_score,j} 得到 {@code s_j}（客户端侧动作）。 */
    public interface ScoreDecryptor {
        long decrypt(edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext ctScore);
    }

    /** 客户端 DECODE 的产物。 */
    public static final class DecodeResult {
        public final boolean fingerprintOk;
        public final List<Integer> accepted;
        public final List<Long> scores;
        public final String verdict;
        /**
         * 判定过程中是否有密文<b>反序列化失败</b>（字节坏了）。
         *
         * <p>不为 {@code false} 本身不是错误：客户端必须能对"服务器回了一段坏字节"做出决断，
         * 所以坏的那条按<b>拒绝</b>处理、并把这件事记下来。负对照 N1 会用到它。
         */
        public boolean loadFailed;

        DecodeResult(boolean fingerprintOk, List<Integer> accepted, List<Long> scores,
                     String verdict) {
            this.fingerprintOk = fingerprintOk;
            this.accepted = accepted;
            this.scores = scores;
            this.verdict = verdict;
        }
    }

    /**
     * 论文 A2 DECODE 3-4 + 8-9 的完整实现（<b>进程内对象版</b>）。
     *
     * <p><b>签名里只有密文</b>：明文分数没有入参 —— 这是刻意的，只要明文能传进来，
     * "判定走密文"就随时可能被悄悄绕过。要走字节的那一版见
     * {@code CapeDefaultPathTest.decode}。
     */
    public static DecodeResult decode(List<edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext> ctScores,
                                      List<Integer> valueIds, long fpWant, long fGot, long tau,
                                      ScoreDecryptor dec) {
        // ---- DECODE 3-4: f != fp(K) => bot（P0-4）----
        if (fGot != fpWant) {
            return new DecodeResult(false, new ArrayList<>(), new ArrayList<>(),
                "f=" + fGot + " != fp(K)=" + fpWant + " => 返回 bot（整条答案作废）");
        }
        // ---- DECODE 8-9: s_j = Dec(ct_score,j) ; 相等才收（P0-3）----
        List<Integer> accepted = new ArrayList<>();
        List<Long> scores = new ArrayList<>();
        for (int j = 0; j < ctScores.size(); j++) {
            long sj = dec.decrypt(ctScores.get(j));
            scores.add(sj);
            if (sj == tau) {
                accepted.add(valueIds.get(j));
            }
        }
        return new DecodeResult(true, accepted, scores,
            "指纹校验通过；逐候选比 Dec(ct_score) 与 tau");
    }

    // ------------------------------------------------------------------
    //  自检 / 端到端
    // ------------------------------------------------------------------

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        String base = "http://127.0.0.1:" + port;

        System.out.println("=== CAPE Algorithm 2 跨进程验收探针 ===");

        Map<String, Object> st = CapeClientQuery.Http.get(base + "/api/state");
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) st.get("params");
        @SuppressWarnings("unchecked")
        Map<String, Object> proto = (Map<String, Object>) st.get("protocol");
        @SuppressWarnings("unchecked")
        Map<String, Object> insecure = (Map<String, Object>) st.get("insecureTestOnly");
        int n = ((Number) params.get("N")).intValue();
        int lBf = ((Number) params.get("lBf")).intValue();
        int maxSetSize = ((Number) params.get("maxSetSize")).intValue();
        double epsBf = ((Number) params.get("epsBf")).doubleValue();
        long nativeT = ((Number) params.get("t")).longValue();
        long scoreT = ((Number) params.get("scoreT")).longValue();
        System.out.printf("[server] N=%d l_BF=%d nativeT=%d scoreT=%d scoreReady=%s%n",
            n, lBf, nativeT, scoreT, params.get("scoreReady"));
        check("两条信道的 t 确实不同（口径差，必须写进报告）", nativeT != scoreT,
            "nativeT=" + nativeT + " scoreT=" + scoreT);
        check("服务端自述了默认路径与判定方式",
            proto != null && String.valueOf(proto.get("defaultPathDecision")).contains("ct_score"),
            proto == null ? "protocol 字段缺失" : String.valueOf(proto.get("defaultPath")));

        // ---------- 客户端 QUERY ----------
        @SuppressWarnings("unchecked")
        Map<String, Object> pool = CapeClientQuery.Http.get(base + "/api/pool");
        @SuppressWarnings("unchecked")
        List<Object> pairs = (List<Object>) pool.get("pool");
        @SuppressWarnings("unchecked")
        Map<String, Object> firstPair = (Map<String, Object>) pairs.get(0);
        @SuppressWarnings("unchecked")
        List<String> query = new ArrayList<>((List<String>) firstPair.get("kws"));

        System.out.println();
        System.out.println("---------------- 1. 客户端 QUERY（b_qry 只在客户端）----------------");
        com.fusepir.common.BfGen bf = com.fusepir.common.BfGen.choose(maxSetSize, epsBf, n);
        if (bf.length() != lBf) {
            throw new IllegalStateException("l_BF mismatch: " + bf.length() + " vs " + lBf);
        }
        boolean[] bQry = bf.bits(query.subList(1, query.size()));
        long tau = 0;
        for (boolean b : bQry) {
            if (b) {
                tau++;
            }
        }
        System.out.println("  查询（来自公开池子，不是隐私）: " + query);
        System.out.printf("  tau = ||b_qry||_1 = %d（**从不进入任何响应**）%n", tau);
        System.out.println("  b_qry 置位下标 = " + setBits(bQry));

        // ---------- 5b. N5：坐标泄露（不依赖任何密钥，先跑）----------
        System.out.println();
        System.out.println("---------------- 2. N5 坐标泄露：一条路径的隐私断言不成立（据实记录）----------------");
        {
            System.out.println("  说明：nativeCapeAnswerSealed 的入参 a / beta / sBits 全在服务器手上，");
            System.out.println("        所以「服务器看不到 r_a」这句话没有机制支撑。下面用真实形状的查询验证：");
            int dLwe = Integer.getInteger("cape.d", 16);
            CapeClientQuery.Sealed demo = new CapeClientQuery.Sealed();
            demo.sBits = new int[dLwe];
            demo.a = new long[1][dLwe];
            demo.beta = new long[1];
            demo.rowIdx = new long[]{7};
            demo.colIdx = new long[]{5};
            java.util.Random rnd = new java.util.Random(20261014L);
            long twoN = 2L * n;
            long sum = 0;
            for (int i = 0; i < dLwe; i++) {
                demo.sBits[i] = rnd.nextBoolean() ? 1 : 0;
                demo.a[0][i] = Math.floorMod(rnd.nextLong(), twoN);
                if (demo.sBits[i] == 1) {
                    sum = (sum + demo.a[0][i]) % twoN;
                }
            }
            demo.beta[0] = (sum + demo.rowIdx[0]) % twoN;   // 与 CapeClientQuery.build 同一个式子
            StringBuilder sb = new StringBuilder();
            boolean leaked = demonstrateCoordinateRecovery(demo, twoN, sb);
            System.out.print(sb);
            check("N5 服务器能从 (a, beta, sBits) 一步还原 r_a（⇒ 该隐私断言不成立）",
                leaked, "这一步不需要任何密码学分析：r_a = beta - <a,sBits>");
            System.out.println("       ⇒ 据实结论：sealed 路径的 (c_a, r_a) 对服务器都是可还原的。");
            System.out.println("         整改归 P1-1（列选择子改客户端加密）与 P1-2（行选择子加噪声）。");
        }

        // ---------- 正确性：需要与服务端同一把打分 sk ----------
        if (insecure == null) {
            System.out.println();
            System.out.println("---------------- 3. 正确性断言：本进程拿不到打分 sk，跳过 ----------------");
            System.out.println("  [note] ct_score 要用**与服务端同一把**打分 sk 才解得出来。");
            System.out.println("         跨进程验它有两种方式（任选其一）：");
            System.out.println("           (a) 服务端加 -Dcape.insecure.keyecho=true，然后跑");
            System.out.println("               .\\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDefaultPathTest 8756");
            System.out.println("           (b) 服务端加 -Dcape.selftest=true，看进程内的 selftestCape()");
            System.out.println("        那两条都会验：Dec(ct_score) == tau、f == fp(K)、以及 5 条负对照。");
            System.out.println("        本进程只验不需要密钥的那部分（上面第 2 节 + 下面第 3 节）。");
            structuralChecks(base, n, lBf, bQry, tau, query, st, params);
            finish();
            return;
        }

        // 拿到 sk：整条判定都能验了
        @SuppressWarnings("unchecked")
        List<Object> skBytes = (List<Object>) insecure.get("insecureScoreSecretKeyBytes");
        long[] skWire = new long[skBytes.size()];
        for (int i = 0; i < skWire.length; i++) {
            skWire[i] = ((Number) skBytes.get(i)).longValue();
        }
        CapeBloomScore.Scorer tmp = CapeBloomScore.setup(n);
        SecretKey sharedSk = CapeScorerWire.deserializeKey(tmp, skWire);
        CapeBloomScore.Scorer sc = CapeBloomScore.setup(n, sharedSk);
        System.out.println();
        System.out.println("---------------- 3. 完整判定（已取到服务端那把打分 sk）----------------");
        System.out.printf("  [scorer] 槽数=%d（sk 与服务端同一把）%n%n", sc.slots);

        long[] qbfWire = CapeBloomScore.encryptQueryWire(sc, bQry);
        System.out.printf("  q_BF 密文 %d 字节（%.1f KB）%n", qbfWire.length, qbfWire.length / 1024.0);
        Map<String, Object> resp = postSealedQuery(base, qbfWire, lBf);
        if (resp == null || !Boolean.TRUE.equals(resp.get("ok"))) {
            check("默认路径接受 q_BF 密文", false,
                resp == null ? "无响应" : String.valueOf(resp.get("error")));
            finish();
            return;
        }
        check("默认路径接受 q_BF 密文（sealed=true）", Boolean.TRUE.equals(resp.get("sealed")),
            "sealed=" + resp.get("sealed"));

        long fGot = ((Number) resp.get("fingerprint")).longValue();
        List<Integer> valueIds = new ArrayList<>();
        List<long[]> ctScores = new ArrayList<>();
        @SuppressWarnings("unchecked")
        List<Object> cands = (List<Object>) resp.get("candidates");
        for (Object o : cands) {
            @SuppressWarnings("unchecked")
            Map<String, Object> one = (Map<String, Object>) o;
            @SuppressWarnings("unchecked")
            List<Object> bytes = (List<Object>) one.get("ctScoreBytes");
            long[] w = new long[bytes.size()];
            for (int i = 0; i < w.length; i++) {
                w[i] = ((Number) bytes.get(i)).longValue();
            }
            ctScores.add(w);
        }
        // 候选值由**客户端**从 ctPay 自己解出（不再由服务器发 id）—— 论文 §4.1 要求
        // "Only the encrypted candidate values and these scores are returned to the client."
        valueIds.addAll(CapeDefaultPathTest.decodePayload(resp));
        check("P0-2 每候选各带自己的 ct_score 字节（条数与 V_K1 一致）", !valueIds.isEmpty()
            && ctScores.size() == valueIds.size(), "V_K1=" + valueIds);

        long fpWant = fpOf(query.get(0), nativeT);
        DecodeResult dr = CapeDefaultPathTest.decode(sc, ctScores, valueIds, fpWant, fGot, tau, 0);
        System.out.printf("  fp(K)=%d  f=%d  => %s%n", fpWant, fGot, dr.verdict);
        check("P0-4 指纹校验（f == fp(K)）通过", dr.fingerprintOk, "");
        for (int j = 0; j < dr.scores.size(); j++) {
            System.out.printf("       候选 v=%d : Dec(ct_score)=%d  %s%n", valueIds.get(j),
                dr.scores.get(j), dr.scores.get(j) == tau ? "== tau => 接受" : "< tau => 拒绝");
        }
        check("P0-3 判定只读 Dec(ct_score)，且至少接受一条", !dr.accepted.isEmpty(),
            "接受=" + dr.accepted);
        List<Integer> wantValues = groundTruth(dbPath(), query);
        check("接受的候选与明文真值完全一致", !wantValues.isEmpty()
            && sameSet(wantValues, dr.accepted),
            "accepted=" + dr.accepted + " want=" + wantValues);

        // 负对照
        List<long[]> broken = new ArrayList<>();
        for (long[] w : ctScores) {
            long[] b2 = w.clone();
            Arrays.fill(b2, 0L);
            broken.add(b2);
        }
        DecodeResult d1 = CapeDefaultPathTest.decode(sc, broken, valueIds, fpWant, fGot, tau, 0);
        check("N1 把 ct_score 字节置零 => 判定一条都不接受（验收定义第 2 条）",
            d1.accepted.isEmpty(), "接受=" + d1.accepted);
        DecodeResult d2 = CapeDefaultPathTest.decode(sc, ctScores, valueIds, fpWant + 1, fGot, tau, 0);
        check("N2 指纹故意用错 => 返回 bot、不给任何值", !d2.fingerprintOk && d2.accepted.isEmpty(),
            d2.verdict);
        DecodeResult d3 = CapeDefaultPathTest.decode(sc, ctScores, valueIds, fpWant, fGot, tau + 1, 0);
        check("N3 把 tau 改错 => 接受集合必须变", !d3.accepted.equals(dr.accepted),
            "tau=" + tau + " -> " + dr.accepted + "；tau+1 -> " + d3.accepted);

        finish();
    }

    private static void finish() {
        System.out.println();
        System.out.println(failed == 0
            ? "=== ALL CHECKS PASSED ==="
            : "=== " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 不需要密钥的那些断言：出站白名单 + 响应结构自述。 */
    private static void structuralChecks(String base, int n, int lBf, boolean[] bQry, long tau,
                                         List<String> query, Map<String, Object> st,
                                         Map<String, Object> params) {
        System.out.println();
        System.out.println("---------------- 4. 响应结构自述（不需要密钥）----------------");
        @SuppressWarnings("unchecked")
        Map<String, Object> proto = (Map<String, Object>) st.get("protocol");
        System.out.println("  defaultPath        = " + proto.get("defaultPath"));
        System.out.println("  判定               = " + proto.get("defaultPathDecision"));
        System.out.println("  qBFBytes 从哪来    = " + proto.get("qbfBytesFrom"));
        System.out.println("  回包判定字段       = " + proto.get("responseDecisionFields"));
        check("服务端回包字段里确实带 ctScoreBytes",
            String.valueOf(proto.get("responseDecisionFields")).contains("ctScoreBytes"), "");
        check("服务端明确区分了 legacy 路径（明文合取）",
            String.valueOf(proto.get("legacyPath")).contains("keywords"), "");
    }

    /** 发一条 sealed 请求（q_BF 密文字节）。 */
    static Map<String, Object> postSealedQuery(String base, long[] qbfWire, int lBf)
        throws Exception {
        StringBuilder sb = new StringBuilder("{\"d\":" + lBf + ",\"qBFBytes\":[");
        for (int i = 0; i < qbfWire.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(qbfWire[i]);
        }
        sb.append("]}");
        return CapeClientQuery.Http.post(base + "/api/query", sb.toString());
    }

    /**
     * <b>N5：坐标泄露的可执行演示（未修）</b>。
     *
     * <p>{@code nativeCapeAnswerSealed} 的 javadoc 一直写着"服务器看不到 r_a"。
     * <b>这句话不成立</b>，而且不需要任何密码学分析就能证明：
     * 服务器收到的三样东西 {@code a}、{@code beta}、{@code sBits} 全是它自己算得出
     * {@code <a,sBits>} 的（{@code a} 与 {@code sBits} 都是明文入参），于是
     * <pre>
     *   r_a = beta - &lt;a, sBits&gt;   (mod 2N)
     * </pre>
     * 一步就还原。再加上 {@code colIdx} 本来就是明文列号，
     * {@code (c_a, r_a)} <b>两者都落在服务器手里</b>。
     *
     * <p>整改属于 P1-1（列选择子改客户端加密）与 P1-2（行选择子加噪声），本轮未做。
     *
     * @return true 表示"坐标确实可以被还原"（即漏洞存在）
     */
    public static boolean demonstrateCoordinateRecovery(CapeClientQuery.Sealed q, long twoN,
                                                        StringBuilder out) {
        boolean leaked = true;
        for (int a = 0; a < q.beta.length; a++) {
            long sum = 0;
            for (int i = 0; i < q.sBits.length; i++) {
                if (q.sBits[i] == 1) {
                    sum = (sum + q.a[a][i]) % twoN;
                }
            }
            long recovered = Math.floorMod(q.beta[a] - sum, twoN);
            boolean ok = recovered == Math.floorMod(q.rowIdx[a], twoN);
            leaked &= ok;
            out.append("       路 ").append(a)
                .append(": 服务器算出的 r_a=").append(recovered)
                .append("  客户端真的 r_a=").append(q.rowIdx[a])
                .append(ok ? "  <- 完全一致" : "  （不一致）")
                .append("；c_a=").append(q.colIdx[a]).append("（本来就明文）\n");
        }
        return leaked;
    }

    /** 服务端侧：把候选 j 的 Bloom 段编成一条槽位密文 {@code ct_BF_j}（A2 ANSWER 4）。 */
    static edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext encryptBloomSegment(
        CapeBloomScore.Scorer sc, long[] bits) {
        return BloomScoring.encryptBloomVector(sc.m, CapeBloomScore.padToSlots(bits, sc.slots));
    }

    /**
     * 客户端本地的明文真值：各查询关键词值集合的<b>交集</b>。
     *
     * <p>客户端本来就有 K 与 DB 的明文侧（它要算 {@code fp(K)}、要算 {@code h_a(K)}），
     * 所以"用它当对照物"不引入任何服务端秘密 —— 池子 {@code /api/pool} 也是同一类公开数据。
     */
    static List<Integer> groundTruth(java.nio.file.Path dbPath, List<String> query)
        throws Exception {
        CapeDemoData db = CapeDemoData.load(dbPath);
        List<Integer> acc = null;
        for (String kw : query) {
            List<Integer> vs = db.kwToMovies.get(kw);
            if (vs == null) {
                return new ArrayList<>();
            }
            if (acc == null) {
                acc = new ArrayList<>(vs);
            } else {
                acc.retainAll(vs);
            }
        }
        List<Integer> out = acc == null ? new ArrayList<>() : new ArrayList<>(acc);
        // 载荷每个关键词只放前 maxValues 个值，真值要按同一个口径截断
        java.util.Collections.sort(out);
        int maxValues = Integer.getInteger("cape.maxValues", 3);
        if (out.size() > maxValues) {
            out = new ArrayList<>(out.subList(0, maxValues));
        }
        return out;
    }

    /** DB 路径：与 {@code CapeDemoService} 的默认值一致，可用 {@code -Dcape.db} 覆盖。 */
    static java.nio.file.Path dbPath() {
        String p = System.getProperty("cape.db");
        if (p != null && !p.isEmpty()) {
            return java.nio.file.Paths.get(p);
        }
        return CapeDemoSetupProbe.resolveDb("cape-demo/db/keywords.json");
    }

    private static boolean sameSet(List<Integer> a, List<Integer> b) {
        return new java.util.TreeSet<>(a).equals(new java.util.TreeSet<>(b));
    }

    private static String setBits(boolean[] bits) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < bits.length; i++) {
            if (bits[i]) {
                sb.append(i).append(',');
            }
        }
        return sb.append(']').toString();
    }

    /**
     * {@code fp(K) = inField(K.hashCode(), t)} —— 与 {@code CapeDemoData} 的载荷指纹同源。
     *
     * <p>它正是 D7 记录的那条偏差：论文是 40-bit 指纹，我们用的是 {@code String.hashCode}。
     * 注意 {@code t} 必须取 <b>native 那条信道的</b>（载荷是在那个域里生成的），
     * 不是打分信道的 65537 —— 取错会让所有查询都返回 bot。
     */
    static long fpOf(String kw, long nativeT) {
        return CapeDemoData.inField(kw.hashCode(), nativeT);
    }
}
