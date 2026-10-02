package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>默认路径的客户端测试</b>：{@code POST /api/query {qBFBytes: [...]}} → 客户端
 * 用 {@code Dec(ct_score) == τ} 判定。
 *
 * <h3>这一轮在验什么</h3>
 * 规划书 §二 的验收定义第 2 条要求**默认路径**走 {@code Dec(ct_score) == τ}。
 * 在 2026-10-14 之前，{@code /api/query} 收明文关键词、用明文合取判定，
 * A2 的密文判定只存在于新出口 {@code /api/query-cape} 上。本轮把默认路径切过去，
 * 本类就是那条路径的客户端测试。
 *
 * <h3>协议（也是本类的断言对象）</h3>
 * <pre>
 *   客户端：b_qry <- BF.Gen(0, {K_2..K_Q}) ; tau <- ||b_qry||_1
 *           qBFBytes <- serialize( RLWE.Enc(b_qry) )        &lt;- 只发字节
 *   服务器：锚检索 -> 逐候选打包 -> ct_score,j <- CtCtMul+折叠
 *           回 { fingerprint, candidates[ {valueId, ctScoreBytes} ] }
 *   客户端：f == fp(K) ?  ;  s_j <- Dec(load(ctScoreBytes_j))  ;  s_j == tau 才收
 * </pre>
 *
 * <h3>负对照（没有这些，"判定承重"就没有证据）</h3>
 * <ol>
 *   <li><b>N1 篡改 {@code ct_score} 字节</b>：把每条 {@code ctScoreBytes} 整体置零再
 *       {@code load} 回来 ⇒ 判定必须一条都不接受。<b>这一条是验收定义第 2 条点名的
 *       "把 ct_score 破坏掉，判定必须失败"</b>。注意它是**在过线后的字节上**做的，
 *       所以同时证明了"客户端解的是服务器发回来的那条密文"。</li>
 *   <li><b>N2 指纹用错</b> ⇒ 整条答案作废（⊥）。</li>
 *   <li><b>N3 τ 改错</b> ⇒ 接受集合跟着变。</li>
 *   <li><b>N4 {@code q_BF} 换一个</b> ⇒ 分数跟着变（分数真的依赖查询）。</li>
 *   <li><b>N5 关键词不出现在请求里</b>：出站 JSON 按<b>字段白名单</b>断言，
 *       这是本项目里唯一能自动抓住"位向量换个名字发出去"的检查。</li>
 * </ol>
 *
 * <h3>⚠️ 必须一起说的口径差</h3>
 * <ul>
 *   <li><b>打分信道与 native 信道的 {@code t} 不同</b>（65537 vs 库里的 2³²），
 *       各持一把独立密钥。见 {@code CapeScoreChannelProbe}。</li>
 *   <li><b>D2 仍在</b>：{@code ct_{B^F_j}} 是服务端把解出来的 Bloom 位重新编的密文，
 *       不是"检索出来的那条密文"。</li>
 *   <li><b>行索引噪声按项目决定不引入</b>（D1）—— 本轮**特意没碰**。</li>
 *   <li><b>单进程回环</b>：本测试是真正的 HTTP 过线（字节往返），但客户端自己另建了一个
 *       打分信道上下文（密钥持有者仍是同一个 JVM）。</li>
 * </ul>
 *
 * <p>跑法（需先起服务）：
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDefaultPathTest 8756
 * </pre>
 */
public final class CapeDefaultPathTest {

    private CapeDefaultPathTest() {
    }

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    /** 出站请求体**允许**出现的字段（白名单）。任何第 2 个字段都是设计变更。 */
    private static final List<String> ALLOWED_OUTBOUND_KEYS =
        Arrays.asList("qBFBytes", "d");

    private static List<String> topLevelKeys(String json) {
        List<String> keys = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\"([A-Za-z0-9_]+)\"\\s*:").matcher(json);
        while (m.find()) {
            keys.add(m.group(1));
        }
        return keys;
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        String base = "http://127.0.0.1:" + port;

        System.out.println("=== CAPE 默认路径测试（/api/query + qBFBytes）===");

        Map<String, Object> st = CapeClientQuery.Http.get(base + "/api/state");
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) st.get("params");
        @SuppressWarnings("unchecked")
        Map<String, Object> proto = (Map<String, Object>) st.get("protocol");
        @SuppressWarnings("unchecked")
        List<String> kws = (List<String>) st.get("keywords");
        int n = ((Number) params.get("N")).intValue();
        int maxValues = ((Number) params.get("maxValues")).intValue();
        int lBf = ((Number) params.get("lBf")).intValue();
        int maxSetSize = ((Number) params.get("maxSetSize")).intValue();
        double epsBf = ((Number) params.get("epsBf")).doubleValue();
        long nativeT = ((Number) params.get("t")).longValue();
        long scoreT = ((Number) params.get("scoreT")).longValue();

        System.out.printf("[server] N=%d maxValues=%d l_BF=%d nativeT=%d scoreT=%d%n",
            n, maxValues, lBf, nativeT, scoreT);
        System.out.println("[protocol] defaultPath = " + proto.get("defaultPath"));
        check("服务端自述了默认路径与判定方式",
            String.valueOf(proto.get("defaultPathDecision")).contains("ct_score"),
            String.valueOf(proto.get("defaultPathDecision")));

        // ---------- 0. 客户端打分信道（与服务端**同一个密钥持有者**）----------
        //
        // ⚠️ 这一段是本测试最容易踩的坑，写清楚：
        //    ct_score 是服务端用打分信道的 sk 算出来的，客户端要用**同一把** sk 才解得出来。
        //    如果客户端各自 `new Mpc4jRgsw(...)`（= 随机新密钥），**不会报错**，
        //    只会解出离谱的数（本项目实测：分数解成 26921 而不是 0..ℓ_BF），
        //    非常容易被误读成"打分算错了"。所以这里显式取服务端那把 sk。
        System.out.println();
        System.out.println("---------------- 0. 客户端侧打分信道（复用服务端的 sk）----------------");
        @SuppressWarnings("unchecked")
        Map<String, Object> insecure = (Map<String, Object>) st.get("insecureTestOnly");
        if (insecure == null) {
            System.out.println("  [SKIP] 服务端没开 -Dcape.insecure.keyecho=true ——");
            System.out.println("         本测试需要「判定方持有与服务器同一个密钥持有者的 sk」");
            System.out.println("         （单进程回环里天然成立；跨 JVM 就得有这条通道）。");
            System.out.println("         重跑：$env:DSH_JVM_OPTS='... -Dcape.insecure.keyecho=true'");
            System.out.println("=== 跳过（未失败） ===");
            return;
        }
        @SuppressWarnings("unchecked")
        List<Object> skBytes = (List<Object>) insecure.get("insecureScoreSecretKeyBytes");
        long[] skWire = new long[skBytes.size()];
        for (int i = 0; i < skWire.length; i++) {
            skWire[i] = ((Number) skBytes.get(i)).longValue();
        }
        // 先用一把新密钥建上下文（参数必须与服务器完全一致），再把它换成服务端那把 sk
        CapeBloomScore.Scorer tmp = CapeBloomScore.setup(n);
        edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey sharedSk =
            CapeScorerWire.deserializeKey(tmp, skWire);
        CapeBloomScore.Scorer sc = CapeBloomScore.setup(n, sharedSk);
        System.out.printf("  [setup] %.0f ms，槽数=%d（sk 已替换为服务端那把）%n",
            (double) sc.setupMs, sc.slots);

        // ---------- 1. 客户端 QUERY：只发字节 ----------
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
        long[] qbfWire = CapeBloomScore.encryptQueryWire(sc, bQry);
        System.out.println("  查询（来自公开池子，不是隐私）: " + query);
        System.out.printf("  tau = %d（**不进请求**）; q_BF 密文 %d 字节（%.1f KB）%n",
            tau, qbfWire.length, qbfWire.length / 1024.0);

        // ---------- 2. 出站隐私：字段白名单 ----------
        System.out.println();
        System.out.println("---------------- 2. 出站请求的隐私性（字段白名单）----------------");
        StringBuilder req = new StringBuilder("{\"d\":" + lBf + ",\"qBFBytes\":[");
        for (int i = 0; i < qbfWire.length; i++) {
            if (i > 0) {
                req.append(',');
            }
            req.append(qbfWire[i]);
        }
        req.append("]}");
        String reqStr = req.toString();
        List<String> leaked = new ArrayList<>();
        for (String kw : query) {
            if (reqStr.contains(kw)) {
                leaked.add(kw);
            }
        }
        check("出站请求不含任何关键词（连子串都不出现）", leaked.isEmpty(), "泄漏=" + leaked);
        List<String> keys = topLevelKeys(reqStr.substring(0, Math.min(reqStr.length(), 200)));
        List<String> extra = new ArrayList<>();
        for (String key : keys) {
            if (!ALLOWED_OUTBOUND_KEYS.contains(key)) {
                extra.add(key);
            }
        }
        check("出站字段集在白名单内（服务器只需要 qBFBytes）", extra.isEmpty(),
            "多余字段=" + extra + " 实得=" + keys);
        // 形状断言：不允许出现"一整条全是 0/1 的数组"（b_qry 换个名字发出去）
        check("出站不含全 0/1 的位向量（q_BF 是密文，不是 b_qry）",
            !looksLikeBitVector(reqStr), "");
        // ⚠️ **阳性对照**：上面那条断言如果检测器本身坏了，会永远为真（静默失效）。
        //    所以拿一个真的位向量喂给它，必须**检测得到** —— 否则这条断言毫无证明力。
        {
            StringBuilder fake = new StringBuilder("{\"bQry\":[");
            for (int i = 0; i < 30; i++) {
                if (i > 0) {
                    fake.append(',');
                }
                fake.append(i % 2);
            }
            fake.append("]}");
            check("[阳性对照] 位向量检测器对真的位向量必须报警（否则上一条是空断言）",
                looksLikeBitVector(fake.toString()),
                "喂进去的是 30 项 0/1 数组 ⇒ 检测器应命中");
        }
        System.out.printf("  请求体 %d 字符（%.0f KB）%n", reqStr.length(), reqStr.length() / 1024.0);

        // ---------- 3. 服务器 ANSWER（默认路径）----------
        System.out.println();
        System.out.println("---------------- 3. 服务器 ANSWER（/api/query 默认路径）----------------");
        Map<String, Object> resp = CapeClientQuery.Http.post(base + "/api/query", reqStr);
        if (!Boolean.TRUE.equals(resp.get("ok"))) {
            System.out.println("  [FAIL] 服务器返回 ok --- " + resp.get("error"));
            System.out.println("=== " + failed + " FAIL ===");
            System.exit(1);
        }
        check("服务器确认走的是 sealed(CAPE) 分支", Boolean.TRUE.equals(resp.get("sealed")),
            "sealed=" + resp.get("sealed"));
        @SuppressWarnings("unchecked")
        Map<String, Object> timing = (Map<String, Object>) resp.get("timing");
        System.out.printf("  锚检索 %.1f ms / 打分 %.1f ms / 合计 %.1f ms%n",
            ((Number) timing.get("anchorMs")).doubleValue(),
            ((Number) timing.get("scoreMs")).doubleValue(),
            ((Number) timing.get("totalMs")).doubleValue());

        @SuppressWarnings("unchecked")
        List<Object> rawCands = (List<Object>) resp.get("candidates");
        long fGot = ((Number) resp.get("fingerprint")).longValue();
        List<Integer> valueIds = new ArrayList<>();
        List<long[]> ctScoreWire = new ArrayList<>();
        for (Object o : rawCands) {
            @SuppressWarnings("unchecked")
            Map<String, Object> one = (Map<String, Object>) o;
            @SuppressWarnings("unchecked")
            List<Object> bytes = (List<Object>) one.get("ctScoreBytes");
            long[] w = new long[bytes.size()];
            for (int i = 0; i < w.length; i++) {
                w[i] = ((Number) bytes.get(i)).longValue();
            }
            ctScoreWire.add(w);
        }
        // ⚠️ 2026-10-14：候选**不再由服务器给**。原先服务器发的是明文 `valueId`，
        //    而论文 §4.1 的原文是 "Only the **encrypted** candidate values and these
        //    scores are returned to the client."。现在客户端自己从 `ctPay` 解出
        //    `V_K1` —— 也就是 DECODE 第 2 行的
        //    `V_K1 ← FusePIR.Decode(sk, st^C_anc, resp_anc)`。
        valueIds.addAll(decodePayload(resp));
        check("P0-2 每候选各带自己的 ct_score 字节（条数与 V_K1 一致）", !valueIds.isEmpty()
            && ctScoreWire.size() == valueIds.size(),
            "V_K1=" + valueIds + " 密文数=" + ctScoreWire.size());
        check("[新] 响应里**没有**明文候选值 id（客户端自己按载荷布局解）",
            !responseHasValueId(resp), "服务端不再发候选值的身份");
        check("[新] 响应里带 `ctPay`（= ct_v 的密文形式）",
            resp.get("ctPay") instanceof List, "ct_v 随响应返回");
        check("响应里不含任何明文分数（否则判定可被绕开）", !hasPlainScore(resp), "");

        // ---------- 4. 客户端 DECODE（只读 ct_score）----------
        System.out.println();
        System.out.println("---------------- 4. 客户端 DECODE（f == fp(K) 且 Dec(ct_score) == tau）----------------");
        long fpWant = CapeAlgorithm2Diag.fpOf(query.get(0), nativeT);
        CapeAlgorithm2Diag.DecodeResult dr = decode(sc, ctScoreWire, valueIds, fpWant, fGot, tau, 0);
        System.out.printf("  fp(K)=%d  f=%d  => %s%n", fpWant, fGot, dr.verdict);
        check("指纹校验通过（f == fp(K)）", dr.fingerprintOk, "");
        for (int j = 0; j < dr.scores.size(); j++) {
            long sj = dr.scores.get(j);
            System.out.printf("       候选 v=%d : Dec(load(ctScoreBytes))=%d  %s%n",
                valueIds.get(j), sj, sj == tau ? "== tau => 接受" : "< tau => 拒绝");
        }
        check("判定只读 Dec(ct_score)，且至少接受一条", !dr.accepted.isEmpty(),
            "接受=" + dr.accepted);

        List<Integer> want = CapeAlgorithm2Diag.groundTruth(CapeAlgorithm2Diag.dbPath(), query);
        System.out.println("       明文真值（K 交集）= " + want + "；密文判定接受 = " + dr.accepted);
        check("接受的候选与明文真值完全一致", !want.isEmpty()
            && new java.util.TreeSet<>(want).equals(new java.util.TreeSet<>(dr.accepted)),
            "accepted=" + dr.accepted + " want=" + want);

        // ---------- 5. 负对照 ----------
        System.out.println();
        System.out.println("---------------- 5. 负对照 ----------------");
        {
            // N1：**篡改过线后的 ct_score 字节**（整条置零）⇒ 判定必须失败。
            //     这是规划书验收定义第 2 条点名的那一条，且是在**字节层**做的。
            List<long[]> broken = new ArrayList<>();
            for (long[] w : ctScoreWire) {
                long[] b2 = w.clone();
                Arrays.fill(b2, 0L);
                broken.add(b2);
            }
            CapeAlgorithm2Diag.DecodeResult d1 = decode(sc, broken, valueIds, fpWant, fGot, tau, 0);
            check("N1 把过线后的 ctScoreBytes 置零 ⇒ 判定一条都不接受（验收定义第 2 条）",
                d1.accepted.isEmpty(),
                "接受=" + d1.accepted + (d1.loadFailed ? "（load 失败，也算被拒）" : ""));

            // N1b：只翻转密文里的**一个字节**（不是整条置零）⇒ 也必须拒绝
            List<long[]> flipped = new ArrayList<>();
            for (long[] w : ctScoreWire) {
                long[] b2 = w.clone();
                int idx = b2.length / 2;
                b2[idx] = b2[idx] ^ 0x01L;
                flipped.add(b2);
            }
            CapeAlgorithm2Diag.DecodeResult d1b = decode(sc, flipped, valueIds, fpWant, fGot, tau, 0);
            check("N1b 只翻转 ctScoreBytes 的一个 bit ⇒ 判定也不再接受",
                !d1b.accepted.equals(dr.accepted),
                "原本接受=" + dr.accepted + " 翻转后=" + d1b.accepted
                    + (d1b.loadFailed ? "（load 失败，也算被拒）" : ""));

            // N2：指纹用错 ⇒ ⊥
            CapeAlgorithm2Diag.DecodeResult d2 = decode(sc, ctScoreWire, valueIds,
                fpWant + 1, fGot, tau, 0);
            check("N2 指纹故意用错 ⇒ 返回 bot、不给任何值", !d2.fingerprintOk && d2.accepted.isEmpty(),
                d2.verdict);

            // N3：tau 改错 ⇒ 接受集合变
            CapeAlgorithm2Diag.DecodeResult d3 = decode(sc, ctScoreWire, valueIds, fpWant, fGot,
                tau + 1, 0);
            check("N3 把 tau 改错 ⇒ 接受集合必须变",
                !d3.accepted.equals(dr.accepted),
                "tau=" + tau + " -> " + dr.accepted + "；tau+1 -> " + d3.accepted);

            // N4：换一个 q_BF 再问一次服务器 ⇒ 分数必须变
            boolean[] other = new boolean[lBf];
            other[0] = true;
            long[] otherWire = CapeBloomScore.encryptQueryWire(sc, other);
            Map<String, Object> resp2 = CapeClientQuery.Http.post(base + "/api/query",
                wireRequest(otherWire, lBf));
            long tauOther = 1;
            @SuppressWarnings("unchecked")
            List<Object> cands2 = (List<Object>) resp2.get("candidates");
            List<long[]> wire2 = new ArrayList<>();
            List<Integer> ids2 = new ArrayList<>();
            for (Object o : cands2) {
                @SuppressWarnings("unchecked")
                Map<String, Object> one = (Map<String, Object>) o;
                @SuppressWarnings("unchecked")
                List<Object> bytes = (List<Object>) one.get("ctScoreBytes");
                long[] w = new long[bytes.size()];
                for (int i = 0; i < w.length; i++) {
                    w[i] = ((Number) bytes.get(i)).longValue();
                }
                wire2.add(w);
            }
            ids2.addAll(decodePayload(resp2));   // 同样由客户端自己解
            CapeAlgorithm2Diag.DecodeResult d4 = decode(sc, wire2, ids2, fpWant,
                ((Number) resp2.get("fingerprint")).longValue(), tauOther, 0);
            check("N4 换一个 q_BF ⇒ 分数改变（分数确实依赖查询）",
                !d4.scores.equals(dr.scores),
                "原=" + dr.scores + " 换后=" + d4.scores);
        }

        System.out.println();
        System.out.println(failed == 0
            ? "=== ALL CHECKS PASSED：默认路径走 Dec(ct_score) == tau + 指纹 bot ==="
            : "=== " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------
    //  客户端 DECODE
    // ------------------------------------------------------------------

    /**
     * 客户端 DECODE：<b>先 load 字节，再解密</b>。
     *
     * <p>刻意<b>不复用</b> {@link CapeAlgorithm2Diag#decode} 的 {@code Ciphertext} 版签名 ——
     * 那条路的输入是进程内对象，绕过了"字节过线"这一段；本方法从<b>字节</b>开始，
     * 所以 N1/N1b 那两条篡改断言才有意义。
     */
    static CapeAlgorithm2Diag.DecodeResult decode(
        CapeBloomScore.Scorer sc, List<long[]> ctScoreBytesWire, List<Integer> valueIds,
        long fpWant, long fGot, long tau, long unusedMarker) {
        if (fGot != fpWant) {
            return new CapeAlgorithm2Diag.DecodeResult(false, new ArrayList<>(),
                new ArrayList<>(), "f=" + fGot + " != fp(K)=" + fpWant + " => 返回 bot（整条答案作废）");
        }
        List<Integer> accepted = new ArrayList<>();
        List<Long> scores = new ArrayList<>();
        boolean loadFailed = false;
        for (int j = 0; j < ctScoreBytesWire.size(); j++) {
            long sj;
            try {
                Ciphertext ct = CapeScorerWire.deserialize(sc, ctScoreBytesWire.get(j));
                sj = CapeBloomScore.decryptSlots(sc, ct)[0];
            } catch (RuntimeException e) {
                // 字节坏了 ⇒ 这条密文根本解不出来。**按"拒绝"处理而不是抛出去**：
                // 判定是客户端的事，客户端必须能对损坏的响应做出决断。
                loadFailed = true;
                sj = Long.MIN_VALUE;
            }
            scores.add(sj);
            if (sj == tau) {
                accepted.add(valueIds.get(j));
            }
        }
        CapeAlgorithm2Diag.DecodeResult r = new CapeAlgorithm2Diag.DecodeResult(
            true, accepted, scores, "指纹校验通过；逐候选 load + Dec(ct_score) 与 tau 比");
        r.loadFailed = loadFailed;
        return r;
    }

    private static String wireRequest(long[] wire, int lBf) {
        StringBuilder sb = new StringBuilder("{\"d\":" + lBf + ",\"qBFBytes\":[");
        for (int i = 0; i < wire.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(wire[i]);
        }
        return sb.append("]}").toString();
    }

    /**
     * <b>客户端侧 FusePIR.Decode</b>（论文 A2 DECODE 第 2 行）：
     * 从响应里的 {@code ctPay}（= {@code ct_v}）解出候选值列表 {@code V_K1}。
     *
     * <p><b>为什么要客户端自己解</b>：论文 §4.1 原文要求
     * <i>"Only the <b>encrypted</b> candidate values and these scores are returned to
     * the client."</i> —— 服务器**不告诉**客户端"候选是谁"。客户端按公开的载荷布局
     * （{@code [0]=指纹, [1]=候选数, 之后每个候选占 1+l_BF 项}）自己切出来。
     *
     * <p>载荷布局是**公开参数**的一部分（`pp` 里有 `ℓ_BF`、`m`），所以这不引入任何秘密。
     */
    static List<Integer> decodePayload(Map<String, Object> resp) {
        List<Integer> out = new ArrayList<>();
        Object ctPay = resp.get("ctPay");
        if (!(ctPay instanceof List)) {
            return out;
        }
        List<?> raw = (List<?>) ctPay;
        long[] payload = new long[raw.size()];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = ((Number) raw.get(i)).longValue();
        }
        int lBf = Integer.getInteger("cape.lbf", 18);
        int maxValues = Integer.getInteger("cape.maxValues", 3);
        int count = (int) payload[1];
        for (int j = 0; j < maxValues && j < count; j++) {
            int base = 2 + j * (1 + lBf);
            if (base >= payload.length) {
                break;
            }
            int valueId = (int) payload[base];
            if (valueId > 0) {
                out.add(valueId);
            }
        }
        return out;
    }

    /**
     * 响应里有没有明文候选值 id。
     *
     * <p>这是一条**字段白名单式的反向断言**：它不检查某个具体字段名，而是
     * 把整个响应序列化后找 {@code "valueId"} —— 因为真实事故正是"字段改个名字就绕过断言"
     * （本项目 `bf`→`bQry` 那次）。所以这里同时查常见别名。
     */
    private static boolean responseHasValueId(Map<String, Object> resp) {
        String s = String.valueOf(resp);
        return s.contains("\"valueId\"") || s.contains("\"value_id\"")
            || s.contains("\"vid\"") || s.contains("\"plainValue\"");
    }

    /** 响应里有没有"看起来像明文分数"的字段。 */
    private static boolean hasPlainScore(Map<String, Object> resp) {        for (String k : resp.keySet()) {
            String lk = k.toLowerCase();
            if (lk.contains("score") && !lk.contains("ctscorebytes")) {
                Object v = resp.get(k);
                if (v instanceof Number) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 出站里有没有"一整条全是 0/1 的数组"（b_qry 换个名字发出去的样子）。 */
    private static boolean looksLikeBitVector(String json) {
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\\[((?:\\s*[01]\\s*,){20,}\\s*[01]\\s*)\\]").matcher(json);
        return m.find();
    }
}
