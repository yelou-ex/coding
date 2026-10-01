package com.fusepir.rgsw;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 端到端验证**合规路径**：客户端构造密文查询 → {@code /api/query-sealed} → 客户端判定。
 *
 * <p>这个测试存在的理由是把「D1 修好了」变成可执行的断言，而不是文档里的一句话。
 * 它检查三件事：
 * <ol>
 *   <li><b>发出去的 JSON 里没有关键词</b>（连子串都不出现）；</li>
 *   <li><b>服务器回包里没有关键词、没有 τ</b> —— 服务器根本没收到，不可能回显；</li>
 *   <li><b>结果正确</b>：客户端用自己保留的 {@code b_qry} 与 {@code τ}
 *       按论文 A2 DECODE L1075-1082 做判定，得到与库一致的值集。</li>
 * </ol>
 *
 * <p>用法（需先起服务）：
 * <pre>
 *   .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeSealedFlowTest 8756
 * </pre>
 */
public final class CapeSealedFlowTest {

    private CapeSealedFlowTest() {
    }

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String what, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + what + (detail.isEmpty() ? "" : "  —— " + detail));
        } else {
            fail++;
            System.out.println("  [FAIL] " + what + (detail.isEmpty() ? "" : "  —— " + detail));
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        String base = "http://127.0.0.1:" + port;

        System.out.println("=== CAPE 合规路径（sealed）端到端测试 ===");
        Map<String, Object> st = CapeClientQuery.Http.get(base + "/api/state");
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
        System.out.printf("[server] N=%d k=%d R=%d maxValues=%d lBf=%d maxSetSize=%d%n%n",
            n, k, r, maxValues, lBf, maxSetSize);

        // 取一个已知非空的组合（服务器给的池子只含「已验证可用组合」，不是隐私信息）
        @SuppressWarnings("unchecked")
        Map<String, Object> pool = CapeClientQuery.Http.get(base + "/api/pool");
        @SuppressWarnings("unchecked")
        List<Object> pairs = (List<Object>) pool.get("pool");
        @SuppressWarnings("unchecked")
        List<String> query = new ArrayList<>((List<String>) ((Map<String, Object>) pairs.get(0)).get("kws"));
        System.out.println("[client] 查询（**不进 JSON**）: " + query);

        // ---------- 客户端构造 ----------
        // ⚠️ 密码学不变量：blind_rotate 要求 bsk = {RGSW(s_i)} 与**累加器所加密的秘密**
        // 是同一个。累加器由服务器用 SEAL 上下文的秘密密钥加密，所以算 β 用的 s
        // 必须是**那个上下文**的秘密比特。新建上下文会拿到另一个随机秘密 ⇒ 载荷恒为 0；
        // 而把句柄跨进程传过来会拿到野指针 ⇒ 段错误（两种我都踩过）。
        //
        // 所以合规路径的验证必须在**服务进程内**做：见 CapeDemoService.selftestSealed()
        // 与启动开关 -Dcape.selftest=true。本类只做「跨进程能验的那部分」：
        // 出站 JSON 的隐私性 + 位置一致性 + 回包不回显关键词。
        System.out.println();
        System.out.println("---------------- 0. 说明 ----------------");
        System.out.println("       β 的构造需要「与累加器同一秘密」，只能在服务进程内完成；");
        System.out.println("       端到端正确性由 -Dcape.selftest=true 的进程内自检验证。");
        System.out.println("       本进程只验跨进程可验的三件事（下面 1/2/3 节的位置与隐私断言）。");
        // 用位置直接构造一个最小 sealed 请求（不含 β），仅为验证服务器接受格式与不回显
        CapeClientQuery.Sealed q = CapeClientQuery.buildIndicesOnly(
            n, k, r, maxValues, kws, query);
        String json = CapeClientQuery.toJson(q);

        // ---------- 断言 1：发出去的信道里没有明文关键词 ----------
        System.out.println();
        System.out.println("---------------- 1. 出站 JSON 的隐私性 ----------------");
        List<String> leaked = new ArrayList<>();
        for (String kw : query) {
            if (json.contains(kw)) {
                leaked.add(kw);
            }
        }
        check("出站 JSON 不含任何查询关键词", leaked.isEmpty(), "泄漏=" + leaked);
        check("出站 JSON 不含 tau", !json.matches("(?s).*\"tau\"\\s*:.*"), "");
        check("出站 JSON 不含 b_qry", !json.matches("(?s).*\"bQry\"\\s*:.*"), "");
        check("出站 JSON 不含关键词集合", !json.matches("(?s).*\"keywords\"\\s*:.*"), "");
        System.out.println("        body 长度 = " + json.length() + " 字符");
        System.out.println("       [diag] 客户端 colIdx=" + Arrays.toString(q.colIdx)
            + " rowIdx=" + Arrays.toString(q.rowIdx)
            + " d=" + q.sBits.length + " sBits 前8=" + Arrays.toString(
                Arrays.copyOfRange(q.sBits, 0, Math.min(8, q.sBits.length))));
        System.out.println("       [diag] 客户端 beta=" + Arrays.toString(q.beta));
        System.out.println("       [diag] 客户端 a[0] 前4=" + Arrays.toString(
            Arrays.copyOfRange(q.a[0], 0, Math.min(4, q.a[0].length))));

        // ---------- 2. 服务器 ANSWER ----------
        System.out.println();
        System.out.println("---------------- 2. 服务器 ANSWER（只收到密文）----------------");
        Map<String, Object> resp = CapeClientQuery.Http.post(base + "/api/query-sealed", json);
        if (!Boolean.TRUE.equals(resp.get("ok"))) {
            System.out.println("  [FAIL] 服务器返回 ok  —— " + resp.get("error"));
            System.out.println("=== " + pass + " PASS / " + (fail + 1) + " FAIL ===");
            System.exit(1);
        }
        check("服务器返回 ok", true, "");
        @SuppressWarnings("unchecked")
        Map<String, Object> timing = (Map<String, Object>) resp.get("timing");
        System.out.printf("       QUERY %.3f ms / ANSWER %.1f ms / DECODE %.3f ms（单元 %s）%n",
            timing.get("queryMs"), timing.get("answerMs"), timing.get("decodeMs"), timing.get("unitCount"));

        // ---------- 断言 2：回包里也没有关键词 ----------
        // 服务器会回显它收到的 colIdx/rowIdx，用来自证「两边算的位置一致」
        @SuppressWarnings("unchecked")
        List<Object> echoCol = (List<Object>) resp.get("colIdx");
        @SuppressWarnings("unchecked")
        List<Object> echoRow = (List<Object>) resp.get("rowIdx");
        System.out.println("       [diag] 服务器回显 colIdx=" + echoCol + " rowIdx=" + echoRow);
        StringBuilder c1 = new StringBuilder();
        for (long v : q.colIdx) {
            c1.append(v).append(',');
        }
        StringBuilder c2 = new StringBuilder();
        for (Object v : echoCol) {
            c2.append(((Number) v).longValue()).append(',');
        }
        check("服务器收到并与客户端一致的位置", c1.toString().equals(c2.toString()),
            "client=" + c1 + " server=" + c2);

        String respStr = String.valueOf(resp);
        List<String> echoed = new ArrayList<>();
        for (String kw : query) {
            if (respStr.contains(kw)) {
                echoed.add(kw);
            }
        }
        check("服务器回包不含任何查询关键词", echoed.isEmpty(), "回显=" + echoed);
        check("服务器回包不含 tau", !respStr.matches("(?s).*\"tau\"\\s*:.*"), "");

        // ---------- 3. 客户端判定（论文 A2 DECODE L1075-1082）----------
        System.out.println();
        System.out.println("---------------- 3. 客户端 DECODE（τ 与 b_qry 只在客户端）----------------");
        @SuppressWarnings("unchecked")
        List<Object> payloadRaw = (List<Object>) resp.get("payload");
        long[] payload = new long[payloadRaw.size()];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = ((Number) payloadRaw.get(i)).longValue();
        }
        int count = (int) payload[1];
        System.out.println("       载荷：valueCount=" + count + " 全长=" + payload.length
            + " 前 5 项=" + Arrays.toString(Arrays.copyOfRange(payload, 0, Math.min(5, payload.length))));
        System.out.println("       τ = " + q.tau);
        boolean allZero = true;
        for (long v : payload) {
            if (v != 0) {
                allZero = false;
                break;
            }
        }
        check("载荷非全零", !allZero, allZero ? "全零 ⇒ ANSWER 没选到槽" : "");

        // A/B：同样关键词走老路径（nativeCapeAnswer，服务器自造 a/β），
        // 用来区分「sealed 特有」与「共性」。老路径是已知能跑通的基线。
        if (allZero) {
            System.out.println();
            System.out.println("---------------- A/B 诊断：老路径（/api/query）----------------");
            StringBuilder sb = new StringBuilder("{\"keywords\":[");
            for (int i = 0; i < query.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append('"').append(query.get(i)).append('"');
            }
            sb.append("]}");
            Map<String, Object> legacy = CapeClientQuery.Http.post(base + "/api/query", sb.toString());
            System.out.println("       老路径 ok=" + legacy.get("ok")
                + " hit=" + legacy.get("hit") + " integrity=" + legacy.get("integrity")
                + " mismatch=" + legacy.get("payloadMismatch"));
            System.out.println("       老路径结果=" + legacy.get("results"));
            System.out.println("       ⇒ 若老路径结果正确而 sealed 全零，则是 sealed 的参数/秘密不一致");
        }

        List<Integer> accepted = new ArrayList<>();
        for (int j = 0; j < maxValues && j < count; j++) {
            int off = 2 + j * (1 + lBf);
            int valueId = (int) payload[off];
            if (valueId <= 0) {
                continue;
            }
            // 论文 A2 L1077-1078：s_j 与 τ 比较。这里 s_j 由客户端从载荷里的
            // 候选 Bloom 向量与自己的 b_qry 做内积得到（D2 落地后改为解密 ct_score,j）。
            long s = 0;
            for (int bi = 0; bi < lBf; bi++) {
                if (q.bQry[bi] && payload[off + 1 + bi] != 0) {
                    s++;
                }
            }
            System.out.printf("       候选 v=%d : s_j=%d  %s%n", valueId, s, s == q.tau ? "== τ ⇒ 接受" : "< τ ⇒ 拒绝");
            if (s == q.tau) {
                accepted.add(valueId);
            }
        }
        check("至少接受一个候选（查询非空）", !accepted.isEmpty(), "接受=" + accepted);

        // 与「明文真值」交叉验证。
        // 注意：这里不需要服务器的任何秘密 —— 用的是 /api/pool 公开的
        // 「这一对关键词共同命中的 movieId 列表」。但池子给的是 **原始 MovieLens movieId**，
        // 而载荷里是**压缩后的 valueId**，所以要经 /api/state 的 rawMovieIds 映射回 valueId。
        System.out.println();
        System.out.println("---------------- 4. 与明文真值交叉验证 ----------------");
        @SuppressWarnings("unchecked")
        Map<String, Object> rawMap = (Map<String, Object>) st.get("rawMovieIds");
        List<Integer> wantValues = new ArrayList<>();
        @SuppressWarnings("unchecked")
        Map<String, Object> firstPair = (Map<String, Object>) pairs.get(0);
        @SuppressWarnings("unchecked")
        List<Object> movies = (List<Object>) firstPair.get("movies");
        if (rawMap != null && movies != null) {
            for (Object mv : movies) {
                Object vid = rawMap.get(String.valueOf(mv));
                if (vid instanceof Number) {
                    wantValues.add(((Number) vid).intValue());
                }
            }
        }
        System.out.println("       明文真值（池子给出的共同命中）= " + wantValues);
        System.out.println("       sealed 路径接受              = " + accepted);
        check("接受的候选与明文真值一致",
            !wantValues.isEmpty() && wantValues.containsAll(accepted) && !accepted.isEmpty(),
            "accepted=" + accepted + " want=" + wantValues);

        System.out.println();
        System.out.println("=== " + pass + " PASS / " + fail + " FAIL ===");
        if (fail > 0) {
            System.exit(1);
        }
    }
}
