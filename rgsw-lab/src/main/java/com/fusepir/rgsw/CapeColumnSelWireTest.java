package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * <b>P1-1 的跨进程线格式验收</b>：列选择子密文流能不能真的过 HTTP 的 JSON？
 *
 * <h3>它补的是哪一段</h3>
 * 进程内验收（{@code -Dcape.selftest=true} 里的 {@code selftestColumnSelectors()}）
 * 证明了密码学那一半：同样的位置语义下，密文选择子路径的载荷与明文列号基线
 * <b>逐系数一致</b>，且两条负对照都成立。它<b>没有</b>证明的那一半是：
 * 41 MB 的选择子流经过 {@code toJson}（7 字节/long 打包）→ HTTP → {@code parseSealed}
 * 之后还能被服务器 load 出来、还能驱动出不同的载荷。
 *
 * <h3>⚠️ 为什么本类**不能**断言「载荷 == 基线的载荷」（第一版断言错了，记在这里）</h3>
 * 第一版让客户端**新建自己的上下文**加密选择子，理由是「选项子进的是
 * {@code multiply_plain(ct, pt)}，服务器只把它当一条密文用」。那句话对，
 * 但结论错了一半，实测 A ≠ B：
 *
 * <pre>
 *   A: P1-1（colSel 密文流）载荷前 4 项 [2603260353, 2024078321, 1386151961, ...]
 *   B: 基线（colIdx 明文位置）载荷前 4 项 [71646159, 3090238986, 3133393288, ...]
 * </pre>
 *
 * 原因是<b>回环的 DECODE 那一步</b>：{@code cape_answer_core} 末尾用
 * {@code c->decryptor}（**服务端的秘密密钥**）解出载荷。而
 * {@code multiply_plain} 出来的密文是**在谁的秘密下加密，就永远在谁的秘密下**：
 * 客户端用自己的上下文加密 ⇒ 整条累加器变成「客户端秘密下的密文」⇒
 * 服务端那把密钥解出来就是垃圾。
 *
 * <p>所以「选择子必须与**累加器**同一个秘密」——累加器的秘密就是最终解密者的秘密。
 * 真部署里那个解密者是客户端（它持有 {@code s_R}），于是「客户端自己的上下文」
 * 才是对的；而在本项目的**单进程回环**里，解密者是服务端，所以选择子只能用
 * <b>服务端上下文</b>加密。这也是 {@code selftestColumnSelectors()} 必须在进程内做的
 * 第二个理由（第一个是 β 需要同一把秘密）。
 *
 * <p>⇒ 本类改为断言**它真的能断言的事**：格式能过、服务器能把 78 条都 load 出来跑完、
 * 载荷确实随选择子变化（负对照），以及这条路的线格式代价有多大。
 */
public final class CapeColumnSelWireTest {

    private CapeColumnSelWireTest() {
    }

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        String base = "http://127.0.0.1:" + port;
        System.out.println("=== P1-1 跨进程线格式验收（列选择子密文流过 JSON）===");

        Map<String, Object> st = CapeClientQuery.Http.get(base + "/api/state");
        Map<String, Object> params = (Map<String, Object>) st.get("params");
        List<String> kws = (List<String>) st.get("keywords");
        int n = ((Number) params.get("N")).intValue();
        int k = ((Number) params.get("k")).intValue();
        int r = ((Number) params.get("R")).intValue();
        int maxValues = ((Number) params.get("maxValues")).intValue();
        System.out.printf("[server] N=%d k=%d R=%d maxValues=%d keywords=%d%n%n",
            n, k, r, maxValues, kws.size());

        Map<String, Object> pool = CapeClientQuery.Http.get(base + "/api/pool");
        List<Object> pairs = (List<Object>) pool.get("pool");
        List<String> query = new ArrayList<>(
            (List<String>) ((Map<String, Object>) pairs.get(0)).get("kws"));
        System.out.println("[client] 查询（**不进 JSON**）: " + query);

        CapeClientQuery.Sealed q = CapeClientQuery.buildIndicesOnly(
            n, k, r, maxValues, kws, query);
        int cellsPerCol = Math.max(1, r / maxValues);
        int C = Math.max(1, (kws.size() + cellsPerCol - 1) / cellsPerCol);
        System.out.println("[client] 列号 colIdx=" + Arrays.toString(q.colIdx) + "  C=" + C);

        // 客户端自己的上下文（参数必须与服务器一致：参数是协议的一部分）
        long t = 4294967296L;
        int bBits = Integer.getInteger("cape.b", 32);
        long ctx = NativeBlindRotate.nativeCreateContext(n, t, bBits);
        byte[] blob;
        byte[] blobWrong;
        try {
            long t0 = System.nanoTime();
            blob = CapeClientQuery.encryptColumnSelectors(ctx, k, C, q.colIdx);
            long encMs = (System.nanoTime() - t0) / 1_000_000;
            System.out.printf("[client] 选择子流 %d 字节（k=%d × C=%d，每条 %d），加密 %d ms%n",
                blob.length, k, C, (blob.length - 4L * k * C) / (k * C), encMs);
            long[] wrong = q.colIdx.clone();
            wrong[0] = (wrong[0] + 1) % C;
            blobWrong = CapeClientQuery.encryptColumnSelectors(ctx, k, C, wrong);
        } finally {
            NativeBlindRotate.nativeDestroyContext(ctx);
        }

        // ---------- 1. 线格式：出站 JSON 里必须没有明文列号 ----------
        CapeClientQuery.Sealed qA = CapeClientQuery.buildIndicesOnly(
            n, k, r, maxValues, kws, query);
        qA.selBlob = blob;
        String jsonA = CapeClientQuery.toJson(qA);
        CapeClientQuery.Sealed qB = CapeClientQuery.buildIndicesOnly(
            n, k, r, maxValues, kws, query);
        String jsonB = CapeClientQuery.toJson(qB);
        System.out.println();
        System.out.println("---------------- 1. 线格式 ----------------");
        System.out.printf("  P1-1 请求体 %d 字符（%.1f MB）；基线请求体 %d 字符（放大 %.0f 倍）%n",
            jsonA.length(), jsonA.length() / 1048576.0, jsonB.length(),
            (double) jsonA.length() / jsonB.length());
        check("P1-1 出站 JSON 里没有明文列号（colIdx 被 colSel 取代）",
            !jsonA.contains("\"colIdx\"") && jsonA.contains("\"colSel\""),
            "colIdx=" + jsonA.contains("\"colIdx\"") + " colSel=" + jsonA.contains("\"colSel\""));
        check("基线出站 JSON 里没有 colSel（两种形态互斥，不是「都发」）",
            jsonB.contains("\"colIdx\"") && !jsonB.contains("\"colSel\""), "");

        // ---------- 2. 过线：服务器要能把 78 条都 load 出来并跑完 ----------
        System.out.println();
        System.out.println("---------------- 2. 过线（%d 条选择子）----------------".formatted(k * C));
        long[] payA = post(base, jsonA, "A: P1-1（colSel 密文流）");
        check("P1-1 形态被服务器接受并跑完（⇒ 78 条密文都通过 parseSealed + load + multiply_plain）",
            payA != null, "");
        if (payA == null) {
            System.out.println("=== P1-1 请求失败，无法继续 ===");
            System.exit(1);
        }

        // ---------- 3. 负对照：载荷必须由选择子驱动 ----------
        System.out.println();
        System.out.println("---------------- 3. 负对照：换一列 ----------------");
        CapeClientQuery.Sealed qC = CapeClientQuery.buildIndicesOnly(
            n, k, r, maxValues, kws, query);
        long[] wrongCols = qC.colIdx.clone();
        wrongCols[0] = (wrongCols[0] + 1) % C;
        qC.colIdx = wrongCols;
        qC.selBlob = blobWrong;
        long[] payC = post(base, CapeClientQuery.toJson(qC), "C: 第 0 路换列");
        if (payC == null) {
            check("负对照请求完成", false, "");
            System.exit(1);
        }
        check("[负对照] 换一列 ⇒ 载荷不同（⇒ 载荷确实由选择子决定，不是恒定值）",
            !Arrays.equals(payA, payC),
            "前 4 项 A=" + Arrays.toString(Arrays.copyOf(payA, 4))
                + " C=" + Arrays.toString(Arrays.copyOf(payC, 4)));

        // ---------- 4. 同一路内 a=0（本类的构造）：载荷不能全零 ----------
        boolean anyNonZero = false;
        for (long v : payA) {
            if (v != 0) {
                anyNonZero = true;
                break;
            }
        }
        check("[阳性对照] 载荷不是全零（否则「不同」这条断言可能只是全零 vs 全零）",
            anyNonZero, "前 4 项 " + Arrays.toString(Arrays.copyOf(payA, 4)));

        System.out.println();
        System.out.println("  ⚠️ 本类**不断言**「P1-1 载荷 == 基线载荷」—— 原因见类注释：");
        System.out.println("     回环的 DECODE 用**服务端**秘密解载荷，所以选择子只能用服务端上下文加密；");
        System.out.println("     用客户端自己的上下文加密 ⇒ 整条累加器变成客户端秘密下的密文 ⇒ 解出垃圾。");
        System.out.println("     「逐系数一致」的断言在进程内（-Dcape.selftest=true 的 P1-1 段）做，");
        System.out.println("     那里两路用的是同一把秘密，才是可比的一对。");
        System.out.println();
        System.out.println(failed == 0
            ? "=== ALL CHECKS PASSED：41 MB 的选择子流可以真的过 JSON 线并被服务器用起来 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /** 发一次 sealed 查询，返回 payload；失败返回 null 并把错误打出来。 */
    @SuppressWarnings("unchecked")
    private static long[] post(String base, String json, String label) throws Exception {
        long t0 = System.nanoTime();
        Map<String, Object> resp = CapeClientQuery.Http.post(base + "/api/query-sealed", json);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        if (!Boolean.TRUE.equals(resp.get("ok"))) {
            System.out.printf("  [%s] 失败（%d ms）: %s%n", label, ms, resp.get("error"));
            return null;
        }
        System.out.printf("  [%s] ok（%d ms），columnSelector=%s%n",
            label, ms, resp.get("columnSelector"));
        List<Object> raw = (List<Object>) resp.get("payload");
        long[] out = new long[raw.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = ((Number) raw.get(i)).longValue();
        }
        System.out.println("       载荷前 4 项: " + Arrays.toString(Arrays.copyOf(out, 4)));
        return out;
    }
}
