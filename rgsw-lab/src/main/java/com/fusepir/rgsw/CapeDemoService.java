package com.fusepir.rgsw;

import com.fusepir.nativejni.NativeBlindRotate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * <b>CAPE native demo service.</b> A long-lived Java process that owns the native
 * context, runs SETUP once at startup, and serves the four-step query over HTTP.
 *
 * <p>Uses only {@code com.sun.net.httpserver} — no framework, no extra jars.
 *
 * <p>What actually crosses into native per query: the flattened plaintext table and
 * three index arrays. The column selectors are built and used inside
 * {@code nativeCapeAnswer}, and the row selector is the LWE index
 * {@code beta_a = sum_i a_i*s_i + rIdx[a]}, also built there. So QUERY sends no
 * ciphertext at all — which is why "QUERY" is cheap here and all the time is ANSWER.
 *
 * <p>⚠️ This is a single-process loopback: the same JVM holds the secret key and runs
 * the query. It demonstrates architecture and timing, not a two-party deployment.
 *
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeDemoService [port] [N] [d] [dbPath]}
 */
public final class CapeDemoService {

    private static final int R = 16;
    private static final int K = 3;
    // t 与 gadget 基位宽【从数据集读】，不再硬编码 —— 这样服务与 keywords.json
    // 不可能不一致。meta.plainModulus 是建库时就写进库里的（build_dataset.py 写了
    // 这个字段却一直没人读）；meta.baseBits 是本次新增的。
    //
    // 为什么默认就是最快的一组（t=2^32, base=2^32 ⇒ levels 6）：
    // 平衡分解的位必须落在 [0, t) 内 ⇒ base < 2t，所以 base 的天花板由 t 决定。
    // t=65537 时 base 只能到 2^16 ⇒ levels=11；t=2^32 时 base 到 2^32 ⇒ levels=6，
    // 一次 CMUX 从 41.4 ms 降到 26.3 ms，ANSWER 176 s -> 102 s。
    // 仍可用 -Dcape.t / -Dcape.b 覆盖（做对照实验用）。
    private static final long T_FALLBACK = 65537L;
    private static final int BASE_BITS_FALLBACK = 16;
    private static final long SEED = 20261013L;
    private static final String ASCII = "ASCII";

    // ---- loaded once at startup ----
    private CapeDemoData db;
    private CapeDemoData.Tables tb;
    private long ctxHandle = -1;
    private long[] tableFlat;
    private final long setupJavaMs;
    private final long setupNativeMs;
    private final String setupAt;
    private final int n;
    private final int d;
    private final int port;
    private final long t;
    private final int baseBits;
    /** SETUP 时标定出来的「一个单元」耗时（ms）；<=0 表示标定失败、已回退。 */
    private final double unitMsMeasured;

    // ---- last query, for polling ----
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final AtomicReference<String> lastResult = new AtomicReference<>("{}");
    private volatile String currentKws = "";

    private CapeDemoService(int port, int n, int d, CapeDemoData db) throws IOException {
        this.port = port;
        this.n = n;
        this.d = d;
        this.db = db;
        this.t = resolveT(db);
        this.baseBits = resolveBaseBits(db, this.t);

        int maxValues = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = Math.max(1, R / maxValues);
        int C = Math.max(1, (kwTotal + cellsPerCol - 1) / cellsPerCol);

        long j0 = System.nanoTime();
        this.tb = db.buildTables(n, C, R, K, this.t, SEED);
        this.tableFlat = CapeDemoSetupProbe.flatten(tb.p, n, tb.bPay);
        this.setupJavaMs = (System.nanoTime() - j0) / 1_000_000;

        long n0 = System.nanoTime();
        this.ctxHandle = NativeBlindRotate.nativeCreateContext(n, this.t, this.baseBits);
        long kh = NativeBlindRotate.nativeBuildBootstrapKey(ctxHandle, d);
        NativeBlindRotate.nativeDestroyKey(kh);   // nativeCapeAnswer rebuilds it per call
        this.setupNativeMs = (System.nanoTime() - n0) / 1_000_000;
        this.setupAt = java.time.LocalDateTime.now().toString();

        // 在 SETUP 里顺手标定一次「每个单元多久」。这是为了让前端首屏能显示
        // **本配置的真实预期**，而不是某份会过期的硬编码基线 —— 之前前端写 154 000、
        // README 写 176 000、实际最快 102 000，三份数互相矛盾就是因为没人在跑之前知道真值。
        // 约 10 轮盲旋转，几百毫秒，且 SETUP 本来就并排单独显示、不计入查询耗时。
        this.unitMsMeasured = measureUnitMs();
    }

    /**
     * {@code t} 取 {@code meta.plainModulus}（建库时写下的），JVM 开关可覆盖。
     *
     * <p>为什么要从库里读：载荷断言（{@code CapeDemoData} 里 payload 每个系数 &lt; t）
     * 和表构造都依赖 t，而 t 同时决定 gadget 基能开多大。硬编码在服务里就有
     * 「库和服务不一致」的隐患，而且这个隐患是**静默**的（载荷被 mod t 截断）。
     */
    private static long resolveT(CapeDemoData db) {
        long fromDb = db.longMeta("plainModulus", T_FALLBACK);
        Long forced = Long.getLong("cape.t");
        if (forced != null && forced != fromDb) {
            System.out.println("[warn] -Dcape.t=" + forced + " 覆盖了库里的 plainModulus="
                + fromDb + "；载荷系数必须 < t，不一致会导致静默截断");
        }
        return forced != null ? forced : fromDb;
    }

    /**
     * gadget 基位宽：优先 {@code meta.baseBits}（建库时定），否则按 {@code base < 2t}
     * 推一个安全值 —— 平衡分解的位要落在 {@code [0, t)} 内，所以 base 的上限由 t 定。
     * 最大值 32（{@code base = 2^32} 的平衡位正好放得进 {@code t = 2^32}）。
     */
    private static int resolveBaseBits(CapeDemoData db, long t) {
        Integer forced = Integer.getInteger("cape.b");
        if (forced != null) {
            return forced;
        }
        int fromDb = db.intMeta("baseBits", 0);
        if (fromDb > 0) {
            return fromDb;
        }
        // 没写就按 t 推：取满足 2^b < 2t 的最大 b，且不超过 32
        int b = 1;
        while (b < 32 && (1L << (b + 1)) < 2 * t) {
            b++;
        }
        return Math.min(b, 32);
    }

    // ------------------------------------------------------------------
    //  query
    // ------------------------------------------------------------------

    private String runQuery(List<String> kws) {
        long total0 = System.nanoTime();

        // ---------- QUERY ----------
        long q0 = System.nanoTime();
        List<String> unknown = new ArrayList<>();
        for (String k : kws) {
            if (!tb.kwIndex.containsKey(k)) {
                unknown.add(k);
            }
        }
        if (!unknown.isEmpty()) {
            return err("unknown keyword(s): " + unknown);
        }
        // anchor = first keyword; the rest go into b_qry
        int anchorIdx = tb.kwIndex.get(kws.get(0));
        List<String> others = new ArrayList<>(kws.subList(1, kws.size()));
        boolean[] bQry = bloomBits(others);
        long tau = 0;
        for (boolean b : bQry) {
            if (b) {
                tau++;
            }
        }
        long[] cIdx = new long[K];
        long[] rIdx = new long[K];
        for (int a = 0; a < K; a++) {
            cIdx[a] = tb.colOf[anchorIdx];
            rIdx[a] = tb.rowOf[anchorIdx] + a;
        }
        long queryUs = (System.nanoTime() - q0) / 1_000;   // QUERY is usually sub-ms

        // ---------- ANSWER ----------
        long a0 = System.nanoTime();
        long[] rec;
        try {
            rec = NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, tb.bPay,
                tableFlat, cIdx, rIdx);
        } catch (Throwable t) {
            return err("native answer failed: " + t);
        }
        long answerUs = (System.nanoTime() - a0) / 1_000;

        // ---------- DECODE ----------
        long d0 = System.nanoTime();
        long[] want = tb.payload[anchorIdx];
        int bad = 0;
        for (int b = 0; b < tb.bPay; b++) {
            if (rec[b] != want[b]) {
                bad++;
            }
        }
        long fp = rec[0];
        long fpWant = want[0];
        int count = (int) rec[1];
        List<Object> results = new ArrayList<>();
        int lookups = tb.maxValues;
        for (int j = 0; j < lookups && j < count; j++) {
            int base = 2 + j * (1 + tb.lBf);
            int valueId = (int) rec[base];
            if (valueId <= 0) {
                continue;
            }
            boolean[] bv = new boolean[tb.lBf];
            for (int bi = 0; bi < tb.lBf; bi++) {
                bv[bi] = rec[base + 1 + bi] != 0;
            }
            // conjunction test: every query bit must also be set on this value
            boolean conj = true;
            for (int bi = 0; bi < tb.lBf; bi++) {
                if (bQry[bi] && !bv[bi]) {
                    conj = false;
                    break;
                }
            }
            if (conj) {
                Map<String, Object> one = new LinkedHashMap<>();
                one.put("valueId", valueId);
                one.put("title", db.title(valueId));
                one.put("rawMovieId", db.rawMovieId(valueId));
                results.add(one);
            }
        }
        long decodeUs = (System.nanoTime() - d0) / 1_000;
        long totalUs = (System.nanoTime() - total0) / 1_000;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("keywords", kws);
        out.put("anchor", kws.get(0));
        out.put("tau", tau);
        out.put("hit", !results.isEmpty());
        out.put("results", results);
        out.put("valueCount", count);
        Map<String, Object> timing = new LinkedHashMap<>();
        // Reported in MICROseconds: QUERY and DECODE are sub-millisecond, so rounding
        // them to whole ms would display a misleading 0 and look like a bug.
        timing.put("queryUs", queryUs);
        timing.put("answerUs", answerUs);
        timing.put("decodeUs", decodeUs);
        timing.put("totalUs", totalUs);
        timing.put("queryMs", queryUs / 1000.0);
        timing.put("answerMs", answerUs / 1000.0);
        timing.put("decodeMs", decodeUs / 1000.0);
        timing.put("totalMs", totalUs / 1000.0);
        timing.put("setupMsLast", setupJavaMs + setupNativeMs);
        timing.put("unitCount", K * tb.bPay);
        timing.put("note", "setupMsLast is NOT included in totalMs");
        out.put("timing", timing);
        out.put("integrity", bad == 0 && fp == fpWant);
        out.put("payloadMismatch", bad);
        return Json.write(out);
    }

    /** BF.Gen over the non-anchor query keywords (client side). */
    private boolean[] bloomBits(List<String> kws) {
        com.fusepir.common.BfGen g = com.fusepir.common.BfGen.choose(
            db.intMeta("maxSetSize", 4), eps(), n);
        if (g.length() != tb.lBf) {
            throw new IllegalStateException("l_BF mismatch: " + g.length() + " vs " + tb.lBf);
        }
        return g.bits(kws);
    }

    private double eps() {
        Object v = db.meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
    }

    private static String err(String msg) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("error", msg);
        return Json.write(m);
    }

    // ------------------------------------------------------------------
    //  HTTP
    // ------------------------------------------------------------------

    private void start() throws IOException {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        srv.setExecutor(Executors.newFixedThreadPool(4));
        srv.createContext("/api/state", this::hState);
        srv.createContext("/api/query", this::hQuery);
        srv.createContext("/api/pool", this::hPool);
        srv.createContext("/", this::hStatic);
        srv.start();

        System.out.printf("%n=== CAPE demo service ready ===%n");
        System.out.printf("  open  http://127.0.0.1:%d/%n", port);
        System.out.printf("  SETUP: java %d ms + native %d ms = %d ms%n",
            setupJavaMs, setupNativeMs, setupJavaMs + setupNativeMs);
        System.out.printf("  N=%d d=%d C=%d R=%d k=%d B_pay=%d units=%d%n",
            n, d, tb.c, R, K, tb.bPay, K * tb.bPay);
    }

    private void hState(HttpExchange ex) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ready", true);
        m.put("busy", busy.get());
        m.put("currentKws", currentKws);
        Map<String, Object> setup = new LinkedHashMap<>();
        setup.put("done", true);
        setup.put("ms", setupJavaMs + setupNativeMs);
        setup.put("javaMs", setupJavaMs);
        setup.put("nativeMs", setupNativeMs);
        setup.put("at", setupAt);
        m.put("setup", setup);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("N", n);
        params.put("t", t);
        params.put("baseBits", baseBits);
        params.put("levels", levelsOf(ctxHandle));
        params.put("d", d);
        params.put("C", tb.c);
        params.put("R", R);
        params.put("k", K);
        params.put("maxValues", tb.maxValues);
        params.put("maxSetSize", db.intMeta("maxSetSize", 4));
        params.put("lBf", tb.lBf);
        params.put("bPay", tb.bPay);
        params.put("unitCount", K * tb.bPay);
        params.put("epsBf", eps());
        m.put("params", params);
        Map<String, Object> database = new LinkedHashMap<>();
        database.put("keywords", db.keywords.size());
        database.put("values", db.valueSpace.size());
        database.put("assoc", db.intMeta("assoc", -1));
        database.put("coveredValues", db.intMeta("covered_values", -1));
        database.put("poolSize", db.pool.size());
        m.put("db", database);
        m.put("keywords", db.keywords);
        m.put("lastResult", lastResult.get());
        m.put("expected", expected());
        send(ex, 200, Json.write(m));
    }

    /**
     * 标定「一个真实单元」的耗时（ms）。
     *
     * <p><b>为什么不是测一次盲旋转再乘系数。</b>第一版是跑 8 轮 {@code nativeRunWithCtx}
     * 取平均，结果三次分别得到 289 / 290 / <b>204</b> ms/单元 —— 抖得没法用。原因是
     * 那条路径的累加器小而热、也读不到那张 {@code [C][B_pay][N]} 大表（本配置 135 MB），
     * 而真实查询里列选出来的密文要去读它。两者差 1.4~2.0× 且不稳定，乘一个固定系数是自欺。
     *
     * <p><b>改成直接跑一个真单元。</b>走的就是生产入口
     * {@code nativeCapeAnswer}，唯一改动是把 {@code bPay} 截断到 {@code k} 个载荷块
     * （只影响答案系数个数，不影响 col/row 选择子、表读取模式、CMUX 轮数）。
     * 这样量到的 ms/单元与真实查询同源。代价约 1~2 s，且只在 SETUP 里付一次。
     *
     * <p>因为同一个单元会被跑 {@code k} 条路都算一遍，而真实 ANSWER 也是
     * {@code k × bPay} 个单元，所以 {@code 耗时 / (k × 截断块数)} 直接就是 ms/单元。
     */
    private double measureUnitMs() {
        try {
            final int probeB = Math.min(K, tb.bPay);          // k 个载荷块
            long[] flat = CapeDemoSetupProbe.flatten(tb.p, n, tb.bPay);
            long[] cIdx = new long[K];
            long[] rIdx = new long[K];
            for (int a = 0; a < K; a++) {
                cIdx[a] = tb.colOf[0];
                rIdx[a] = tb.rowOf[0] + a;
            }
            // 预热一次（把 native 内存池、NTT 表、页缓存都跑热）
            NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, probeB, flat, cIdx, rIdx);
            long t0 = System.nanoTime();
            NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, probeB, flat, cIdx, rIdx);
            long t1 = System.nanoTime();
            double ms = (t1 - t0) / 1e6 / (K * probeB);
            System.out.printf("[setup] 标定：一个真实单元 = %.1f ms"
                    + "（跑 %d 路 × %d 块，含 %d 轮 CMUX + %d 次读大表）%n",
                ms, K, probeB, d, tb.c);
            return ms;
        } catch (Throwable ex) {
            System.out.println("[warn] 单元标定失败，回退到旧的一次盲旋转估计：" + ex);
            try {
                int reps = 8;
                long job = NativeBlindRotate.nativePrepare(ctxHandle, d);
                try {
                    NativeBlindRotate.nativeRunWithCtx(ctxHandle, job, 2);
                    long t0 = System.nanoTime();
                    NativeBlindRotate.nativeRunWithCtx(ctxHandle, job, reps);
                    long t1 = System.nanoTime();
                    return (t1 - t0) / 1e6 / reps;
                } finally {
                    NativeBlindRotate.nativeFreeJob(job);
                }
            } catch (Throwable ex2) {
                System.out.println("[warn] 回退也失败：" + ex2);
                return 0;
            }
        }
    }

    /**
     * 前端首屏要显示的「本配置预期」，取代前端里那份硬编码基线
     * （那份一直没跟上 README：前端写 154 000、README 写 176 000、实际最快是 102 000）。
     *
     * <p>数值 = SETUP 时**实测的一个真实单元** × 单元数。测的是生产入口
     * {@code nativeCapeAnswer}（只把载荷块截断到 k），所以读表模式、CMUX 轮数、
     * 选择子构造都与真实查询同源，不是「一次孤立盲旋转 × 修正系数」那种外推。
     */
    private Map<String, Object> expected() {
        Map<String, Object> e = new LinkedHashMap<>();
        int unitCount = K * tb.bPay;
        e.put("unitCount", unitCount);
        e.put("bPay", tb.bPay);
        e.put("d", d);
        e.put("levels", levelsOf(ctxHandle));
        if (unitMsMeasured <= 0) {
            e.put("answerMs", 0);
            e.put("source", "标定失败，无预期值");
            return e;
        }
        e.put("unitMs", Math.round(unitMsMeasured));
        e.put("answerMs", Math.round(unitCount * unitMsMeasured));
        e.put("queryUs", 320);
        e.put("decodeUs", 100);
        e.put("setupMs", setupJavaMs + setupNativeMs);
        e.put("source", "SETUP 时实测一个真实单元（nativeCapeAnswer，载荷块截断到 k）× unitCount");
        e.put("note", "预期值 = 单元实测 × " + unitCount
            + "；与端到端会有几个百分点的出入（不同单元的缓存状态不同），跑一次查询即换成实测");
        return e;
    }

    /** 从 nativeDescribe 文本里取 levels（如 "levels=6"）。 */
    private static int levelsOf(long ctx) {
        String s = NativeBlindRotate.nativeDescribe(ctx);
        int i = s.indexOf("levels=");
        if (i < 0) {
            return -1;
        }
        i += "levels=".length();
        int j = i;
        while (j < s.length() && Character.isDigit(s.charAt(j))) {
            j++;
        }
        return j == i ? -1 : Integer.parseInt(s.substring(i, j));
    }

    /** Curated keyword pairs that are known to return a non-empty answer. */
    private void hPool(HttpExchange ex) throws IOException {
        List<Object> out = new ArrayList<>();
        for (CapeDemoData.PoolEntry e : db.pool) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("kws", Arrays.asList(e.kws));
            one.put("count", e.movies.size());
            out.add(one);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total", out.size());
        m.put("pool", out);
        send(ex, 200, Json.write(m));
    }

    private void hQuery(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        String body = read(ex);
        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) new CapeDemoData.JsonParser(body)
            .parse().v;
        Object kwsObj = req.get("keywords");
        List<String> kws = new ArrayList<>();
        if (kwsObj instanceof List) {
            for (Object o : (List<?>) kwsObj) {
                kws.add(String.valueOf(o));
            }
        }
        if (kws.isEmpty()) {
            send(ex, 200, err("no keywords"));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        currentKws = String.join(" + ", kws);
        try {
            String res = runQuery(kws);
            lastResult.set(res);
            send(ex, 200, res);
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    private void hStatic(HttpExchange ex) throws IOException {
        String p = ex.getRequestURI().getPath();
        if (p.equals("/") || p.isEmpty()) {
            p = "/index.html";
        }
        Path f = webRoot().resolve(p.substring(1)).normalize();
        if (!f.startsWith(webRoot()) || !Files.exists(f)) {
            send(ex, 404, "not found");
            return;
        }
        byte[] b = Files.readAllBytes(f);
        String ct = p.endsWith(".html") ? "text/html; charset=utf-8"
            : p.endsWith(".css") ? "text/css; charset=utf-8"
            : p.endsWith(".js") ? "application/javascript; charset=utf-8"
            : "application/octet-stream";
        ex.getResponseHeaders().set("Content-Type", ct);
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    /**
     * 页面根目录。
     *
     * <p><b>这里以前是坏的</b>：候选只有 {@code cape-demo/web} 和 1~2 级 {@code ..}，
     * 而 {@code run-mpc4j.ps1} 以 {@code coding\rgsw-lab} 为 CWD 跑 java ——
     * 到 {@code coding\cape-demo\web} 要爬 4 级（{@code ../../../../cape-demo/web}），
     * 于是三个候选全落空、{@code GET /} 返回 404：**服务正常但页面打不开**。
     * 同一个坑 {@link CapeDemoSetupProbe#resolveDb} 已经用「多级 .. 回溯」绕过了，
     * 这里补齐到 5 级，并支持 {@code -Dcape.web} 显式指定（启动脚本用它传绝对路径）。
     */
    private static Path webRoot() {
        String forced = System.getProperty("cape.web");
        if (forced != null && !forced.isEmpty()) {
            Path p = Paths.get(forced);
            if (Files.isDirectory(p)) {
                return p.toAbsolutePath().normalize();
            }
        }
        Path base = Paths.get("cape-demo", "web");
        Path[] cands = {
            base,
            Paths.get("..", "cape-demo", "web"),
            Paths.get("..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "..", "..", "cape-demo", "web"),
        };
        for (Path c : cands) {
            if (Files.isDirectory(c)) {
                return c.toAbsolutePath().normalize();
            }
        }
        return base.toAbsolutePath().normalize();
    }

    private static String read(HttpExchange ex) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = ex.getRequestBody()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) {
                bos.write(buf, 0, r);
            }
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    // ------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 3 ? args[3] : "cape-demo/db/keywords.json");

        System.out.println("=== CAPE native demo service ===");
        System.out.printf("[db] %s%n", dbPath);
        CapeDemoData db = CapeDemoData.load(dbPath);
        CapeDemoService svc = new CapeDemoService(port, n, d, db);
        svc.start();
        Thread.currentThread().join();      // serve until killed
    }
}
