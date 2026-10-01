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
    // t 与 gadget 基位宽可覆盖：验证「抬 t 换大 base」时用
    //   -Dcape.t=4294967296 -Dcape.b=32
    private static final long T = Long.getLong("cape.t", 65537L);
    private static final int BASE_BITS = Integer.getInteger("cape.b", 16);
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

    // ---- last query, for polling ----
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final AtomicReference<String> lastResult = new AtomicReference<>("{}");
    private volatile String currentKws = "";

    private CapeDemoService(int port, int n, int d, CapeDemoData db) throws IOException {
        this.port = port;
        this.n = n;
        this.d = d;
        this.db = db;

        int maxValues = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = Math.max(1, R / maxValues);
        int C = Math.max(1, (kwTotal + cellsPerCol - 1) / cellsPerCol);

        long j0 = System.nanoTime();
        this.tb = db.buildTables(n, C, R, K, T, SEED);
        this.tableFlat = CapeDemoSetupProbe.flatten(tb.p, n, tb.bPay);
        this.setupJavaMs = (System.nanoTime() - j0) / 1_000_000;

        long n0 = System.nanoTime();
        this.ctxHandle = NativeBlindRotate.nativeCreateContext(n, T, BASE_BITS);
        long kh = NativeBlindRotate.nativeBuildBootstrapKey(ctxHandle, d);
        NativeBlindRotate.nativeDestroyKey(kh);   // nativeCapeAnswer rebuilds it per call
        this.setupNativeMs = (System.nanoTime() - n0) / 1_000_000;
        this.setupAt = java.time.LocalDateTime.now().toString();
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
        params.put("t", T);
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
        send(ex, 200, Json.write(m));
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

    private static Path webRoot() {
        for (String c : new String[]{"cape-demo/web", "../cape-demo/web", "../../cape-demo/web"}) {
            Path p = Paths.get(c);
            if (Files.isDirectory(p)) {
                return p.toAbsolutePath().normalize();
            }
        }
        return Paths.get("cape-demo/web").toAbsolutePath().normalize();
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
