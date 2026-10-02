package com.fusepir.probe;


import com.fusepir.prim.*;
import com.fusepir.bff.*;
import com.fusepir.demo.*;
import com.fusepir.nativejni.NativeBlindRotate;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <b>Step 1 of the demo-frontend plan: measure SETUP.</b>
 *
 * <p>Why this class exists: {@code CapeEndToEnd4} times only ANSWER (its two
 * {@code nanoTime} calls bracket the blind rotation), so the SETUP cost has never been
 * measured. The frontend's first panel is supposed to show it, and inventing a number
 * for that panel is not acceptable.
 *
 * <p>SETUP is deliberately split into its two very different halves:
 * <ul>
 *   <li><b>纯 Java 侧</b>：载荷、Bloom 位、BFF 三份份额、明文表 {@code P}；
 *   <li><b>native 侧</b>：{@code nativeCreateContext}（建 SEALContext + 各编解码器）
 *       与 {@code nativeBuildBootstrapKey}（{@code d} 个 RGSW 引导密钥，每个
 *       {@code 2 x levels} 次 {@code encrypt_symmetric}）。
 * </ul>
 * The split matters because only the native half can be avoided by caching the key in
 * native memory; the Java half is cheap but must be redone if the DB changes.
 *
 * <p>Usage: {@code .\run-mpc4j.ps1 -Class com.fusepir.probe.CapeDemoSetupProbe [N] [d] [jsonPath] [alsoAnswer]}
 */
public final class CapeDemoSetupProbe {

    private CapeDemoSetupProbe() {
    }

    /**
     * Resolves the demo DB path. The run scripts start java from several different
     * working directories, so a bare relative path is not reliable.
     */
    public static Path resolveDb(String given) {
        Path p = Paths.get(given);
        if (p.isAbsolute()) {
            return p;
        }
        Path[] cands = {
            p,
            Paths.get("..", given),
            Paths.get("..", "..", given),
            Paths.get("..", "..", "..", given),
        };
        for (Path c : cands) {
            if (java.nio.file.Files.exists(c)) {
                return c.toAbsolutePath().normalize();
            }
        }
        return p.toAbsolutePath().normalize();
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int d = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        Path json = resolveDb(args.length > 2 ? args[2] : "cape-demo/db/keywords.json");
        boolean alsoAnswer = args.length > 3 && Boolean.parseBoolean(args[3]);

        System.out.println("=== CAPE SETUP timing probe (demo frontend, plan step 1) ===");
        System.out.printf("[input] N=%d  d=%d  db=%s%n%n", n, d, json);

        // ---------- Java-side SETUP ----------
        long t0 = System.nanoTime();
        CapeDemoData db = CapeDemoData.load(json);
        long tLoad = System.nanoTime() - t0;

        // ---- grid geometry ----
        // A keyword uses one cell; the k BFF shares sit in that cell's column at
        // k consecutive rows. So a cell costs maxValues rows and a column holds
        // floor(R/maxValues) cells; we add columns until every keyword fits.
        final int R = 16;
        final int K = 3;
        final long T = 65537L;
        int maxValuesMeta = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = Math.max(1, R / maxValuesMeta);
        int C = Math.max(1, (kwTotal + cellsPerCol - 1) / cellsPerCol);

        System.out.printf("[db] keywords=%d valueSpace=%d pool=%d assoc=%d%n",
            kwTotal, db.valueSpace.size(), db.pool.size(), db.intMeta("assoc", -1));
        System.out.printf("[grid] R=%d maxValues=%d => %d cells/col => C=%d (capacity %d >= %d)%n%n",
            R, maxValuesMeta, cellsPerCol, C, C * cellsPerCol, kwTotal);

        long t1 = System.nanoTime();
        CapeDemoData.Tables tb = db.buildTables(n, C, R, K, T, 20261013L);
        long tTables = System.nanoTime() - t1;

        int bPay = tb.bPay;
        int lBf = tb.lBf;
        int units = K * bPay;
        System.out.println("---------------- Java-side SETUP ----------------");
        System.out.printf("  JSON load                          : %8.1f ms%n", tLoad / 1e6);
        System.out.printf("  payload + P tables                 : %8.1f ms%n", tTables / 1e6);
        System.out.printf("    B_pay = %d, l_BF = %d, P = %d x %d x %d = %.1f MB%n",
            bPay, lBf, C, bPay, n, (double) C * bPay * n * 8 / (1024 * 1024));
        System.out.printf("  units (k x B_pay) = %d%n%n", units);

        // ---------- native-side SETUP ----------
        System.out.println("---------------- native-side SETUP ---------------");
        long t2 = System.nanoTime();
        long h = NativeBlindRotate.nativeCreateContext(n, T, 16);
        long tCtx = System.nanoTime() - t2;
        System.out.printf("  nativeCreateContext(N=%d)          : %8.1f ms%n", n, tCtx / 1e6);
        System.out.println("    " + NativeBlindRotate.nativeDescribe(h));

        long t3 = System.nanoTime();
        long kh = NativeBlindRotate.nativeBuildBootstrapKey(h, d);
        long tKey = System.nanoTime() - t3;
        System.out.printf("  nativeBuildBootstrapKey(d=%d)      : %8.1f ms%n", d, tKey / 1e6);

        long setupJavaMs = (tLoad + tTables) / 1_000_000;
        long setupNativeMs = (tCtx + tKey) / 1_000_000;
        System.out.printf("%n================ SETUP TOTAL ================%n");
        System.out.printf("  Java side   : %8d ms%n", setupJavaMs);
        System.out.printf("  native side : %8d ms%n", setupNativeMs);
        System.out.printf("  TOTAL       : %8d ms   (= %.1f s)%n",
            setupJavaMs + setupNativeMs, (setupJavaMs + setupNativeMs) / 1000.0);

        // ---------- optional: one ANSWER, for the ratio ----------
        if (alsoAnswer) {
            long[] tableFlat = flatten(tb.p, n, bPay);
            long[] cIdx = new long[K];
            long[] rIdx = new long[K];
            for (int a = 0; a < K; a++) {
                cIdx[a] = tb.colOf[0];
                rIdx[a] = tb.rowOf[0] + a;   // k shares: same column, consecutive rows
            }
            System.out.printf("%n---------------- ANSWER (1 unit x %d) ----------------%n", units);
            long t4 = System.nanoTime();
            long[] rec = NativeBlindRotate.nativeCapeAnswer(h, d, C, K, bPay, tableFlat, cIdx, rIdx);
            long tAns = System.nanoTime() - t4;
            System.out.printf("  ANSWER = %d ms  (%.2f ms/unit)%n", tAns / 1_000_000,
                tAns / 1e6 / units);
            int bad = 0;
            int firstBad = -1;
            for (int b = 0; b < bPay; b++) {
                if (rec[b] != tb.payload[0][b]) {
                    if (firstBad < 0) {
                        firstBad = b;
                    }
                    bad++;
                }
            }
            System.out.printf("  payload mismatch: %d / %d  => %s%n", bad, bPay,
                bad == 0 ? "PASS" : "FAIL");
            if (firstBad >= 0) {
                System.out.printf("  first bad index %d: got %d, want %d%n",
                    firstBad, rec[firstBad], tb.payload[0][firstBad]);
                int lo = Math.max(0, firstBad - 3);
                int hi = Math.min(bPay, firstBad + 4);
                for (int b = lo; b < hi; b++) {
                    System.out.printf("    [%3d] got=%-12d want=%-12d %s%n",
                        b, rec[b], tb.payload[0][b], rec[b] == tb.payload[0][b] ? "" : "<-- dif");
                }
            }
            System.out.printf("  SETUP / ANSWER ratio = %.2f x%n",
                (setupJavaMs + setupNativeMs) / (tAns / 1e6));
        }

        NativeBlindRotate.nativeDestroyKey(kh);
        NativeBlindRotate.nativeDestroyContext(h);
    }

    public static long[] flatten(long[][][] p, int n, int bPay) {
        long[] flat = new long[p.length * bPay * n];
        int ptr = 0;
        for (int c = 0; c < p.length; c++) {
            for (int b = 0; b < bPay; b++) {
                System.arraycopy(p[c][b], 0, flat, ptr, n);
                ptr += n;
            }
        }
        return flat;
    }
}
