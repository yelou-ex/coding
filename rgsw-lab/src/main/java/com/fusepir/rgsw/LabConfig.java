package com.fusepir.rgsw;

/*
 * !!! ROUTE C - self-built RLWE, DEPRECATED, NOT THE DEFAULT !!!
 *
 * Default implementation (route B): the sibling Mpc4jRgsw.java (RGSW / external
 * product / CMUX) and BlindRotateOps.java (blind rotation). They run on
 * coding/lib/mpc4j-crypto-fhe-seal.jar - MPC4J's pure-Java SEAL port, patched so
 * that the Galois permutation tables are lazily allocated - and are verified at
 * the paper's parameters (N=16384, t=65537, 9 declared primes).
 *
 * This file is kept only as a cross-check tool. See coding/docs/RLWE路线审计.md.
 */


import com.fusepir.rlwe.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * 参数装载：让参数可以"改文件不改代码"。
 *
 * <p>取值优先级：<b>系统环境变量 &gt; params.env 文件 &gt; 代码默认值</b>。
 * 所以临时试一组参数可以在命令行直接设，例如
 * <pre>  $env:RGSW_BASE=256; .\run.ps1</pre>
 *
 * <p>文件格式就是最简单的 <code>KEY=VALUE</code>，<code>#</code> 开头是注释。
 */
public final class LabConfig {
    /** 运行模式：test / scale / sweep */
    public final String mode;
    /** 多项式次数 */
    public final int n;
    /** 素数个数（1 或 2） */
    public final int primes;
    /** 每个素数的位宽 */
    public final int primeBits;
    /** gadget 基数 */
    public final int base;
    /** gadget 层数；0 表示按 B^l > q 自动取最小值 */
    public final int levels;
    /** 噪声分布参数 */
    public final int noiseBits;
    /** 明文模数 */
    public final long t;
    /** 每项测试重复次数 */
    public final int trials;
    /** scale 模式的 N */
    public final int scaleN;
    /** sweep 模式的 N */
    public final int sweepN;

    private LabConfig(Map<String, String> c) {
        this.mode = str(c, "RGSW_MODE", "test");
        this.n = num(c, "RGSW_N", 1024);
        this.primes = num(c, "RGSW_PRIMES", 1);
        this.primeBits = num(c, "RGSW_PRIME_BITS", 31);
        this.base = num(c, "RGSW_BASE", 4);
        this.levels = num(c, "RGSW_LEVELS", 0);
        this.noiseBits = num(c, "RGSW_NOISE_BITS", 4);
        this.t = num(c, "RGSW_T", 65537);
        this.trials = num(c, "RGSW_TRIALS", 4);
        this.scaleN = num(c, "RGSW_SCALE_N", 16384);
        this.sweepN = num(c, "RGSW_SWEEP_N", 512);
    }

    /** 从环境变量 + params.env 装载 */
    public static LabConfig load() {
        Map<String, String> conf = new HashMap<>();
        // 先读文件
        String envFile = System.getenv("RGSW_ENV_FILE");
        Path path = envFile != null ? Paths.get(envFile) : Paths.get("params.env");
        if (Files.exists(path)) {
            try {
                List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) {
                        continue;
                    }
                    int eq = line.indexOf('=');
                    conf.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            } catch (IOException e) {
                System.out.println("[config] cannot read " + path.toAbsolutePath() + ": " + e.getMessage());
            }
        } else {
            System.out.println("[config] " + path.toAbsolutePath() + " not found, using defaults");
        }
        // 环境变量覆盖文件
        for (String key : new String[]{"RGSW_MODE", "RGSW_N", "RGSW_PRIMES", "RGSW_PRIME_BITS",
            "RGSW_BASE", "RGSW_LEVELS", "RGSW_NOISE_BITS", "RGSW_T", "RGSW_TRIALS",
            "RGSW_SCALE_N", "RGSW_SWEEP_N"}) {
            String v = System.getenv(key);
            if (v != null && !v.isEmpty()) {
                conf.put(key, v);
            }
        }
        return new LabConfig(conf);
    }

    /** 按当前配置生成环参数 */
    public RingParams toRingParams() {
        return build(n, primes, primeBits, base, levels, noiseBits, t);
    }

    /** 按给定 N 生成环参数（scale / sweep 用） */
    public RingParams toRingParams(int degree) {
        return build(degree, primes, primeBits, base, levels, noiseBits, t);
    }

    /** 组装参数对象；levels = 0 表示自动 */
    public static RingParams build(int n, int primeCount, int primeBits, int base,
                                   int levels, int noiseBits, long t) {
        if (primeCount < 1 || primeCount > 16) {
            throw new IllegalArgumentException("RGSW_PRIMES 必须落在 1..16，实际为 " + primeCount);
        }
        long[] primes = new long[primeCount];
        long cursor = 0; // 下一个素数的搜索起点（相对 2^(bits-1) 的偏移）
        for (int i = 0; i < primeCount; i++) {
            // 用 NTT 友好的素数（满足 2N | p-1）：这样环乘法走 NTT 而不是 O(N^2)。
            // 每次从"上一个素数之后"继续找，避免重复（重复会让 CRT 的逆元不存在）。
            primes[i] = NttContext.findPrime(primeBits, n, cursor);
            cursor = primes[i] - (1L << (primeBits - 1)) + 1;
        }
        java.math.BigInteger q = java.math.BigInteger.ONE;
        for (long p : primes) {
            q = q.multiply(java.math.BigInteger.valueOf(p));
        }
        int l = levels > 0 ? levels : RingParams.autoLevels(base, q);
        String name = String.format("custom(p=%d,bits=%d,B=%d)", primeCount, primeBits, base);
        return new RingParams(name, n, primes, t, base, l, noiseBits);
    }

    public String describe() {
        return String.format(
            "mode=%s, N=%d, primes=%d x %d bit, base=%d, levels=%s, noiseBits=%d, t=%d, trials=%d",
            mode, n, primes, primeBits, base, levels == 0 ? "auto" : String.valueOf(levels),
            noiseBits, t, trials);
    }

    // ---------- 取值工具 ----------

    private static String str(Map<String, String> c, String key, String def) {
        String v = c.get(key);
        return v == null || v.isEmpty() ? def : v;
    }

    private static int num(Map<String, String> c, String key, int def) {
        String v = c.get(key);
        if (v == null || v.isEmpty()) {
            return def;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            System.out.println("[config] bad value for " + key + ": " + v + " (using " + def + ")");
            return def;
        }
    }

    private static long num(Map<String, String> c, String key, long def) {
        String v = c.get(key);
        if (v == null || v.isEmpty()) {
            return def;
        }
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            System.out.println("[config] bad value for " + key + ": " + v + " (using " + def + ")");
            return def;
        }
    }
}
