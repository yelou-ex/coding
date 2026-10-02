package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Decryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Evaluator;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.RelinKeys;

/**
 * ⚠️ 路线：<b>B（纯 Java 移植版）</b>，不是目标路线 native —— 详见 coding/docs/RLWE路线审计.md。
 *
 * <p>native 侧的等价物在 `coding/native-jni/`：
 * <ul>
 *   <li>{@code src/seal_params_probe.cpp} —— 参数位宽（已成为权威结果：
 *       N=16384 → 9 素数 / 438 位，工作层 8 素数 / 389 位）；</li>
 *   <li>{@code SealPirNativeTest} / {@code NativeApiProbe} —— 真 SEAL 上的打包、旋转、
 *       ct×pt 累加、模数切换、密文×密文（批量 PIR 族接口）。</li>
 * </ul>
 *
 * <p>MPC4J 的 RLWE 能力探针：CAPE 在 RLWE 层需要的四件事能不能做、做得对不对。
 *
 * <p>这不是"能不能编译"的检查，而是把 CAPE 真正要用的运算各跑一遍并核对结果：
 * <ol>
 *   <li>槽打包（BatchEncoder）：一次打包 N 个整数 —— 对应 CAPE 的 Pack/slot 布局</li>
 *   <li>密文×密文 + 重线性化 —— 对应 CtCtMul（自研模块卡在这里）</li>
 *   <li>槽旋转 —— 对应 CtRotate</li>
 *   <li>模数切换 —— 对应 LWE(q=2N) ↔ RLWE(多素数) 的桥，也是响应压缩的手段</li>
 * </ol>
 * 另外读噪声余量（invariant noise budget），这是判断"够不够用"的硬指标。
 */
public class Mpc4jCapability {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        System.out.println("=== MPC4J RLWE 能力探针 ===");
        long tCtx = System.nanoTime();
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.printf("[ctx] N=%d，上下文 + 密钥生成 %.0f ms%n",
            n, (System.nanoTime() - tCtx) / 1e6);
        System.out.println("[params] " + m.describe());
        System.out.println();

        Evaluator ev = m.evaluator;
        Decryptor dec = m.decryptor;
        KeyGenerator kg = m.keyGen;
        BatchEncoder encoder = new BatchEncoder(m.context);
        int slots = encoder.slotCount();
        System.out.println("[slots] 槽数 = " + slots + "（N=" + m.n + "）");
        System.out.println();

        // ---------- A. 重线性化密钥 / 旋转密钥 ----------
        RelinKeys relinKeys = new RelinKeys();
        long t0 = System.nanoTime();
        kg.createRelinKeys(relinKeys);
        long relinMs = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("[key] 重线性化密钥生成 %d ms%n", relinMs);

        GaloisKeys galoisKeys = null;
        String galoisNote;
        t0 = System.nanoTime();
        try {
            galoisKeys = new GaloisKeys();
            kg.createStepGaloisKeys(new int[]{1}, galoisKeys);
            galoisNote = String.format("生成成功 %.1f ms", (System.nanoTime() - t0) / 1_000_000.0);
        } catch (OutOfMemoryError | Exception e) {
            galoisNote = "失败：" + e.getClass().getSimpleName() + " " + e.getMessage();
        }
        System.out.println("[key] 旋转密钥（steps=1）" + galoisNote);
        System.out.println();

        // ---------- B. 槽打包 ----------
        long[] a = new long[slots];
        long[] b = new long[slots];
        for (int i = 0; i < slots; i++) {
            a[i] = (i * 7 + 3) % 1000;
            b[i] = (i * 13 + 5) % 1000;
        }
        Plaintext ptA = new Plaintext();
        Plaintext ptB = new Plaintext();
        encoder.encode(a, ptA);
        encoder.encode(b, ptB);
        Ciphertext ctA = new Ciphertext();
        Ciphertext ctB = new Ciphertext();
        m.encryptor.encryptSymmetric(ptA, ctA);
        m.encryptor.encryptSymmetric(ptB, ctB);
        long[] backA = decode(ev, dec, encoder, ctA, m.n);
        failed += report("A  槽打包 + 加解密往返", diff(a, backA) == 0,
            "错位个数 = " + diff(a, backA) + "，密文 NTT 形式 = " + ctA.isNttForm());

        // ---------- C. 密文×密文 + 重线性化（CtCtMul） ----------
        Ciphertext ctC = new Ciphertext();
        t0 = System.nanoTime();
        ev.multiply(ctA, ctB, ctC);
        long mulMs = (System.nanoTime() - t0) / 1_000_000;
        int noiseBeforeRelin = noise(dec, ctC);
        System.out.printf("[mul] 密文×密文 %d ms，规模 %d → 重线性化前噪声余量 %s bit%n",
            mulMs, ctC.size(), noiseBeforeRelin < 0 ? "n/a" : String.valueOf(noiseBeforeRelin));
        t0 = System.nanoTime();
        ev.relinearizeInplace(ctC, relinKeys);
        long relinOpMs = (System.nanoTime() - t0) / 1_000_000;
        int noiseAfterRelin = noise(dec, ctC);
        System.out.printf("[mul] 重线性化 %d ms，规模 → %d，噪声余量 %s bit%n",
            relinOpMs, ctC.size(), noiseAfterRelin < 0 ? "n/a" : String.valueOf(noiseAfterRelin));

        long[] wantC = new long[slots];
        for (int i = 0; i < slots; i++) {
            wantC[i] = (a[i] * b[i]) % m.t;
        }
        long[] gotC = decode(ev, dec, encoder, ctC, m.n);
        failed += report("B  密文×密文 + 重线性化 = 逐槽乘积", diff(wantC, gotC) == 0,
            "错位个数 = " + diff(wantC, gotC) + "/" + slots + "，最终规模 = " + ctC.size());

        // ---------- D. 槽旋转（CtRotate） ----------
        if (galoisKeys == null) {
            failed += report("C  槽旋转", false, "旋转密钥不可用：" + galoisNote);
        } else {
            Ciphertext ctR = new Ciphertext();
            ctR.copyFrom(ctA);
            t0 = System.nanoTime();
            ev.rotateRowsInplace(ctR, 1, galoisKeys);
            long rotMs = (System.nanoTime() - t0) / 1_000_000;
            long[] gotR = decode(ev, dec, encoder, ctR, m.n);
            // 不去猜 SEAL 的左右方向，两个都试，把实际方向测出来
            boolean left = matchesRowRotation(a, gotR, slots, 1);
            boolean right = matchesRowRotation(a, gotR, slots, -1);
            failed += report("C  槽旋转（rotateRows 1 步）", left || right,
                String.format("%d ms，实测方向 = %s", rotMs,
                    left ? "正向（槽下标 +1）" : right ? "反向（槽下标 −1）" : "两边都不匹配"));
        }

        // ---------- E. 模数切换（LWE ↔ RLWE 的桥） ----------
        Ciphertext ctS = new Ciphertext();
        ctS.copyFrom(ctA);
        if (ctS.isNttForm()) {
            ev.transformFromNttInplace(ctS);   // BFV 的模数切换不能在 NTT 形式下做
        }
        int noiseBeforeSwitch = noise(dec, ctS);
        String switchNote;
        boolean switchOk = false;
        long[] gotS = null;
        try {
            ev.modSwitchToNextInplace(ctS);
            gotS = decode(ev, dec, encoder, ctS, m.n);
            switchOk = diff(a, gotS) == 0;
            switchNote = String.format("工作层素数 %d 个 → %d 个，噪声余量 %s → %s bit",
                m.workingPrimeCount, m.workingPrimeCount - 1,
                noiseBeforeSwitch < 0 ? "n/a" : String.valueOf(noiseBeforeSwitch),
                noise(dec, ctS) < 0 ? "n/a" : String.valueOf(noise(dec, ctS)));
        } catch (OutOfMemoryError | Exception e) {
            switchNote = "失败：" + e.getClass().getSimpleName() + " " + e.getMessage();
        }
        failed += report("D  模数切换后仍能正确解密", switchOk, switchNote
            + (switchOk ? "" : "，错位个数 = " + (gotS == null ? "异常" : String.valueOf(diff(a, gotS)))));

        System.out.println();
        System.out.println(failed == 0 ? "=== 结论：CAPE 需要的 RLWE 能力在 MPC4J 上全部可用 ==="
            : "=== 有 " + failed + " 项不可用或不对 ===");
    }

    // ---------------- 工具 ----------------

    private static long[] decode(Evaluator ev, Decryptor dec, BatchEncoder encoder,
                                 Ciphertext ct, int n) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            ev.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(n);
        dec.decrypt(copy, pt);
        long[] out = new long[encoder.slotCount()];
        encoder.decode(pt, out);
        return out;
    }

    /** 噪声余量；SEAL 对形式有要求时可能抛异常，这里统一降级成 -1 */
    private static int noise(Decryptor dec, Ciphertext ct) {
        try {
            return dec.invariantNoiseBudget(ct);
        } catch (OutOfMemoryError | Exception e) {
            return -1;
        }
    }

    /** 按 SEAL 的两行布局检查"行内旋转 +step"是否吻合 */
    private static boolean matchesRowRotation(long[] src, long[] got, int slots, int step) {
        int half = slots / 2;
        for (int r = 0; r < 2; r++) {
            for (int j = 0; j < half; j++) {
                int jj = ((j + step) % half + half) % half;
                if (src[r * half + jj] != got[r * half + j]) {
                    return false;
                }
            }
        }
        return true;
    }

    private static int diff(long[] a, long[] b) {
        int c = 0;
        for (int i = 0; i < a.length && i < b.length; i++) {
            if (a[i] != b[i]) {
                c++;
            }
        }
        return c;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
