package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * 验证 <b>一般多项式消息的 RGSW</b>：{@code RGSW(m) ⊗ ct} 应当解密为 {@code m ⊛ msg}
 * （负循环环 Z_t[X]/(X^N+1) 上的卷积）。
 *
 * <p>这是"完成盲旋转"的关键一步：有了它，服务器就能在不知道密钥 s 的前提下
 * 用 {@code RGSW(s)} 把一条密文乘上 s（相位变成 phase(Q)·s），
 * 从而从加密查询里导出控制位——这是 Pirouette/OnionPIR 的手法，不需要 circuit bootstrapping。
 */
public class RgswPolyTest {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== RGSW 一般多项式消息验证 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20260919L);
        long[] msg = new long[n];
        for (int i = 0; i < n; i++) {
            msg[i] = (i % 1000) + 1;
        }
        Ciphertext ct = m.encrypt(msg);
        long t = m.t;

        // ---- 用例 1：小系数多项式（±100）----
        long[] poly = new long[n];
        for (int i = 0; i < n; i++) {
            poly[i] = rnd.nextInt(201) - 100;
        }
        long[] polyMod = toModT(poly, t);
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw r1 = m.encryptRgswPoly(polyMod);
        long buildMs = ms(t0);
        t0 = System.nanoTime();
        Ciphertext p1 = m.externalProduct(r1, ct);
        long prodMs = ms(t0);
        long[] got1 = m.decrypt(p1);
        long[] want1 = convolve(polyMod, msg, t, n);
        int d1 = diff(got1, want1);
        failed += report("1  RGSW(多项式) ⊗ ct = m ⊛ msg", d1 == 0,
            String.format("构造 %d ms、外部乘积 %d ms；错位 %d/%d（首个系数 got=%d want=%d）",
                buildMs, prodMs, d1, n, got1[0], want1[0]));

        // ---- 用例 2：与常数版一致（m = μ·X^0 应等价于 encryptRgswConstant）----
        long[] constPoly = new long[n];
        constPoly[0] = 1;
        Mpc4jRgsw.Rgsw rConst = m.encryptRgswPoly(constPoly);
        long[] gotC = m.decrypt(m.externalProduct(rConst, ct));
        Mpc4jRgsw.Rgsw rOld = m.encryptRgswConstant(1);
        long[] gotO = m.decrypt(m.externalProduct(rOld, ct));
        int dC = diff(gotC, gotO);
        failed += report("2  多项式版在常数情形与常数版一致", dC == 0,
            String.format("两者差 %d/%d 个系数（都应等于原消息）", dC, n));

        // ---- 用例 3：m = 三元小多项式（与密钥同分布，正是 enc_sk 的形态）----
        long[] tern = new long[n];
        for (int i = 0; i < n; i++) {
            tern[i] = rnd.nextInt(3) - 1;
        }
        long[] ternMod = toModT(tern, t);
        Mpc4jRgsw.Rgsw r3 = m.encryptRgswPoly(ternMod);
        long[] got3 = m.decrypt(m.externalProduct(r3, ct));
        long[] want3 = convolve(ternMod, msg, t, n);
        int d3 = diff(got3, want3);
        failed += report("3  RGSW(三元多项式) ⊗ ct = m ⊛ msg", d3 == 0,
            String.format("错位 %d/%d", d3, n));

        System.out.println();
        System.out.println(failed == 0
            ? "=== 一般多项式 RGSW 通过：服务器可在不知 s 的前提下乘上 s ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long[] toModT(long[] v, long t) {
        long[] out = new long[v.length];
        for (int i = 0; i < v.length; i++) {
            out[i] = ((v[i] % t) + t) % t;
        }
        return out;
    }

    /** 负循环卷积：c_i = Σ_{j≤i} a_j·b_{i−j} − Σ_{j>i} a_j·b_{i−j+N}  (mod t) */
    private static long[] convolve(long[] a, long[] b, long t, int n) {
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            long acc = 0;
            for (int j = 0; j < n; j++) {
                int d = i - j;
                if (d >= 0) {
                    acc += a[j] * b[d];
                } else {
                    acc -= a[j] * b[d + n];
                }
            }
            out[i] = ((acc % t) + t) % t;
        }
        return out;
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

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
