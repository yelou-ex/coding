package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * 盲旋转（口径 2 = CAPE 口径）的压力测试——专门打现有自检<b>没有覆盖</b>的两件事：
 *
 * <ol>
 *   <li><b>轮数</b>：现有自检只跑过 d=64；CAPE 的真实参数是 d=512。逐轮 CMUX 的噪声是累加的，
 *       d 从 64 涨到 512 会不会塌？</li>
 *   <li><b>索引噪声</b>：现有自检里 LWE 索引密文是 <b>e=0（无噪声）</b> 造的
 *       （{@code b = ⟨a,s⟩ + r}，没有误差项）。真实 LWE 一定有噪声。噪声会不会把
 *       旋转量整体推偏、从而选错条目？</li>
 * </ol>
 *
 * <p>跑法：{@code run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateStress 2048}
 */
public class BlindRotateStress {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 2048;
        int qL = 2 * n;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("=== 盲旋转压力测试（口径 2 = CAPE 口径）===");
        System.out.println("[params] " + m.describe() + ", q_L = 2N = " + qL);
        System.out.println();

        Random rnd = new Random(20260919L);
        long[] p = new long[n];
        for (int i = 0; i < n; i++) {
            p[i] = (i % 1000) + 1;
        }
        Ciphertext acc = m.encrypt(p);
        long index = 1234;

        // ---------------- 1) 轮数扫描 ----------------
        System.out.println("--- 1) 轮数扫描：d = LWE 维数，无噪声索引 ---");
        int maxBroken = 0;
        for (int d : new int[]{64, 128, 256, 512}) {
            int[] s = new int[d];
            for (int i = 0; i < d; i++) {
                s[i] = rnd.nextInt(2);
            }
            long t0 = System.nanoTime();
            Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
            for (int i = 0; i < d; i++) {
                bk[i] = m.encryptRgswConstant(s[i]);
            }
            long keyMs = (System.nanoTime() - t0) / 1_000_000;

            long[] a = new long[d];
            long sum = 0;
            for (int i = 0; i < d; i++) {
                a[i] = Math.floorMod(rnd.nextLong(), qL);
                sum = (sum + a[i] * s[i]) % qL;
            }
            long beta = Math.floorMod(sum + index, qL);

            t0 = System.nanoTime();
            long[] got = m.decrypt(BlindRotateOps.blindRotate(m, bk, acc, a, beta));
            long brMs = (System.nanoTime() - t0) / 1_000_000;
            int match = countMatch(got, p, index, m.t, n);
            boolean ok = got[0] == p[(int) index];
            if (!ok) {
                maxBroken = d;
            }
            System.out.printf("  d=%3d | 密钥 %5d ms | 盲旋转 %5d ms | 常数位 got=%d want=%d %s | 整条 %d/%d%n",
                d, keyMs, brMs, got[0], p[(int) index], ok ? "OK" : "**FAIL**", match, n);
            bk = null;
        }
        System.out.println(maxBroken == 0
            ? "  → d 到 512 全过：轮数累加在这一档参数下没塌。"
            : "  → d=" + maxBroken + " 起失败：轮数累加会塌。");
        System.out.println();

        // ---------------- 2) 索引噪声扫描 ----------------
        int d = 512;
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        long[] a = new long[d];
        long sum = 0;
        for (int i = 0; i < d; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + a[i] * s[i]) % qL;
        }

        System.out.println("--- 2) 索引噪声扫描（d=512）：β = ⟨a,s⟩ + r + e，看 e≠0 会怎样 ---");
        System.out.println("      若 got == p[r+e]，说明噪声<b>干净地把旋转量推偏一格</b>（选错条目）；");
        System.out.println("      若既不是 p[r] 也不是 p[r+e]，说明是噪声污染。");
        for (long e : new long[]{0, 1, 2, 3, 4, 8, 64, 256, -1, -2, -4}) {
            long beta = Math.floorMod(sum + index + e, qL);
            long[] got = m.decrypt(BlindRotateOps.blindRotate(m, bk, acc, a, beta));
            long wantR = p[(int) index];
            long wantShift = p[(int) Math.floorMod(index + e, n)];
            String verdict;
            if (got[0] == wantR) {
                verdict = "= p[r]  ✅ 正确";
            } else if (got[0] == wantShift) {
                verdict = "= p[r+e]  ⚠️ 整体推移 " + e + " 格（选错条目）";
            } else {
                verdict = "既非 p[r] 也非 p[r+e]  ❌ 噪声污染";
            }
            System.out.printf("  e=%5d | 常数位=%6d | p[r]=%d p[r+e]=%d | %s%n",
                e, got[0], wantR, wantShift, verdict);
        }
    }

    private static int countMatch(long[] got, long[] p, long index, long t, int n) {
        int match = 0;
        for (int i = 0; i < n; i++) {
            int src = (int) ((i + index) % n);
            long expect = (i + index) < n ? p[src] : (p[src] == 0 ? 0 : t - p[src]);
            if (got[i] == expect) {
                match++;
            }
        }
        return match;
    }
}
