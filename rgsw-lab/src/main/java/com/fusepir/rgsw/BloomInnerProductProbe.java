package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;

/**
 * 判定实验：<b>Bloom 的二进制同态内积到底该在哪个域做？</b>
 *
 * <h3>背景</h3>
 * CAPE 的 Bloom 打分为
 * <pre>
 *   ct_score,j ← CtCtMul(q_BF, ct_j^BF)
 *   for r = 0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
 * </pre>
 * 姊妹论文 BKPIR 把这一族算子定义为 <b>SIMD / slot-wise</b>。若如此，则
 * {@code CtCtMul} 是<b>逐槽相乘</b>，折叠是"把所有槽汇总" ⇒ 内积。
 * 但若数据摆在<b>系数</b>上，{@code CtCtMul} 是<b>卷积</b>，折叠会把所有系数求和：
 * <pre>
 *   Σ_k (a⊛b)_k = (Σ_i a_i)(Σ_j b_j) = |a|·|b|      ← 两个汉明重量之积，与查询无关
 * </pre>
 * 那就永远算不出内积。
 *
 * <p>本类把两条路都跑一遍，用结果裁决：
 * <ul>
 *   <li><b>A 槽位域</b>：预期 A1 逐点 = AND、A2 折叠 = 内积 ✅</li>
 *   <li><b>B 系数域</b>：预期"全部系数之和" = |a|·|b|，<b>不等于</b>内积 ❌</li>
 * </ul>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.BloomInnerProductProbe 2048}
 */
public final class BloomInnerProductProbe {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        long t = 65537L;
        Mpc4jRgsw m = new Mpc4jRgsw(n, t, 0, 1 << 16);
        System.out.println("=== Bloom 二进制同态内积：槽位域 vs 系数域 ===");
        System.out.println("[params] " + m.describe());
        System.out.println();

        BatchEncoder be = new BatchEncoder(m.context);
        int slots = be.slotCount();
        System.out.printf("[slots] 槽数 = %d（N = %d）%n%n", slots, n);

        // 两组二进制向量（模拟 b_qry 与某个候选的 b_v）
        long[] a = new long[slots];
        long[] b = new long[slots];
        for (int i = 0; i < slots; i++) {
            a[i] = (i % 3 == 0) ? 1 : 0;
            b[i] = (i % 5 == 0) ? 1 : 0;
        }
        long inner = 0, wa = 0, wb = 0;
        for (int i = 0; i < slots; i++) {
            inner += a[i] * b[i];
            wa += a[i];
            wb += b[i];
        }
        System.out.printf("[truth] <a,b> = %d ;  |a| = %d ;  |b| = %d ;  |a|·|b| = %d%n%n",
            inner, wa, wb, wa * wb);

        RelinKeys rk = new RelinKeys();
        m.keyGen.createRelinKeys(rk);

        // ================= A) 槽位域 =================
        Plaintext pa = new Plaintext();
        Plaintext pb = new Plaintext();
        be.encode(a, pa);
        be.encode(b, pb);
        Ciphertext ca = new Ciphertext();
        Ciphertext cb = new Ciphertext();
        m.encryptor.encryptSymmetric(pa, ca);
        m.encryptor.encryptSymmetric(pb, cb);

        Ciphertext prod = new Ciphertext();
        m.evaluator.multiply(ca, cb, prod);
        m.evaluator.relinearizeInplace(prod, rk);

        long[] pointwise = decodeSlots(m, be, prod, slots);
        int diff = 0;
        for (int i = 0; i < slots; i++) {
            if (pointwise[i] != a[i] * b[i]) {
                diff++;
            }
        }
        report("A1 槽位域：CtCtMul 得到【逐槽】乘积（= 按位 AND）", diff == 0,
            String.format("错位 %d/%d（前 8 个: %s）", diff, slots, first(pointwise, 8)));

        // 折叠：按 2^r 做槽旋转再自加 → 每个槽变成"本行全部槽之和"
        int[] steps = new int[Integer.numberOfTrailingZeros(n / 2)];
        for (int r = 0; r < steps.length; r++) {
            steps[r] = 1 << r;
        }
        GaloisKeys gk = new GaloisKeys();
        m.keyGen.createStepGaloisKeys(steps, gk);
        Ciphertext folded = new Ciphertext();
        folded.copyFrom(prod);
        for (int r = 1; r < n / 2; r *= 2) {
            Ciphertext tmp = new Ciphertext();
            tmp.copyFrom(folded);
            m.evaluator.rotateRowsInplace(tmp, r, gk);
            m.evaluator.addInplace(folded, tmp);
        }
        long[] fv = decodeSlots(m, be, folded, slots);
        int half = slots / 2;
        long row0Inner = 0, row1Inner = 0;
        for (int i = 0; i < half; i++) {
            row0Inner += a[i] * b[i];
            row1Inner += a[half + i] * b[half + i];
        }
        boolean row0ok = true, row1ok = true;
        for (int i = 0; i < half; i++) {
            if (fv[i] != row0Inner) {
                row0ok = false;
            }
            if (fv[half + i] != row1Inner) {
                row1ok = false;
            }
        }
        report("A2 槽位域：折叠（Σ CtRotate(·,2^r)）把每个槽变成【本行内积】",
            row0ok && row1ok,
            String.format("第0行全槽 = %d（期望 %d）→ %b；第1行全槽 = %d（期望 %d）→ %b；两行相加 = %d vs <a,b> = %d",
                fv[0], row0Inner, row0ok, fv[half], row1Inner, row1ok, row0Inner + row1Inner, inner));

        // ================= B) 系数域 =================
        // 先确认 Plaintext(long[]) 到底是"系数"还是"槽位"语义：加密再解密应当原样回来
        long[] roundTrip = m.decrypt(m.encrypt(a));
        int rtDiff = 0;
        for (int i = 0; i < n; i++) {
            if (roundTrip[i] != a[i]) {
                rtDiff++;
            }
        }
        report("B0 编码语义确认：Plaintext(long[]) 是【系数】语义（往返逐位相等）", rtDiff == 0,
            String.format("往返错位 %d/%d；加密后密文 NTT 形式 = %b", rtDiff, n, m.encrypt(a).isNttForm()));

        System.out.println();
        System.out.println("[B] 系数域：多组向量对照（若 Σ系数 恒等于 <a,b>，说明这里其实也是槽位语义）");
        System.out.printf("     %-10s %-12s %-14s %-14s %-10s%n", "向量对", "<a,b> mod t", "|a|·|b| mod t", "Σ系数 mod t", "等于谁");
        int[][] pairs = {{3, 5}, {7, 11}, {2, 3}, {9, 4}};
        boolean anyEqualsInner = false;
        boolean anyEqualsWeight = false;
        for (int[] pair : pairs) {
            long[] x = new long[n];
            long[] y = new long[n];
            long xi = 0, wx = 0, wy = 0;
            for (int i = 0; i < n; i++) {
                x[i] = (i % pair[0] == 0) ? 1 : 0;
                y[i] = (i % pair[1] == 0) ? 1 : 0;
                xi += x[i] * y[i];
                wx += x[i];
                wy += y[i];
            }
            Plaintext cpx = new Plaintext(x);
            Plaintext cpy = new Plaintext(y);
            Ciphertext ccx = new Ciphertext();
            Ciphertext ccy = new Ciphertext();
            m.encryptor.encryptSymmetric(cpx, ccx);
            m.encryptor.encryptSymmetric(cpy, ccy);
            Ciphertext cp = new Ciphertext();
            m.evaluator.multiply(ccx, ccy, cp);
            m.evaluator.relinearizeInplace(cp, rk);
            long[] cf = m.decrypt(cp);
            long s = 0;
            for (int i = 0; i < n; i++) {
                long v = cf[i];
                s += (v > t / 2) ? v - t : v;
            }
            long sm = ((s % t) + t) % t;
            long wp = ((wx * wy) % t + t) % t;
            long im = ((xi % t) + t) % t;
            boolean eqInner = sm == im;
            boolean eqWeight = sm == wp;
            anyEqualsInner |= eqInner;
            anyEqualsWeight |= eqWeight;
            System.out.printf("     %-10s %-12d %-14d %-14d %-10s%n",
                pair[0] + "|" + pair[1], im, wp, sm,
                eqInner ? "<a,b>" : (eqWeight ? "|a|·|b|" : "都不是"));
        }
        report("B1 系数域：Σ全部系数【不等于】|a|·|b|（我的推导）—— 需要按实测结论修正",
            !anyEqualsWeight,
            String.format("四组向量里：等于 <a,b> 的有 %s；等于 |a|·|b| 的有 %s",
                anyEqualsInner ? "是" : "否", anyEqualsWeight ? "是" : "否"));

        System.out.println();
        System.out.println(failed == 0
            ? "=== 裁决：二进制同态内积【必须】在槽位域做（系数域得到的是重量之积）==="
            : "=== 有 " + failed + " 项与预期不符，需要重新审视 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long[] decodeSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct, int slots) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        long[] out = new long[slots];
        be.decode(pt, out);
        return out;
    }

    private static String first(long[] v, int k) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(k, v.length); i++) {
            sb.append(v[i]).append(i + 1 < k ? " " : "");
        }
        return sb.toString();
    }

    private static void report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        if (!ok) {
            failed++;
        }
    }
}
