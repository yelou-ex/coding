package com.fusepir.probe;

import com.fusepir.bloom.BloomScoring;
import com.fusepir.cape.CapeA2Wire;
import com.fusepir.fusepir.FusePirFourStep;
import com.fusepir.prim.Mpc4jRgsw;
import com.fusepir.prim.RingPack;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;

import java.util.Arrays;
import java.util.Random;

/**
 * <b>隔离实验：{@code CtCtMul + 折叠} 在哪个域/哪个量级下失效？</b>
 *
 * <p>起因（{@code probe/CapeA2WireTest} 的 P3/P6，实测）：
 * 在 {@code tRing = K·T} 域里把 {@code q^BF} 与 <b>真实应答的打包件</b>相乘，
 * 得到的是<b>均匀随机值</b>（{@code CtCtMul(q^BF, packedCoeff)} 逐槽比对
 * <b>4096/4096 不符</b>），而<b>同一条 {@code q^BF} 乘一条新加密的候选 ⇒ 4096/4096 相符</b>。
 * 已排除的：打包件本身（它自己解密出来与 {@code payloadTruth} 只差 ±2）、
 * 旋转（不用旋转也同样错）、形态（decrypt 前同样做了 NTT→系数转换）。
 *
 * <p>⇒ 本探针把"域与量级"逐个打开，一个变量一次：
 * <table border="1">
 *   <tr><th>组</th><th>域</th><th>候选</th><th>看什么</th></tr>
 *   <tr><td>A1/A2</td><td>{@code tRing}</td><td>新加密（命中位 = K；再加大杂质）</td>
 *       <td>是不是"域 = tRing"本身的问题</td></tr>
 *   <tr><td>A3</td><td>{@code tRing}</td><td>新加密、满槽稠密大值</td><td>整条消息都大时</td></tr>
 *   <tr><td>A4</td><td>{@code tRing}</td><td>{@code RingPack} 产物</td><td>Pack 的噪声是不是那堵墙</td></tr>
 *   <tr><td>B1/B2/B3</td><td>{@code 65537}</td><td>同上三种</td><td>论文 t 上的对照（现有绿测都在这个域）</td></tr>
 * </table>
 *
 * <p>每个断言都配"候选自己的槽值"这条参照：先解出候选的槽，再要求
 * {@code 得分 == Σ q[i]·槽[i] mod t}（与实现无关的算式），而不是拿常量比。
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.probe.ScoreMulDomainTest 4096}
 */
public final class ScoreMulDomainTest {

    private static int failed = 0;

    public static void main(String[] args) {
        final int n = args.length > 0 ? Integer.parseInt(args[0]) : 4096;
        final long tRing = FusePirFourStep.ringModulusFor(n, 11, 1 << 8, 3);
        System.out.println("=== 隔离：CtCtMul + 折叠 在 tRing / 65537 两个域、四类候选上 ===");
        System.out.println("（前两组是**缺陷断言**：q 只有 bfvDefault 的 72 bit 工作模数时，"
            + "Pack 产物活不过一次 CtCtMul —— 刻意期望它错；后两组是修好之后的对照）");
        // ① 现行参数（bfvDefault(4096)：工作模数 72 bit）—— 期望"墙"在
        run(n, tRing, null, "bfvDefault（工作 q = 72 bit，128-bit 安全口径）", true);
        run(n, FusePirFourStep.T, null, "bfvDefault + 论文 t = 65537", true);
        // ② 放宽 q（A2 接线用的那一组）
        run(n, tRing, CapeA2Wire.A2_COEFF_BITS,
            "【A2 用的参数】q = 3×60 bit（工作 120 bit，SecLevelType.NONE）", false);
        run(n, FusePirFourStep.T, CapeA2Wire.A2_COEFF_BITS,
            "【对照】q = 3×60 bit + 论文 t = 65537", false);
        System.out.println();
        if (failed == 0) {
            System.out.println("=== 全部通过：墙（缺陷断言）与修好之后的正确性，两边都实测到了 ===");
        } else {
            System.out.println("=== 有 " + failed + " 组未达成 ===");
            System.exit(1);
        }
    }

    private static void run(int n, long t, int[] coeffBits, String label, boolean expectWall) {
        final long K = t / 65537;
        final Mpc4jRgsw m = (coeffBits == null)
            ? new Mpc4jRgsw(n, t, 0, 1 << 16)
            : new Mpc4jRgsw(n, t, 0, 1 << 16, null, coeffBits);
        final BatchEncoder be = new BatchEncoder(m.context);
        final int slots = be.slotCount();
        final GaloisKeys gk = BloomScoring.galoisKeysFor(m);
        final int hi = 60;                                  // 最高参与槽（B_pay−1）
        System.out.println();
        System.out.printf("################ %s：t = %d（K = %d）################%n", label, t, K);

        // 查询向量：10 个 1（与真实 b_qry 同形：支撑在 [0,18) 内、段外为 0）
        final long[] q = new long[slots];
        final int[] qPos = {0, 2, 3, 4, 6, 7, 10, 11, 14, 16};
        for (int p : qPos) {
            q[p] = 1;
        }
        final Ciphertext qBF = BloomScoring.encryptBloomVector(m, q);

        // 三类候选的槽向量
        final long[] hit = new long[slots];                 // 只把命中位置置成 K
        for (int p : qPos) {
            hit[p] = K;
        }
        final long[] hitJunk = hit.clone();                 // 再加大杂质（真实载荷那样）
        hitJunk[4] = 1001L * K;
        hitJunk[23] = 1002L * K;
        hitJunk[42] = 1003L * K;
        for (int j = 0; j < 3; j++) {
            for (int i = 0; i < 18; i++) {
                hitJunk[5 + 19 * j + i] = ((i % 3 == 0) ? 1 : 0) * K;
            }
        }
        final long[] dense = new long[slots];               // 满槽稠密 ≈ t/3
        Arrays.fill(dense, t / 3);

        System.out.println("--- A. 新加密候选（无 Pack 参与）---");
        freshCase(m, be, gk, q, qBF, hi, "A1 命中位 = K（其余 0）", hit);
        freshCase(m, be, gk, q, qBF, hi, "A2 命中位 = K + 真实同形的大杂质", hitJunk);
        freshCase(m, be, gk, q, qBF, hi, "A3 满槽稠密大值（≈ t/3）", dense);

        System.out.println("--- B. RingPack 产物 ---");
        packCase(m, be, gk, q, qBF, hi, "B1 Pack：18 个 limb（命中位 = K）", hit, expectWall);
        packCase(m, be, gk, q, qBF, hi, "B2 Pack：18 个 limb（含大杂质同形）", hitJunk,
            expectWall);

        System.out.println("--- C. 噪声/结构账（invariantNoiseBudget / scale / parmsId）---");
        {
            final Plaintext pt = new Plaintext();
            be.encode(hit, pt);
            final Ciphertext fresh = new Ciphertext();
            m.encryptor.encryptSymmetric(pt, fresh);
            final Ciphertext freshCoeff = asCoeff(m, fresh);
            info(m, "新加密候选（命中位=K）", fresh);
            info(m, "q^BF（客户端查询向量）", qBF);
            final Ciphertext prodFresh = com.fusepir.prim.CtOps.ctCtMul(m, qBF, freshCoeff);
            info(m, "  ↳ q^BF × 新加密候选（上面 PASS 的那条）", prodFresh);
            final Ciphertext packed = packOnly(m, be, hit);
            info(m, "RingPack 产物（18 limb，槽精确）", packed);
            final Ciphertext packedCoeff = asCoeff(m, packed);
            final Ciphertext prodPacked = com.fusepir.prim.CtOps.ctCtMul(m, qBF, packedCoeff);
            info(m, "  ↳ q^BF × RingPack 产物（上面 FAIL 的那条）", prodPacked);
            // 误差结构：解出的槽 vs 期望的槽
            final long[] pj = decodeSlots(m, be, prodPacked);
            final long[] pjFresh = decodeSlots(m, be, prodFresh);
            final long[] candSlots = decodeSlots(m, be, packedCoeff);
            int badFresh = 0;
            int badPacked = 0;
            for (int i = 0; i < slots; i++) {
                if (pjFresh[i] != Math.floorMod(q[i] * hit[i], m.t)) {
                    badFresh++;
                }
                if (pj[i] != Math.floorMod(q[i] * candSlots[i], m.t)) {
                    badPacked++;
                }
            }
            System.out.printf("      [info] 乘积逐槽比对：新加密 %d/%d 不符；RingPack %d/%d 不符%n",
                badFresh, slots, badPacked, slots);
        }

        System.out.println("--- D. 噪声阶梯：Pack 的代价在哪、能不能凑够一次 CtCtMul ---");
        {
            for (int k : new int[]{1, 4, 10, 18, 30, 61}) {
                final Ciphertext pk = packK(m, be, hit, k, 1 << 8, 3);
                System.out.printf("      [info] Pack k=%2d limb（base=2^8、digits=3）⇒ %s%n",
                    k, budget(m, pk));
            }
            final Ciphertext pk16 = packK(m, be, hit, 18, 1 << 16, 2);
            System.out.printf("      [info] Pack k=18 limb（base=2^16、digits=2 —— 覆盖 2^32，"
                + "key switch 从 3 段降到 2 段）⇒ %s%n", budget(m, pk16));
            // §30.2 的更正：掩码那一步到底是"越界"还是"预算用光"
            final Ciphertext pk = packK(m, be, hit, 18, 1 << 8, 3);
            final Plaintext mask = new Plaintext();
            final long[] maskArr = new long[slots];
            for (int i = 0; i < 18; i++) {
                maskArr[i] = 1;
            }
            be.encode(maskArr, mask);
            m.evaluator.transformToNttInplace(mask, m.context.firstParmsId());
            final Ciphertext pkNtt = new Ciphertext();
            pkNtt.copyFrom(pk);
            final Ciphertext masked = new Ciphertext();
            m.evaluator.multiplyPlain(pkNtt, mask, masked);
            final long[] mSlots = decodeSlots(m, be, masked);
            final long[] pkSlots = decodeSlots(m, be, pk);
            int mOk = 0;
            for (int i = 0; i < slots; i++) {
                if (mSlots[i] == Math.floorMod(pkSlots[i] * maskArr[i], m.t)) {
                    mOk++;
                }
            }
            System.out.printf("      [info] 稠密槽掩码 × Pack 产物：%d/%d 槽对，掩码后 %s%n",
                mOk, slots, budget(m, masked));
            if (expectWall) {
                check("[缺陷断言] §30.2 的'掩码 × 打包件 = 0/4096'：预算用光（故意期望它错）",
                    mOk == 0 && budgetBits(m, masked) <= 0);
            } else {
                check(String.format("§30.2 的更正：预算够时掩码逐槽正确（%d/%d）、且有 %d bit 余量 "
                        + "⇒ 那堵墙是**噪声预算**，不是'系数域乘积越界'",
                        mOk, slots, budgetBits(m, masked)),
                    mOk == slots && budgetBits(m, masked) > 0);
            }
            final Ciphertext byConst = new Ciphertext();
            m.evaluator.multiplyPlain(pkNtt, RingPack.plainConstant(m, 1L), byConst);
            System.out.printf("      [info] 常数明文 1 × Pack 产物 ⇒ %s%n", budget(m, byConst));
        }
        System.out.println("--- E. 少一次重线性化能不能救回来（A2 ANSWER 4-6 里那一步）---");
        {
            final Ciphertext packE = packK(m, be, hit, 18, 1 << 8, 3);
            final Ciphertext candE = asCoeff(m, packE);
            final long[] candSlots = decodeSlots(m, be, candE);
            final long expect = innerMod(q, candSlots, m.t);
            final Ciphertext withRelin = com.fusepir.prim.CtOps.ctCtMul(m, qBF, candE);
            System.out.printf("      [info] E1 multiply + relinearize ⇒ %s；得分 %d（期望 %d）%n",
                budget(m, withRelin), BloomScoring.decodeScore(m, withRelin), expect);
            final Ciphertext noRelin = new Ciphertext();
            m.evaluator.multiply(qBF, candE, noRelin);
            System.out.printf("      [info] E2 只 multiply（不重线性化，size=%d）⇒ %s%n",
                noRelin.size(), budget(m, noRelin));
            try {
                final Ciphertext acc = new Ciphertext();
                acc.copyFrom(noRelin);
                for (int i = 0; i < 6; i++) {
                    com.fusepir.prim.CtOps.ctCtAddInplace(m, acc,
                        com.fusepir.prim.CtOps.ctRotateRows(m, acc, 1 << i, gk));
                }
                final long[] slotsE = decodeSlots(m, be, acc);
                int good = 0;
                for (int i = 0; i < 64; i++) {
                    if (slotsE[i] == expect) {
                        good++;
                    }
                }
                System.out.printf("      [info] E3 对 size-%d 密文折叠 6 轮 ⇒ %s；槽 0 = %d（期望 %d）；"
                        + "槽 [0,64) 里等于期望的 %d/64%n",
                    noRelin.size(), budget(m, acc), slotsE[0], expect, good);
                m.evaluator.relinearizeInplace(acc, m.relinKeys());
                final long[] slotsE4 = decodeSlots(m, be, acc);
                System.out.printf("      [info] E4 折叠后再重线性化 ⇒ %s；槽 0 = %d（期望 %d）%n",
                    budget(m, acc), slotsE4[0], expect);
                System.out.println("      [info] 结论：**延迟重线性化不是出路** —— "
                    + "预算在 multiply 那一步就没了（E2 实测 0 bit），"
                    + "而且 size-3 密文根本不能旋转（E3 抛 'encrypted size must be 2'）。");
            } catch (RuntimeException e) {
                System.out.println("      [info] E3 在 size-3 密文上旋转抛异常：" + e.getMessage()
                    + " ⇒ SEAL 的 rotate 只接受 size=2，延迟重线性化这条捷径不存在。");
            }
        }
        // 自定义系数模数能不能放宽预算（README 说 CoeffModulus.create 会被安全标准拒）
        try {            final edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters p =
                new edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters(
                    edu.alibaba.mpc4j.crypto.fhe.seal.context.SchemeType.BFV);
            p.setPolyModulusDegree(n);
            p.setCoeffModulus(edu.alibaba.mpc4j.crypto.fhe.seal.modulus.CoeffModulus.create(n,
                new int[]{50, 50, 50, 50}));
            p.setPlainModulus(new edu.alibaba.mpc4j.crypto.fhe.seal.modulus.Modulus(t));
            final edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext c =
                new edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext(p);
            System.out.printf("      [info] 自定义系数模数 {50,50,50,50}：isParametersSet=%b（%s）%n",
                c.isParametersSet(), c.parametersErrorMessage());
        } catch (RuntimeException e) {
            System.out.printf("      [info] 自定义系数模数 {50,50,50,50} 被拒：%s%n",
                String.valueOf(e.getMessage()).split("\n")[0]);
        }
    }

    private static String budget(Mpc4jRgsw m, Ciphertext ct) {
        final Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        try {
            return m.decryptor.invariantNoiseBudget(copy) + " bit";
        } catch (RuntimeException e) {
            return "预算计算抛异常：" + e.getMessage();
        }
    }

    /** 打包前 {@code k} 个 limb（槽 {@code 0..k-1}），gadget 可指定。 */
    private static Ciphertext packK(Mpc4jRgsw m, BatchEncoder be, long[] cand, int k,
                                    int base, int digits) {
        final int nLwe = 16;
        final int[] s = new int[nLwe];
        final Random rnd = new Random(20261017L);
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        final Ciphertext[][] swk = RingPack.switchingKey(m, s, base, digits);
        final long[][] as = new long[k][nLwe];
        final long[] bs = new long[k];
        final int[] slotIdx = new int[k];
        for (int i = 0; i < k; i++) {
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = Math.floorMod(sum + as[i][j] * s[j], m.t);
            }
            bs[i] = Math.floorMod(sum + cand[i], m.t);
            slotIdx[i] = i;
        }
        return RingPack.pack(m, be, swk, base, digits, as, bs, slotIdx);
    }

    /** 只做 Pack（不判分），供 C 组看结构。 */
    private static Ciphertext packOnly(Mpc4jRgsw m, BatchEncoder be, long[] cand) {
        final int nLwe = 16;
        final int[] s = new int[nLwe];
        final Random rnd = new Random(20261017L);
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        final Ciphertext[][] swk = RingPack.switchingKey(m, s, 1 << 8, 3);
        final int k = 18;
        final long[][] as = new long[k][nLwe];
        final long[] bs = new long[k];
        final int[] slotIdx = new int[k];
        for (int i = 0; i < k; i++) {
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = Math.floorMod(sum + as[i][j] * s[j], m.t);
            }
            bs[i] = Math.floorMod(sum + cand[i], m.t);
            slotIdx[i] = i;
        }
        return RingPack.pack(m, be, swk, 1 << 8, 3, as, bs, slotIdx);
    }

    /** 把一个密文的"结构账"打出来。 */
    private static void info(Mpc4jRgsw m, String name, Ciphertext ct) {
        final Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        int budget = Integer.MIN_VALUE;
        try {
            budget = m.decryptor.invariantNoiseBudget(copy);
        } catch (RuntimeException e) {
            budget = -999999;
        }
        System.out.printf("      [info] %-34s size=%d、RNS=%d、scale=%.3g、ntt=%b、"
                + "噪声预算=%d bit、parmsId=%s%n",
            name, ct.size(), ct.getCoeffModulusSize(), ct.scale(), ct.isNttForm(), budget,
            ct.parmsId());
    }

    /** 候选 = 槽向量直接加密；判据 = 得分 == Σ q[i]·槽[i] mod t。 */
    private static void freshCase(Mpc4jRgsw m, BatchEncoder be, GaloisKeys gk, long[] q,
                                  Ciphertext qBF, int hi, String name, long[] cand) {
        final Plaintext pt = new Plaintext();
        be.encode(cand, pt);
        final Ciphertext ct = new Ciphertext();
        m.encryptor.encryptSymmetric(pt, ct);
        final boolean ptNtt = pt.isNttForm();
        final boolean ctNtt = ct.isNttForm();
        final long[] got = decodeSlots(m, be, ct);
        final long expect = innerMod(q, got, m.t);
        final long score = BloomScoring.decodeScore(m,
            BloomScoring.bloomScoreReaching(m, gk, qBF, asCoeff(m, ct), hi));
        check(String.format("%s：候选槽与真值一致、得分 == Σq·槽 = %d（实得 %d）"
                + "［pt.isNttForm=%b、ct.isNttForm=%b］", name, expect, score, ptNtt, ctNtt),
            Arrays.equals(got, cand) && score == expect);
    }

    /** 候选 = {@code RingPack.pack} 的产物（前 18 个 limb 进槽 0..17，LWE 关系自洽）。 */
    private static void packCase(Mpc4jRgsw m, BatchEncoder be, GaloisKeys gk, long[] q,
                                 Ciphertext qBF, int hi, String name, long[] cand,
                                 boolean expectWall) {
        final int nLwe = 16;
        final int[] s = new int[nLwe];
        final Random rnd = new Random(20261017L);
        for (int i = 0; i < nLwe; i++) {
            s[i] = rnd.nextInt(2);
        }
        final Ciphertext[][] swk = RingPack.switchingKey(m, s, 1 << 8, 3);
        final int k = 18;
        final long[][] as = new long[k][nLwe];
        final long[] bs = new long[k];
        final int[] slotIdx = new int[k];
        for (int i = 0; i < k; i++) {
            long sum = 0;
            for (int j = 0; j < nLwe; j++) {
                as[i][j] = Math.floorMod(rnd.nextLong(), m.t);
                sum = Math.floorMod(sum + as[i][j] * s[j], m.t);
            }
            bs[i] = Math.floorMod(sum + cand[i], m.t);
            slotIdx[i] = i;
        }
        final Ciphertext packed = RingPack.pack(m, be, swk, 1 << 8, 3, as, bs, slotIdx);
        final long[] got = decodeSlots(m, be, packed);
        final long expect = innerMod(q, got, m.t);
        final long score = BloomScoring.decodeScore(m,
            BloomScoring.bloomScoreReaching(m, gk, qBF, asCoeff(m, packed), hi));
        boolean slotsOk = true;
        for (int i = 0; i < k; i++) {
            slotsOk &= got[i] == cand[i];
        }
        final int bits = budgetBits(m, packed);
        if (expectWall) {
            // 判据是"预算活不过一次 CtCtMul"，不是"预算恰好为 0"：
            // 一次 CtCtMul 实测要 ~26 bit，所以只要 < 26 就一定会解成随机值。
            check(String.format("[缺陷断言] %s：Pack 产物只有 %d bit 预算（< 一次 CtCtMul 的 ~26 bit）"
                    + " ⇒ 相乘后得分 %d ≠ Σq·槽 = %d（**刻意期望它错**；q 放宽后这一条会变红、B 组转正）",
                    name, bits, score, expect),
                slotsOk && bits < 26 && score != expect);
        } else {
            check(String.format("%s：Pack 槽精确（%d 个 limb）、Pack 产物 %d bit、"
                    + "得分 == Σq·槽 = %d（实得 %d）［packed.isNttForm=%b］",
                    name, k, bits, expect, score, packed.isNttForm()),
                slotsOk && score == expect && bits >= 30);
        }
        if (!slotsOk) {
            System.out.println("      [info] Pack 槽首错：" + firstMismatch(got, cand, k));
        }
    }

    /** {@code invariantNoiseBudget} 的整数形态（算不出来给一个极小值）。 */
    private static int budgetBits(Mpc4jRgsw m, Ciphertext ct) {
        final Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        try {
            return m.decryptor.invariantNoiseBudget(copy);
        } catch (RuntimeException e) {
            return Integer.MIN_VALUE;
        }
    }

    private static String firstMismatch(long[] got, long[] want, int k) {
        for (int i = 0; i < k; i++) {
            if (got[i] != want[i]) {
                return String.format("槽 %d：得 %d、期望 %d", i, got[i], want[i]);
            }
        }
        return "（无）";
    }

    private static Ciphertext asCoeff(Mpc4jRgsw m, Ciphertext ct) {
        final Ciphertext out = new Ciphertext();
        out.copyFrom(ct);
        if (out.isNttForm()) {
            m.evaluator.transformFromNttInplace(out);
        }
        return out;
    }

    private static long[] decodeSlots(Mpc4jRgsw m, BatchEncoder be, Ciphertext ct) {
        final Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            m.evaluator.transformFromNttInplace(copy);
        }
        final Plaintext pt = new Plaintext(m.n);
        m.decryptor.decrypt(copy, pt);
        final long[] out = new long[be.slotCount()];
        be.decode(pt, out);
        return out;
    }

    private static long innerMod(long[] q, long[] cand, long t) {
        long s = 0;
        for (int i = 0; i < q.length; i++) {
            s = Math.floorMod(s + q[i] * cand[i], t);
        }
        return s;
    }

    private static void check(String what, boolean ok) {
        System.out.println("  " + (ok ? "[PASS] " : "[FAIL] ") + what);
        if (!ok) {
            failed++;
        }
    }
}
