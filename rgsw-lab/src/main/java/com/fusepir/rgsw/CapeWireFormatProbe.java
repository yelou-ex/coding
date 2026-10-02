package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.BatchEncoder;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.GaloisKeys;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.serialization.SealSerializable;

/**
 * <b>线上往返探针：打分信道的密文能不能真的"过线"？</b>
 *
 * <h3>为什么必须测这一条</h3>
 * 现在的 {@code /api/query-cape} 收的是 <b>{@code b_qry} 的明文槽向量</b>
 * （{@code d2PlaintextBf}）—— 那是 D12 记录的口径差，也是"客户端加密上传 {@code q_BF}"
 * 这件事还没做的直接后果。要把那个明文口关掉，{@code q_BF} 就必须**真的能被序列化成字节、
 * 发过线、在另一侧 load 回来**。
 *
 * <p>而 Java 侧 SEAL 移植的 API 里，{@code Ciphertext} 只有 {@code load(...)}、
 * <b>看不到 {@code save(...)}</b> —— 直觉上会以为"发不出去"。本探针把这个直觉变成实测：
 * {@code SealSerializable<T>} 才是 save 的入口，{@code Encryptor.encryptSymmetric(pt)}
 * 返回的就是它。
 *
 * <h3>测什么</h3>
 * <ol>
 *   <li>{@code q_BF} 序列化 → 反序列化 → 解密，槽位逐位与原文一致；</li>
 *   <li><b>过线之后打分是否仍然相等</b>：A 侧造 {@code ct_BF}，把 {@code q_BF} 的
 *       <b>字节</b>搬到 B 侧,由 B 侧 load 回来再算 {@code ct_score}；若结果仍等于 τ，
 *       则"客户端只发字节、服务端只拿字节"这条链路成立；</li>
 *   <li><b>负对照</b>：把字节里改一个字节（模拟线上损坏）⇒ 分数必须不再是 τ
 *       （否则"过线"这件事没有证明力）。</li>
 * </ol>
 *
 * <p>跑法：{@code .\run-mpc4j.ps1 -Class com.fusepir.rgsw.CapeWireFormatProbe 8192 18}
 */
public final class CapeWireFormatProbe {

    private CapeWireFormatProbe() {
    }

    private static int failed = 0;

    private static void check(String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  --- " + detail);
        if (!ok) {
            failed++;
        }
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 8192;
        int lBf = args.length > 1 ? Integer.parseInt(args[1]) : 18;

        System.out.println("=== 打分信道线上往返探针 ===");
        System.out.printf("[参数] N=%d  l_BF=%d  t=%d%n%n", n, lBf, CapeBloomScore.SCORE_T);

        CapeBloomScore.Scorer sc = CapeBloomScore.setup(n);
        System.out.printf("[setup] 打分信道 %.0f ms，槽数=%d%n%n",
            (double) sc.setupMs, sc.slots);

        // ---- 1. 客户端：造 b_qry 与其密文 q_BF ----
        boolean[] bQry = new boolean[lBf];
        for (int i = 0; i < lBf; i += 3) {
            bQry[i] = true;
        }
        long tau = 0;
        for (boolean b : bQry) {
            if (b) {
                tau++;
            }
        }
        System.out.println("---------------- 1. 客户端：q_BF 序列化成字节 ----------------");
        long[] slots = CapeBloomScore.toSlotVector(bQry, sc.slots);
        SealSerializable<Ciphertext> ser = sc.m.encryptor.encryptSymmetric(encode(sc, slots));
        byte[] wire = ser.save();
        // 注：encryptSymmetric 返回的是 SealSerializable<Ciphertext>，不是 Ciphertext
        // （要拿对象本体得用重载 encryptSymmetric(Plaintext, Ciphertext)）。
        // 服务端手上就只有下面这串字节。
        System.out.printf("  τ = %d；q_BF 序列化后 %d 字节（%.1f KB）%n",
            tau, wire.length, wire.length / 1024.0);
        check("q_BF 能序列化（SealSerializable.save() 可用）", wire.length > 0,
            wire.length + " 字节");
        check("线长在合理量级（一条槽位密文 = 2 × workingPrimes × N × 8 字节的上下）",
            wire.length > 1000 && wire.length < 8 * 1024 * 1024, wire.length + " 字节");

        // ---- 2. 服务端：只有字节，load 回来 ----
        System.out.println();
        System.out.println("---------------- 2. 服务端：只有字节，load 回来再用 ----------------");
        Ciphertext qBFLoaded = new Ciphertext();
        qBFLoaded.load(sc.m.context, wire);
        // 槽位逐位对拍（这一条证明"搬过线的就是同一条密文"）
        long[] back = CapeBloomScore.decryptSlots(sc, qBFLoaded);
        int mism = 0;
        for (int i = 0; i < slots.length; i++) {
            if (back[i] != slots[i]) {
                mism++;
            }
        }
        check("load 回来的 q_BF 解密后槽位逐位一致", mism == 0, "失配槽 = " + mism);

        // ---- 3. 过线之后打分是否仍然相等 ----
        System.out.println();
        System.out.println("---------------- 3. 过线之后打分 ----------------");
        long[] candBits = new long[lBf];
        for (int i = 0; i < lBf; i++) {
            candBits[i] = bQry[i] ? 1 : 0;      // 完全命中
        }
        Ciphertext ctBF = BloomScoring.encryptBloomVector(sc.m,
            CapeBloomScore.padToSlots(candBits, sc.slots));
        long scLocal = BloomScoring.decodeScore(sc.m,
            BloomScoring.bloomScore(sc.m, sc.galoisKeys, freshQuery(sc, slots), ctBF));
        long scWire = BloomScoring.decodeScore(sc.m,
            BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBFLoaded, ctBF));
        System.out.printf("  本地算的分数 = %d；过线后算的分数 = %d；τ = %d%n", scLocal, scWire, tau);
        check("过线后的分数 == 本地分数（字节往返无损）", scLocal == scWire,
            scLocal + " vs " + scWire);
        check("分数 == τ（命中判定在过线后仍成立）", scWire == tau,
            "s=" + scWire + " τ=" + tau);

        // ---- 4. 负对照：线上损坏一字节 ⇒ 分数必须变 ----
        System.out.println();
        System.out.println("---------------- 4. 负对照：线上损坏 ----------------");
        {
            byte[] broken = wire.clone();
            broken[broken.length / 2] ^= 0x01;     // 翻转中间一个 bit
            Ciphertext qBad = new Ciphertext();
            boolean loaded = true;
            try {
                qBad.load(sc.m.context, broken);
            } catch (Throwable e) {
                loaded = false;
                System.out.println("      损坏的字节直接 load 失败：" + e);
            }
            if (!loaded) {
                check("N1 损坏一字节 ⇒ load 直接失败（更强的结果）", true, "");
            } else {
                long sBad;
                try {
                    sBad = BloomScoring.decodeScore(sc.m,
                        BloomScoring.bloomScore(sc.m, sc.galoisKeys, qBad, ctBF));
                } catch (Throwable e) {
                    sBad = Long.MIN_VALUE;
                    System.out.println("      打分阶段抛异常：" + e);
                }
                System.out.printf("      损坏后的分数 = %s%n", sBad);
                check("N1 损坏一字节 ⇒ 分数不再等于 τ（过线这件事有证明力）",
                    sBad != tau, "s=" + sBad + " τ=" + tau);
            }
        }

        // ---- 5. P1-1：列选择子流的打包往返 ----
        packedWireChecks();

        System.out.println();
        System.out.println(failed == 0
            ? "=== 全部通过：q_BF 与列选择子流都能真的过线 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /**
     * <b>P1-1 的列选择子流的打包往返</b>（离线，不需要服务）。
     *
     * <h3>为什么单开一段测它</h3>
     * 列选择子流实测约 41 MB（k×C = 78 条 × 524,401 字节）。走
     * {@link CapeScorerWire#bytesToWire} 那种"一字节一个 JSON 数字"会编出上亿个数字，
     * 所以 P1-1 用了 {@link CapeScorerWire#bytesToPackedWire}（7 字节/long）。
     * 这是一条<b>新的编解码路径</b>，而新编解码路径必须有往返断言 + 负对照，
     * 否则"打包对了"只是个说法。
     *
     * <p>用真实的 41 MB 而不是缩样：打包函数按位置取模，缩样会掩盖跨 long 边界的错。
     * 代价是几十 MB 内存，可接受。
     */
    static int packedWireChecks() {
        int before = failed;
        System.out.println();
        System.out.println("---------------- P1-1：列选择子流的打包往返 ----------------");
        final int k = 3;
        final int c = 26;
        final int perSel = 524401;
        int len = k * c * (4 + perSel);
        byte[] blob = new byte[len];
        // 伪随机内容（XorShift 常量，与本仓库其它探针一致）：全零或全同的载荷
        // 会让"打包正确"退化成一个巧合。
        long st = 20260930L;
        for (int i = 0; i < len; i++) {
            st ^= st << 13;
            st ^= st >>> 7;
            st ^= st << 17;
            blob[i] = (byte) (st & 0xFF);
        }
        System.out.printf("  选择子流 %d 字节（k=%d × C=%d 条，每条 %d 字节）%n",
            len, k, c, perSel);

        long t0 = System.nanoTime();
        long[] packed = CapeScorerWire.bytesToPackedWire(blob);
        long packMs = (System.nanoTime() - t0) / 1_000_000;
        t0 = System.nanoTime();
        byte[] back = CapeScorerWire.packedWireToBytes(packed, len);
        long unpackMs = (System.nanoTime() - t0) / 1_000_000;
        int diff = 0;
        for (int i = 0; i < len; i++) {
            if (blob[i] != back[i]) {
                diff++;
            }
        }
        check("打包 → 解包逐字节一致", diff == 0,
            "失配 " + diff + " 字节；" + packed.length + " 个 long，打包 " + packMs
                + " ms / 解包 " + unpackMs + " ms");
        // 7 字节/long 而不是 8 的理由：本项目的 JsonParser 解成有符号 long，
        // 8 字节会产出 >= 2^63 的值、静默变成负数。
        boolean anyNegative = false;
        for (long v : packed) {
            if (v < 0) {
                anyNegative = true;
                break;
            }
        }
        check("打包后的每个 long 都是非负（JSON 解析器不会把它读成负数）",
            !anyNegative, "7 字节/long，最大 2^56-1");
        // 负对照：线太短必须抛，不能静默补零 —— 静默补零会把"截断的查询"
        // 变成一个"合法的、但选错列的查询"，那是最坏的一种失败。
        boolean threw = false;
        try {
            CapeScorerWire.packedWireToBytes(new long[10], len);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check("[负对照] 线短于声明的字节数 ⇒ 抛，而不是静默补零", threw, "");
        return failed - before;
    }

    /** 把槽位向量编成 Plaintext（NTT 域/系数域交给 SEAL 自己按需处理）。 */
    private static Plaintext encode(CapeBloomScore.Scorer sc, long[] slots) {
        Plaintext pt = new Plaintext();
        new BatchEncoder(sc.m.context).encode(slots, pt);
        return pt;
    }

    /** 本地新造一条 q_BF（作为"没过线"的对照）。 */
    private static Ciphertext freshQuery(CapeBloomScore.Scorer sc, long[] slots) {
        Ciphertext ct = new Ciphertext();
        sc.m.encryptor.encryptSymmetric(encode(sc, slots), ct);
        return ct;
    }
}
