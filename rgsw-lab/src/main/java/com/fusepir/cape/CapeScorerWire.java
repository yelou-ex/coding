package com.fusepir.cape;


import com.fusepir.bff.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.serialization.SealSerializable;

/**
 * <b>打分信道的线上格式</b>：把 {@code q_BF} / {@code ct_score} 编成能过 JSON 的字节数组。
 *
 * <h3>为什么需要它（D12 那条明文口的关闭方式）</h3>
 * 在 {@code /api/query-sealed} 里，{@code q_BF} 一直只是"接入口"：客户端算出
 * {@code b_qry} 后<b>把明文位向量发给了服务器</b>（字段 {@code d2PlaintextBf}），
 * 服务器自己 {@code encryptQuery} 造密文。那条信道等于把查询关键词交出去
 * （`CapeBfLeakProbe` 实测：用公开的 {@code H} 穷举即可唯一反解关键词）。
 *
 * <p>本类把那条信道换成<b>真的密文</b>：客户端自己加密、自己序列化，服务器只拿到字节。
 *
 * <h3>实测结论（{@code CapeWireFormatProbe}，N=8192）</h3>
 * <table border="1">
 *   <tr><th>项</th><th>实测</th></tr>
 *   <tr><td>{@code q_BF} 序列化长度</td><td><b>216,414 字节（211 KB）</b></td></tr>
 *   <tr><td>load 回来解密后槽位</td><td>与原向量<b>逐位一致</b>（失配 0）</td></tr>
 *   <tr><td>过线后打分</td><td>{@code 6 == 本地 6 == τ} ⇒ 命中判定在过线后仍成立</td></tr>
 *   <tr><td>负对照：翻转一字节</td><td>load 直接抛 {@code ciphertext data is invalid}</td></tr>
 * </table>
 *
 * <h3>为什么用 {@code long[]} 而不是 base64 字符串</h3>
 * 本项目的 {@code CapeDemoData.JsonParser} 只支持<b>扁平</b>数组，但 {@code long[]} 是扁平的、
 * 而且走的是 JSON 数字 ⇒ 不需要再引入 base64 编解码，也不会有字符串转义问题。
 * 代价是每个字节变成一个 JSON 数字（约 2~4 字符），所以 211 KB 的密文在 JSON 里约 600 KB
 * —— 单进程回环里无所谓；真部署应当换二进制帧，这一条记在
 * {@link CapeAlgorithm2Diag} 的口径差里。
 *
 * <h3>⚠️ Java 侧 SEAL 的 save 入口不明显，写在这里免得下次再找</h3>
 * {@code Ciphertext} <b>没有</b> {@code save()} 方法（只有 {@code load}），
 * save 的入口是 {@code SealSerializable<T>}：
 * <pre>
 *   SealSerializable&lt;Ciphertext&gt; ser = m.encryptor.encryptSymmetric(pt);
 *   byte[] wire = ser.save();
 *   ...
 *   ct.load(m.context, wire);
 * </pre>
 */
public final class CapeScorerWire {

    private CapeScorerWire() {
    }

    /**
     * 把一个 {@code byte[]} 编成 JSON 友好的 {@code long[]}（每项 0..255）。
     *
     * <p>用 {@code long[]} 而不是 {@code int[]}：请求/响应的其余数值字段都是 long，
     * 统一一种类型可以让 {@code toLongs} 那类辅助函数直接复用。
     */
    public static long[] bytesToWire(byte[] bytes) {
        long[] out = new long[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            out[i] = bytes[i] & 0xFFL;
        }
        return out;
    }

    /** {@link #bytesToWire} 的逆。越界的项直接抛，不静默截断。 */
    public static byte[] wireToBytes(long[] wire) {
        byte[] out = new byte[wire.length];
        for (int i = 0; i < wire.length; i++) {
            long v = wire[i];
            if (v < 0 || v > 255) {
                throw new IllegalArgumentException("wire[" + i + "] = " + v + " 不在 0..255");
            }
            out[i] = (byte) v;
        }
        return out;
    }

    /**
     * <b>压缩 7 倍的一字节一数字线格式</b>（P1-1 的列选择子用）。
     *
     * <p>为什么需要第二个格式：{@link #bytesToWire} 把<b>每个字节</b>编成一个 JSON
     * 数字，对 211 KB 的 {@code q_BF} 只是"浪费但可行"；而 P1-1 的列选择子流
     * 在 N=8192、C=26、k=3 时是 <b>41 MB</b>，按一字节一数字编出来是 120 MB 的
     * JSON 数字串，单进程回环里也会把内存吃光。
     *
     * <p>每 {@code long} 装 7 个字节（56 位）：<b>刻意不用 8 个</b> —— 8 个字节会
     * 产出 ≥ 2^63 的值，而本项目的 {@code JsonParser} 解成有符号 {@code long}，
     * 那样会静默变成负数。7 字节是"能过我们的 JSON 解析器"的最大宽度。
     *
     * <p>如实说边界：这是<b>本演示的折中</b>，不是论文的线格式。真部署应当走二进制帧。
     */
    public static long[] bytesToPackedWire(byte[] bytes) {
        final int per = 7;
        int n = (bytes.length + per - 1) / per;
        long[] out = new long[n];
        for (int i = 0; i < bytes.length; i++) {
            out[i / per] |= (bytes[i] & 0xFFL) << (8 * (i % per));
        }
        return out;
    }

    /** {@link #bytesToPackedWire} 的逆。末尾的填充字节由 {@code byteLen} 剪掉。 */
    public static byte[] packedWireToBytes(long[] wire, int byteLen) {
        final int per = 7;
        if ((long) wire.length * per < byteLen) {
            throw new IllegalArgumentException("packed wire 太短: " + wire.length
                + " 个 long 最多装 " + (wire.length * per) + " 字节，需要 " + byteLen);
        }
        byte[] out = new byte[byteLen];
        for (int i = 0; i < byteLen; i++) {
            out[i] = (byte) ((wire[i / per] >>> (8 * (i % per))) & 0xFFL);
        }
        return out;
    }

    /** 序列化一条密文（客户端侧发出去、或服务端侧发回来）。 */
    public static long[] serialize(Ciphertext ct) {
        try {
            return bytesToWire(new SealSerializable<>(ct).save());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("密文序列化失败: " + e, e);
        }
    }

    /**
     * 反序列化一条密文。
     *
     * <p><b>它必须用与生产出这条密文时<u>完全相同的</u>参数上下文</b>
     * （{@code N}、{@code t}、系数模数、层数）—— 否则 load 会抛
     * {@code ciphertext data is invalid}。所以打分信道的参数是协议的一部分，
     * 不是实现细节；{@code /api/state} 的 {@code params.scoreT} 与 {@code N} 就是为它服务的。
     */
    public static Ciphertext deserialize(CapeBloomScore.Scorer sc, long[] wire) {
        Ciphertext ct = new Ciphertext();
        try {
            ct.load(sc.m.context, wireToBytes(wire));
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("密文反序列化失败（线长 " + wire.length
                + "）: " + e, e);
        }
        return ct;
    }

    /**
     * <b>测试专用</b>：序列化打分信道的密钥。
     *
     * <p>被 {@code CapeDemoService} 的 {@code -Dcape.insecure.keyecho=true} 后门用到 ——
     * 只有当"判定方在另一个 JVM 里、却仍要当同一个密钥持有者"时才需要它。
     * 真部署里服务器绝不该调用它。
     */
    public static long[] serializeKey(edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey sk) {
        try {
            return bytesToWire(new SealSerializable<>(sk).save());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("密钥序列化失败: " + e, e);
        }
    }

    /** {@link #serializeKey} 的逆。 */
    public static edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey deserializeKey(
        CapeBloomScore.Scorer sc, long[] wire) {
        edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey sk =
            new edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey();
        try {
            sk.load(sc.m.context, wireToBytes(wire));
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("密钥反序列化失败: " + e, e);
        }
        return sk;
    }
}
