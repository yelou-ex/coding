package com.fusepir.cape;

import com.fusepir.bff.*;
import com.fusepir.bloom.*;
import com.fusepir.prim.*;
import com.fusepir.fusepir.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 论文 <b>Algorithm 2 · DECODE</b> —— <b>客户端</b>那一侧。
 *
 * <pre>
 *   A2 DECODE 2: V_{K_1} ← FusePIR.Decode(sk, st^C_anc, resp_anc)
 *   A2 DECODE 3: if V_{K_1} = ⊥ then return ⊥
 *   A2 DECODE 7: for j = 1 to |V_{K_1}| do
 *   A2 DECODE 8:     s_j ← Dec_{sk}(ct_{score,j})
 *   A2 DECODE 9:     if s_j = τ then R ← R ∪ {v_j}
 * </pre>
 *
 * <h3>两条 DECODE 入口，刻意不合并</h3>
 * <table border="1">
 *   <tr><th>入口</th><th>输入</th><th>为什么需要它</th></tr>
 *   <tr><td>{@link #decode}</td><td><b>进程内 {@code Ciphertext} 对象</b></td>
 *       <td>快，但绕过了"字节过线"这一段</td></tr>
 *   <tr><td>{@link #decodeWire}</td><td><b>过线后的字节</b></td>
 *       <td>从字节 load 再解密 ⇒ 负对照 N1/N1b（把字节置零 / 翻一个 bit）
 *           才有证明力</td></tr>
 * </table>
 *
 * <p><b>签名里只有密文</b>：明文分数没有入参 —— 这是刻意的，
 * 只要明文能传进来，"判定走密文"就随时可能被悄悄绕过。
 *
 * <h3>为什么这一步单独成类（2026-10-14 深夜）</h3>
 * 它此前住在 {@code probe.CapeAlgorithm2Diag} 与 {@code probe.CapeDefaultPathTest} 里 ——
 * 两个都叫"诊断/测试"的类。判定是**协议的一步**，不是测试夹具。
 */
public final class CapeDecode {

    private CapeDecode() {
    }

    /** 解密一条 {@code ct_score,j} 得到 {@code s_j}（客户端侧动作）。 */
    public interface ScoreDecryptor {
        long decrypt(Ciphertext ctScore);
    }

    /** 客户端 DECODE 的产物。 */
    public static final class DecodeResult {
        public final boolean fingerprintOk;
        public final List<Integer> accepted;
        public final List<Long> scores;
        public final String verdict;
        /**
         * 判定过程中是否有密文<b>反序列化失败</b>（字节坏了）。
         *
         * <p>不为 {@code false} 本身不是错误：客户端必须能对"服务器回了一段坏字节"做出决断，
         * 所以坏的那条按<b>拒绝</b>处理、并把这件事记下来。负对照 N1 会用到它。
         */
        public boolean loadFailed;

        public DecodeResult(boolean fingerprintOk, List<Integer> accepted, List<Long> scores,
                            String verdict) {
            this.fingerprintOk = fingerprintOk;
            this.accepted = accepted;
            this.scores = scores;
            this.verdict = verdict;
        }
    }

    /**
     * DECODE 3-4 + 8-9 的实现（<b>进程内对象版</b>）。
     *
     * <p>要走字节的那一版见 {@link #decodeWire}。
     */
    public static DecodeResult decode(List<Ciphertext> ctScores,
                                      List<Integer> valueIds, long fpWant, long fGot, long tau,
                                      ScoreDecryptor dec) {
        // ---- DECODE 3-4: f != fp(K) => bot（P0-4）----
        if (fGot != fpWant) {
            return new DecodeResult(false, new ArrayList<>(), new ArrayList<>(),
                "f=" + fGot + " != fp(K)=" + fpWant + " => 返回 bot（整条答案作废）");
        }
        // ---- DECODE 8-9: s_j = Dec(ct_score,j) ; 相等才收（P0-3）----
        List<Integer> accepted = new ArrayList<>();
        List<Long> scores = new ArrayList<>();
        for (int j = 0; j < ctScores.size(); j++) {
            long sj = dec.decrypt(ctScores.get(j));
            scores.add(sj);
            if (sj == tau) {
                accepted.add(valueIds.get(j));
            }
        }
        return new DecodeResult(true, accepted, scores,
            "指纹校验通过；逐候选比 Dec(ct_score) 与 tau");
    }

    /**
     * DECODE 3-4 + 8-9 的实现（<b>从字节开始</b>）。
     *
     * <p>从<b>字节</b>开始是刻意的：只有这样才能做"服务器回的字节被破坏"这类负对照
     * （N1 整条置零 / N1b 翻一个 bit）。坏字节**按拒绝处理而不是抛出去** ——
     * 判定是客户端的事，客户端必须能对损坏的响应做出决断。
     *
     * @param unusedMarker 历史参数，保留只为不动已有调用点
     */
    public static DecodeResult decodeWire(BloomChannel.Scorer sc, List<long[]> ctScoreBytesWire,
                                          List<Integer> valueIds, long fpWant, long fGot, long tau,
                                          long unusedMarker) {
        if (fGot != fpWant) {
            return new DecodeResult(false, new ArrayList<>(),
                new ArrayList<>(), "f=" + fGot + " != fp(K)=" + fpWant + " => 返回 bot（整条答案作废）");
        }
        List<Integer> accepted = new ArrayList<>();
        List<Long> scores = new ArrayList<>();
        boolean loadFailed = false;
        for (int j = 0; j < ctScoreBytesWire.size(); j++) {
            long sj;
            try {
                Ciphertext ct = ScorerWire.deserialize(sc, ctScoreBytesWire.get(j));
                sj = BloomChannel.decryptSlots(sc, ct)[0];
            } catch (RuntimeException e) {
                // 字节坏了 ⇒ 这条密文根本解不出来。按"拒绝"处理，并记下来。
                loadFailed = true;
                sj = Long.MIN_VALUE;
            }
            scores.add(sj);
            if (sj == tau) {
                accepted.add(valueIds.get(j));
            }
        }
        DecodeResult r = new DecodeResult(true, accepted, scores,
            "指纹校验通过；逐候选 load + Dec(ct_score) 与 tau 比");
        r.loadFailed = loadFailed;
        return r;
    }

    /**
     * <b>{@code FusePIR.Decode} 的载荷切分那一半</b>（A2 DECODE 2）：
     * 从响应里的 {@code payloadPlain} 解出候选值列表 {@code V_{K_1}}。
     *
     * <p><b>为什么客户端自己解</b>：论文 §4.1 原文要求
     * <i>"Only the <b>encrypted</b> candidate values and these scores are returned to
     * the client."</i> —— 服务器**不告诉**客户端"候选是谁"。客户端按公开的载荷布局
     * （{@code [0]=指纹, [1]=候选数, 之后每个候选占 1+ℓ_BF 项}）自己切出来。
     * 载荷布局是**公开参数**的一部分（{@code pp} 里有 {@code ℓ_BF}、{@code m}）。
     *
     * <p>⚠️ <b>边界</b>：{@code payloadPlain} 是**明文**（单进程回环里服务端持秘密、
     * 解密在服务端做完了）。所以上面那句"服务器不告诉客户端候选是谁"，
     * 在本回环里只对**字段**成立 —— 候选 id 就在这份载荷里。
     * 真修要发 {@code B_pay} 条密文（约 30.9 MB/响应），要等 Pack 的决定。
     */
    public static List<Integer> decodePayload(Map<String, Object> resp) {
        return FusePirDecode.decodePayload(resp);   // 实现已搬到 com.fusepir.fusepir.FusePirDecode
    }
    /**
     * {@code fp(K)} —— A1 DECODE 6 里的 {@code fp}。
     *
     * <p><b>实现已收口到 {@link com.fusepir.bff.BffSetup#fp(String)}</b>
     * （{@code bff} 层是它唯一的家：{@code fp} 是 `BFF.Setup` 的产物之一）。
     * 这里只做转发。
     *
     * <p>⚠️ <b>2026-10-14 深夜起 {@code fp} 是 40-bit</b>（论文 §5.1 μ=40），
     * 不再是 32-bit {@code String.hashCode}（D7 那条偏差已修）。
     * 它占 {@code FusePirSetup.fpSlots(t)} 个载荷槽，校验走
     * {@link com.fusepir.fusepir.FusePirDecode#fingerprintOk}。
     *
     * <p>⚠️ {@code nativeT} 参数<b>保留但不再参与计算</b>：指纹值本身与 `t` 无关
     * （`t` 只决定拆几个槽）。保留它是为了不改动调用点签名；
     * 需要拆/拼槽的地方请显式传 `t` 给 {@code fpDigits}/{@code fpFromDigits}。
     */
    public static long fpOf(String kw, long nativeT) {
        return FusePirDecode.fpOf(kw);
    }
}
