package com.fusepir.fusepir;

import com.fusepir.bff.*;
import com.fusepir.bloom.*;
import com.fusepir.prim.*;
import com.fusepir.cape.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;

import java.util.List;
import java.util.Map;

/**
 * 论文 <b>Algorithm 1 · DECODE</b>（FusePIR 那一半）。
 *
 * <pre>
 *   Alg 1 DECODE 2: for each packed ciphertext ct_{pay,β} ∈ resp do
 *   Alg 1 DECODE 3:     y[β] ← Dec_{s_R}(ct_{pay,β})
 *   Alg 1 DECODE 5: Recover (f, m_K, v_1, ..., v_m) ← y
 *   Alg 1 DECODE 6: if f ≠ fp(K) then return ⊥
 * </pre>
 *
 * <h3>我们的实现落在哪一步</h3>
 * 论文这一步有两件事：**(a)** 解密载荷；**(b)** 从载荷里切出
 * {@code (指纹, 候选数, 值列表)} 并做指纹校验。
 * <ul>
 *   <li>**(a) 在回环里由服务端做**（{@code cape_answer_core} 末尾用 {@code c->decryptor}）
 *       ⇒ 响应字段 {@code payloadPlain} 是**明文**。真修要发 {@code B_pay} 条密文
 *       （约 30.9 MB/响应），**要等 Pack 的决定**。</li>
 *   <li>**(b) 就是本类**：{@link #decodePayload} 按公开的载荷布局切出候选值。</li>
 * </ul>
 *
 * <p>载荷布局是**公开参数**的一部分（{@code pp} 里有 {@code ℓ_BF}、{@code m}），
 * 所以切分不引入任何秘密。
 *
 * <p>CAPE 自己的 DECODE（{@code s_j = τ} 判定 + 指纹 ⊥）在
 * {@link com.fusepir.cape.CapeDecode}；本类只放 FusePIR 的那一半。
 */
public final class FusePirDecode {

    private FusePirDecode() {
    }

    /**
     * {@code V_{K_1} ← FusePIR.Decode(sk, st^C_anc, resp_anc)} 的载荷切分部分
     * （A1 DECODE 5 的 {@code Recover}）。
     *
     * <p><b>为什么客户端自己解</b>：论文 §4.1 原文要求
     * <i>"Only the <b>encrypted</b> candidate values and these scores are returned to
     * the client."</i> —— 服务器**不告诉**客户端"候选是谁"。
     * 客户端按 `[0]=指纹, [1]=候选数, 之后每个候选占 1+ℓ_BF 项` 自己切。
     *
     * <p>⚠️ <b>边界（必须一起说）</b>：{@code payloadPlain} 是**明文**
     * （回环里服务端持秘密、解密在服务端做完了）。所以"服务器不告诉客户端候选是谁"
     * 这句话在本回环里只对**字段**成立 —— 候选 id 就在这份载荷里。
     */
    public static List<Integer> decodePayload(Map<String, Object> resp) {
        List<Integer> out = new java.util.ArrayList<>();
        Object payloadField = resp.get("payloadPlain");
        if (!(payloadField instanceof List)) {
            return out;
        }
        List<?> raw = (List<?>) payloadField;
        long[] payload = new long[raw.size()];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = ((Number) raw.get(i)).longValue();
        }
        int lBf = Integer.getInteger("cape.lbf", 18);
        int maxValues = Integer.getInteger("cape.maxValues", 3);
        int count = (int) payload[1];
        for (int j = 0; j < maxValues && j < count; j++) {
            int base = 2 + j * (1 + lBf);
            if (base >= payload.length) {
                break;
            }
            int valueId = (int) payload[base];
            if (valueId > 0) {
                out.add(valueId);
            }
        }
        return out;
    }

    /**
     * {@code fp(K) = inField(K.hashCode(), t)} —— A1 DECODE 6 里的 {@code fp}。
     *
     * <p>它正是 D7 记录的那条偏差：论文是 40-bit 指纹，我们用的是 {@code String.hashCode}。
     * {@code t} 必须取 <b>native 那条信道的</b>（载荷在那个域里生成），
     * 不是打分信道的 65537 —— 取错会让所有查询都返回 bot。
     */
    public static long fpOf(String kw, long nativeT) {
        return CapeDemoData.inField(kw.hashCode(), nativeT);
    }
}
