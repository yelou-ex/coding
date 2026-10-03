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
 *       ⇒ 响应字段 {@code payloadPlain} 是**明文**。
 *       ⚠️ <b>2026-10-15 起有了一条"不这么干"的路</b>：{@code fusepir/FusePirPack}
 *       的变体 R1（系数域打包）能把载荷以<b>密文</b>形式交回客户端，由客户端自己
 *       {@code SampleExtract_β} 再解密；{@link #decodePayloadCoefficients} 就是那条路的
 *       {@code Recover}（切分算式<b>只有一份</b>，两个入口共用）。
 *       <b>但 R1 不是论文的 {@code Pack}</b>：输出不可槽位寻址 ⇒ A2 ANSWER 3 仍无法
 *       satisfy ⇒ <b>D2 仍开放</b>；且它的条数与"发 {@code B_pay} 条密文"相同
 *       （密集打包在本库实测不成立，见 {@code probe/CoeffPackTest} 第 6 节）。
 *       本类<b>不</b>因此改默认路径 —— 这一段只是把边界说清楚，别把它读成"Pack 做完了"。</li>
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
     * 客户端按 `fp 的 fpSlots 个槽 → [fpSlots]=候选数 → 之后每个候选占 1+ℓ_BF 项` 自己切。
     *
     * <p>⚠️ <b>fp 的槽数由 {@code t} 决定</b>（{@code ⌈40/⌊log2 t⌋⌉}）：`t = 2^32` ⇒ 2 个槽。
     * 这里的 {@code t} 取 native 载荷域（{@code -Dcape.t} 可覆盖），
     * <b>必须与构造侧同一个 t</b>，否则槽数与槽边界全错 —— 症状是候选切错位。
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
        return decodePayloadCoefficients(payload, nativeFieldModulus());
    }

    /**
     * <b>A1 DECODE 5 的 {@code Recover}</b> —— 直接吃 {@code y} 的系数数组（不经过 JSON）。
     *
     * <p><b>为什么需要这个重载</b>：{@link #decodePayload(java.util.Map)} 的入参是
     * <b>响应 JSON</b>，也就是"服务端已经解好、以明文发回来"的形状（见类注释的边界说明）。
     * 一旦载荷以<b>密文</b>形式回来（变体 R1 的 {@code resp_anc}），客户端手里就是
     * 一个 {@code long[] y}，没有 JSON 可切。切分算式<b>必须仍然只有一份</b>，
     * 所以这里把原来的切分逻辑原样搬进来，由两个入口共用。
     *
     * <p>行为与 {@link #decodePayload(java.util.Map)} <b>逐位相同</b>
     * （后者现在就是"读字段 → 调本方法"）：{@code ℓ_BF} 与 {@code m} 仍从
     * {@code -Dcape.lbf} / {@code -Dcape.maxValues} 取（默认 18 / 3），
     * {@code t} 由调用方给。
     *
     * <p>⚠️ 已知边界（与原来那一份同一处，未变）：{@code t} 走参数、
     * {@code ℓ_BF}/{@code m} 走系统属性，而 {@code CapeDemoService} 那边读的是数据集
     * {@code meta}（本 demo 的 {@code meta.lBf = 18}、{@code meta.maxValues = 3}，
     * 与默认值恰好一致）。**"恰好一致"不是"保证一致"** —— 数据集一改就会静默切错槽。
     *
     * @param payload 载荷系数 {@code y}（{@code Z_t}）
     * @param t       载荷域 {@code t}（必须与构造侧同一个）
     */
    public static List<Integer> decodePayloadCoefficients(long[] payload, long t) {
        List<Integer> out = new java.util.ArrayList<>();
        if (payload == null || payload.length == 0) {
            return out;
        }
        int lBf = Integer.getInteger("cape.lbf", 18);
        int maxValues = Integer.getInteger("cape.maxValues", 3);
        final int fpSlots = FusePirSetup.fpSlots(t);
        final int countOff = FusePirSetup.countOffset(fpSlots);
        final int count = countOff < payload.length ? (int) payload[countOff] : 0;
        for (int j = 0; j < maxValues && j < count; j++) {
            int base = FusePirSetup.valueOffset(fpSlots, j, 1 + lBf);
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
     * 载荷所在的域 {@code t}（native 信道）：{@code -Dcape.t} 覆盖，默认 {@code 2^32}。
     *
     * <p>与 {@code CapeDemoService.resolveT} 的口径一致 —— 那一份读数据集 meta，
     * 这一份读系统属性，所以**两边都必须由调用方保证一致**。
     * 之所以不做成一处：解析侧拿不到 DB 对象（它只有响应的 JSON）。
     */
    public static long nativeFieldModulus() {
        return Long.getLong("cape.t", 1L << 32);
    }

    /**
     * {@code fp(K)} —— A1 DECODE 6 里的 {@code fp}。
     *
     * <p><b>实现是 {@link BffSetup#fp(String)}</b>：{@code fp} 是 A1 SETUP 1 的
     * {@code (D, H, fp) ← BFF.Setup(n, 3)} 三个产物之一，<b>属于 BFF 层</b>，
     * 所以这里只做转发，不自己再写一遍算式。
     *
     * <p>⚠️ <b>2026-10-14 深夜起 {@code fp} 是 40-bit</b>（论文 §5.1 μ=40；
     * 此前是 32-bit {@code String.hashCode}，即 D7 登记的那条偏差）。
     * 它<b>装不进一个 {@code Z_t} 槽</b>，所以载荷里占
     * {@code FusePirSetup.fpSlots(t)} 个槽；校验要用 {@link #fingerprintOk}。
     *
     * <p>⚠️ 这一处此前是**第三份**重复实现（{@code BffSetup.fp} 与
     * {@code CapeDemoData} 各一份，这里第三份）。三份一致的后果是**看不出来**
     * —— 而一旦要改指纹长度，只有被改的那一处会变，
     * 症状是"某些关键词解出来是 ⊥"，且**不会有任何报错**。
     */
    public static long fpOf(String kw) {
        return BffSetup.fp(kw);
    }

    /**
     * <b>A1 DECODE 6</b>：{@code if f ≠ fp(K) then return ⊥}。
     *
     * <p>从解出的载荷里把 {@code fpSlots} 个槽拼回 40-bit 指纹再比。
     * <b>构造侧拆、解析侧拼，用的必须是同一对函数</b>（{@code BffSetup.fpDigits} /
     * {@code fpFromDigits}）—— 任一边手写都会让这个校验"永远通过"或"永远失败"，
     * 而后者看起来像"查询没命中"，很难查。
     *
     * @param t 载荷域（native 信道），必须与构造侧同一个
     */
    public static boolean fingerprintOk(String kw, long[] y, long t) {
        final int fpSlots = FusePirSetup.fpSlots(t);
        if (y.length < fpSlots) {
            return false;
        }
        return BffSetup.fpFromDigits(y, 0, fpSlots, t) == fpOf(kw);
    }
}
