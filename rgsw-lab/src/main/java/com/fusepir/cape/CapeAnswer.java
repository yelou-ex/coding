package com.fusepir.cape;

import com.fusepir.bloom.*;
import com.fusepir.bff.*;
import com.fusepir.prim.*;
import com.fusepir.fusepir.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.ArrayList;
import java.util.List;

/**
 * 论文 <b>Algorithm 2 · ANSWER 4-8</b>：把「锚检索出来的载荷」变成
 * <b>每候选一条密文分数</b> {@code ct_score,j}。
 *
 * <pre>
 *   A2 ANSWER 4: ct_{score,j} ← CtCtMul(q^BF, ct^{BF}_j)
 *   A2 ANSWER 5: for r = 0 to log2 ℓ_BF − 1 do
 *   A2 ANSWER 6:     ct_{score,j} ← CtCtAdd(ct_{score,j}, CtRotate(ct_{score,j}, 2^r))
 *   A2 ANSWER 8: resp ← ({(c_{v_j}, ct_{score,j})}_{j=1}^m)
 * </pre>
 *
 * <h3>为什么这一步单独成类（2026-10-14 深夜）</h3>
 * 它是**协议实现**，此前却住在名为 {@code probe.CapeAlgorithm2Diag} 的验收类里 ——
 * 于是"CAPE 的 ANSWER 在哪"在文件树里看不出来。现在它有了自己的文件，
 * {@code CapeAlgorithm2Diag} 只做验收。
 *
 * <p>服务端入口是 {@link com.fusepir.cape.CapeDemoService#runQueryCapeSealed}：
 * 它先拿锚检索的载荷，再调本类。真正的同态运算在
 * {@link com.fusepir.bloom.BloomScoring#bloomScore}（乘 → relinearize → 折叠）。
 *
 * <h3>⚠️ 与论文仍差的一处</h3>
 * ANSWER 3 要求 {@code ct^{BF}_j} 是**从 {@code resp_anc} 里解析出来的**
 * （{@code resp_anc = Pack({ct_{pay,b}})}）。我们没有 {@code Pack}，
 * 所以候选的 Bloom 段是**在这个打分信道里重新加密**的 —— 这就是缺陷总表的 <b>D2</b>，
 * 而它的根因是 **Pack 缺失**，不是独立 bug。
 * 见 {@code docs/reports/伪代码逐行复核-两处硬偏离-2026-10-14.md} §1.1。
 */
public final class CapeAnswer {

    private CapeAnswer() {
    }

    /** 一条候选的应答：论文 A2 ANSWER 8 的 {@code (ct_{v_j}, ct_score,j)}（服务端侧）。 */
    public static final class Cand {
        public final int valueId;
        public final long[] bloomBits;
        public final Ciphertext ctBloom;
        public final Ciphertext ctScore;

        Cand(int valueId, long[] bloomBits, Ciphertext ctBloom, Ciphertext ctScore) {
            this.valueId = valueId;
            this.bloomBits = bloomBits;
            this.ctBloom = ctBloom;
            this.ctScore = ctScore;
        }
    }

    /** 服务器侧 ANSWER 的产物（论文 A2 的 {@code resp}）。 */
    public static final class Answer {
        public final long fingerprint;
        public final int valueCount;
        /** **每候选一组**（P0-2 的落点）。 */
        public final List<Cand> candidates;
        /** 服务端为对照顺手解出来的槽值。**判定不读它**，只用来对拍。 */
        public final long[] serverPlainScore;
        public final long scoreMs;

        Answer(long fingerprint, int valueCount, List<Cand> candidates,
               long[] serverPlainScore, long scoreMs) {
            this.fingerprint = fingerprint;
            this.valueCount = valueCount;
            this.candidates = candidates;
            this.serverPlainScore = serverPlainScore;
            this.scoreMs = scoreMs;
        }
    }

    /**
     * 服务端 ANSWER：按候选分组 -> 把候选的 Bloom 段打包成一条槽位密文 -> 同态打分。
     *
     * <p>生产路径是 {@link com.fusepir.cape.CapeDemoService#runQueryCapeSealed}
     * （它持有打分信道与 native 上下文）；本方法供进程内自检与跨进程探针共用。
     *
     * @param qBF  客户端的 {@code q^BF}（服务器看不到 {@code b_qry} 本身）
     * @param payload 锚检索解出来的载荷（{@code B_pay} 个系数）
     */
    public static Answer answer(CapeBloomScore.Scorer sc, Ciphertext qBF,
                                long[] payload, int maxCandidates, int lBf) {
        CapeBloomScore.Result r = CapeBloomScore.score(sc, qBF, payload, maxCandidates, lBf);
        List<Cand> cands = new ArrayList<>();
        for (CapeBloomScore.Candidate c : r.candidates) {
            cands.add(new Cand(c.valueId, c.bloomBits, c.ctBloom, c.ctScore));
        }
        return new Answer(CapeBloomScore.fingerprintOf(payload), (int) payload[1],
            cands, r.plainScoreSlots, r.scoreMs);
    }
}
