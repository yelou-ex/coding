package com.fusepir.database;

import com.fusepir.common.BfGen;

/**
 * CAPE 参数。
 *
 * <h3>两个预设，用途完全不同</h3>
 * <table border="1">
 *   <tr><th>预设</th><th>用途</th><th>规模</th></tr>
 *   <tr><td>{@link #paperAligned()}</td><td><b>对齐论文</b>：报数字、做对照</td><td>N=16384、ε_BF=2^-20；极重</td></tr>
 *   <tr><td>{@link #testMinimal()}</td><td><b>测原理能否跑通</b>（当前阶段）</td><td>N=512、ε_BF=2^-8；秒级、几 MB</td></tr>
 * </table>
 *
 * <h3>为什么需要 testMinimal</h3>
 * 论文参数下明文侧的量级（实测 MovieLens small，n=1475、m=131、ε_BF=2^-20）：
 * <pre>
 *   ℓ_BF  = 5075 位
 *   Bpay  = 665092 个 Z_t 系数     ← 单个关键词的载荷长度
 *   表规模 = L_BFF × Bpay = 2048 × 665092 ≈ 13.6 亿系数
 * </pre>
 * 光是 BFF（明文、尚未加密）就要 GB 级磁盘与长时间计算，而真正的目标——
 * "加密的 Bloom 合取判定能不能跑通"——**完全不需要这么大的参数**。
 * 所以测试阶段用最小参数，等原理验证完再换回 paperAligned 出数字。
 *
 * <p><b>缩小的是规模，不是结构</b>：k=3 位置、分段 BFF、fast-plain-lift 窗口、
 * ℓ ≤ N 这些约束都保持不变，所以原理验证的结论对论文参数同样成立。
 *
 * @param securityBits             安全参数 λ（本层不参与运算，仅记录）
 * @param ringDegreeN              环维度 N。它同时是 <b>Bloom 长度 ℓ_BF 的上限</b>（ℓ ≤ N）
 * @param bffK                     Binary Fuse Filter 的位置数（论文 k=3）
 * @param fingerprintBits          载荷指纹位数（论文 40 bit）
 * @param bloomFalsePositiveTarget Bloom 目标假阳性率 ε_BF
 * @param plaintextModulus         明文模数 t（论文 65537）
 */
public record CapeParameters(int securityBits, int ringDegreeN, int bffK, int fingerprintBits,
                             double bloomFalsePositiveTarget, int plaintextModulus) {

    /** 论文对齐：N=16384、k=3、40 bit 指纹、ε_BF=2^-20、t=65537 */
    public static CapeParameters paperAligned() {
        return new CapeParameters(128, 16384, 3, 40, Math.pow(2, -20), 65537);
    }

    /**
     * 最小测试参数：只验证原理能否跑通。
     *
     * <p>取值依据（逐项都取到"还能表现结构"的最小值）：
     * <ul>
     *   <li><b>N = 4096</b>：环维度取小。它同时是 <b>Bloom 长度 ℓ_BF 的上限</b>（ℓ ≤ N）——
     *       实测真实 MovieLens 的 {@code maxSetSize=173}，N 再小就装不下了
     *       （N=512 时 ℓ=1611 直接超限）。</li>
     *   <li><b>ε_BF = 2⁻⁶</b>：实际 ℓ 由 {@link BfGen#choose} 定。
     *       ε 不能再压低 —— ℓ 随 −log(ε) 增长，压低会撞上 ℓ ≤ N 而抛异常。
     *       注意 ε 放宽意味着假阳性变多，这是测试阶段为了"能跑起来"主动付的代价。</li>
     *   <li><b>fingerprintBits = 16</b>：载荷里指纹按 16 bit 一组存 3 组（3 个 limb）。
     *       只用于"查错了就返回 ⊥"的判定，测试阶段够用。</li>
     *   <li><b>t = 65537</b>：<b>不动</b>。它既是 RLWE 的明文模数，又是 fast plain lift
     *       的可表达窗口（±t/2）—— 换掉会掩盖 gadget 切段的真实约束。</li>
     *   <li><b>k = 3</b>：<b>不动</b>。BFF 的三位置结构是必须验证的东西。</li>
     * </ul>
     *
     * <p>实测规模对比（MovieLens small，n=1475）：
     * <pre>
     *   paperAligned: Bpay=665092, 表系数=1.36e9  -> 5196 MB
     *   testMinimal : Bpay=  ~2e4, 表系数= ~4e7  ->  ~150 MB
     * </pre>
     */
    public static CapeParameters testMinimal() {
        return new CapeParameters(128, 4096, 3, 16, Math.pow(2, -6), 65537);
    }

    /**
     * <b>默认预设 = 最小测试参数</b>。
     *
     * <p>理由：当前阶段的目标是"验证原理能否跑通"，而不是出论文数字。
     * 论文参数下明文侧就是 GB 级（实测 MovieLens small：表系数 1.36e9 ≈ 5196 MB），
     * 光编码就要很久，且完全没必要 —— Bloom 合取判定、BFF 三位置、指纹校验
     * 这些**结构**在小参数下与论文参数完全一致。
     *
     * <p>要出论文数字时显式用 {@link #paperAligned()}。
     */
    public static CapeParameters defaults() {
        return testMinimal();
    }

    /** Bloom 参数（用 N 作为长度上限）。服务端与客户端必须调同一个方法。 */
    public BfGen bloomParameters(int maxSetSize) {
        return BfGen.choose(maxSetSize, bloomFalsePositiveTarget, ringDegreeN);
    }

    public String describe() {
        return String.format("N=%d, k=%d, 指纹=%d bit, ε_BF=2^%.0f, t=%d",
            ringDegreeN, bffK, fingerprintBits,
            Math.log(bloomFalsePositiveTarget) / Math.log(2), plaintextModulus);
    }
}
