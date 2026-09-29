package cape.tiny;

import java.util.Random;

/**
 * LWE 密文：{@code (a, b)}，相位 {@code b − ⟨a, s_L⟩ = Δ_L·m}（本实现噪声为 0）。
 *
 * <p>按规范第 0 节，LWE 层的明文模数取 {@code t}，缩放 {@code Δ_L = 1}
 * —— 即相位直接等于明文（0/1 或行索引），便于手工验算。
 */
public final class LWECipher {

    /** 公开向量 a（长度 d），元素 ∈ [0, qL) */
    public final int[] a;
    /** 标量 b ∈ [0, qL) */
    public final int b;
    /** LWE 模数 qL */
    public final int qL;

    public LWECipher(int[] a, int b, int qL) {
        this.a = a;
        this.b = b;
        this.qL = qL;
    }

    /** 同态相加（BFF 三路径合并用）：a、b 分别相加 */
    public LWECipher add(LWECipher other) {
        if (other.qL != qL || other.a.length != a.length) {
            throw new IllegalArgumentException("LWE 参数不一致");
        }
        int[] na = new int[a.length];
        for (int i = 0; i < a.length; i++) na[i] = Math.floorMod(a[i] + other.a[i], qL);
        return new LWECipher(na, Math.floorMod(b + other.b, qL), qL);
    }

    /** 模切换 / 缩放到另一个模数（这里用于把 qL 对齐到 q） */
    public LWECipher switchModulus(int newQL) {
        int[] na = new int[a.length];
        for (int i = 0; i < a.length; i++) na[i] = (int) Math.round((double) a[i] * newQL / qL) % newQL;
        int nb = (int) Math.round((double) b * newQL / qL) % newQL;
        return new LWECipher(na, nb, newQL);
    }

    @Override
    public String toString() {
        return "LWE{a=" + Poly.show(a) + ", b=" + b + ", qL=" + qL + "}";
    }
}
