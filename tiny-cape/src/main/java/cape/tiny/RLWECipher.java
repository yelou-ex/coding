package cape.tiny;

import java.util.Arrays;

/**
 * RLWE 密文：{@code (c0, c1)}，相位 {@code c0 + c1·s_R = Δ·m(X) + e}（模 q）。
 *
 * <p>本实现（噪声为 0）下相位<b>精确</b>等于 {@code Δ·m(X)}，所以解密
 * 永远得到精确明文 —— 这正是《极简验证版》第 0 节的要求。
 */
public final class RLWECipher {

    /** 分量 0（长度 N，模 q） */
    public final int[] c0;
    /** 分量 1（长度 N，模 q） */
    public final int[] c1;
    /** 模 q */
    public final int q;

    public RLWECipher(int[] c0, int[] c1, int q) {
        this.c0 = c0;
        this.c1 = c1;
        this.q = q;
    }

    /** CtAdd */
    public RLWECipher add(RLWECipher other) {
        requireSame(other);
        return new RLWECipher(Poly.add(c0, other.c0, q), Poly.add(c1, other.c1, q), q);
    }

    /** CtSub */
    public RLWECipher sub(RLWECipher other) {
        requireSame(other);
        return new RLWECipher(Poly.sub(c0, other.c0, q), Poly.sub(c1, other.c1, q), q);
    }

    /** 明密文加：相位 += Δ·v（v 是 Z_t 上的多项式） */
    public RLWECipher addPlain(int[] v, TinyParams p) {
        int[] scaled = new int[v.length];
        for (int i = 0; i < v.length; i++) scaled[i] = v[i] * p.delta % q;
        return new RLWECipher(Poly.add(c0, scaled, q), Poly.copy(c1), q);
    }

    /**
     * CtPtMul：密文 × 公开明文多项式。
     *
     * <p>相位变 {@code v(X)·(Δm + e)}。注意如果 v 的系数是 0/1，
     * 这<b>不是</b>逐位 AND —— 环乘法是卷积。要做逐位逻辑必须转槽位域。
     */
    public RLWECipher mulPlain(int[] v, TinyParams p) {
        return new RLWECipher(Poly.mul(c0, v, q), Poly.mul(c1, v, q), q);
    }

    /** CtRotate：把相位多项式乘上 X^k（Galois 自同构的公开特例） */
    public RLWECipher mulMonomial(long k) {
        return new RLWECipher(Poly.mulMonomial(c0, k, q), Poly.mulMonomial(c1, k, q), q);
    }

    public RLWECipher negate() {
        return new RLWECipher(Poly.neg(c0, q), Poly.neg(c1, q), q);
    }

    private void requireSame(RLWECipher other) {
        if (other.q != q || other.c0.length != c0.length) {
            throw new IllegalArgumentException("密文参数不一致");
        }
    }

    @Override
    public String toString() {
        return "RLWE{c0=" + Poly.show(c0) + ", c1=" + Poly.show(c1) + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof RLWECipher)) return false;
        RLWECipher x = (RLWECipher) o;
        return q == x.q && Arrays.equals(c0, x.c0) && Arrays.equals(c1, x.c1);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(c0) * 31 + Arrays.hashCode(c1) + q;
    }
}
