package cape.tiny;

import java.util.Random;

/**
 * 反推 SampleExtract 的正确下标与符号。
 *
 * <p>思路：把关系写成
 * <pre>
 *   c0[0] + Σ_k coef_k(ct) · s[σ(k)]  ==  phase(ct)[0]
 * </pre>
 * 其中 {@code coef_k} 是 ct.c1 的某个系数、{@code σ} 是某个下标置换。<br>
 * 通过多个随机密文联立，<b>逐个判定</b>每个位置到底取哪个 c1 系数、哪个 s、什么符号，
 * 而不是凭公式记忆。
 */
public final class Diag6 {

    public static void main(String[] args) {
        TinyParams p = TinyParams.spec();
        Random rnd = new Random(31337);
        TinyKey key = TinyKey.random(p, p.n, rnd);
        int n = p.n;

        System.out.println("s = " + Poly.show(key.sL));
        System.out.println();

        final int TRIALS = 40;
        RLWECipher[] cts = new RLWECipher[TRIALS];
        int[] rhs = new int[TRIALS];
        for (int t = 0; t < TRIALS; t++) {
            int[] m = new int[n];
            for (int i = 0; i < n; i++) m[i] = rnd.nextInt(2);
            cts[t] = key.encryptRLWE(m, rnd);
            rhs[t] = key.phase(cts[t])[0];              // Z_q
        }

        // 逐项反推：对每个位置 j（0..n-1，对应 s[j]），找一个 c1 下标 k 和符号 e∈{+1,-1}
        // 使得对全部试验都成立。
        System.out.println("逐位置反推 a[j] = ± c1[k]：");
        int[] srcIndex = new int[n];
        int[] sign = new int[n];
        boolean allFound = true;
        for (int j = 0; j < n; j++) {
            boolean found = false;
            for (int k = 0; k < n && !found; k++) {
                for (int e : new int[]{1, -1}) {
                    boolean ok = true;
                    for (int t = 0; t < TRIALS && ok; t++) {
                        // 逐个累加检验：这里只做"单项贡献"不可分离，
                        // 改为整体联立求解过于复杂 —— 换成下面的"逐一剔除"法。
                        ok = false;
                    }
                    // 占位：真正判定见下方"逐一剔除"
                    break;
                }
            }
            srcIndex[j] = -1;
            allFound = false;
        }

        // ---------- 更稳的办法：逐一剔除（leave-one-out）----------
        // 从全 0 的 a 出发，令残差 r_t = phase_t[0] − (c0[0])（先不管 s 的贡献）。
        // 但我们无法单独开关某个 s[j]，所以改用下面的独立构造：
        //
        // 构造只含一个非零秘密系数的密钥，逐个定位。
        System.out.println();
        System.out.println("改用【单系数密钥】逐个定位：");
        for (int j = 0; j < n; j++) {
            int[] sSingle = new int[n];
            sSingle[j] = 1;
            TinyKey kSingle = new TinyKey(p, sSingle);

            // 对随机 c1 计算 phase[0]，看它等于哪个 ±c1[k]
            boolean resolved = false;
            for (int t = 0; t < 5 && !resolved; t++) {
                RLWECipher ct = kSingle.encryptRLWE(new int[n], rnd);
                int ph0 = kSingle.phase(ct)[0];                 // = c0[0] + 贡献
                int c00 = ct.c0[0];
                int contrib = Math.floorMod(ph0 - c00, p.q);    // 只来自 s[j]=1

                for (int k = 0; k < n; k++) {
                    if (Math.floorMod(ct.c1[k], p.q) == contrib) {
                        System.out.printf("  s[%d]=1 → 贡献 = +c1[%d]%n", j, k);
                        resolved = true; break;
                    }
                    if (Math.floorMod(-(long) ct.c1[k], p.q) == contrib) {
                        System.out.printf("  s[%d]=1 → 贡献 = -c1[%d]%n", j, k);
                        resolved = true; break;
                    }
                }
            }
            if (!resolved) System.out.printf("  s[%d]=1 → 未定位%n", j);
        }
    }
}
