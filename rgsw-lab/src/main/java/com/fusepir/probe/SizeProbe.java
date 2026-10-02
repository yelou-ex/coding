package com.fusepir.probe;


import com.fusepir.prim.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.*;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;
import java.io.ByteArrayOutputStream;

/** 量一量：N=16384 下真实密文/公钥的素数个数与字节数 */
public class SizeProbe {
    public static void main(String[] args) throws Exception {
        Mpc4jRgsw m = new Mpc4jRgsw(16384, 65537L, 0, 1 << 16);
        System.out.println("[ctx] " + m.describe());
        SealContext ctx = m.context;
        System.out.println("declared coeffModulus length = "
            + ctx.firstContextData().parms().coeffModulus().length);
        System.out.println("firstParmsId  coeffModulus length = "
            + ctx.getContextData(ctx.firstParmsId()).parms().coeffModulus().length);
        System.out.println("lastParmsId   coeffModulus length = "
            + ctx.getContextData(ctx.lastParmsId()).parms().coeffModulus().length);

        long[] msg = new long[16384];
        for (int i = 0; i < 16384; i++) { msg[i] = i % 1000 + 1; }
        Ciphertext ct = m.encrypt(msg);
        int size = ct.size();
        int coeffMod = ct.getCoeffModulusSize();
        long[] data = ct.data();
        System.out.printf("ct: size=%d, getCoeffModulusSize()=%d, data.length=%d%n", size, coeffMod, data.length);
        System.out.printf("    data.length/(size*N) = %d 个素数分量%n", data.length / (size * 16384));
        System.out.printf("    NTT 形式 = %b%n", ct.isNttForm());

        // 序列化后的真实字节数（含 SEAL 头部）
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ct.saveMembers(bos);
            System.out.printf("saveMembers = %d B = %.2f KiB%n", bos.size(), bos.size() / 1024.0);
        } catch (Throwable t) {
            System.out.println("saveMembers failed: " + t);
        }
        System.out.printf("%n核对：9 素数 × 16384 × 8 = %d B = %.2f KiB%n", 9 * 16384 * 8, 9 * 16384 * 8 / 1024.0);
        System.out.printf("      8 素数 × 16384 × 8 = %d B = %.2f KiB%n", 8 * 16384 * 8, 8 * 16384 * 8 / 1024.0);
    }
}
