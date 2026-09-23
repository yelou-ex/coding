package com.fusepir.database;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** 40-bit payload fingerprint derived independently from the BFF hash seed. */
public final class PayloadFingerprint {
    private PayloadFingerprint() {}

    public static int[] limbs(String keyword, long seed) {
        byte[] input = ByteBuffer.allocate(Long.BYTES + keyword.getBytes(StandardCharsets.UTF_8).length)
                .putLong(seed).put(keyword.getBytes(StandardCharsets.UTF_8)).array();
        byte[] digest = sha256(input);
        return new int[]{u16(digest, 0), u16(digest, 2), u16(digest, 4)};
    }

    public static boolean matches(String keyword, long seed, int[] payload) {
        if (payload.length < 3) return false;
        int[] fingerprint = limbs(keyword, seed);
        return payload[0] == fingerprint[0] && payload[1] == fingerprint[1] && payload[2] == fingerprint[2];
    }

    static byte[] sha256(byte[] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }
}
