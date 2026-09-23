package com.fusepir.database;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * FastFilter-compatible 3-wise Binary Fuse position derivation over a canonical UTF-8 keyword.
 * The SHA-256 prefix defines the 64-bit key input; the remaining layout and mixing match FastFilter.
 */
public final class BffHashGen {
    private static final long MIX_1 = 0xff51afd7ed558ccdL;
    private static final long MIX_2 = 0xc4ceb9fe1a85ec53L;

    private BffHashGen() {}

    public static Layout layout(int keywordCount) {
        if (keywordCount < 1) throw new IllegalArgumentException("keywordCount must be positive");
        int segmentLength = 1 << (int) Math.floor(Math.log(keywordCount) / Math.log(3.33) + 2.11);
        segmentLength = Math.min(segmentLength, 1 << 18);
        double sizeFactor = Math.max(1.125, 0.875 + 0.25 * Math.log(1_000_000.0) / Math.log(Math.max(2, keywordCount)));
        int capacity = (int) (keywordCount * sizeFactor);
        int segmentCount = (capacity + segmentLength - 1) / segmentLength - 2;
        int provisionalLength = (segmentCount + 2) * segmentLength;
        segmentCount = (provisionalLength + segmentLength - 1) / segmentLength;
        segmentCount = segmentCount <= 2 ? 1 : segmentCount - 2;
        int tableLength = (segmentCount + 2) * segmentLength;
        return new Layout(segmentLength, segmentCount, segmentCount * segmentLength, tableLength);
    }

    public static int[] positions(String canonicalKeyword, long seed, int segmentLength, int segmentCountLength) {
        if (Integer.bitCount(segmentLength) != 1 || segmentCountLength < segmentLength)
            throw new IllegalArgumentException("invalid segmented BFF layout");
        long hash = hash64(keyword64(canonicalKeyword), seed);
        int mask = segmentLength - 1;
        int h0 = reduce((int) (hash >>> 32), segmentCountLength);
        int h1 = h0 + segmentLength;
        int h2 = h1 + segmentLength;
        h1 ^= (int) ((hash >>> 18) & mask);
        h2 ^= (int) (hash & mask);
        return new int[]{h0, h1, h2};
    }

    public static long keyword64(String canonicalKeyword) {
        byte[] digest = PayloadFingerprint.sha256(canonicalKeyword.getBytes(StandardCharsets.UTF_8));
        return ByteBuffer.wrap(digest).getLong();
    }

    private static long hash64(long value, long seed) {
        long mixed = value + seed;
        mixed = (mixed ^ (mixed >>> 33)) * MIX_1;
        mixed = (mixed ^ (mixed >>> 33)) * MIX_2;
        return mixed ^ (mixed >>> 33);
    }

    private static int reduce(int hash, int bound) {
        return (int) (((hash & 0xffffffffL) * (bound & 0xffffffffL)) >>> 32);
    }

    public record Layout(int segmentLength, int segmentCount, int segmentCountLength, int tableLength) {}
}
