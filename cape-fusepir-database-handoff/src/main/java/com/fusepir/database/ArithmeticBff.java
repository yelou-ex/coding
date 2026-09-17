package com.fusepir.database;

import java.util.Arrays;

/** Plaintext arithmetic BFF table: every entry is a vector over Z_t. */
public final class ArithmeticBff {
    private final int tableLength;
    private final int segmentSize;
    private final int segmentCountLength;
    private final int payloadLength;
    private final int modulus;
    private final long hashSeed;
    private final long fingerprintSeed;
    private final int[][] table;

    ArithmeticBff(int tableLength, int segmentSize, int segmentCountLength, int payloadLength, int modulus,
                  long hashSeed, long fingerprintSeed, int[][] table) {
        this.tableLength = tableLength;
        this.segmentSize = segmentSize;
        this.segmentCountLength = segmentCountLength;
        this.payloadLength = payloadLength;
        this.modulus = modulus;
        this.hashSeed = hashSeed;
        this.fingerprintSeed = fingerprintSeed;
        this.table = table;
    }

    public int tableLength() { return tableLength; }
    public int segmentSize() { return segmentSize; }
    public int segmentCountLength() { return segmentCountLength; }
    public int payloadLength() { return payloadLength; }
    public int modulus() { return modulus; }
    public long hashSeed() { return hashSeed; }
    public long fingerprintSeed() { return fingerprintSeed; }

    public int[] positions(String keyword) {
        return ArithmeticBffEncoder.positions(keyword, hashSeed, segmentSize, segmentCountLength);
    }

    public int[] reconstruct(String keyword) {
        int[] result = new int[payloadLength];
        for (int position : positions(keyword)) {
            for (int block = 0; block < payloadLength; block++) result[block] = add(result[block], table[position][block]);
        }
        return result;
    }

    public boolean matchesFingerprint(String keyword, int[] reconstructed) {
        return PayloadFingerprint.matches(keyword, fingerprintSeed, reconstructed);
    }

    public int[] entryAt(int position) {
        if (position < 0 || position >= tableLength) throw new IndexOutOfBoundsException(position);
        return table[position].clone();
    }

    int coefficientAt(int position, int block) { return table[position][block]; }

    private int add(int left, int right) {
        int sum = left + right;
        return sum >= modulus ? sum - modulus : sum;
    }
}
