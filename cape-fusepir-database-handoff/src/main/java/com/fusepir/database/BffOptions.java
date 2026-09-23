package com.fusepir.database;

import java.security.SecureRandom;

/** Injected seeds make BFF construction reproducible in tests. */
public record BffOptions(long hashSeed, long fingerprintSeed, long tableSeed, int maxRetries, long maxTableCoefficients) {
    public BffOptions {
        if (hashSeed == fingerprintSeed || hashSeed == tableSeed || fingerprintSeed == tableSeed)
            throw new IllegalArgumentException("BFF seeds must be independent");
        if (maxRetries < 1 || maxTableCoefficients < 1) throw new IllegalArgumentException("invalid BFF options");
    }

    public BffOptions(long hashSeed, long fingerprintSeed, int maxRetries, long maxTableCoefficients) {
        this(hashSeed, fingerprintSeed, hashSeed ^ 0x9e3779b97f4a7c15L, maxRetries, maxTableCoefficients);
    }

    public static BffOptions defaults() {
        return new BffOptions(0x4f1bbcdc8e53a1d9L, 0x32c736c9f49b7e05L, 0x7b2ec2af9db1f406L, 32, 100_000_000L);
    }

    public static BffOptions random() {
        SecureRandom random = new SecureRandom();
        long hashSeed = random.nextLong();
        long fingerprintSeed, tableSeed;
        do { fingerprintSeed = random.nextLong(); } while (fingerprintSeed == hashSeed);
        do { tableSeed = random.nextLong(); } while (tableSeed == hashSeed || tableSeed == fingerprintSeed);
        return new BffOptions(hashSeed, fingerprintSeed, tableSeed, 32, 100_000_000L);
    }
}
