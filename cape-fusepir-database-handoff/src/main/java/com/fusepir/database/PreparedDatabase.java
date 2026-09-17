package com.fusepir.database;

import java.util.Map;

public record PreparedDatabase(Map<String, PlaintextPayload> payloads, BloomParameters bloom,
                               int maxValueCount, int payloadLength, long fingerprintSeed) {
    public PreparedDatabase { payloads = Map.copyOf(payloads); }
}
