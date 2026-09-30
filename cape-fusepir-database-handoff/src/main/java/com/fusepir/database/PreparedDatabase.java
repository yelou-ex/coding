package com.fusepir.database;

import com.fusepir.common.BfGen;

import java.util.Map;

public record PreparedDatabase(Map<String, PlaintextPayload> payloads, BfGen bloom,
                               int maxValueCount, int payloadLength, long fingerprintSeed) {
    public PreparedDatabase { payloads = Map.copyOf(payloads); }
}
