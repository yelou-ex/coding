package com.fusepir.database;

import java.util.*;

public final class DatabasePreprocessor implements PlaintextDatabasePreprocessor {
    public static final long DEFAULT_FINGERPRINT_SEED = 0x32c736c9f49b7e05L;

    @Override public PreparedDatabase prepare(CanonicalDatabase db, CapeParameters params) {
        return prepare(db, params, DEFAULT_FINGERPRINT_SEED);
    }

    public PreparedDatabase prepare(CanonicalDatabase db, CapeParameters params, long fingerprintSeed) {
        PayloadBlockProvider provider = PayloadBlockProvider.from(db, params, fingerprintSeed);
        Map<String, PlaintextPayload> payloads = new TreeMap<>();
        for (String keyword : provider.keywords()) payloads.put(keyword, new PlaintextPayload(keyword, provider.materialize(keyword)));
        PayloadLayout layout = provider.layout();
        return new PreparedDatabase(payloads, layout.bloom(), layout.maxValueCount(), layout.payloadLength(), layout.fingerprintSeed());
    }
}
