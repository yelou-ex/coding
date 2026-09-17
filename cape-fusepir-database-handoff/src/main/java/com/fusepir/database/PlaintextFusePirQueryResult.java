package com.fusepir.database;

import java.util.List;

/** Result of a plaintext reconstruction from the persisted BFF matrix. */
public record PlaintextFusePirQueryResult(boolean found, List<Integer> values) {
    public PlaintextFusePirQueryResult { values = List.copyOf(values); }
}
