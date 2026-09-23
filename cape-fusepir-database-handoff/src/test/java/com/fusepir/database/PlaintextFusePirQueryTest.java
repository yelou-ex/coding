package com.fusepir.database;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.util.*;
import org.junit.jupiter.api.Test;

class PlaintextFusePirQueryTest {
    @Test void returnsValuesForExistingKeywordAndBottomForMissingKeyword() throws Exception {
        CanonicalDatabase database = new CanonicalDatabase(
                List.of(new KeywordRecord("a", new int[]{1, 2}), new KeywordRecord("b", new int[]{2, 3}), new KeywordRecord("c", new int[]{2})),
                Map.of(1, Set.of("a"), 2, Set.of("a", "b", "c"), 3, Set.of("b")), 2, 32);
        BffOptions options = new BffOptions(7L, 42L, 99L, 32, 1_000_000L);
        var output = Files.createTempDirectory("plaintext-fusepir-test-");
        new DiskBffEncoder().encode(database, CapeParameters.defaults(), options, output, 64);
        PlaintextFusePirQuery query = PlaintextFusePirQuery.open(output);
        assertEquals(List.of(1, 2), query.query("a").values());
        assertFalse(query.query("missing").found());
    }
}
