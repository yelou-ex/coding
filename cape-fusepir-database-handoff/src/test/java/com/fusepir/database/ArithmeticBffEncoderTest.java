package com.fusepir.database;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class ArithmeticBffEncoderTest {
    private static CanonicalDatabase database() {
        return new CanonicalDatabase(
                List.of(new KeywordRecord("a", new int[]{1, 2}), new KeywordRecord("b", new int[]{2, 3}), new KeywordRecord("c", new int[]{2})),
                Map.of(1, Set.of("a"), 2, Set.of("a", "b", "c"), 3, Set.of("b")), 2, 32);
    }

    @Test void reconstructsEveryEncodedPayloadAndRejectsMissingKeyword() {
        CapeParameters parameters = CapeParameters.defaults();
        PreparedDatabase prepared = new DatabasePreprocessor().prepare(database(), parameters, 42L);
        ArithmeticBff bff = new ArithmeticBffEncoder().encode(prepared, parameters, new BffOptions(7L, 42L, 32, 1_000_000));
        prepared.payloads().forEach((keyword, payload) -> {
            int[] actual = bff.reconstruct(keyword);
            short[] coefficients = payload.coefficients();
            int[] expected = new int[coefficients.length];
            for (int block = 0; block < coefficients.length; block++) expected[block] = coefficients[block] & 0xffff;
            assertArrayEquals(expected, actual);
            assertTrue(bff.matchesFingerprint(keyword, actual));
        });
        int[] missing = bff.reconstruct("missing");
        assertFalse(bff.matchesFingerprint("missing", missing));
    }

    @Test void matrixViewReconstructsEveryBffEntry() {
        CapeParameters parameters = CapeParameters.defaults();
        PreparedDatabase prepared = new DatabasePreprocessor().prepare(database(), parameters, 42L);
        ArithmeticBff bff = new ArithmeticBffEncoder().encode(prepared, parameters, new BffOptions(7L, 42L, 32, 1_000_000));
        BffMatrixLayout matrix = BffMatrixLayout.of(bff, parameters);
        for (int slot = 0; slot < bff.tableLength(); slot++) assertArrayEquals(bff.entryAt(slot), matrix.reconstructSlot(slot));
    }
}
