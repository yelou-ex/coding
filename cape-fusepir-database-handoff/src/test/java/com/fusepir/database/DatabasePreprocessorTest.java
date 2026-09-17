package com.fusepir.database;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DatabasePreprocessorTest {
    @Test void preservesManyToManyRelationsAndCanonicalizesTags() throws Exception {
        Path file = Files.createTempFile("tags", ".csv");
        Files.writeString(file, "userId,movieId,tag,timestamp\n1,1, Sci-Fi ,0\n2,1, sci-fi,0\n3,2,comedy,0\n4,2,sci-fi,0\n");
        CanonicalDatabase db = MovieLensTagLoader.load(file);
        assertArrayEquals(new int[]{1, 2}, db.records().stream().filter(r -> r.keyword().equals("sci-fi")).findFirst().orElseThrow().values());
        assertEquals(Set.of("sci-fi", "comedy"), db.keywordsByValue().get(2));
    }

    @Test void payloadsHaveUniformLengthAndBloomHasNoFalseNegatives() {
        CanonicalDatabase db = new CanonicalDatabase(
                java.util.List.of(new KeywordRecord("a", new int[]{1, 2}), new KeywordRecord("b", new int[]{2, 3}), new KeywordRecord("c", new int[]{2})),
                java.util.Map.of(1, java.util.Set.of("a"), 2, java.util.Set.of("a", "b", "c"), 3, java.util.Set.of("b")), 2, 32);
        PreparedDatabase prepared = new DatabasePreprocessor().prepare(db, CapeParameters.defaults());
        assertEquals(3, prepared.payloads().size());
        assertEquals(3 + 2 + 2 * (2 + prepared.bloom().length()), prepared.payloadLength());
        assertEquals(1, prepared.payloads().values().stream().map(p -> p.coefficients().length).distinct().count());
    }
}
