package com.fusepir.database;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class BffHashGenTest {
    @Test void matchesTheFrozenCrossLanguageTestVector() {
        BffHashGen.Layout layout = BffHashGen.layout(1475);
        assertEquals(256, layout.segmentLength());
        assertEquals(6, layout.segmentCount());
        assertEquals(1536, layout.segmentCountLength());
        assertEquals(2048, layout.tableLength());
        assertArrayEquals(new int[]{32, 375, 557}, BffHashGen.positions("sci-fi", 0x0123456789abcdefL,
                layout.segmentLength(), layout.segmentCountLength()));
    }
}
