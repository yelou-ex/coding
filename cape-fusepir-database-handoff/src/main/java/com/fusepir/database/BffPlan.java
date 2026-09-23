package com.fusepir.database;

import java.util.*;

/** Successful BFF topology: it is independent of payload coefficients and reusable per disk block. */
public final class BffPlan {
    private final List<String> keywords;
    private final int[][] positions;
    private final List<Assignment> peelingStack;
    private final int tableLength;
    private final int segmentSize;
    private final int segmentCountLength;
    private final long hashSeed;

    BffPlan(List<String> keywords, int[][] positions, List<Assignment> peelingStack,
            int tableLength, int segmentSize, int segmentCountLength, long hashSeed) {
        this.keywords = List.copyOf(keywords);
        this.positions = positions;
        this.peelingStack = List.copyOf(peelingStack);
        this.tableLength = tableLength;
        this.segmentSize = segmentSize;
        this.segmentCountLength = segmentCountLength;
        this.hashSeed = hashSeed;
    }

    public List<String> keywords() { return keywords; }
    public int tableLength() { return tableLength; }
    public int segmentSize() { return segmentSize; }
    public int segmentCountLength() { return segmentCountLength; }
    public long hashSeed() { return hashSeed; }
    int[] positions(int keyIndex) { return positions[keyIndex]; }
    List<Assignment> peelingStack() { return peelingStack; }

    record Assignment(int keyIndex, int position) {}
}
