package com.fusepir.database;

import java.util.*;

/** Algorithm 3 plaintext arithmetic BFF encoder for k=3. */
public final class ArithmeticBffEncoder {
    public ArithmeticBff encode(PreparedDatabase prepared, CapeParameters parameters, BffOptions options) {
        if (parameters.bffK() != 3) throw new IllegalArgumentException("only the paper's k=3 BFF is implemented");
        BffPlan plan = plan(prepared.payloads().keySet(), parameters, options);
        long coefficientCount = Math.multiplyExact((long) plan.tableLength(), prepared.payloadLength());
        if (coefficientCount > options.maxTableCoefficients()) {
            throw new IllegalArgumentException("BFF needs " + coefficientCount + " coefficients; limit is " + options.maxTableCoefficients());
        }
        int[][] table = randomTable(plan.tableLength(), prepared.payloadLength(), parameters.plaintextModulus(), options.tableSeed());
        for (int index = plan.peelingStack().size() - 1; index >= 0; index--) {
                BffPlan.Assignment assignment = plan.peelingStack().get(index);
                int[] target = table[assignment.position()];
                short[] payload = prepared.payloads().get(plan.keywords().get(assignment.keyIndex())).coefficients();
                for (int block = 0; block < target.length; block++) {
                    int value = payload[block] & 0xffff;
                    for (int position : plan.positions(assignment.keyIndex())) {
                        if (position != assignment.position()) value = subtract(value, table[position][block], parameters.plaintextModulus());
                    }
                    target[block] = value;
                }
        }
        return new ArithmeticBff(plan.tableLength(), plan.segmentSize(), plan.segmentCountLength(), prepared.payloadLength(), parameters.plaintextModulus(),
                plan.hashSeed(), prepared.fingerprintSeed(), table);
    }

    public BffPlan plan(Collection<String> keys, CapeParameters parameters, BffOptions options) {
        if (parameters.bffK() != 3) throw new IllegalArgumentException("only the paper's k=3 BFF is implemented");
        if (keys.isEmpty()) throw new IllegalArgumentException("cannot encode an empty database");
        List<String> keywords = new ArrayList<>(keys);
        Collections.sort(keywords);
        BffHashGen.Layout layout = BffHashGen.layout(keywords.size());
        SplittableRandom seedSource = new SplittableRandom(options.hashSeed());
        for (int attempt = 0; attempt < options.maxRetries(); attempt++) {
            long seed = seedSource.nextLong();
            int[][] positions = positions(keywords, seed, layout.segmentLength(), layout.segmentCountLength());
            List<BffPlan.Assignment> stack = mappingStep(positions, layout.tableLength());
            if (stack != null) return new BffPlan(keywords, positions, stack, layout.tableLength(), layout.segmentLength(), layout.segmentCountLength(), seed);
        }
        throw new IllegalStateException("BFF mapping failed after " + options.maxRetries() + " hash-seed attempts");
    }

    BffPlan planForHashSeed(Collection<String> keys, CapeParameters parameters, long hashSeed) {
        if (parameters.bffK() != 3 || keys.isEmpty()) throw new IllegalArgumentException("invalid BFF plan input");
        List<String> keywords = new ArrayList<>(keys);
        Collections.sort(keywords);
        BffHashGen.Layout layout = BffHashGen.layout(keywords.size());
        int[][] positions = positions(keywords, hashSeed, layout.segmentLength(), layout.segmentCountLength());
        List<BffPlan.Assignment> stack = mappingStep(positions, layout.tableLength());
        if (stack == null) throw new IllegalArgumentException("manifest hash seed does not yield a peelable BFF graph");
        return new BffPlan(keywords, positions, stack, layout.tableLength(), layout.segmentLength(), layout.segmentCountLength(), hashSeed);
    }

    /** Algorithm 3 k=3 table length, including its finite-size correction. */
    public static int tableLength(int n) {
        return BffHashGen.layout(n).tableLength();
    }

    /** Algorithm 3 k=3 segment-size parameter. */
    public static int segmentSize(int n) {
        return BffHashGen.layout(n).segmentLength();
    }

    static int[] positions(String keyword, long seed, int segmentSize, int segmentCountLength) {
        return BffHashGen.positions(keyword, seed, segmentSize, segmentCountLength);
    }

    private static int[][] positions(List<String> keywords, long seed, int segmentSize, int segmentCountLength) {
        return keywords.stream().map(keyword -> positions(keyword, seed, segmentSize, segmentCountLength)).toArray(int[][]::new);
    }

    private static List<BffPlan.Assignment> mappingStep(int[][] positions, int tableLength) {
        List<List<Integer>> keysAt = new ArrayList<>(tableLength);
        int[] degree = new int[tableLength];
        for (int slot = 0; slot < tableLength; slot++) keysAt.add(new ArrayList<>());
        for (int key = 0; key < positions.length; key++) for (int slot : positions[key]) { keysAt.get(slot).add(key); degree[slot]++; }
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        for (int slot = 0; slot < tableLength; slot++) if (degree[slot] == 1) queue.add(slot);
        boolean[] removed = new boolean[positions.length];
        List<BffPlan.Assignment> stack = new ArrayList<>(positions.length);
        while (!queue.isEmpty()) {
            int slot = queue.removeFirst();
            if (degree[slot] != 1) continue;
            int key = keysAt.get(slot).stream().filter(candidate -> !removed[candidate]).findFirst().orElse(-1);
            if (key < 0) throw new IllegalStateException("inconsistent peeling state");
            removed[key] = true;
            stack.add(new BffPlan.Assignment(key, slot));
            for (int position : positions[key]) {
                degree[position]--;
                if (degree[position] == 1) queue.addLast(position);
            }
        }
        return stack.size() == positions.length ? stack : null;
    }

    private static int[][] randomTable(int length, int payloadLength, int modulus, long seed) {
        int[][] table = new int[length][payloadLength];
        SplittableRandom random = new SplittableRandom(seed ^ 0x9e3779b97f4a7c15L);
        for (int[] entry : table) for (int block = 0; block < entry.length; block++) entry[block] = random.nextInt(modulus);
        return table;
    }

    private static int subtract(int left, int right, int modulus) {
        int difference = left - right;
        return difference < 0 ? difference + modulus : difference;
    }

}
