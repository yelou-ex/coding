package com.fusepir.database;

import java.io.IOException;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** Reads the three BFF positions from disk and reconstructs a single plaintext keyword payload. */
public final class PlaintextFusePirQuery {
    private final Path directory;
    private final int tableLength;
    private final int payloadLength;
    private final int bloomLength;
    private final int segmentSize;
    private final int segmentCountLength;
    private final int rows;
    private final int columns;
    private final int blockSize;
    private final int modulus;
    private final long hashSeed;
    private final long fingerprintSeed;

    private PlaintextFusePirQuery(Path directory, String manifest) {
        this.directory = directory;
        tableLength = integer(manifest, "tableLength");
        payloadLength = integer(manifest, "payloadLength");
        bloomLength = integer(manifest, "bloomLength");
        segmentSize = integer(manifest, "segmentSize");
        segmentCountLength = integer(manifest, "segmentCountLength");
        rows = integer(manifest, "rows");
        columns = integer(manifest, "columns");
        blockSize = integer(manifest, "blockSize");
        modulus = integer(manifest, "plaintextModulus");
        hashSeed = longValue(manifest, "hashSeed");
        fingerprintSeed = longValue(manifest, "fingerprintSeed");
    }

    public static PlaintextFusePirQuery open(Path directory) throws IOException {
        return new PlaintextFusePirQuery(directory, Files.readString(directory.resolve("bff-manifest.json"), StandardCharsets.UTF_8));
    }

    public PlaintextFusePirQueryResult query(String rawKeyword) throws IOException {
        String keyword = TagCanonicalizer.canonicalize(rawKeyword);
        int[] payload = reconstruct(keyword);
        if (!PayloadFingerprint.matches(keyword, fingerprintSeed, payload)) return new PlaintextFusePirQueryResult(false, List.of());
        long count = ((long) payload[3] << 16) | payload[4];
        int groupLength = 2 + bloomLength;
        if (count > (payloadLength - 5L) / groupLength) throw new IllegalStateException("decoded value count exceeds payload");
        List<Integer> values = new ArrayList<>((int) count);
        for (int index = 0; index < count; index++) {
            int base = 5 + index * groupLength;
            values.add((payload[base] << 16) | payload[base + 1]);
        }
        return new PlaintextFusePirQueryResult(true, values);
    }

    private int[] reconstruct(String keyword) throws IOException {
        int[] positions = ArithmeticBffEncoder.positions(keyword, hashSeed, segmentSize, segmentCountLength);
        int[] payload = new int[payloadLength];
        int blockCount = (int) Math.ceil((double) payloadLength / blockSize);
        for (int blockIndex = 0; blockIndex < blockCount; blockIndex++) {
            int offset = blockIndex * blockSize;
            int length = Math.min(blockSize, payloadLength - offset);
            int[][] selected = readSelectedEntries(blockIndex, length, positions);
            for (int block = 0; block < length; block++) {
                int value = 0;
                for (int[] entry : selected) value = (value + entry[block]) % modulus;
                payload[offset + block] = value;
            }
        }
        return payload;
    }

    private int[][] readSelectedEntries(int blockIndex, int blockLength, int[] positions) throws IOException {
        Map<Integer, List<Integer>> indexesByColumn = new TreeMap<>();
        for (int index = 0; index < positions.length; index++) indexesByColumn.computeIfAbsent(positions[index] / rows, ignored -> new ArrayList<>()).add(index);
        int[][] selected = new int[positions.length][blockLength];
        Path file = directory.resolve(String.format(Locale.ROOT, "bff-block-%05d.bin", blockIndex));
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            for (Map.Entry<Integer, List<Integer>> entry : indexesByColumn.entrySet()) {
                long byteOffset = (long) entry.getKey() * blockLength * rows * Integer.BYTES;
                ByteBuffer buffer = ByteBuffer.allocate(Math.multiplyExact(blockLength * rows, Integer.BYTES)).order(ByteOrder.BIG_ENDIAN);
                while (buffer.hasRemaining()) {
                    int read = channel.read(buffer, byteOffset + buffer.position());
                    if (read < 0) throw new IOException("truncated BFF block: " + file);
                }
                for (int index : entry.getValue()) {
                    int row = positions[index] % rows;
                    for (int block = 0; block < blockLength; block++) selected[index][block] = buffer.getInt((block * rows + row) * Integer.BYTES);
                }
            }
        }
        return selected;
    }

    private static int integer(String json, String name) { return (int) longValue(json, name); }

    private static long longValue(String json, String name) {
        Matcher matcher = Pattern.compile("\\\"" + Pattern.quote(name) + "\\\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!matcher.find()) throw new IllegalArgumentException("manifest is missing " + name);
        return Long.parseLong(matcher.group(1));
    }
}
