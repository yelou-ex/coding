package com.fusepir.database;

import java.io.DataInputStream;
import java.nio.file.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Verifies one encoded keyword payload block directly against the on-disk BFF matrix. */
public final class DiskBffVerifierMain {
    private DiskBffVerifierMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > 4)
            throw new IllegalArgumentException("usage: DiskBffVerifierMain <tags.csv> <bff-directory> <keyword> [block-index]");
        Path directory = Path.of(args[1]);
        String manifest = Files.readString(directory.resolve("bff-manifest.json"));
        int blockSize = integer(manifest, "blockSize");
        int payloadLength = integer(manifest, "payloadLength");
        int tableLength = integer(manifest, "tableLength");
        int segmentSize = integer(manifest, "segmentSize");
        int segmentCountLength = integer(manifest, "segmentCountLength");
        int rows = integer(manifest, "rows");
        int columns = integer(manifest, "columns");
        long hashSeed = longValue(manifest, "hashSeed");
        long fingerprintSeed = longValue(manifest, "fingerprintSeed");
        int blockIndex = args.length == 4 ? Integer.parseInt(args[3]) : 0;
        int offset = Math.multiplyExact(blockIndex, blockSize);
        if (offset >= payloadLength) throw new IllegalArgumentException("block index is outside payload");
        int length = Math.min(blockSize, payloadLength - offset);
        CanonicalDatabase database = MovieLensTagLoader.load(Path.of(args[0]));
        PayloadBlockProvider provider = PayloadBlockProvider.from(database, CapeParameters.defaults(), fingerprintSeed);
        String keyword = TagCanonicalizer.canonicalize(args[2]);
        int[] expected = new int[length];
        provider.fill(keyword, offset, length, expected);
        int[] actual = reconstruct(directory.resolve(String.format("bff-block-%05d.bin", blockIndex)),
                ArithmeticBffEncoder.positions(keyword, hashSeed, segmentSize, segmentCountLength), tableLength, rows, columns, length);
        for (int index = 0; index < length; index++) if (expected[index] != actual[index])
            throw new AssertionError("BFF mismatch at payload coefficient " + (offset + index));
        System.out.printf("BFF block verified: keyword=%s block=%d offset=%d length=%d%n", keyword, blockIndex, offset, length);
    }

    private static int[] reconstruct(Path blockFile, int[] positions, int tableLength, int rows, int columns, int blockLength) throws Exception {
        int[][] selected = new int[positions.length][blockLength];
        try (DataInputStream input = new DataInputStream(Files.newInputStream(blockFile))) {
            for (int column = 0; column < columns; column++) for (int block = 0; block < blockLength; block++) for (int row = 0; row < rows; row++) {
                int slot = row + column * rows;
                int value = input.readInt();
                if (slot >= tableLength) continue;
                for (int index = 0; index < positions.length; index++) if (positions[index] == slot) selected[index][block] = value;
            }
        }
        int[] reconstructed = new int[blockLength];
        for (int block = 0; block < blockLength; block++) for (int[] entry : selected) reconstructed[block] = (reconstructed[block] + entry[block]) % 65537;
        return reconstructed;
    }

    private static int integer(String json, String name) { return (int) longValue(json, name); }

    private static long longValue(String json, String name) {
        Matcher matcher = Pattern.compile("\\\"" + Pattern.quote(name) + "\\\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!matcher.find()) throw new IllegalArgumentException("manifest is missing " + name);
        return Long.parseLong(matcher.group(1));
    }
}
