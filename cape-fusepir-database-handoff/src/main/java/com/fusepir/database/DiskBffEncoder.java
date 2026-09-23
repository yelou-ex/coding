package com.fusepir.database;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Encodes a complete BFF table in bounded memory and persists matrix polynomials by payload block. */
public final class DiskBffEncoder {
    public DiskBffEncoding encode(CanonicalDatabase database, CapeParameters parameters, BffOptions options,
                                  Path outputDirectory, int blockSize) throws IOException {
        if (blockSize < 1) throw new IllegalArgumentException("blockSize must be positive");
        if (Files.exists(outputDirectory)) {
            try (var files = Files.list(outputDirectory)) {
                if (files.findAny().isPresent()) return resume(database, parameters, outputDirectory);
            }
        }
        Files.createDirectories(outputDirectory);
        PayloadBlockProvider provider = PayloadBlockProvider.from(database, parameters, options.fingerprintSeed());
        BffPlan plan = new ArithmeticBffEncoder().plan(provider.keywords(), parameters, options);
        int rows = Math.min(parameters.ringDegreeN(), Math.max(1, (int) Math.ceil(Math.sqrt(plan.tableLength()))));
        int columns = (int) Math.ceil((double) plan.tableLength() / rows);
        int blockCount = (int) Math.ceil((double) provider.layout().payloadLength() / blockSize);
        writeManifest(outputDirectory, database, provider.layout(), plan, parameters, options, rows, columns, blockSize, blockCount);
        return writeBlocks(provider, plan, parameters, options, outputDirectory, rows, columns, blockSize, blockCount, false);
    }

    /** Continues an interrupted encoding using the exact seeds and layout frozen in bff-manifest.json. */
    public DiskBffEncoding resume(CanonicalDatabase database, CapeParameters parameters, Path outputDirectory) throws IOException {
        String manifest = Files.readString(outputDirectory.resolve("bff-manifest.json"), StandardCharsets.UTF_8);
        int blockSize = integer(manifest, "blockSize");
        int blockCount = integer(manifest, "blockCount");
        long hashSeed = longValue(manifest, "hashSeed");
        long fingerprintSeed = longValue(manifest, "fingerprintSeed");
        long tableSeed = longValue(manifest, "tableSeed");
        BffOptions options = new BffOptions(hashSeed, fingerprintSeed, tableSeed, 1, Long.MAX_VALUE);
        PayloadBlockProvider provider = PayloadBlockProvider.from(database, parameters, fingerprintSeed);
        BffPlan plan = new ArithmeticBffEncoder().planForHashSeed(provider.keywords(), parameters, hashSeed);
        int rows = integer(manifest, "rows");
        int columns = integer(manifest, "columns");
        if (plan.tableLength() != integer(manifest, "tableLength") || provider.layout().payloadLength() != integer(manifest, "payloadLength"))
            throw new IllegalArgumentException("input database does not match the manifest layout");
        return writeBlocks(provider, plan, parameters, options, outputDirectory, rows, columns, blockSize, blockCount, true);
    }

    private DiskBffEncoding writeBlocks(PayloadBlockProvider provider, BffPlan plan, CapeParameters parameters, BffOptions options,
                                         Path outputDirectory, int rows, int columns, int blockSize, int blockCount, boolean resume) throws IOException {
        for (int blockIndex = 0; blockIndex < blockCount; blockIndex++) {
            int offset = blockIndex * blockSize;
            int length = Math.min(blockSize, provider.layout().payloadLength() - offset);
            Path blockFile = outputDirectory.resolve(String.format(Locale.ROOT, "bff-block-%05d.bin", blockIndex));
            Path checksumFile = blockFile.resolveSibling(blockFile.getFileName() + ".sha256");
            if (resume && Files.exists(blockFile) && Files.exists(checksumFile)) continue;
            long blockCoefficients = Math.multiplyExact((long) plan.tableLength(), length);
            if (blockCoefficients > options.maxTableCoefficients())
                throw new IllegalArgumentException("BFF block needs " + blockCoefficients + " coefficients; limit is " + options.maxTableCoefficients());
            int[][] table = initialize(plan.tableLength(), length, parameters.plaintextModulus(), options.tableSeed(), offset);
            encodeBlock(table, plan, provider, offset, length, parameters.plaintextModulus());
            writeMatrixBlock(blockFile, table, plan.tableLength(), rows, columns);
            Files.deleteIfExists(checksumFile);
            writeChecksum(blockFile);
            if ((blockIndex + 1) % 25 == 0 || blockIndex + 1 == blockCount)
                System.out.printf(Locale.ROOT, "BFF progress: %d/%d blocks%n", blockIndex + 1, blockCount);
        }
        return new DiskBffEncoding(outputDirectory, plan.tableLength(), plan.segmentSize(), plan.segmentCountLength(), provider.layout().payloadLength(), rows, columns,
                blockSize, blockCount, plan.hashSeed(), provider.layout().fingerprintSeed());
    }

    private static void encodeBlock(int[][] table, BffPlan plan, PayloadBlockProvider provider,
                                    int offset, int length, int modulus) {
        int[] payload = new int[length];
        List<BffPlan.Assignment> stack = plan.peelingStack();
        for (int index = stack.size() - 1; index >= 0; index--) {
            BffPlan.Assignment assignment = stack.get(index);
            provider.fill(plan.keywords().get(assignment.keyIndex()), offset, length, payload);
            int[] target = table[assignment.position()];
            for (int block = 0; block < length; block++) {
                int value = payload[block];
                for (int position : plan.positions(assignment.keyIndex())) if (position != assignment.position()) value = subtract(value, table[position][block], modulus);
                target[block] = value;
            }
        }
    }

    private static int[][] initialize(int tableLength, int blockLength, int modulus, long tableSeed, int offset) {
        int[][] table = new int[tableLength][blockLength];
        SplittableRandom random = new SplittableRandom(tableSeed ^ ((long) offset * 0x9e3779b97f4a7c15L));
        for (int[] entry : table) for (int index = 0; index < blockLength; index++) entry[index] = random.nextInt(modulus);
        return table;
    }

    private static void writeMatrixBlock(Path path, int[][] table, int tableLength, int rows, int columns) throws IOException {
        try (DataOutputStream output = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(path), 1 << 20))) {
            int blockLength = table[0].length;
            for (int column = 0; column < columns; column++) for (int block = 0; block < blockLength; block++) for (int row = 0; row < rows; row++) {
                int slot = row + column * rows;
                output.writeInt(slot < tableLength ? table[slot][block] : 0);
            }
        }
    }

    private static void writeManifest(Path directory, CanonicalDatabase db, PayloadLayout layout, BffPlan plan,
                                      CapeParameters parameters, BffOptions options, int rows, int columns,
                                      int blockSize, int blockCount) throws IOException {
        String content = """
                {\n  \"format\": \"fusepir-arithmetic-bff-fastfilter-hashgen-v2\",\n  \"hashAlgorithm\": \"sha256-key64-plus-fastfilter-hash64-segmented-k3\",\n  \"n\": %d,\n  \"valueCount\": %d,\n  \"maxValues\": %d,\n  \"bloomHashCount\": %d,\n  \"bloomLength\": %d,\n  \"payloadLength\": %d,\n  \"tableLength\": %d,\n  \"segmentSize\": %d,\n  \"segmentCountLength\": %d,\n  \"rows\": %d,\n  \"columns\": %d,\n  \"plaintextModulus\": %d,\n  \"hashSeed\": %d,\n  \"fingerprintSeed\": %d,\n  \"tableSeed\": %d,\n  \"blockSize\": %d,\n  \"blockCount\": %d,\n  \"blockFormat\": \"big-endian signed int32 [column][payloadBlock][row]\"\n}\n""".formatted(
                db.records().size(), db.keywordsByValue().size(), layout.maxValueCount(), layout.bloom().hashCount(), layout.bloom().length(),
                layout.payloadLength(), plan.tableLength(), plan.segmentSize(), plan.segmentCountLength(), rows, columns, parameters.plaintextModulus(),
                plan.hashSeed(), layout.fingerprintSeed(), options.tableSeed(), blockSize, blockCount);
        Files.writeString(directory.resolve("bff-manifest.json"), content, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    private static void writeChecksum(Path blockFile) throws IOException {
        try (InputStream input = Files.newInputStream(blockFile)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1 << 20];
            for (int read; (read = input.read(buffer)) >= 0;) digest.update(buffer, 0, read);
            Files.writeString(blockFile.resolveSibling(blockFile.getFileName() + ".sha256"), HexFormat.of().formatHex(digest.digest()) + "\n", StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
        } catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static int subtract(int left, int right, int modulus) {
        int difference = left - right;
        return difference < 0 ? difference + modulus : difference;
    }

    private static int integer(String json, String name) { return (int) longValue(json, name); }

    private static long longValue(String json, String name) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\\"" + java.util.regex.Pattern.quote(name) + "\\\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!matcher.find()) throw new IllegalArgumentException("manifest is missing " + name);
        return Long.parseLong(matcher.group(1));
    }
}
