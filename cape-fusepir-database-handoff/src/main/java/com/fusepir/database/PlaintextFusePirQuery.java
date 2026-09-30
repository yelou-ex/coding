package com.fusepir.database;

import com.fusepir.common.BfGen;

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
    private final int bloomHashCount;
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
        bloomHashCount = integer(manifest, "bloomHashCount");
        segmentSize = integer(manifest, "segmentSize");
        segmentCountLength = integer(manifest, "segmentCountLength");
        rows = integer(manifest, "rows");
        columns = integer(manifest, "columns");
        blockSize = integer(manifest, "blockSize");
        modulus = integer(manifest, "plaintextModulus");
        hashSeed = longValue(manifest, "hashSeed");
        fingerprintSeed = longValue(manifest, "fingerprintSeed");
    }

    /** 客户端侧的 Bloom 查询向量与阈值。 */
    public record BloomQuery(long[] bits, long tau) {}

    /**
     * <b>CAPE 算法 2 · QUERY 第 2~3 行：{@code b_qry ← BF.Gen(0, {K_2,…,K_Q})}、{@code τ ← ‖b_qry‖₁}。</b>
     *
     * <p>本模块此前<b>完全没有</b>客户端 Bloom 查询 —— `query()` 只重建 payload、校指纹、取值，
     * `bloomLength` 仅用于算 `groupLength` 以便<b>跳过</b> Bloom 段（见缺陷总表 P1-5）。
     *
     * <p><b>只用到关键词</b>，且与服务器构造 {@code b_v} 用的是<b>同一份</b>
     * {@link BfGen}（共享模块 `common`）—— 两边位位置必然对得上。
     *
     * @param keywordsExceptAnchor 查询关键词里除锚以外的部分 {@code K_2..K_Q}
     */
    public BloomQuery bloomQuery(java.util.List<String> keywordsExceptAnchor) {
        BfGen gen = new BfGen(bloomHashCount, bloomLength);
        boolean[] bits = new boolean[bloomLength];
        for (String keyword : keywordsExceptAnchor) {
            boolean[] single = gen.bits(TagCanonicalizer.canonicalize(keyword));
            for (int i = 0; i < bloomLength; i++) {
                if (single[i]) bits[i] = true;
            }
        }
        long[] vector = new long[bloomLength];
        long tau = 0;
        for (int i = 0; i < bloomLength; i++) {
            vector[i] = bits[i] ? 1 : 0;
            tau += vector[i];
        }
        return new BloomQuery(vector, tau);
    }

    /** 该库的 Bloom 参数（服务端与客户端必须一致）。 */
    public BfGen bloomParameters() {
        return new BfGen(bloomHashCount, bloomLength);
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
