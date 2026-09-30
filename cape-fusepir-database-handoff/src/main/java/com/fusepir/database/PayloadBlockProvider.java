package com.fusepir.database;

import com.fusepir.common.BfGen;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Generates payload coefficients on demand without materializing every keyword payload. */
public final class PayloadBlockProvider {
    private final Map<String, int[]> valuesByKeyword;
    private final Map<Integer, BitSet> bloomByValue;
    private final PayloadLayout layout;

    private PayloadBlockProvider(Map<String, int[]> valuesByKeyword, Map<Integer, BitSet> bloomByValue, PayloadLayout layout) {
        this.valuesByKeyword = Map.copyOf(valuesByKeyword);
        this.bloomByValue = Map.copyOf(bloomByValue);
        this.layout = layout;
    }

    public static PayloadBlockProvider from(CanonicalDatabase database, CapeParameters parameters, long fingerprintSeed) {
        int maxSetSize = database.keywordsByValue().values().stream().mapToInt(Set::size).max().orElse(0);
        BfGen bloom = parameters.bloomParameters(maxSetSize);
        int payloadLength = 3 + 2 + database.maxValues() * (2 + bloom.length());
        Map<String, int[]> values = new TreeMap<>();
        for (KeywordRecord record : database.records()) values.put(record.keyword(), record.values());
        Map<Integer, BitSet> filters = new TreeMap<>();
        database.keywordsByValue().forEach((value, keywords) -> filters.put(value, bloom(value, keywords, bloom)));
        return new PayloadBlockProvider(values, filters, new PayloadLayout(bloom, database.maxValues(), payloadLength, fingerprintSeed));
    }

    public PayloadLayout layout() { return layout; }
    public Set<String> keywords() { return valuesByKeyword.keySet(); }

    /** 规模摘要（用于判断一组参数是不是"测试规模"） */
    public String describe() {
        int tableLength = ArithmeticBffEncoder.tableLength(valuesByKeyword.size());
        long coefficients = (long) tableLength * layout.payloadLength();
        return String.format(
            "关键词=%d, m=%d, h=%d, lBF=%d, payload=%d, L_BFF=%d, 表系数=%,d (%.1f MB @ int32)",
            valuesByKeyword.size(), layout.maxValueCount(), layout.bloom().hashCount(),
            layout.bloom().length(), layout.payloadLength(), tableLength,
            coefficients, coefficients * 4.0 / 1048576.0);
    }

    public void fill(String keyword, int offset, int length, int[] output) {
        if (length < 0 || offset < 0 || offset + length > layout.payloadLength() || output.length != length)
            throw new IllegalArgumentException("invalid payload block");
        int[] values = valuesByKeyword.get(keyword);
        if (values == null) throw new NoSuchElementException("unknown keyword: " + keyword);
        int[] fingerprint = PayloadFingerprint.limbs(keyword, layout.fingerprintSeed());
        int groupLength = 2 + layout.bloom().length();
        for (int local = 0; local < length; local++) {
            int index = offset + local;
            if (index < 3) output[local] = fingerprint[index];
            else if (index == 3) output[local] = values.length >>> 16;
            else if (index == 4) output[local] = values.length & 0xffff;
            else {
                int relative = index - 5;
                int valueIndex = relative / groupLength;
                int field = relative % groupLength;
                if (valueIndex >= values.length) output[local] = 0;
                else if (field == 0) output[local] = values[valueIndex] >>> 16;
                else if (field == 1) output[local] = values[valueIndex] & 0xffff;
                else output[local] = bloomByValue.get(values[valueIndex]).get(field - 2) ? 1 : 0;
            }
        }
    }

    public short[] materialize(String keyword) {
        int[] coefficients = new int[layout.payloadLength()];
        fill(keyword, 0, coefficients.length, coefficients);
        short[] result = new short[coefficients.length];
        for (int index = 0; index < result.length; index++) result[index] = (short) coefficients[index];
        return result;
    }

    private static BitSet bloom(int value, Set<String> keywords, BfGen parameters) {
        // 位位置只依赖关键词 —— 见 BfGen.bits() 的说明。
        // 早期这里写的是 digest(keyword + ":" + value)，把 value 混进了哈希，
        // 导致客户端的查询向量与服务端候选的位位置对不上（README 第 11 项）。
        boolean[] bits = parameters.bits(keywords);
        BitSet result = new BitSet(bits.length);
        for (int index = 0; index < bits.length; index++) {
            if (bits[index]) result.set(index);
        }
        return result;
    }
}
