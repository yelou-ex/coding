package com.fusepir.database;

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
        BloomParameters bloom = BloomParameters.choose(database.keywordsByValue().values().stream().mapToInt(Set::size).max().orElse(0),
                parameters.bloomFalsePositiveTarget(), parameters.ringDegreeN());
        int payloadLength = 3 + 2 + database.maxValues() * (2 + bloom.length());
        Map<String, int[]> values = new TreeMap<>();
        for (KeywordRecord record : database.records()) values.put(record.keyword(), record.values());
        Map<Integer, BitSet> filters = new TreeMap<>();
        database.keywordsByValue().forEach((value, keywords) -> filters.put(value, bloom(value, keywords, bloom)));
        return new PayloadBlockProvider(values, filters, new PayloadLayout(bloom, database.maxValues(), payloadLength, fingerprintSeed));
    }

    public PayloadLayout layout() { return layout; }
    public Set<String> keywords() { return valuesByKeyword.keySet(); }

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

    private static BitSet bloom(int value, Set<String> keywords, BloomParameters parameters) {
        BitSet bits = new BitSet(parameters.length());
        for (String keyword : keywords) {
            byte[] digest = digest(keyword + ":" + value);
            for (int index = 0; index < parameters.hashCount(); index++) bits.set(Math.floorMod(intAt(digest, index * 4), parameters.length()));
        }
        return bits;
    }

    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    private static int intAt(byte[] bytes, int offset) {
        int start = offset % (bytes.length - 3);
        return ByteBuffer.wrap(bytes, start, Integer.BYTES).getInt();
    }
}
