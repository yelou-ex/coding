package com.fusepir.database;

/** Fixed payload metadata shared by in-memory and streaming encoders. */
public record PayloadLayout(BloomParameters bloom, int maxValueCount, int payloadLength, long fingerprintSeed) {}
