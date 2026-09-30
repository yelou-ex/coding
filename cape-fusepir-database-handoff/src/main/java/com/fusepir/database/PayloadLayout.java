package com.fusepir.database;

import com.fusepir.common.BfGen;

/** Fixed payload metadata shared by in-memory and streaming encoders. */
public record PayloadLayout(BfGen bloom, int maxValueCount, int payloadLength, long fingerprintSeed) {}
