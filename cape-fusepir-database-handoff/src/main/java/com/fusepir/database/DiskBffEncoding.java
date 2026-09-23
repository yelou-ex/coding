package com.fusepir.database;

import java.nio.file.Path;

/** On-disk BFF result. Each block file is ordered as [column][payload block][row]. */
public record DiskBffEncoding(Path directory, int tableLength, int segmentSize, int segmentCountLength, int payloadLength, int rows, int columns,
                              int blockSize, int blockCount, long hashSeed, long fingerprintSeed) {}
