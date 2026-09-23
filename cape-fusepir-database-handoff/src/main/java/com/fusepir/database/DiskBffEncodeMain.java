package com.fusepir.database;

import java.nio.file.Path;

/** Runs bounded-memory BFF encoding for a tags.csv file. */
public final class DiskBffEncodeMain {
    private DiskBffEncodeMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3)
            throw new IllegalArgumentException("usage: DiskBffEncodeMain <tags.csv> <empty-output-directory> [block-size]");
        int blockSize = args.length == 3 ? Integer.parseInt(args[2]) : 2048;
        CanonicalDatabase database = MovieLensTagLoader.load(Path.of(args[0]));
        DiskBffEncoding encoding = new DiskBffEncoder().encode(database, CapeParameters.defaults(), BffOptions.random(), Path.of(args[1]), blockSize);
        System.out.printf("BFF complete: directory=%s L_BFF=%d Bpay=%d R=%d C=%d blocks=%d%n", encoding.directory(), encoding.tableLength(), encoding.payloadLength(), encoding.rows(), encoding.columns(), encoding.blockCount());
    }
}
