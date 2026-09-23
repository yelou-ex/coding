package com.fusepir.database;

import java.nio.file.Path;

public final class DatabaseInitializerMain {
    private DatabaseInitializerMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("usage: DatabaseInitializerMain <tags.csv>");
        CanonicalDatabase db = MovieLensTagLoader.load(Path.of(args[0]));
        PayloadLayout payload = PayloadBlockProvider.from(db, CapeParameters.defaults(), DatabasePreprocessor.DEFAULT_FINGERPRINT_SEED).layout();
        double average = db.records().stream().mapToInt(r -> r.values().length).average().orElse(0);
        int bffLength = ArithmeticBffEncoder.tableLength(db.records().size());
        int rows = Math.min(CapeParameters.defaults().ringDegreeN(), Math.max(1, (int) Math.ceil(Math.sqrt(bffLength))));
        int columns = (int) Math.ceil((double) bffLength / rows);
        long tableCoefficients = Math.multiplyExact((long) bffLength, payload.payloadLength());
        System.out.printf("n=%d |V|=%d m=%d averageValues=%.2f smax=%d h=%d lBF=%d Bpay=%d L_BFF=%d R=%d C=%d tableCoefficients=%d%n",
                db.records().size(), db.keywordsByValue().size(), db.maxValues(), average,
                db.keywordsByValue().values().stream().mapToInt(java.util.Set::size).max().orElse(0),
                payload.bloom().hashCount(), payload.bloom().length(), payload.payloadLength(),
                bffLength, rows, columns, tableCoefficients);
    }
}
