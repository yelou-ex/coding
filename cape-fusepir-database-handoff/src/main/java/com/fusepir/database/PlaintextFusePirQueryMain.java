package com.fusepir.database;

import java.nio.file.Path;
import java.util.Scanner;

/** Interactive local test: input one keyword and receive its decoded candidate values or bottom. */
public final class PlaintextFusePirQueryMain {
    private PlaintextFusePirQueryMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("usage: PlaintextFusePirQueryMain <bff-directory>");
        PlaintextFusePirQuery query = PlaintextFusePirQuery.open(Path.of(args[0]));
        System.out.println("输入单关键词；输入 exit 退出。");
        try (Scanner scanner = new Scanner(System.in)) {
            while (scanner.hasNextLine()) {
                String keyword = scanner.nextLine();
                if (keyword.equalsIgnoreCase("exit")) return;
                PlaintextFusePirQueryResult result = query.query(keyword);
                System.out.println(result.found() ? "候选 value = " + result.values() : "结果 = ⊥（关键词不存在）");
                System.out.println("请输入下一个关键词：");
            }
        }
    }
}
