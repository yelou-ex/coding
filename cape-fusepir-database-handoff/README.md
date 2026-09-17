# CAPE/FusePIR 数据库初始化

首阶段只包含明文数据库初始化，不实现或修改 RLWE/LWE 协议逻辑。

## 导入 Eclipse

`File -> Import -> General -> Existing Projects into Workspace`，选择本目录 `E:\pir`。

输入 MovieLens 的 `tags.csv` 后运行：

```text
com.fusepir.database.DatabaseInitializerMain E:\data\ml-25m\tags.csv
```

输出包括关键词数、值数、最大关联数、Bloom 参数、payload 长度，以及按 Arithmetic BFF 算法估算的 `L_BFF` 和矩阵布局。原始 MovieLens 数据不放入本项目。

## 分块 BFF 编码

对 MovieLens small 使用 `DiskBffEncodeMain`。该程序按 payload block 编码，避免将整个 BFF 表保存在内存中：

```text
com.fusepir.database.DiskBffEncodeMain
    E:\pir\data\ml-latest-small\tags.csv
    E:\pir\data\bff-latest-small-fastfilter-20260914-r2
    2048
```

第二个参数必须是不存在或为空的目录。输出包含 `bff-manifest.json`、每个 payload block 的矩阵文件 `bff-block-*.bin`，以及对应 SHA-256 文件。当前数据参数预计会占用约 5.2 GB 磁盘空间。manifest 中的 `hashAlgorithm`、`segmentSize` 和 `segmentCountLength` 是客户端、服务端必须共用的 BFF.HashGen 规范。

可从磁盘重构并校验某个关键词的任意 block：

```text
com.fusepir.database.DiskBffVerifierMain
    E:\pir\data\ml-latest-small\tags.csv
    E:\pir\data\bff-latest-small-fastfilter-20260914-r2
    sci-fi
    0
```

## 单关键词端到端明文查询

运行 `PlaintextFusePirQueryMain` 并传入已生成的 BFF 目录：

```text
com.fusepir.database.PlaintextFusePirQueryMain
    E:\pir\data\bff-latest-small-fastfilter-20260914-r2
```

在 Eclipse Console 输入一个关键词，例如 `sci-fi`，程序会从三个 BFF 位置重构完整 payload 并返回候选 `movieId`；输入不存在的关键词会返回 `⊥`。这是 FusePIR 数据流正确性测试，不提供查询隐私。
