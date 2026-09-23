# CAPE/FusePIR 数据库模块交接说明

## 已完成

- `MovieLensTagLoader`：读取 `tags.csv`，完成 UTF-8、Unicode NFC、小写、空白规范化。
- `CanonicalDatabase`：提供关键词到 value 的正向关系，以及 value 到关键词集合的反向关系。
- `DatabasePreprocessor`：根据统一的 CAPE 参数生成 Bloom 参数和固定长度明文 payload。
- `ArithmeticBffEncoder`：实现论文 Algorithm 3 的三位置 MappingStep、peeling、seed 重试和模 `t` payload 重构。
- `BffMatrixLayout`：将 BFF 数组作为 `P[c][b](X)` 的非复制矩阵视图。
- `PayloadBlockProvider` 与 `DiskBffEncoder`：按 payload block 生成 BFF，并将矩阵多项式写入磁盘，适用于完整 MovieLens 开发档。
- `PlaintextDatabasePreprocessor`：密码模块应依赖的最小接口。
- `DatabasePreprocessorTest`：验证多对多关系和 payload 长度一致性。

## 密码模块接口

密码模块可以直接调用：

```java
CanonicalDatabase db = MovieLensTagLoader.load(tagsCsv);
PreparedDatabase prepared = new DatabasePreprocessor().prepare(db, CapeParameters.defaults());
```

然后读取：

- `prepared.payloads()`：关键词到明文 payload；
- `prepared.bloom()`：Bloom 的 `h` 和 `lBF`；

在完成 BFF 编码后，使用：

```java
ArithmeticBff bff = new ArithmeticBffEncoder().encode(prepared, params, options);
BffMatrixLayout matrix = BffMatrixLayout.of(bff, params);
```

## 当前边界

本模块不实现 RLWE、LWE、BlindRotate、SampleExtract、Pack 或查询协议；也不保存客户端私钥。

实际 BFF 表为 `int[L_BFF][Bpay]`，其中每个元素是 `Z_t` 系数。大型数据集的该表可能超过可用内存；编码器会根据 `BffOptions.maxTableCoefficients` 先拒绝不安全的分配，而不是触发 OOM。

`DiskBffEncoder` 的 block 文件按 `[column][payloadBlock][row]` 的大端 `int32` 顺序保存，供服务端后续依次读取 `P[c][b](X)`。`bff-manifest.json` 固化参数、三个独立 seed、矩阵尺寸、block 格式，以及 FastFilter-compatible segmented `BFF.HashGen` 参数。

`BffHashGen` 先取 `SHA-256(UTF-8 canonical keyword)` 的前 64 bit 作为 key，再执行 FastFilter 的 `hash64(key, rhoH)`、Lemire reduce 和三段连续 segment 定位。其他语言实现必须严格复现这一字节序和规则；旧 `fusepir-arithmetic-bff-v1` 输出与该规则不兼容，不能混用。

跨语言测试向量：当 `n=1475`、`rhoH=0x0123456789abcdef`、关键词为 `sci-fi` 时，布局必须为 `segmentLength=256`、`segmentCount=6`、`segmentCountLength=1536`、`L_BFF=2048`，且三位置必须为 `[32, 375, 557]`。对应测试见 `BffHashGenTest`。

`DiskBffVerifierMain` 可不加载完整 BFF 表，直接从磁盘重构一个关键词的指定 block，用于离线正确性验证。

`PlaintextFusePirQueryMain` 读取三个 BFF 位置、重构全部 payload、验证 fingerprint 并解析 value 列表。它是接入 RLWE/LWE 前的单关键词端到端正确性基线。

原始 MovieLens 数据没有打包，队友需要自行下载 `tags.csv` 并传入路径。
