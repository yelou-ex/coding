> **归档说明**：本文件原在 `D:\DFY-ws\` 根目录，2026-10 收进 `cape\docs\reports\`。文中的历史路径（如 `D:\DFY-ws\_pirouette\`、`D:\DFY-MMBS-ws`）是当时的记录，不必照做。

# Pirouette 源码定位：BlindRotate 与 SampleExtract

**代码库**：`KULeuven-COSIC/Pirouette`（分支 `main`）
**获取方式**：`codeload.github.com/.../zip/refs/heads/main` → 解压到 `D:\DFY-ws\_pirouette\Pirouette-main\`
**仓库规模**：约 113 KB 源码，C++ / OpenFHE(LibPALISADE) + HEXL，CMake 构建
**定位时间**：本次会话

---

## 一、位置总览

| 目标 | 文件 | 行号 | 签名 |
|---|---|---|---|
| **BlindRotate**（基础版，参考实现） | `lib/src/blind_rotator.cpp` | **101–136** | `BlindRotationKey::BlindRotate(RLWECiphertext& in, NativeVector A)` |
| **BlindRotate**（快速版入口，分发） | `lib/src/blind_rotator.cpp` | **909–919** | `FastBlindRotationKey::BlindRotate(...)` |
| ├ BlindRotate1（step_size=1） | 同上 | 827–848 | `FastBlindRotationKey::BlindRotate1(...)` |
| ├ BlindRotate2（step_size=2）**← Pirouette 实际使用** | 同上 | 850–875 | `FastBlindRotationKey::BlindRotate2(...)` |
| └ BlindRotate3（step_size=3） | 同上 | 877–907 | `FastBlindRotationKey::BlindRotate3(...)` |
| **SampleExtract** | `lib/src/functional_bootstrap.cpp` | **61–75** | `FunctionalBootstrapEngine::SampleExtract(NativePoly& rlwe_A, NativePoly& rlwe_B)` |
| 声明：BlindRotate | `lib/include/blind_rotator.h` | 20 / 46–50 | — |
| 声明：SampleExtract | `lib/include/functional_bootstrap.h` | 21 | — |

### 关键调用点（谁在用这两个函数）

| 调用 | 位置 | 说明 |
|---|---|---|
| `m_br_key.BlindRotate(rlwect, ct->GetA())` | `functional_bootstrap.cpp:49` | `Boot()` 内部主路径 |
| `m_br_key.BlindRotate(ct_acc, ct->GetA())` | `functional_bootstrap.cpp:143` | `BitDecompose()` 内部 |
| `m_br_key.BlindRotate(acc, -ct->GetA())` | `scheme_switch.cpp:120` | 方案切换 |
| `SampleExtract(msb_A, msb_B)` | `functional_bootstrap.cpp:157` | 取回 MSB |
| `SampleExtract(bit_A, bit_B)` | `functional_bootstrap.cpp:172` | 取回其余比特 |
| `blind_rotator.BlindRotate(acc, A)` | `tests/blind_rotator_tests.cpp:78, 169` | 单元测试 |

> **注意**：`FunctionalBootstrapEngine` 构造函数里写死了 `step_size = 2`
> （`functional_bootstrap.cpp:9`：`m_br_key(params, sk_rlwe, sk_lwe, 2)`），
> 所以**实际运行走的是 `BlindRotate2`**，而不是带 `ternary_mux` 的 `BlindRotationKey::BlindRotate`。

---

## 二、BlindRotate 基础版（`blind_rotator.cpp:101–136`）

```cpp
RLWECiphertext BlindRotationKey::BlindRotate(lbcrypto::RLWECiphertext &in, NativeVector A) {
    auto N = m_params->GetN();

    // copy to buffer
    for(uint32_t i = 0; i < m_params->GetN(); i++) {
        m_acc_buffer[i] = in->GetElements()[0][i].ConvertToInt();
        m_acc_buffer[i + N] = in->GetElements()[1][i].ConvertToInt();
    }

    for(int i = 0; i < A.GetLength(); i++) {
        auto a_idx = A.at(i).ConvertToInt<uint32_t>();

        // TODO: as weird as it is, it might make sense to sort the LWE sample first (the  vector at least)
        // TODO: for n \approx q duplicates become quite likely, so we could re-use the monomial and it's nice for cache
        if (a_idx == 0) [[unlikely]] {
        } else {
            auto a_neg = (2 * N - a_idx) % (2 * N);
            //m_brk.at(i).first.cmux(m_acc_buffer.data(), a_neg);
            m_brk.at(i).first.ternary_mux(m_acc_buffer.data(), m_monomials_raw.data() + a_neg * N, m_monomials_raw.data() + a_idx * N, m_brk.at(i).second);
        }
    }

    NativeVector W(N, in->GetElements()[0].GetModulus());
    for(uint32_t i = 0; i < N; i++)
        W[i] = m_acc_buffer[i];
    in->GetElements()[0].SetValues(W, EVALUATION);

    for(uint32_t i = 0; i < N; i++)
        W[i] = m_acc_buffer[i + N];
    in->GetElements()[1].SetValues(W, EVALUATION);

    return in;
}
```

**算法要点**
- 累加器 `in = (A_0, B_0)` 先展平进 `m_acc_buffer`（长度 `2N`），在**系数域**做乘法（HEXL 的 `ternary_mux`），最后统一回 `EVALUATION` 域。
- 每位 LWE 系数 `A[i]` 对应一个 RGSW 样本 `m_brk[i]`；`a_idx == 0` 时直接跳过（CMUX 保持原值，省一次乘法）。
- 预计算单子表 `m_monomials_raw`：`q × N`，第 `idx` 块表示 `X^idx - 1`（即在 NTT 域即可直接用的 `(X^idx - 1)`）。
- 该实现是 **OpenFHE 版的替代品，明确不丢弃最低位（does not drop the least significant digit）** —— 见 `blind_rotator.h:11` 的注释，这是 Pirouette 的关键改动点。
- 副作用：**原地修改并返回 `in`**，不分配新的 RLWE 密文。

---

## 三、BlindRotate 快速版（`blind_rotator.cpp:827–919`）

### 入口分发（909–919）

```cpp
RLWECiphertext FastBlindRotationKey::BlindRotate(RLWECiphertext &in, NativeVector A) {
    if (m_step_size == 1) { return BlindRotate1(in, A); }
    if (m_step_size == 2) { return BlindRotate2(in, A); }
    return BlindRotate3(in, A);
}
```

### BlindRotate2（850–875）— **实际执行路径**

```cpp
RLWECiphertext FastBlindRotationKey::BlindRotate2(RLWECiphertext &in, NativeVector A) {
    auto N = m_engine->GetDegree();

    Vector buffer(2 * N);

    auto lwe_n = A.GetLength();
    for (uint32_t i = 0; i < N; i++) {
        buffer[i]     = in->GetElements()[0][i].ConvertToInt<uint64_t>();
        buffer[i + N] = in->GetElements()[1][i].ConvertToInt<uint64_t>();
    }

    for (uint32_t i = 0; i < lwe_n; i+=2) {
        Step2(buffer, i, A[i].ConvertToInt<uint64_t>(), A[i + 1].ConvertToInt<uint64_t>());
    }

    if (lwe_n & 1) {                    // LWE 维数为奇数时的尾巴
        Step1(buffer, lwe_n - 1, A[lwe_n - 1].ConvertToInt<uint64_t>());
    }

    for (uint32_t i = 0; i < N; i++) {
        in->GetElements()[0][i] = buffer[i];
        in->GetElements()[1][i] = buffer[i + N];
    }

    return in;
}
```

**与基础版的差异**

| 维度 | `BlindRotationKey::BlindRotate` | `FastBlindRotationKey::BlindRotate2` |
|---|---|---|
| 每轮处理 | 1 位 LWE 系数 | **2 位**（`Step2`，一次 CMUX 吃两个 digit） |
| 累加器存储 | `std::vector<uint64_t> m_acc_buffer`（成员，复用） | `Vector buffer`（**栈上临时**，32 字节对齐 `AlignedAllocator`） |
| 单子表规模 | `q * N`（按 `a_idx` 索引） | 由 `MakePoly2` 动态生成到 `m_poly_buffer` |
| 内存对齐 | 无特殊要求 | `ALIGN_AT 32`，`__restrict` 指针，面向 AVX/HEXL |
| 乘法实现 | `ternary_mux`（RGSW 样本对象） | `ExtProd` / `RLWEVectorProd2` 手写指针循环 |

- `BlindRotate1/3` 结构同构：分别按 1 位 / 3 位步长走 `Step1` / `Step3`。
- `BlindRotate3` 里对 `lwe_n % 3 == 2` 直接 `std::exit(-1)` 并打印 `NOPE`（未实现的分支，见 892–899）；构造函数中也有对应断言 `assert(sk_lwe.GetLength() % 3 != 2 or step_size != 3)`（146 行）。
- `BlindRotate2` 的 `if (lwe_n & 1)` 是**奇数尾处理**；而 `BlindRotate3` 的尾部处理只调用了 `Step1` 一次、且用 `lwe_n - 2` 作索引，看起来只覆盖了 `lwe_n % 3 == 1` 的情形 —— 若你想做代码审计/验证，这里是值得核对的一处。
- 与基础版一致：**原地修改 `in` 并返回**，`in` 的两个元素最终被写回 `in`（注意 `buffer` 是局部变量，生命周期只在本函数内）。

---

## 四、SampleExtract（`functional_bootstrap.cpp:61–75`）

```cpp
LWECiphertext
FunctionalBootstrapEngine::SampleExtract(lbcrypto::NativePoly &rlwe_A, lbcrypto::NativePoly &rlwe_B) {
    auto N = rlwe_A.GetLength();
    auto Q = rlwe_B.GetModulus();

    NativeVector A(N, Q);
    NativeInteger B = rlwe_B.at(0);

    A[0] = rlwe_A[0];
    for(uint32_t idx = 1; idx < N; idx++) {
        A[idx] = Q.ModSub(rlwe_A[N - idx], Q);
    }

    return std::make_shared<LWECiphertextImpl>(A, B);
}
```

**算法要点**

- 输入：RLWE 密文在**系数域**的两个多项式 `(rlwe_A, rlwe_B)`，模数 `Q`。
- 输出：维度 `N` 的 LWE 密文 `(A, B)`，模数 `Q`。
- **常数项提取**：`B = rlwe_B.at(0)`，即 `rlwe_B` 的常数系数 → LWE 的 `b`。
- **密钥映射**：`A[0] = rlwe_A[0]`；`A[idx] = -rlwe_A[N - idx] mod Q`（`idx = 1..N-1`）。
  即把 RLWE 的 `a(X) = Σ a_i X^i` 反向、取负后铺成 LWE 向量 —— 对应 RLWE 秘密 `s(X)` 的系数序列 `(s_0, s_1, ..., s_{N-1})`，实现"常量项 = `b - <a, s>`"的相位对齐。
- 所有取负都用 `Q.ModSub(·, Q)` 做模约减，**无符号下溢风险**。
- 用 `NativeInteger B = rlwe_B.at(0)` **值拷贝**，不会因后续修改 `rlwe_B` 而改变。

**前置条件（重要）**
- 调用点是 `functional_bootstrap.cpp:157` 与 `:172`，两次都在 `bit_A.SwitchFormat(); bit_B.SwitchFormat();` **之后**（152–155、167–170 行）。
- 函数体内部按**系数下标**直接索引，**隐含要求入参已是 COEFFICIENT 格式**；若传入 NTT/EVALUATION 域的多项式，`A[idx] = -rlwe_A[N-idx]` 这个映射就不再成立（不会报错，只会得到错误结果）。
- `N = rlwe_A.GetLength()`，所以输出 LWE 维度等于环维度，与 `m_br_params->GetN()` 一致。

**MSB 的符号修正**（紧接在调用之后，`158–160` 行）：
```cpp
ct_msb_bit->GetB().ModAddEq(Q / 4, Q);
```
注释解释了原因：MSB 在累加器里是按符号翻转编码的（`MSB == 0 ⇒ -Q/4`，否则 `Q/4`），加 `Q/4` 把它映射回 `0` 或 `Q/2`。

---

## 五、附：仓库文件清单（与本题相关的部分）

```
Pirouette-main/
├── lib/include/blind_rotator.h            ← BlindRotate 声明
├── lib/include/functional_bootstrap.h     ← SampleExtract 声明
├── lib/src/blind_rotator.cpp              ← BlindRotate 全部实现（919 行）
├── lib/src/functional_bootstrap.cpp       ← SampleExtract + BitDecompose + Boot
├── lib/src/scheme_switch.cpp              ← 另一处 BlindRotate 调用
├── lib/src/digit_decomposer.cpp           ← 使用 blind_rotate_Q 做模数切换
├── tests/blind_rotator_tests.cpp          ← BlindRotate 单元测试
└── tests/Giant_lut_eval_test.cpp
```

本地副本路径：`D:\DFY-ws\_pirouette\Pirouette-main\`
