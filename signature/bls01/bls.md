### BLS数字签名方案接口文档

#### 简介
此Go语言代码实现了基于BN254曲线的BLS（Boneh-Lynn-Shacham）数字签名方案。它提供了一套完整的函数，用于生成密钥、对消息签名以及验证签名。

---

### 数据结构

#### **1. `BLSParams`**
定义了BLS签名方案所需的公共参数。

| 字段          | 类型             | 描述                                     |
|---------------|------------------|------------------------------------------|
| `Field`       | `*big.Int`       | 底层有限域的阶（q），私钥的取值范围。      |
| `G1Generator` | `bn254.G1Affine` | G1群的生成元。                              |
| `DST`         | `[]byte`         | 用于哈希到G2的域分隔标签。                 |

#### **2. `BLSKeyPair`**
定义了一个BLS密钥对。

| 字段          | 类型             | 描述                                     |
|---------------|------------------|------------------------------------------|
| `PrivateKey`  | `*big.Int`       | 私钥，一个随机大整数x。                   |
| `PublicKey`   | `bn254.G1Affine` | 公钥，计算为G1^x。                         |

#### **3. `BLSSignature`**
定义了一个BLS签名。

| 字段        | 类型             | 描述                                     |
|-------------|------------------|------------------------------------------|
| `Message`   | `[]byte`         | 被签名的原始消息。                         |
| `Signature` | `bn254.G2Affine` | 签名结果，计算为H(m)^x。                   |

---

### 公共函数

#### **1. `SetUp()`**
- **功能**: 初始化并返回BLS签名方案的公共参数。
- **返回**: `*BLSParams` - 包含曲线标量域、G1生成元和域分隔标签的参数结构体。

#### **2. `KeyGeneration(blsParams BLSParams)`**
- **功能**: 基于提供的公共参数生成一个BLS密钥对。
- **参数**:
    - `blsParams` (`BLSParams`): 初始化后的BLS参数。
- **返回**:
    - `*BLSKeyPair`: 新生成的密钥对。
    - `error`: 如果密钥生成失败则返回错误。

#### **3. `Sign(blsParams BLSParams, privateKey *big.Int, message []byte)`**
- **功能**: 使用私钥对消息进行签名。
- **参数**:
    - `blsParams` (`BLSParams`): 初始化后的BLS参数。
    - `privateKey` (`*big.Int`): 用于签名的私钥。
    - `message` (`[]byte`): 待签名的消息。
- **返回**:
    - `*BLSSignature`: 包含消息和签名结果的结构体。
    - `error`: 如果签名过程失败则返回错误。

#### **4. `Verify(blsParams BLSParams, publicKey bn254.G1Affine, blsSignature BLSSignature)`**
- **功能**: 验证BLS签名的有效性。
- **参数**:
    - `blsParams` (`BLSParams`): 初始化后的BLS参数。
    - `publicKey` (`bn254.G1Affine`): 验证签名所需的公钥。
    - `blsSignature` (`BLSSignature`): 待验证的签名结构体。
- **返回**:
    - `bool`: 签名是否有效。
    - `error`: 如果验证过程失败则返回错误。