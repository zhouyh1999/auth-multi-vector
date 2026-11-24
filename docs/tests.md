# 核心测试迁移对照

下面路径均在本 workspace。完整测试名和状态见 [Cargo 与 Python 原始输出](evidence/isolated-tests.log)，显式运行的长测试见 [release 日志](evidence/extended-rust.log)。

| 原测试或案例 | 新位置与检查内容 |
|---|---|
| gem-core 的数值与编码 | [gem-core/src](../crates/gem-core/src) 保留两种数值表示对应的测试。覆盖 FP16 转换、负值、抵消、实际溢出、编码长度与帧边界。 |
| gem-search 固定点与图搜索 | [gem-search/src/v3](../crates/gem-search/src/v3) 的负分 MaxSim、同分按 ID、多入口、遍历和候选复验；[上游差分](../tests/fixtures/reference) 固定构建、成员和图搜索的期望值。 |
| 原 C++ qEMD shim | [构建入口](../crates/gem-qemd-lemon/build.rs) 与 [冻结输入和最优值](../tests/fixtures/golden/qemd-lemon-v3.json)。默认 feature 实际编译和调用 C++，包含并行冷、热缓存用例。 |
| 源索引、签名与 Merkle | [gem-auth-v3/src](../crates/gem-auth-v3/src) 核对元数据、组件标签、叶哈希、签名、披露集合和 multiproof。 |
| 行/列投影、证明编解码 | [gem-matrix-proof/src](../crates/gem-matrix-proof/src) 和 [vendor_vectors.rs](../crates/e2e-benchmark/tests/vendor_vectors.rs)。解析器维度边界、原版 Merlin 已知答案、固定生成元和并行证明一致性。 |
| 原协议 copy 与实测分支重叠的单元测试 | [gem-auth-scheme-v3/src](../crates/gem-auth-scheme-v3/src) 保留原协议两种表示的完整测试，包括有界解析、空入口、损坏证明及精确披露。实测生成树内原测试曾把相同夹具发到另一种帧格式，并遗漏该入口要求的固定配置。首次失败和修正依据见[原始失败](evidence/test.log)。 |
| 正常客户端入口与文件持久化 | [gem-cli/tests](../crates/gem-cli/tests) 保留跨进程客户端、快照、兼容载入、签名与旧参数拒绝测试。线程默认值随可用 CPU 缩小，显式指定仍校验。 |
| 四方案端到端与拒绝行为 | [regression.rs](../crates/authentication/src/regression.rs) 从实际 release 的 4 个诚实全查询 VO 产生 52 个定向变体。每个变体与对应诚实响应共用请求、公钥、发布和验证函数。[结构化拒绝原因](../results/sample/sample-cupx2_hd/rejections.json) |
| 编排、准备与独立参考 | [Python 测试](../scripts/tests) 核对内容篡改、路径边界、冻结顺序、原始样本排名、两次从零准备、损坏分片的重试拒绝。[独立定点程序](../tools/verify_frozen_sample.py) 独立重放 2857 并核对三个阶段的矩阵。 |

四条 workspace 默认 ignored 中，两条百万坐标 witness 测试和一条并行证明一致性测试已用 release 显式执行。另一条历史 10k 原始快照测试需要 `GEM_RAW_AUTH_AUDIT_ARTIFACT_ROOT` 指向独立的 10,000 文档、661 条查询及 `snapshot/server/snapshot.auth3`，并设置 `GEM_RAW_AUTH_AUDIT_OUTPUT`。当前冻结 LoTTE 使用另一种快照格式，此历史用例的实际状态见[验收报告](acceptance.md)。

离线拒绝用例覆盖错误版本、发布摘要、请求、阶段、Merkle 开启、重放缺失的邻接、材料 ID、真长、表值、证明、最终文档 ID、距离及顺序。Raw 的证明变体修改认证坐标，VIDA 修改 IPA，Block 修改投影 IPA。报告记录验证器实际遇到的第一层失败，包括材料绑定先在 Merkle 校验被拒的情形。

