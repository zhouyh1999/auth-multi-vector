# 本地 Merlin 3.0.0 修改

来源为 crates.io 的 Merlin 3.0.0，原许可证和 Cargo.toml.orig 保留。
`../MERLIN_PROVENANCE.json` 记录原文件、当前文件及其 SHA-256。

运行时代码只修改 `src/strobe.rs` 的 `absorb`：在当前 166 字节的
STROBE 区间内一次处理连续输入，减少每个字节的位置更新和边界判断。
到达区间末尾时仍立即调用原 `run_f`，Keccak 实现不变。
空消息、操作标志、元数据、输入顺序、挑战、随机数和清零逻辑均沿用原实现。
没有增加 unsafe，也没有加入跳过公开输入的路径。

`reference/strobe.rs` 是原版文件，只在测试时编译。差分测试覆盖全部
166 种起始位置、空输入、跨多个区间的输入、操作延续和 PRF 输出。
原有 STROBE/Merlin 一致性及随机数绑定测试也保留。

工作区通过根 Cargo.toml 的 `[patch.crates-io]` 让所有依赖使用同一版本。
独立构建 `vendor/ipa` 时需要同样传入该 patch，才能测试本项目实际使用的
Merlin；当前工作区构建已经应用它。
