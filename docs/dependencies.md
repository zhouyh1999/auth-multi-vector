# 依赖、工具链与可复验构建

支持目标为 `x86_64-unknown-linux-gnu`。本次验收运行在 Oracle Linux Server 8.10（RHEL 8.10 兼容）、glibc 2.28、AMD EPYC 7313、GCC/G++ 8.5.0、Bubblewrap 0.4.0 及 CPython 3.10.21。最终编译器为 rustc 1.91.0 `f8297e351`、Cargo 1.91.0 `ea2d97820`、LLVM 21.1.2。原实测构建记录为 rustc 1.91.0-nightly `ec7c02612`，旧父工程声明 stable。本副本将实际通过的稳定版写入 [rust-toolchain.toml](../rust-toolchain.toml)。

| 组件 | 锁定、来源与实际检查 |
|---|---|
| Cargo | 原锁和新锁均为 117 个包，含 106 个 registry 包和 11 个无外部 source 的包（9 个成员、2 个路径库）。版本与来源逐项对照见 [解析清单](dependency-inventory.json)。工作区保留 release thin LTO、单 codegen unit、原 package/lib 名及本地依赖别名。 |
| registry | `third_party/cargo/<包目录>/` 保留 Cargo vendor 生成的逐文件 `.cargo-checksum.json`、包级 registry checksum、源码和许可。`.cargo/config.toml` 启用离线模式和目录替换；根锁约束构建、测试与平台条件依赖。 |
| IPA / Merlin | 实测的 `ipa 5.0.0` 通过本地依赖解析，Merlin 3.0.0 通过根 `[patch.crates-io]` 解析。两者从工作区默认测试中排除。release 真实证明和 workspace 内单独的已知答案测试覆盖二者。见 [已知答案](../crates/e2e-benchmark/tests/vendor_vectors.rs)。 |
| C++ | `gem-search` 的默认 `lemon-qemd` feature 依赖 `gem-qemd-lemon`。`build.rs` 从同一副本的 `gem-search/vendor/gem-otlib` 编译 C++17 shim 和头文件；测试运行冻结的 LEMON 求解夹具。查询服务不需要外部 C++ 可执行文件。 |
| 原生 TLS | [组件版本](../third_party/native/packages.txt)固定 OpenSSL 1.1.1k 及 zlib 1.2.11 的 EL8 包。CLI、开发头、libssl、libcrypto、libz 和版权文件都在 `third_party/native`。Cargo 的 `OPENSSL_DIR` 指向本副本，运行时库目录排在首位。release 的 ldd 检查显示三项动态依赖都从本副本加载。 |
| Python | [requirements.lock](../third_party/python/requirements.lock) 固定 13 个 wheel 及 SHA-256，包含 NumPy、Matplotlib、tomli 和传递依赖。wheel 保留发行版元数据和许可。独立 venv 用 `--no-index --require-hashes` 安装，禁用用户 site。预装 CPython 发行版的 ssl 模块报告 OpenSSL 3.5.7，TLS 1.3 服务与 Rust 客户端实际互通。 |

[Cargo metadata](evidence/metadata.json) 和 [feature 树](evidence/features.txt) 来自最终根在空 Cargo 缓存中的离线解析。metadata 中的路径记录运行位置，本包通过根相对路径重新解析。Rust openssl bindings 与 openssl-sys 也由目录内 vendor 提供。

锁中的工程边变化有四处。实测认证 crate 引入原协议 crate 共享编码、快照及类型；工作区测试解析使 gem-auth-scheme-v3 和 gem-core 多记入 serde_json，gem-search 多记入 half 和 serde_json。相关版本均已在原锁内。

### 签名身份与实际源文件

`third_party/SPRING_PROVENANCE.json`、`third_party/MERLIN_PROVENANCE.json` 保留原件。Spring 的历史清单与实测副本在 `Cargo.toml` 和 `src/spring_linear_proof.rs` 有两处已存在的字节差异。[依赖清单](dependency-inventory.json) 给出两套哈希。保留发布时绑定的身份及实际编译实现；KAT 覆盖维度绑定解析，矩阵证明检查固定生成元与证明等价性。Merlin 的挑战字节与固定原版的 STROBE 实现独立对照。[原版输出](evidence/merlin-pristine.txt)

布局参考为 [hkbudb/auth-ann 的固定版本](https://github.com/hkbudb/auth-ann/tree/44d0f042b237e75b95e8399920c77f6695c92bf6)。其 checkout 不参与构建、运行或测试。普通验证直接读取随包上游差分金标准，固定历史 C++ harness 和补丁用于归溯。

### 自检

在新根用 CPython 3.10 或更高执行 `python3 tools/check_package.py`，核对实现、导入夹具、平台依赖和样本输入。完整编译、pip 命令及实际加载库路径见[首轮干净构建](evidence/isolated-build-3.log)，第二份目录的编译见[含空格目录的构建](evidence/relocated-build.log)。

