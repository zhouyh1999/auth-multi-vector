# GEM 整理验收记录

2026-11-24，香港时间。**任务书第六节八项验收通过。** 对象为 LoTTE 实测 `first-visit` 代码的独立 workspace。所有新版运行均从新根的源码编译。以下分别给出新版请求、旧归档、独立复算和代码层面的适用条件。

## 版本及运行环境

| 标识 | SHA-256 或环境 |
|---|---|
| 实测旧 release | `40011cba9cab18d92c3f17665dc35867cd45f995e09f806f1b73fa3007610589` |
| 实测生成树 full.rs | `7172a91701cd81eab6963ddaa0804b5c2108269264ec8d2bf7c3ca7d7eb9d20a` |
| 实测生成树 e2e.rs | `fd174a6fd95ac445deb4e397cee74ed8f6aaa1536a2ef76440cb913707e7d691` |
| 此次执行 smoke 和 512 计划的 release | `3d4ceebbd332440fb2859b7ef4bbf9868d5939a28cfd86dff6506e0f639409d3` |
| 冻结索引清单摘要 | `07987e1d0ddd7a5176ec3befff58167f29aa9e114c20cfa4840f63e903baeaac` |
| 冻结的 2,931 条原生参考文件 | `5f98f6ca9132f27480d0aea6cc2320d2b519d7bfa839729ad389486f849fa3d1` |
| 主验收目录 | `hkbu-csr35:/tmp/local/csyhzhou/auth-gem-delivery`，新建网络及 PID 命名空间，只有 lo |
| 含空格的第二目录 | `/tmp/local/csyhzhou/auth gem relocated`，独立 target、Cargo home、venv 和 TLS 状态 |
| 计算与网络 | Oracle Linux 8.10 x86-64、AMD EPYC 7313。LoTTE 使用 16 线程、CPU 0–15，旧实验标记为 CPU 16–31。来源获取走真实回环 TLS 1.3，检索传输按 300 Mbps 和零额外 RTT 折算。 |

编译、测试、绘图与参考复算都在新根下写入。LoTTE 完整原生复算另外使用 `artifacts/lotte-reference/` 的独立普通文件和 CPU 40–47。同机共享资源与回环路径使本次时长适用于正确性复验。跨机性能数据见[历史报表](../results/history/summary.csv)。

## 按任务书逐项验收

| 项 | 执行、预期与实际 | 原始证据 |
|---|---|---|
| 1　单目录离线构建 | 两个路径分别从源码构建 release。主目录另构建全部 debug/test 目标，离线 metadata 和 feature tree 解析成功。空 Cargo 缓存和新 venv，106 个 registry 包全来自本目录，pip 以哈希校验安装 13 个 wheel。第二路径的 16 个样本请求全通过。命令均以 0 退出。 | [主构建](evidence/isolated-build-3.log) · [第二路径构建](evidence/relocated-build.log) · [第二路径样本与脚本](evidence/relocated-verification.log) |
| 2　基础算法与格式 | workspace 默认测试有 137 项通过，0 项失败；5 项 Python 测试通过。默认 ignored 的四项中，两个大维度 witness 和一个串并行证明一致性用例另以 release 运行，3 项全过。独立的历史 raw10k oracle 缺少其专用输入，未执行。C++ qEMD、Merlin 和 IPA 均有实际执行结果。 | [最终 workspace 日志](evidence/final-workspace.log) · [额外 3 项](evidence/extended-rust.log) · [测试迁移表](tests.md) |
| 3　重复准备与恢复 | 两个空输出目录用相同输入和准备程序，生成源快照、材料、全局根、发布和参考，对比 45 个文件逐字节相同。分别更换原始分片字节、破坏已完成承诺，重试均被拒绝。模拟尚未提交完成标记的中断后，重试重建出相同的承诺与完成回执。第二路径重新编译改变准备二进制哈希，签名绑定的 provenance 相应改变；两边的源文档根、compact 文档根、三棵材料树根、精确候选、排名及三阶段矩阵仍一致。 | [45 项哈希](evidence/repeat-prepare.json) · [跨路径实际值](evidence/relocation-parity.json) · [中断及完整查询复验](evidence/recovery-and-e2e.log) |
| 4　四方法、四范围 | 样本 16/16，含 4 个完整请求。LoTTE query 0、2857 的 smoke 为 32/32，含 8 个完整请求。每条恰匹配一条独立来源回执。单阶段验证索引和 1 个阶段清单，完整请求验证索引和 3 个阶段清单；校验 0/1/2/5 的实际线路、8/32/128 块高、VIDA 32/1 个 IPA、材料和响应字节。 | [样本审计](../results/sample/sample-cupx2_hd/audit.json) · [LoTTE smoke](../results/lotte/smoke-6azegpv9/audit.json) · [独立阶段对照](evidence/native-smoke.json) |
| 5　冻结金标准 | 已发布的 LoTTE 16 个签名包从认证码本和冻结重排根重建，与原发布每个字节相同。样本冻结诚实请求与 VO 通过当前 release。历史 2857 FP16 VO 经过 SHA-256、帧头和后端核对，仅在内存中转换 8 字节帧标识，随后用保留的原协议验证器验签、验路径、重放并核对有序结果摘要。独立 Python 另验证 22,124 个已开启文档和 93,225 个源树兄弟节点、1,024 个重排材料及 7,118 个兄弟节点；三个矩阵摘要及完整摘要与该 query 的 16 个新请求全部吻合。 | [旧 VO 兼容入口](../crates/e2e-benchmark/historical.rs) · [独立复算](evidence/independent-2857.json) · [release 夹具日志](evidence/final-sample-and-oracle.log) |
| 6　完整客户端拒绝 | 每个方法先通过一份诚实完整响应，再分别注入 13 种错误。52/52 返回结构化拒绝，诚实对照全部通过。每项记录方法、实际拒绝原因、诚实执行摘要、运行二进制身份。 | [逐项拒绝结果](../results/sample/sample-cupx2_hd/rejections.json) · [诚实字节](../results/sample/sample-cupx2_hd/fixtures) |
| 7　批量正确性和报表 | 新版按冻结顺序完成 512 条查询，每种方法 512 次 all，共 2,048 个不同组合，0 预热、0 重复，2,048 条来源回执逐条匹配。两份旧归档各核对 28,672 条记录，合计 10,240 次正式完整请求（五次重复）。两种计数单独审计。命令退出码均为 0。 | [新版逐条审计](../results/lotte/prefix512-hg0oo473/audit.json) · [该次计划](../results/lotte/prefix512-hg0oo473/plan.json) · [历史归档复核](../results/history/audit.json) |
| 8　旧版隔离 | 只读导入时记录旧源码、实测二进制、正式身份、清单和包；后续在外层只读重算 238 个远端静态路径哈希。900 个大型导入文件与旧源 inode 各异，全部为单链接常规文件。针对原位置与新副本各重读 148,992,762,652 字节，两侧 900/900 个 SHA-256 均与逐项清单相符。隔离环境中旧项目目录不可见、仅回环可用。新运行使用独立端口、证书、临时令牌、PID 和结果目录。 | [远端静态来源逐项对照](evidence/source-check.json) · [900 个数据哈希](evidence/data-parity.json) · [构建隔离检查](evidence/package-check.log) · [隔离与加载库](evidence/history-report.log) |

从 2,931 份查询的完整索引与 FP16 原始分片复算原生参考，2,931/2,931 与冻结字段逐项一致。复算附带每查询三个阶段矩阵摘要、精确候选 ID 和有序距离。[计算日志](evidence/lotte-reference.log) · [可离线读取的逐查询参考](../results/native/lotte-reference.jsonl.gz)

query 2857 的完整执行摘要为 `5ad4033f59654baf7eff89ad41c9b5e6bb2ad98c660d8ef50c98140e3f1e4390`，1,024 个候选、100 个结果，首个文档 ID 为 2,413,937，定点距离为 10,618,617,452。合成样本完整执行摘要为 `9def56139f7f944b5e02a78b901b436a0bcffa507cdac9230a2c68b463230ec8`。

## 新版 512 条完整查询

| 方法 | 不同查询 | 平均请求 B | 平均 VO 字节 | 平均实测清单获取 ms | 平均折算总时长 ms |
|---|---:|---:|---:|---:|---:|
| raw | 512 | 16,486 | 55,333,310 | 2.66 | 2,088.4 |
| vida_per_token | 512 | 16,486 | 39,263,434 | 2.63 | 4,780.1 |
| vida_batched | 512 | 16,486 | 39,209,122 | 2.76 | 1,833.1 |
| block_fast | 512 | 16,486 | 33,949,545 | 2.66 | 1,575.3 |

每行按查询等权。冻结顺序来自正式计划。本次每个查询和方法各执行一次，总时长包含实测事务及按 300 Mbps 折算的请求/响应传输。审计程序按记录核对分项守恒及回执唯一性。历史归档总计 57,344 条匹配回执，含 40,960 条正式记录和 16,384 条预热记录。正式完整请求计数为 10,240，来自同一批 512 个查询。

[摘要及分项 CSV](../results/lotte/prefix512-hg0oo473/summary.csv) · [2,048 项逐查询 CSV](../results/lotte/prefix512-hg0oo473/per-query.csv) · [图](../results/lotte/prefix512-hg0oo473/latency.svg) · [原始请求记录](../results/lotte/prefix512-hg0oo473/records) · [来源回执](../results/lotte/prefix512-hg0oo473/origin/origin-receipts.jsonl) · [运行日志](evidence/lotte-campaign.log) · [结束后再次审计](evidence/prefix-report.log) · [与复算参考逐项对照](evidence/native-comparison.json)

## 实际运行命令

主根设置 `PYTHON_BIN=$HOME/.local/share/uv/python/cpython-3.10.21-linux-x86_64-gnu/bin/python`，第二路径同样启动。脚本中的 build/tests 用于 Cargo 与 pip，不依赖已有二进制。归档验证可指定 release 的完整哈希直接在新副本离线重审，命令见[首页](../README.md)。

```sh
bash scripts/isolated.sh bash scripts/acceptance.sh build
bash scripts/isolated.sh bash scripts/acceptance.sh tests
bash scripts/isolated.sh bash scripts/acceptance.sh sample
py=artifacts/acceptance/venv/bin/python
taskset -c 0-15 bash scripts/isolated.sh "$py" scripts/artifact.py test-e2e --dataset lotte --plan smoke
taskset -c 0-15 bash scripts/isolated.sh "$py" scripts/artifact.py benchmark --dataset lotte --plan prefix512
bash scripts/isolated.sh "$py" tools/history.py --plot
bash scripts/isolated.sh "$py" tools/verify_frozen_sample.py \
  artifacts/lotte/inputs/offline.compact artifacts/lotte/inputs/trusted.json \
  tests/fixtures/lotte/2857/source.vo --raw-tree artifacts/lotte/native-material/global-h1-r0.tree \
  --records results/lotte/smoke-6azegpv9/records/q2857.jsonl
```

## 已修正的问题及范围

- 原生成树原样组装后的测试曾出现 13 个旧 compact 用例失败，涉及帧格式和缺少固定配置。公共原协议实现在 `gem-auth-scheme-v3` 保留并重跑原测试，当前实测完整验证器用真实四线路的请求、诚实 VO 及 52 个拒绝变体回归。[首次失败](evidence/test.log) · [现版记录](evidence/sample-frozen.log)
- 旧 CLI 的默认 48 线程在受限 CPU 集上导致两个跨进程测试失败。默认值改为可用逻辑 CPU 数与 48 中的较小值；显式资源配置保持检查。重跑工作区及完整样本查询通过。[原错误](evidence/tests-2.log) · [完整复验](evidence/isolated-tests.log)
- 初次环境封装因 Bubblewrap 0.4.0 不支持 `--clearenv`，以及隔离 PATH 缺少 `/usr/sbin/ip`，在编译前退出。改用 `env -i` 并加入系统程序目录，随后两个位置完成隔离构建。[首次日志](evidence/isolated-build.log) · [第二次日志](evidence/isolated-build-2.log)
- 对含空格副本做最终逐文件校验时发现其中一份差分夹具说明仍是旧版。同步该说明后重新校验全部 5,588 个文件并重跑样本、脚本和冻结夹具，退出码为 0。[发现差异](evidence/relocated-inventory-first.log) · [重验](evidence/relocated-verification.log)
- 整理期间，原工作区的独立 Python 审计程序增加了源图及 Raw 重排树的 multiproof 检查。对这一只读来源保留了初读和复读哈希，按更新后的实现重做独立复算。最终采用的 14 份本地来源逐项复核相符。[本地清单](evidence/local-source-check.json)实测旧 Rust、二进制及冻结发布的核对记录单独列出。[两个来源版本](evidence/oracle-source-versions.json)
- 适用域为有限、幅度不超过 1 的坐标及实际内积可用 i32 表示的确定性定点 GEM；排序使用协议规定的有符号定点距离。超出域的输入、任意空候选或超大码本/协议帧的普遍可用性未作认证。本轮验证导入图上的检索及认证材料生成。跨机性能、新版全部 11,724 个完整组合、上游 C++ 全套从源码再生成及历史 raw10k 专项留在本次执行范围以外。原生参考全量覆盖、旧版正式重复及新版完整请求分别计数。

