# 冻结 LoTTE 输入

实验使用 LoTTE pooled dev / ColBERTv2。输入含 2,428,854 个文档、266,205,513 个 token 和 2,931 个查询。查询形状 32×128，`cluster_top_t=4`、`ef_search=1024`、`rerank_k=1024`、`k=100`。原正式实验为 16 线程、CPU 16–31；本次在另一个 16 核集合运行，详见验收报告。

| 来源分组 | 常规文件 | 字节 | 相对目标 |
|---|---:|---:|---|
| 输入绑定、快照、可信索引、FP16 分片、码本、查询与 runner | 107 | 71,173,716,756 | `artifacts/lotte/inputs/` |
| 固定点原材料、行/块承诺、分片完成记录、全局树与签名 | 793 | 77,819,045,896 | `artifacts/lotte/native-material/` |

每个具体文件的相对路径、长度和 SHA-256 见 [files.json](files.json)。原实验目录 `hkbu-csr35:/tmp/local/csyhzhou/test_rag/lotte-first-visit-four-20261124-csr35/` 的 `inputs` 最终指向同一父目录下的 `lotte-fullquery-20261122-csr35/inputs`，`native-material` 最终指向 `lotte-fullquery-five-current-20261122-csr35/native-material`。逐级链接及新旧副本的 inode 检查见[来源检查](../../docs/evidence/source-check.json)。历史绑定与签名文件按原字节读取，程序仅在加载时把逻辑分片名映射到当前输入目录。

导入命令为 `artifacts/acceptance/venv/bin/python scripts/artifact.py import --dataset lotte --source DIR`。DIR 的第一层包含上述两组文件。程序先写临时文件，校验后重命名；已完成文件重算哈希。运行及验收只读取复制出的常规文件。大型输入需要由拥有相应数据访问权的使用方准备，随交付物提供完整内容清单。

LoTTE 复用冻结的已发布图、源快照和全局重排签名。`prepare` 从已认证的快照码本及根构造阶段清单，检查重排签名，并重建四种方法 × 四个范围的发布包，逐文件比较冻结字节。`reference` 从完整索引与 FP16 原始分片计算查询轨迹、候选、排名和三个阶段矩阵摘要，与冻结的 2,931 行逐项比对，写入 `artifacts/lotte/recomputed-reference.jsonl`。`native-reference.jsonl` 维持冻结身份。编译依赖中的 C++ qEMD 用于可选建图流程；此次在线检索使用导入图。

[历史身份与冻结计划](../../tests/fixtures/lotte) · [query 2857 夹具](../../tests/fixtures/lotte/2857) · [批量与 smoke 命令](../../README.md)

