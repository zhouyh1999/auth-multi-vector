# GEM 首次访问认证检索

这个 workspace 在已发布的多向量索引上执行确定性定点 GEM。每次请求都通过新的 TLS 1.3 连接获取签名清单。服务端生成验证对象（VO），客户端独立验证并重放检索。随包样本可以从原始向量、图和码本生成全部认证材料。

归档解包后，可先执行 `python3 tools/check_package.py` 核对源码、样本、夹具和离线依赖，再用 `sha256sum -c docs/result-manifest.sha256` 核对随包运行记录。

## 从零运行样本

在 Linux x86-64 上解包并进入本目录。验收使用 Oracle Linux 8.10（RHEL 8.10 兼容）、Rust/Cargo 1.91.0、GCC/G++ 8.5、CPython 3.10.21、Bubblewrap 和 iproute。解释器需要 venv、pip 和 TLS 1.3。系统工具链须已就绪，项目及绘图依赖全部随包。下列命令从空的 `artifacts/` 构建 release 和测试目标、离线安装 wheel，然后执行 16 次实际请求和 52 项拒绝测试。

```sh
export PYTHON_BIN="$(command -v python3.10)"
chmod +x third_party/native/bin/openssl
bash scripts/isolated.sh bash scripts/acceptance.sh all
```

`isolated.sh` 只挂载本副本及系统和工具链，建立仅有回环的网络命名空间。已构建的副本可直接运行以下命令。每次 `test-e2e` 创建新的运行目录、端口、证书和令牌，结束时关闭该来源。终端打印本次目录及核对数，失败返回非零。

```sh
py=artifacts/acceptance/venv/bin/python
bash scripts/isolated.sh "$py" scripts/artifact.py test-e2e --dataset sample
bash scripts/isolated.sh "$py" scripts/artifact.py report --dataset sample
```

如已在只含本副本的离线容器内，可分别执行 `bash scripts/acceptance.sh build`、`tests`、`sample`。先把 `PYTHON` 指向预装的 CPython 3.10，设置 `CARGO_HOME="$PWD/artifacts/acceptance/cargo-home"`、`CARGO_TARGET_DIR="$PWD/artifacts/acceptance/target"`、`CARGO_NET_OFFLINE=true`、`PYTHONNOUSERSITE=1`、`LD_LIBRARY_PATH="$PWD/third_party/native/lib"`，将 `$PWD/third_party/native/bin` 放在 PATH 首位。验收脚本中的 build 同时初始化 venv。按阶段复验可保留相同工作目录，验证干净构建时请使用新副本。

## 运行 LoTTE

`dataset/lotte/files.json` 列出导入的 900 个常规文件、长度及 SHA-256。准备一个包含 `inputs/` 和 `native-material/` 的只读来源。导入在有来源可见的环境运行，随后只在新副本里执行。源数据约 149 GB，导入程序逐文件复制与验哈希，支持重试。完整输入来源、图和认证结构的边界见[数据说明](dataset/lotte/README.md)。

```sh
py=artifacts/acceptance/venv/bin/python
"$py" scripts/artifact.py import --dataset lotte --source "/path/to/acquired-lotte"
run() { bash scripts/isolated.sh "$py" scripts/artifact.py "$@"; }
run validate-data --dataset lotte
run prepare --dataset lotte
run reference --dataset lotte
run test-e2e --dataset lotte --plan smoke
run benchmark --dataset lotte --plan prefix512
run audit --dataset lotte
run report --dataset lotte
```

| 计划 | 查询 | 每条查询的请求 |
|---|---|---|
| sample | 合成 query 0 | 四种方法 × 四种范围，各一次 |
| smoke | LoTTE 0、2857 | 四种方法 × 四种范围，各一次 |
| prefix512 | 冻结顺序的前 512 条 | 四种方法的完整请求，共 2,048 次 |
| full | 冻结顺序的全部 2,931 条 | 历史正式计划含四范围、预热与重复，按 `tests/fixtures/lotte/full-plan.json` 执行 |

`audit`、`report` 默认选择当前数据集最近结束的运行，可用 `--run results/lotte/<运行目录>` 指定。配置中的路径相对于新根。样本默认 4 个 Rayon 线程，冻结 LoTTE 要求 16 个。显式划分资源可在隔离命令前加 `taskset -c` 和分配到的 CPU 列表。

### 只拿交付包复核本次运行

交付包中保留了每次正式请求及其来源回执。可直接读取冻结材料重审记录，无须导入 149 GB 数据或重新构建同字节的二进制。以下命令中的 SHA-256 来自本次实际执行的 release。复核已有记录和重新执行检索分别由 `audit` 和 `benchmark` 完成。

```sh
release_sha=3d4ceebbd332440fb2859b7ef4bbf9868d5939a28cfd86dff6506e0f639409d3
run audit --dataset lotte --run results/lotte/prefix512-hg0oo473 --recorded-binary "$release_sha"
bash scripts/isolated.sh "$py" tools/check_native.py results/native/lotte-reference.jsonl.gz \
    results/lotte/smoke-6azegpv9 results/lotte/prefix512-hg0oo473
```

## 方法和验证路径

| 名称 | 线路值 | 三个阶段怎样验证 |
|---|---:|---|
| raw | 0 | 验证坐标和文档 ID Merkle 开启，在客户端用定点内积重算表 |
| vida_per_token | 1 | 对每个查询 token 验一个维度 128 的 Spring IPA，每阶段 32 个 |
| vida_batched | 2 | 对材料行轴和查询 token 轴使用独立挑战，每阶段验 1 个 IPA |
| block_fast | 5 | 粗、细、重排块高分别为 8、32、128，验块聚合、投影 IPA 及各 token 等式 |

1. [measure_visit](crates/authentication/src/measure_visit.rs#L116) 开始连续计时并发起 HTTPS 获取。[verify_visit](crates/authentication/src/first_visit.rs#L41) 使用所有者公钥验签，当次返回的索引与阶段摘要绑定后续请求。
2. [PopulationService::server](crates/authentication/src/population_serve.rs#L355) 接收序列化请求，在完整索引上检索并生成结构和各阶段的 VO。
3. [e_full_client_pinned](crates/authentication/src/full.rs#L89) 绑定请求、来源、签名和图 multiproof。[e_client_inner](crates/authentication/src/e2e.rs#L536) 验证材料和表值。
4. [replay_fixed_search_v3](crates/gem-search/src/v3/fixed.rs#L148) 用认证后的入口、细码、邻接和表重放图搜索。完整验证核对精确披露集合、候选 ID 和真实长度。[rerank_fixed_matrices_v3](crates/gem-search/src/v3/fixed.rs#L183) 执行 MaxSim，与 VO 中有序的文档和距离逐项比较。单阶段 rerank 的输入是预先选出的候选。
5. 客户端返回接受结果后，[计时器](crates/authentication/src/measure_visit.rs) 才将其与计时外原生参考核对。[审计器](scripts/artifact/audit.py) 再逐条匹配 TLS 回执、清单、方法、布局及字节/时间分项。

## 输入、输出与时间口径

[样本格式和预期结果](dataset/sample/README.md) · [准备与发布](scripts/artifact/data.py) · [快照共用代码](crates/gem-cli/src/full_snapshot.rs) · [配置](config.toml)

`artifacts/<dataset>/` 保存导入与准备的材料、签名、`bundles/`、可信发布 `public/` 和原生参考。每次运行在 `results/<dataset>/<plan>-*/` 下产生计划、每查询一份 JSONL、`records/identity.json`、完成状态、来源回执及 `audit.json`。每条记录含方法/范围、阶段与完整执行摘要、实际字节数、计时分项及回执 ID。报表写出 `per-query.csv`、`summary.csv`、`latency.svg`。先按查询取正式重复中的中位数，再跨查询等权汇总。对两个只读历史归档使用 `bash scripts/isolated.sh "$py" tools/history.py --plot`。

可信清单获取、请求编码、服务端执行及客户端验证都使用实测墙钟。连续事务时间含编排开销；检索请求和 VO 在进程内跨序列化边界，传输时间按 `(request_bytes + response_bytes) / 37500` 毫秒折算（300 Mbps，额外 RTT 为零）。建库和参考核对在计时之外。此次回环数据用于检验正确性，历史跨机数据保存在独立的报表中。

正式双机沿用相同的 Rust 获取和验签代码。来源主机在新根下建立本次专用的 `results/<run>/origin/`，以同一 Python 启动 `scripts/artifact/origin.py STATE PUBLIC --bind ORIGIN_IP --peer CLIENT_IP`。将新来源的 `connection.json`、`source-v1.pem`（在客户端命名为 `source.pem`）、`auth-token` 以及所有者认可的 `bundles/anchors.bin` 经可信配置渠道放在客户端本次 `RUN/client-runtime/`。在新根执行 `first-visit DATA PLAN RUN`（release 目标目录中的程序）。测试结束后在来源状态目录创建 `stop-source`，保存本次回执以便审计，销毁临时凭据。正式双机的地址和受信公钥由部署方配置。

[验收结果及限制](docs/acceptance.md) · [依赖、工具链与来源](docs/dependencies.md) · [核心测试迁移表](docs/tests.md) · [逐文件来源](docs/source-manifest.json)

