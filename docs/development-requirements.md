# Banner 指纹识别系统需求开发文档

## 1. 文档目的

本文档将面试题转换为可执行的产品需求、技术方案、并行开发计划和验收清单。交付目标是在 30 分钟时限内完成一个使用 Go 编写、规则可配置、Client/Server 分离，并能通过 Docker Compose 一键启动的 Banner 指纹识别系统。

## 2. 项目范围

### 2.1 目标

系统接收已经采集好的网络扫描记录：

```json
{
  "ip": "1.2.3.4",
  "port": 22,
  "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
}
```

系统根据 Banner 内容识别协议、软件、版本和操作系统提示，并返回置信度。

### 2.2 不在范围内

- 不主动连接目标 IP 或执行网络扫描。
- 不提供 Web UI。
- 不引入数据库、消息队列或外部规则服务。
- 不承诺识别任意私有协议。
- 本版本不实现规则热加载；规则在 Server 启动时加载并校验。

## 3. 功能需求

### FR-01 批量识别接口

- Server 必须提供 `POST /fingerprint`。
- 请求体必须是扫描记录 JSON 数组。
- 响应必须是识别结果 JSON 数组，不增加外层包装。
- 响应顺序必须与输入顺序一致。
- 一个无法识别的 Banner 不得影响同批其他记录。

请求示例：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
  }
]
```

响应示例：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

### FR-02 健康检查

- Server 必须提供 `GET /health`。
- 只有规则成功加载、识别引擎完成初始化后服务才可进入健康状态。
- 健康检查返回 HTTP 200 和 JSON 状态。
- 其他 HTTP 方法返回 405。

### FR-03 未识别记录

无法识别时必须正常返回：

```json
{
  "ip": "1.2.3.23",
  "port": 12345,
  "protocol": "unknown",
  "product": "",
  "version": "",
  "os_hint": "",
  "confidence": 0
}
```

未知 Banner 不属于接口错误，不得返回 4xx/5xx，也不得 panic。

### FR-04 识别范围

最低识别能力：

| 协议 | 产品或特征 | 版本提取 |
|---|---|---|
| SSH | OpenSSH、通用 SSH 握手 | 是 |
| HTTP | nginx、Apache、Jetty | 是 |
| MySQL | 二进制握手包 | 是 |
| Redis | PONG、NOAUTH、ERR 等 RESP 响应 | 通常无版本 |
| FTP | ProFTPD、vsFTPd、Pure-FTPd | 有版本时提取 |

低成本扩展识别项包括 Microsoft-IIS、FileZilla 和 TLS 记录头，但不得以牺牲必选协议准确率为代价。

### FR-05 OS Hint

- Banner 出现 Ubuntu、Debian 等明确发行版标记时填充 `os_hint`。
- 没有充分证据时必须返回空字符串，不能仅根据默认端口猜测。

### FR-06 独立 Client

Client 必须是与 Server 分离的可执行程序，支持：

- 从本地文件读取 JSON 数组。
- 通过参数指定 Server 地址。
- 设置请求超时。
- 请求 `POST /fingerprint`。
- 将识别结果以格式化 JSON 输出到标准输出。
- 文件、JSON、网络和非 2xx 错误返回明确错误及非零退出码。

建议命令：

```text
client -input /data/input.json -server http://server:8080 -timeout 10s
```

## 4. 数据约束

### 4.1 输入字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `ip` | string | 原样透传，兼容 IPv4 和 IPv6 文本 |
| `port` | integer | 扫描目标端口 |
| `banner` | string | 原始 Banner 的 JSON 字符串表示 |

### 4.2 输出字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `ip` | string | 输入 IP |
| `port` | integer | 输入端口 |
| `protocol` | string | SSH、HTTP、MySQL、Redis、FTP 或 `unknown` 等 |
| `product` | string | 产品名称，未知为空 |
| `version` | string | 版本，未知为空 |
| `os_hint` | string | 操作系统提示，未知为空 |
| `confidence` | number | 闭区间 `[0, 1]` |

### 4.3 二进制 Banner

JSON 标准不支持 `\xNN` 转义。MySQL 等二进制 Banner 必须使用 JSON 合法转义，例如 NUL 写为 `\u0000`。题目文本中的双写引号 `""ip""` 也必须还原为合法的 `"ip"`。

## 5. 技术设计

### 5.1 组件

```text
JSON 文件
   │
   ▼
Client ──HTTP──▶ Server Handler ──▶ Fingerprint Engine ──▶ rules.json
   ▲                                      │
   └──────────── JSON Results ◀───────────┘
```

### 5.2 指纹规则

- 所有协议、产品、正则、端口约束和置信度存放在外部 `rules/rules.json`。
- 代码只实现通用的规则加载、正则编译、匹配和命名捕获组提取。
- 支持命名捕获组 `product`、`version` 和 `os_hint`。
- 规则按明确顺序求值，具体规则必须排在通用规则之前。
- 强特征规则不限制标准端口，以覆盖非标准端口。
- `220` 等可能跨协议的弱特征必须结合产品标记或端口降低误报。
- Server 启动时编译全部正则；空规则集、非法 JSON 或非法正则必须启动失败。

### 5.3 API 防护

- 限制请求体字节数，默认值允许通过环境变量调整。
- 限制单次批量记录数。
- 对空数组返回空数组。
- 对非法 JSON、超大请求、超大批次返回 4xx JSON 错误。
- 设置 HTTP Header、Read、Write 和 Idle 超时。
- 支持 SIGINT/SIGTERM 优雅关闭。
- 日志不得输出完整原始 Banner。

## 6. 容器与部署要求

### 6.1 镜像

- 使用多阶段 Docker 构建。
- 构建阶段使用固定 Go 版本。
- 使用 `CGO_ENABLED=0`、`-trimpath`、`-s -w` 编译静态精简二进制。
- Server 和 Client 使用独立构建目标。
- 运行阶段使用 distroless nonroot 镜像。
- 最终 Server 镜像只包含 Server 二进制和规则。
- 最终 Client 镜像只包含 Client 二进制和演示输入。

### 6.2 Compose

- 执行 `docker compose up` 能构建并启动完整演示。
- Client 必须通过 Compose 服务名 `server` 访问 Server，不能在容器中使用 `localhost`。
- 两个服务只加入专用内部网络。
- Server 宿主端口只绑定 `127.0.0.1`。
- Client 使用 `depends_on.condition: service_healthy`。
- 健康检查必须真实访问 `/health`，不得只检查进程存在。
- 使用 Server 二进制自带的 `healthcheck` 子命令，避免在运行镜像安装 shell、curl 或 wget。

### 6.3 运行权限

- 容器以非 root 用户运行。
- 根文件系统只读。
- 删除全部 Linux capabilities。
- 设置 `no-new-privileges`。
- 设置 PID、内存和 CPU 上限。
- Client 为一次性任务，成功输出后退出；Server 持续运行。

## 7. 并行开发计划

同一个并行组内的任务可以同时开发；后续组依赖前置接口或代码完成。

| 任务 | 内容 | 并行标记 | 依赖 | 主要文件 |
|---|---|---|---|---|
| T1 | 固化数据模型与引擎接口 | 并行组 A | 无 | `internal/fingerprint` |
| T2 | 编写外部识别规则与引擎测试 | 并行组 A | T1 的接口约定 | `rules/`、引擎测试 |
| T3 | 开发 HTTP Handler、Server 生命周期 | 并行组 A | 使用已约定的引擎接口 | `internal/api`、`cmd/server` |
| T4 | 开发独立 Client | 并行组 A | API 契约 | `cmd/client` |
| T5 | 编写需求文档、README 和样例 | 并行组 A | API 契约 | `docs/`、`README.md`、`testdata/` |
| T6 | Dockerfile 与 Compose 加固 | 并行组 A | Server 健康检查命令约定 | `Dockerfile`、`compose.yaml` |
| T7 | 独立代码审查、安全审查和隐藏数据推演 | 并行组 B，可与 A 后半程重叠 | 至少一条开发线产生代码 | 全项目只读审查 |
| T8 | 修复审查问题并做集成验证 | 并行组 C | T2–T7 | 全项目 |
| T9 | Git 提交、推送及仓库可访问性验证 | 串行收尾 | T8 | GitHub |

推荐并行工作流：

```text
Agent 1: T1 + T2 ───────────────┐
Agent 2: T3 + T4 ───────────────┼─▶ T8 集成修复 ─▶ T9 交付
主 Agent: T5 + T6 ──────────────┤
审查 Agent:       T7 ───────────┘
```

为减少冲突，各开发 Agent 使用互斥的目录所有权；审查 Agent 默认只报告问题，由主 Agent 统一修复跨模块问题。

## 8. 测试要求

### 8.1 引擎单元测试

- 覆盖题目全部样例。
- 覆盖非标准端口。
- 覆盖 HTTP Header 大小写及 CRLF/LF。
- 覆盖空 Banner、随机文本和 `QUIT\r\n`。
- 覆盖 MySQL NUL 字节握手。
- 覆盖非法规则 JSON、空规则和非法正则。
- 验证未知结果字段及置信度。

### 8.2 Handler 测试

- `GET /health` 成功。
- 批量识别成功并保持顺序。
- unknown 记录不导致请求失败。
- 空数组返回 `[]` 而不是 `null`。
- 非法 JSON、超大请求、超大批次返回正确状态。
- 不支持的方法返回 405。

### 8.3 集成验证

```bash
go test ./...
go vet ./...
docker compose config
docker compose build
docker compose up
```

同时从宿主机验证：

```bash
curl http://127.0.0.1:8080/health
```

## 9. 完成定义

只有同时满足以下条件才算完成：

- `go test ./...` 全部通过。
- `go vet ./...` 无错误。
- 必选协议和产品均有自动化测试。
- unknown 输入正常返回，不 panic。
- 规则与程序代码解耦。
- Client 和 Server 是两个独立二进制。
- `docker compose config` 成功。
- Docker Compose 使用真实健康检查和健康依赖。
- 镜像为多阶段构建并以非 root 只读方式运行。
- README 足以让评估者在无现场讲解的情况下构建、运行、扩展规则和复测。
- 源代码在截止前推送至可访问的 GitHub 仓库，并回传仓库地址及 AI 编程工具名称。

## 10. 30 分钟时间盒

| 时间 | 目标 |
|---|---|
| 0–3 分钟 | 固化契约、目录和并行边界 |
| 3–12 分钟 | 并行完成引擎、规则、Server 和 Client 主体 |
| 12–20 分钟 | 并行完成测试、Docker、Compose、需求文档 |
| 20–25 分钟 | 独立审查、隐藏数据推演、集成修复 |
| 25–28 分钟 | 执行完整测试和容器配置验证 |
| 28–30 分钟 | 提交、推送、验证仓库地址并回传 |
