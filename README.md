# Banner Fingerprint

一个使用 Go 编写的数据驱动 Banner 指纹识别服务。项目接收已经采集好的 `ip`、`port`、`banner` 批量数据，识别协议、产品、版本和操作系统提示；由独立 Client 调用 Server，并通过 Docker Compose 一键运行。

## 快速开始

要求：

- Docker Engine 24+
- Docker Compose v2

在项目根目录执行：

```bash
docker compose up
```

首次运行会构建两个最小化镜像。Compose 会先启动 Server，用真实的 `GET /health` 检查其规则引擎就绪状态；Server 健康后，Client 自动提交 [`testdata/sample.json`](testdata/sample.json) 并在日志中打印格式化结果。

宿主机健康检查：

```bash
curl http://127.0.0.1:8080/health
```

停止并清理容器：

```bash
docker compose down
```

如宿主机 8080 已被占用，可只改变宿主绑定端口：

```bash
SERVER_PORT=18080 docker compose up
```

容器间仍通过固定服务地址 `http://server:8080` 通信。

## API

### `GET /health`

成功响应：

```json
{
  "status": "ok",
  "rules": 22
}
```

规则未加载时返回 `503`。生产启动会在规则无效时直接失败，因此不会接受处于半初始化状态的识别请求。

### `POST /fingerprint`

请求必须是 JSON 数组：

```bash
curl -X POST http://127.0.0.1:8080/fingerprint \
  -H "Content-Type: application/json" \
  --data '[
    {
      "ip": "1.2.3.4",
      "port": 22,
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    }
  ]'
```

响应也是数组，顺序与输入一致：

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

识别不到的记录不是错误：

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

默认请求限制：

| 项目 | 默认值 | 环境变量 |
|---|---:|---|
| 请求体 | 4 MiB | `MAX_BODY_BYTES` |
| 单批记录 | 1000 | `MAX_BATCH_SIZE` |
| 监听地址 | `:8080` | `ADDR` |
| 规则文件 | `rules/rules.json` | `RULES_FILE` |

Compose 演示配置将限制提高到 16 MiB 和 10000 条，仍保持有界内存使用。

## 独立 Client

本机已安装 Go 时，可以只启动 Server 容器，然后直接运行 Client：

```bash
go run ./cmd/client \
  -input ./testdata/sample.json \
  -server http://127.0.0.1:8080 \
  -timeout 10s
```

也可让一次性 Client 容器读取其他文件：

```bash
docker compose run --rm \
  -v "$PWD/your-input.json:/data/input.json:ro" \
  client \
  -input /data/input.json \
  -server http://server:8080 \
  -timeout 10s
```

Client 会校验输入必须是单个 JSON 数组、阻止重定向、检查非 2xx 响应及响应记录数，并将结果写到标准输出。

## 支持的指纹

当前规则覆盖：

- SSH：OpenSSH、Dropbear、libssh、通用 SSH 握手
- HTTP：nginx、Apache、Jetty、Microsoft-IIS 以及通用 HTTP
- MySQL：二进制握手版本
- Redis：`PONG`、`NOAUTH`、`ERR` 等 RESP 响应
- FTP：ProFTPD、vsFTPd、Pure-FTPd、FileZilla 和端口约束的通用 FTP
- SMTP：带 SMTP/ESMTP 标记的 `220` Greeting
- TLS：TLS record header

强 Banner 特征不会绑定标准端口，因此可以识别运行在 8443、65022 等非标准端口上的服务。只包含 `220` 之类跨协议弱特征的规则会结合产品文本或端口，以控制误报。

## 规则与代码解耦

规则位于 [`rules/rules.json`](rules/rules.json)。Server 启动时加载并一次性编译所有规则，按照文件顺序进行匹配，第一条命中的规则胜出。因此具体产品规则必须位于通用协议规则之前。

规则示例：

```json
{
  "id": "http-server",
  "protocol": "HTTP",
  "product": "",
  "pattern": "(?is)^HTTP/...",
  "confidence": 0.9
}
```

可用字段：

| 字段 | 必需 | 说明 |
|---|---|---|
| `id` | 建议 | 唯一规则标识 |
| `protocol` | 是 | 输出协议 |
| `product` | 否 | 静态产品名 |
| `version` | 否 | 静态版本 |
| `os_hint` | 否 | 静态 OS 提示 |
| `pattern` | 是 | Go/RE2 正则 |
| `ports` | 否 | 非空时限制匹配端口 |
| `confidence` | 是 | `[0,1]` |

正则中的命名捕获组会覆盖对应静态值：

- `(?P<product>...)`
- `(?P<version>...)`
- `(?P<os_hint>...)`

新增规则后执行测试即可，无需改识别引擎代码。修改运行时规则后需要重启 Server。

## 二进制 Banner

JSON 不支持 `\xNN` 转义。MySQL 等二进制 Banner 中的控制字节应使用 JSON 标准 Unicode 转义：

```json
{
  "ip": "1.2.3.7",
  "port": 3306,
  "banner": "J\u0000\u0000\u0000\n8.0.32\u0000"
}
```

JSON 解码后 `\u0000` 会恢复为 NUL 字节供规则匹配。题目文本排版中的 `""ip""` 也需要恢复为合法 JSON 的 `"ip"`。

## 项目结构

```text
.
├── cmd/
│   ├── client/             # 独立文件 Client
│   └── server/             # HTTP Server 与 healthcheck 子命令
├── docs/
│   └── development-requirements.md
├── internal/
│   ├── api/                # HTTP Handler、限制和错误响应
│   └── fingerprint/        # 通用规则加载及匹配引擎
├── rules/
│   └── rules.json          # 外部指纹规则
├── testdata/
│   └── sample.json
├── Dockerfile              # Server/Client 多目标构建
└── compose.yaml
```

完整需求、并行开发任务和完成定义见 [`docs/development-requirements.md`](docs/development-requirements.md)。

## 测试

```bash
go test ./...
go vet ./...
docker compose config
```

引擎测试覆盖题目全部自测 Banner、非标准端口、配置校验、未知输入和随机 Banner 不 panic；Handler 测试覆盖健康状态、批量顺序、unknown、空数组、方法限制、非法 JSON、请求体与批次上限。

Docker daemon 可用时再执行：

```bash
docker compose build
docker compose up
```

## 生产级部署设计

- 多阶段构建；运行镜像不包含 Go 工具链或 shell。
- `CGO_ENABLED=0`、`-trimpath`、去除调试符号。
- distroless nonroot 运行用户。
- Compose 设置只读根文件系统、删除全部 capabilities，并启用 `no-new-privileges`。
- 服务仅加入内部网络；Client 使用 Compose DNS 名 `server`。
- 宿主端口只绑定环回地址，不暴露到所有网卡。
- Server 使用自身二进制请求 `/health`，无需为探针安装 curl/wget。
- Client 只有在 Server 真实健康后才启动。
- HTTP 请求体、批次、Header、超时、资源和 PID 均有上限。
- Server 支持 SIGINT/SIGTERM 优雅关闭。
- 原始 Banner 不写入服务日志。

## AI 编程说明

本项目在屏幕录制环境中通过 OpenAI Codex 完成需求拆解、并行开发、代码审查、测试和交付操作。
