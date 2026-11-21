# QuickPool / awsquick2api

Amazon Quick 原生桌面 OAuth、多账号池与 OpenAI Chat Completions 兼容网关。参考 Antigravity-Manager 和 workbuddy2api-panel 的授权与调度思路，独立实现。运行时不依赖官方 exe，不读取官方客户端凭据库，不使用网页 Cookie、HAR 或浏览器配置。

协议核对版本为官方桌面客户端 **1.2.4660**。本项目与 Amazon / AWS 无隶属关系；请使用自己有权使用的账号，并遵守服务规则与配额。

## 快速启动

Python 3.11+。Windows：

```powershell
.\start.ps1
```

Linux / macOS：

```sh
sh start.sh
```

或手动安装：

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
. .venv/bin/activate
python -m pip install -e .
python -m quickpool
```

打开 `http://127.0.0.1:8045`，输入 `data/admin.key` 中的管理密钥。客户端 API Key 独立保存在 `data/api.key`；控制台默认脱敏，只有主动显示、复制或发送测试时才获取真实值。普通 `/api/config` 不返回明文 Key。

## 原生账号授权

1. 添加账号，工作区地址可用 `https://quick.aws.com/sn`。
2. Google / GitHub 等选择“个人账号”；企业 QuickSight 身份选择企业入口。
3. 退出占用 `18080` 回调端口的官方 Quick 客户端。
4. 生成一次性 PKCE 链接，在自己的 Edge 等浏览器中完成官方登录和 MFA。
5. 回到控制台，点击“测试”。真实聊天通过后，账号才进入调度池。

每个账号独立授权。回调为本机 `127.0.0.1`，链接含一次性 nonce/state，15 分钟过期；已用链接不能刷新重用。密码、验证码始终只在官方页面输入。

access / refresh token 使用本机 Fernet 密钥加密持久化。服务提前刷新到期凭据，并保存服务器返回的轮换令牌。网络错误保留现有 refresh token；AWS 明确拒绝时标记授权失效，需要重新授权。早期真实凭据发生过后续 `invalid_grant`，原因尚未确定；短时刷新、重启和迁移测试不能证明永不过期或长期免重新登录。

**添加多个账号时，为每个账号使用独立浏览器配置文件，或新建 InPrivate/隐私窗口。不要通过退出前一个 Quick 网页账号来换号。**AWS 的退出登录会结束相关会话，已取得的原生授权也可能随后被服务端拒绝；访问令牌显示的一小时到期时间不保证它不会提前被撤销。独立窗口用于隔离登录选择，网关不会读取这些窗口的 Cookie。QuickPool 管理台的“退出管理”只清除本地管理登录，不调用 AWS 注销。

认证恢复机制：后台每 30 秒检查，在访问令牌剩余 10 分钟内刷新；暂时失败时，在仍剩至少 60 秒的条件下继续使用旧访问令牌，并至少等待 60 秒再尝试。聊天在输出前遇到 401 时刷新并重试一次，403 不盲目刷新；输出后不重发。只有令牌端点明确拒绝 OAuth grant 才标记授权失效，代理/WAF 的无 OAuth 错误 401/403 进入临时冷却。账号刷新使用数据目录内的跨进程锁，取消 API 请求不取消已开始的令牌交换，正常关闭会等待轮换落盘。跨机器共享导出凭据仍须停源端；强制结束进程或断电无法提供服务端轮换与本地落盘之间的原子保证。

## 模型与思考深度

`GET /v1/models` 返回三组、每组四个名称：

- `amazon-quick`、`amazon-quick-low`、`amazon-quick-medium`、`amazon-quick-high`
- `amazon-balance`、`amazon-balance-low`、`amazon-balance-medium`、`amazon-balance-high`
- `amazon-smart`、`amazon-smart-low`、`amazon-smart-medium`、`amazon-smart-high`

无后缀为 `off`；后缀对应 `low / medium / high`。短名 `quick / balance / smart` 及其深度后缀也是明确别名。未知模型名直接报错，不自动回退。

模式映射为 `quick → fast`、`balance → balanced`、`smart → smart`，通过官方 `agent_mode`、`thinking_effort` 字段发送。它们是 Quick 的路由模式，不是任意指定底层 Claude 等模型。也支持标准 `reasoning_effort`，以及 `agent_mode` / `thinking_effort` 扩展字段；显式字段优先于名称后缀，默认为关闭思考。

**Quick/fast 限制：**官方此版本的固定能力逻辑会把 fast 的思考深度归为 off。代理保留并透传所选后缀，12 个组合均已取得真实聊天回复，但 HTTP 200 不能证明 fast 开启了思考；最终能力取决于账号配置与 AWS 服务。需要思考时优先使用 balance/smart 后缀。

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8045/v1",
    api_key="YOUR_QUICKPOOL_API_KEY",
)
stream = client.chat.completions.create(
    model="amazon-smart-high",
    messages=[{"role": "user", "content": "你好"}],
    stream=True,
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="", flush=True)
```

## 兼容范围

- 文本非流式、实时 SSE；支持文本内容数组。
- 多轮：每次新建 Quick 对话，将完整角色、历史和 tool call ID 序列化成上下文，不在账号间复用服务端 conversation。
- 图片：OpenAI `image_url` 的 PNG/JPEG base64 data URL，单图最多 3 MiB、最多 4 张、请求总计最多 5 MiB。通过官方上传、DLP、附件交付流程，不把图片 base64 当文本。WARN/BLOCK 不自动绕过。暂不下载远程图片 URL（防止 SSRF）；企业 Gateway 图片路径尚未实现。
- `tools / tool_choice / parallel_tool_calls`，旧版 `functions / function_call`，以及 `role=tool` 的后续结果消息。
- `response_format` 的 `json_object / json_schema`，验证 JSON Schema；不允许外部 `$ref`。

**工具与 JSON 是提示词适配层，不是原生 Outpost/MCP 函数注册。**模型获得客户端函数定义并返回 JSON，网关验证函数名、参数和选择约束后才生成 OpenAI `tool_calls`，不会替客户端执行函数。工具与结构化响应先缓冲、验证，再返回非流式或标准 SSE；普通文本仍实时输出。模型不遵守格式会返回 502，不伪造成功。原生 MCP 注册机制已有研究，但尚未作为此兼容接口的实现。

暂不提供 `/v1/responses`、音频、视频或任意文件协议。不编造 token usage，也不保证所有 OpenAI 参数均改变上游行为；例如 temperature/max_tokens 不对应此版本已核对的桌面字段。仅 `n=1`。

## 多号调度与剩余额度

加权最少连接、账号并发限制、异常冷却。输出前最多重试三个不同账号；输出开始后不切号。失效账号隔离，不把授权错误伪装成空回答。

控制台展示官方月度剩余额度、会话用量以及更新时间/重置提示。首次进入自动获取，界面活动期间每五分钟刷新，也可点“刷新额度”。使用原生 user-info / metering 接口；失败或账号不提供时显示“暂不可用”，不推测为满额。官方额度按分钟/小时计算，不是 token，也不是现金余额；界面统一显示分钟。剩余配额本身不改变服务端限流、overage 或计费规则。

## 加密导出与远程迁移

控制台账号池可“加密导出”与“导入账号”。使用至少 12 位独立密码，Scrypt 派生密钥与 AES-256-GCM；文件携带原生凭据与账号配置，不含本机管理/API/数据库加密密钥。导入原子校验，账号冲突直接拒绝，不静默覆盖；导入后须逐个真实测试才能参与调度。

**迁移前先停止源端。**不要让两台机器长期同时刷新同一份授权，以免轮换竞争。导出文件仍应视为敏感备份，通过安全渠道传输并另行保管密码，不得提交到 GitHub。

本地 CLI（停止使用同一数据目录的服务后运行）：

```sh
python -m quickpool.transfer export accounts.quickpool.json --data-dir ./data
# 交互输入迁移密码；不要把密码直接写进命令行
```

远程 Linux 服务器：

```sh
git clone https://github.com/avilliai/awsquick2api.git
cd awsquick2api
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
# 将加密文件安全传到本机，由当前服务用户读取
python -m quickpool.transfer import /secure/accounts.quickpool.json --data-dir ./data
python -m quickpool
```

通过 SSH 本地端口转发打开远端面板，再逐个“测试”：

```sh
ssh -L 8045:127.0.0.1:8045 user@YOUR_SERVER
```

远端不需要再次使用网页 Cookie。首次原生授权建议在本机完成后迁移；容器内首次 OAuth 回调未做真实验证。所有 worker/实例须独立数据目录与独立授权；当前实现只支持单 worker。

Docker 可使用 `docker compose up -d --build`。默认只绑定宿主机 `127.0.0.1:8045`，数据存储于持久卷；在容器对应数据卷内运行同一迁移 CLI。迁移文件应对容器用户 UID 10001 可读，导入过程需停止网关。不要把含真实数据的目录加入构建上下文。本轮未进行本机 Docker 构建验证。

## 配置与安全

环境变量须在启动前设置，程序不会自动读取 `.env`：

- `QUICKPOOL_HOST=127.0.0.1`、`QUICKPOOL_PORT=8045`
- `QUICKPOOL_CALLBACK_PORT=18080`
- `QUICKPOOL_DATA_DIR=./data`
- `QUICKPOOL_ADMIN_KEY`、`QUICKPOOL_API_KEY`：可覆盖自动生成的独立密钥。

建议保持回环监听，经 SSH 或带 HTTPS 的受控反代访问。不要把管理密钥交给 API 调用方。日志仅记录账号引用、模型、状态、耗时、输出字符数与安全错误，不记录消息、回答正文或令牌。授权诊断接口只返回状态与令牌指纹，不返回凭据。

保管 `data/encryption.key` 与数据库，遗失密钥无法解密。`.gitignore` / `.dockerignore` 已排除数据、密钥、数据库、HAR 和迁移文件；发布前仍应检查暂存内容。公开仓库不包含真实授权、账号导出或本机验证账本。

## 测试与证据边界

```sh
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check quickpool tests
node --check quickpool/static/app.js
node tests/test_admin_session.cjs
```

自动测试使用合成账号和本地传输替身，覆盖 PKCE、回调防重放、轮换/并发刷新、加密导入导出、模型映射、图片上传/DLP/交付、工具验证、SSE、额度、失败隔离与租约释放。仓库 CI 覆盖 Windows/Linux；CI 结果以 GitHub Actions 实际运行状态为准。

真实联调已覆盖个人 Social/IdC 原生授权、两个不同身份、模型后缀、文本/SSE/历史、PNG 图片、工具适配与结构化输出。企业/Gateway 仍以离线协议验证为主。真实服务可能变更；短时成功不能当作长期授权可用性的保证。

## 代码入口

- `quickpool/native_auth.py`：PKCE、原生回调、令牌刷新。
- `quickpool/native_protocol.py`：Gateway/AIDP 桌面编码与事件。
- `quickpool/native_upstream.py`：原生 WebSocket、图片上传与交付。
- `quickpool/compat.py`：消息、工具与 JSON 兼容层。
- `quickpool/quota.py`：原生月度/会话配额。
- `quickpool/transfer.py`：加密迁移 API 逻辑与 CLI。
- `quickpool/main.py`、`pool.py`、`store.py`：管理路由、调度与加密持久化。
- `quickpool/static/`：中文控制台。

MIT License。
