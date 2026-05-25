# GgySSH Bridge

GgySSH 是一个基于 Web 的 WebSocket-to-SSH 桥接工具，支持远程终端操作和通过 SFTP 上传文件。

## 配置文件 (config.json)

在项目根目录下创建 `config.json` 以配置服务器端口和默认 SSH 连接信息。

示例内容：

```json
{
  "server_port": "8080",
  "default_ssh_host": "127.0.0.1",
  "default_ssh_port": 22
}
```

## 功能特性

- **WebSocket 终端**: 基于 Xterm.js 的实时远程 Shell 交互。
- **多种认证**: 支持密码登录和私钥 (id_rsa) 登录。
- **WebAuthn/FIDO Gate**: 可要求使用安全金钥通过 WebAuthn 后，才允许使用 SSH Web UI。
- **Admin 管理页**: `/admin/` 可注册、停用、命名安全金钥，并查看登入纪录。
- **SFTP 上传**: 支持将本地文件上传到远程服务器。
- **路径自动输入**: 上传成功后可选择自动将路径输入到终端（不带换行符）。
- **配置驱动**: 通过 `config.json` 轻松设置默认值。

## WebAuthn / FIDO 安全金钥

此功能保护的是 GgySSH Web UI。通过 WebAuthn 后，使用者仍会使用原本的密码或私钥流程登入 SSH 主机。

正式环境建议放在 HTTPS 反向代理后面；WebAuthn 只在 HTTPS 或 `localhost` 这类安全 context 可用。`rp_id` 通常是网域本身，不含 scheme 和 port，例如 `ggyssh.example.com`；`origin` 需要包含 scheme，例如 `https://ggyssh.example.com`。

示例：

```json
{
  "server_port": "8080",
  "hosts": [
    { "host": "127.0.0.1", "port": 22 }
  ],
  "webauthn": {
    "enabled": true,
    "rp_id": "ggyssh.example.com",
    "rp_display_name": "GgySSH",
    "origin": "https://ggyssh.example.com",
    "admin_user": "admin",
    "db_path": "ggyssh.sqlite",
    "session_hours": 24
  },
  "admin": {
    "enabled": true,
    "path": "/admin",
    "token_required": true,
    "token_hash": "sha256:<hex-encoded-sha256>",
    "bootstrap_token_hash": "sha256:<hex-encoded-sha256>"
  }
}
```

产生 token hash：

```bash
printf '%s' 'your-long-random-token' | sha256sum
```

首次注册安全金钥：

1. 确认 `webauthn.enabled=true` 且 `admin.token_required=true`。
2. 设置 `admin.bootstrap_token_hash`。
3. 打开 `https://ggyssh.example.com/admin/?token=your-long-random-token`。
4. 按 `Register Security Key`，触碰安全金钥完成注册。
5. 后续新增金钥必须先通过既有 admin security key，再进入 `/admin/` 注册。

`/admin/` 的管理 API 需要同时满足：

- admin token gate cookie 尚未过期。
- 已通过 WebAuthn。
- 使用者角色为 `admin`。

登入成功、失败、admin token gate、金钥注册、金钥停用等事件会写入 SQLite audit log，并可在 `/admin/` 查看。

### WebAuthn 后自动 SSH SSO

如果 GgySSH 只需要登入固定的受控 SSH 帐号，可以启用 server-side SSO。使用者通过 WebAuthn 后，前端会自动呼叫 `/login/sso`，后端读取服务器上的 SSH private key 建立 SSH/SFTP session；private key 不会传到浏览器。

```json
{
  "sso": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 22,
    "username": "codex",
    "private_key_path": "/home/codex/.ssh/ggyssh_sso_key",
    "home_root": "/home/codex"
  }
}
```

建议：

- `private_key_path` 指向只供 GgySSH SSO 使用的 key。
- private key 权限设为 `600`。
- public key 放入目标帐号的 `authorized_keys`。
- SSO 失败时会退回原本的手动 SSH login form。

## 反向代理（子路径）部署

如果你需要把 GgySSH 挂在某个子路径下（例如 `https://example.com/xxx/`），推荐让反向代理**剥离**路径前缀再转发到后端，这样后端仍然看到 `/login`、`/ws` 等根路径。

Nginx 示例（注意 `proxy_pass` 结尾的 `/`）：

```nginx
location /xxx/ {
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_pass http://127.0.0.1:8080/;
}
```

如果你的反向代理**不会**剥离前缀（后端收到的是 `/xxx/login`、`/xxx/ws`），可以在 `config.json` 里设置 `base_path`（例如 `"/xxx"`），或者由代理加上 `X-Forwarded-Prefix` 头。后端也会尝试自动兼容这类带前缀的请求路径。

## 快速开始

1. 确保已安装 Go。
2. 在 `ggyssh` 目录下运行：
   ```bash
   go run main.go
   ```
3. 访问 `http://localhost:8080`（或你在配置中设置的端口）。
