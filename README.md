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
- **SFTP 上传**: 支持将本地文件上传到远程服务器。
- **路径自动输入**: 上传成功后可选择自动将路径输入到终端（不带换行符）。
- **配置驱动**: 通过 `config.json` 轻松设置默认值。

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
