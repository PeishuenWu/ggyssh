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

## 快速开始

1. 确保已安装 Go。
2. 在 `ggyssh` 目录下运行：
   ```bash
   go run main.go
   ```
3. 访问 `http://localhost:8080`（或你在配置中设置的端口）。
