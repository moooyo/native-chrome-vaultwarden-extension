# CLAUDE.md

本文件为本仓库提供给 Claude Code 的项目级指引。

## 测试环境（实测 Vaultwarden 服务端）

用于把客户端代码跑在真实 Bitwarden 兼容服务端上做端到端验证。**该测试账户与服务端均为一次性测试用途，凭据可明文记录于此。**

### 服务器与登录

- **SSH 登录**：`ssh test-env`（已在 dotssh 配置 `D:\Code\dotssh\config.d/hosts` 定义 → `root@10.0.1.20:22`，认证走 Bitwarden SSH Agent 命名管道）。
  - ⚠️ **必须用 Windows 原生 ssh.exe**（`$env:WINDIR\System32\OpenSSH\ssh.exe`，经 PowerShell 调用）。Git Bash 自带的 ssh 会因 `~/.ssh/config` 开头的 UTF-8 BOM 报 `Bad configuration option: \357\273\277include` 而失败，且其无法访问 Windows 命名管道里的 agent 私钥。
  - 远程命令避免在 PowerShell 单引号里带 `()`（bash 会当语法）；多行命令用 PowerShell here-string `@' ... '@` 传给 ssh.exe。
- **服务器**：test-env = Debian 13 (trixie) x86_64，对外 IP `10.0.1.20`，当前网络可直连。
- **Vaultwarden**：docker 容器 `vaultwarden`（镜像 `vaultwarden/server:latest`，服务端 version `2025.12.0`），数据卷 `/opt/vaultwarden/data`，端口映射 `8080:80`。
  - 启动参数：`DOMAIN=http://10.0.1.20:8080`、`SIGNUPS_ALLOWED=true`、`WEBSOCKET_ENABLED=true`、`ADMIN_TOKEN=testadmintoken123`。
  - **客户端服务端 URL**：`http://10.0.1.20:8080`（客户端接受 http，无需 HTTPS）。
  - 健康检查：`curl http://10.0.1.20:8080/alive`；管理后台：`http://10.0.1.20:8080/admin`（token `testadmintoken123`）。
- **测试账户**：邮箱 `test@winvaultwarden.local` / 主密码 `Test-Master-Password-1!`（KDF = PBKDF2-SHA256，600000 次）。
