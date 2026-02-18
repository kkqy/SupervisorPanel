# SupervisorPanel

SupervisorPanel 是一个基于 Go + SQLite3 的 Supervisor Web 管理面板。

## 功能

- 管理员登录/退出，支持修改密码
- 创建项目并自动创建项目目录
- 上传文件（支持普通多文件和目录结构上传）
- 在项目文件列表中指定主程序（立即生效）并设置启动参数
- 通过 Supervisor 启动、停止、重启项目
- 支持删除项目、删除项目内文件
- 支持常见文本文件在线编辑（txt/json/yaml/ini 等，1MB 限制）
- 支持查看项目日志（最近 N 行）
- 日志页支持 SSE 实时跟踪
- 支持项目复制（可选是否复制符号链接，复制后默认未启动）
- 项目文件支持资源管理器式浏览，并可在当前目录新建文件夹/文件

## 技术栈

- Go
- SQLite3 (`modernc.org/sqlite`)
- 前端模板（Go `html/template`）

## 本地开发运行

```bash
go mod tidy
go run ./cmd/supervisor-panel
```

默认配置（可通过环境变量覆盖）：

- `SP_ADDR=:8080`
- `SP_DB_PATH=./data/supervisor-panel.db`
- `SP_PROJECTS_DIR=./projects`
- `SP_SUPERVISOR_CONF_DIR=/etc/supervisor/conf.d`
- `SP_SUPERVISORCTL_BIN=/usr/bin/supervisorctl`
- `SP_RUNTIME_USER=www-data`

首次创建管理员：

```bash
go run ./cmd/supervisor-panel init-admin --db ./data/supervisor-panel.db --username admin --password your_password
```

## 安装（Debian/Ubuntu）

```bash
curl -fsSL -o /tmp/supervisorpanel-install.sh https://raw.githubusercontent.com/kkqy/SupervisorPanel/main/scripts/install.sh
chmod +x /tmp/supervisorpanel-install.sh
sudo env RELEASE_VERSION=v1.0.0 bash /tmp/supervisorpanel-install.sh
```

安装最新版本（默认 `latest`）：

```bash
curl -fsSL -o /tmp/supervisorpanel-install.sh https://raw.githubusercontent.com/kkqy/SupervisorPanel/main/scripts/install.sh
chmod +x /tmp/supervisorpanel-install.sh
sudo bash /tmp/supervisorpanel-install.sh
```

安装脚本会完成：

1. 按当前系统架构下载预编译安装包（`x86/x64/arm/arm64`）
2. 安装 `supervisor-panel` 到 `/usr/local/bin/supervisor-panel`
3. 生成 `/etc/supervisor-panel/config.env`
4. 初始化管理员账号密码
5. 注册并启动 `supervisor-panel` systemd 服务

环境变量说明：

- `RELEASE_VERSION`：版本号（默认 `latest`），例如 `v1.0.0`
- `GITHUB_REPO`：GitHub 仓库路径（默认 `kkqy/SupervisorPanel`）
- `DOWNLOAD_BASE_URL`：可选，自定义下载源地址（例如 `https://your-server/releases`），设置后会优先使用该地址

安装脚本下载路径规则：

- 默认（GitHub Release）：

  `https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_VERSION}/supervisor-panel_{RELEASE_VERSION}_linux_{ARCH}.tar.gz`

- 自定义下载源（设置 `DOWNLOAD_BASE_URL` 时）：

  `{DOWNLOAD_BASE_URL}/{RELEASE_VERSION}/supervisor-panel_{RELEASE_VERSION}_linux_{ARCH}.tar.gz`

其中 `ARCH` 自动映射为：`386/amd64/arm/arm64`。

## 发布打包（单机多架构交叉编译）

```bash
chmod +x scripts/build-release.sh
VERSION=v1.0.0 TARGETS=linux/386,linux/amd64,linux/arm,linux/arm64 ./scripts/build-release.sh
```

可选参数：

- `TARGETS`：逗号分隔目标列表，可按需增减（默认 `linux/386,linux/amd64,linux/arm,linux/arm64`）
- `ARM_VARIANT`：`linux/arm` 的默认变体（默认 `7`，可设 `6`）
- `OUTPUT_DIR`：输出根目录（默认 `dist/releases`）

生成目录结构：

```text
dist/releases/<VERSION>/
  supervisor-panel_<VERSION>_linux_386.tar.gz
  supervisor-panel_<VERSION>_linux_amd64.tar.gz
  supervisor-panel_<VERSION>_linux_arm.tar.gz
  supervisor-panel_<VERSION>_linux_arm64.tar.gz
  SHA256SUMS
```

如果使用自定义下载源，可将 `dist/releases/<VERSION>/` 同步到下载服务器的 `/releases/<VERSION>/`，安装脚本即可按架构自动下载。

## GitHub Actions 自动发布

仓库已包含工作流：`.github/workflows/release.yml`

- 当推送标签（如 `v1.0.0`）时，会自动：
  1. 交叉编译 `linux/386,linux/amd64,linux/arm,linux/arm64`
  2. 生成 `dist/releases/<VERSION>/` 下的压缩包和 `SHA256SUMS`
  3. 上传到 GitHub Release 附件
- 也支持手动触发 `workflow_dispatch`，并输入版本号。

示例：

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 目录说明

- `cmd/supervisor-panel/main.go`: 程序入口
- `internal/server`: 路由、页面渲染、业务处理
- `internal/db`: SQLite 初始化和数据访问
- `internal/supervisor`: Supervisor 配置与控制
- `scripts/install.sh`: 安装脚本
- `scripts/build-release.sh`: 多架构发布打包脚本

## 注意事项

- 建议在 Linux（Debian/Ubuntu）部署，确保已安装并运行 `supervisord`。
- 主程序文件需要具备可执行能力（如带 shebang 的脚本或二进制）。
- 如果系统不存在 `www-data` 用户，会回退到 `root`（可在页面修改运行用户）。
- 新建项目目录使用项目 ID（例如 `/opt/supervisor-panel/projects/12`），避免同名冲突与改名影响。
