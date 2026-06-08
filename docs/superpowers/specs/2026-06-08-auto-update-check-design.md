# 后台自动检测更新设计

## 目标

后台服务定时检测 SupervisorPanel 是否有新版本；发现新版后，管理员可以在页面上一键提交升级。升级复用现有 `scripts/upgrade.sh`，继续保留脚本中的备份、回滚和重启逻辑。

## 范围

- 后端启动后定时检测更新，并缓存检测结果。
- 管理员可通过 API 手动触发检测。
- 管理员可通过 API 提交升级任务，任务异步执行，避免 HTTP 请求阻塞到服务重启。
- 前端展示当前版本、最新版本、检测状态和一键升级入口。
- 默认使用 GitHub Release；支持自定义仓库和自定义下载源。

## 架构

新增 `internal/update` 包，负责版本比较、Release 查询、缓存状态和升级命令执行。`internal/server` 只暴露认证后的 API，并在启动时启动后台检测循环。`cmd/supervisor-panel` 注入构建版本，传入配置和服务层。

## 配置

- `SP_UPDATE_CHECK_ENABLED`：是否启用更新检测，默认 `true`。
- `SP_UPDATE_CHECK_INTERVAL_HOURS`：检测间隔，默认 `6`。
- `SP_UPDATE_GITHUB_REPO`：GitHub 仓库，默认 `kkqy/SupervisorPanel`。
- `SP_UPDATE_DOWNLOAD_BASE_URL`：自定义下载源，可为空。
- `SP_UPDATE_SCRIPT_PATH`：升级脚本路径，默认优先使用安装目录脚本，开发环境使用 `scripts/upgrade.sh`。

## API

- `GET /api/system/update`：读取缓存状态。
- `POST /api/system/update/check`：手动触发检测并返回最新状态。
- `POST /api/system/update/upgrade`：如果检测到新版本，异步执行升级脚本。

## 错误处理

检测失败时保留上次状态并记录错误信息。升级任务同一时间只允许一个运行；重复点击返回当前任务状态。未检测到新版时拒绝升级请求。

## 测试

后端使用 Go 单元测试覆盖版本比较、Release 查询解析、检测缓存、重复升级保护和 API 路由。前端通过 TypeScript 构建验证接口类型和页面接入。
