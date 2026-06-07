# 系统状态与进程状态设计

## 背景

SupervisorPanel 当前已经支持项目创建、文件管理、Supervisor 启停与日志查看。项目列表和项目详情页只能看到 Supervisor 返回的运行状态，例如 `RUNNING`、`STOPPED`、`FATAL`。运维排查时还需要看到宿主机资源占用，以及每个由 Supervisor 管理的项目进程的基础资源状态。

本次新增两个能力：

1. 系统状态：查看当前 CPU、内存、硬盘占用情况。
2. 进程状态：查看每个 Supervisor 管理进程的 CPU、内存、网络占用。

进程网络占用采用轻量口径：显示监听端口和连接数量，不统计每进程网络收发速率。

## 目标

- 在后台顶部导航新增“系统状态”页面。
- 系统状态页面展示 CPU 使用率、内存总量/已用/占比、磁盘总量/已用/占比。
- 项目列表展示每个项目对应 Supervisor 进程的 PID、CPU、内存、监听端口、连接数。
- 项目详情页顶部展示当前项目的进程资源摘要。
- 指标刷新沿用当前项目状态轮询风格，默认 5 秒刷新一次，页面隐藏时暂停刷新。
- 后端采集逻辑以 Linux `/proc` 和 `/sys` 为主，不依赖额外守护进程。

## 非目标

- 不统计每进程网络上行/下行速率或累计流量。
- 不引入 eBPF、内核模块、sidecar agent 或后台常驻采样服务。
- 不新增告警、阈值配置、历史趋势图或审计日志。
- 不改变现有 Supervisor 启停、重启和配置生成逻辑。

## 推荐方案

新增 `internal/monitor` 包作为资源采集层。该包独立于 `internal/supervisor`，避免把“控制 Supervisor”和“采集运行指标”混在一起。

主要能力：

- 读取 `/proc/stat`，通过两次采样计算系统 CPU 使用率。
- 读取 `/proc/meminfo`，计算内存总量、可用量、已用量和使用率。
- 使用 `syscall.Statfs` 获取项目所在磁盘或根分区的容量与使用率。
- 从 `supervisorctl status <program>` 输出中解析 PID。
- 读取 `/proc/<pid>/stat`、`/proc/<pid>/status` 获取进程 CPU 与 RSS 内存。
- 读取 `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/udp`、`/proc/net/udp6`，结合 `/proc/<pid>/fd` socket inode，统计监听端口和连接数量。

如果进程已停止、PID 不存在或权限不足，接口仍返回项目记录，并在资源字段中标记不可用，前端显示 `-` 或“不可用”。

## API 设计

### `GET /api/system/status`

返回系统级快照：

```json
{
  "ok": true,
  "system": {
    "cpu": {
      "usage_percent": 12.4
    },
    "memory": {
      "total_bytes": 16777216000,
      "used_bytes": 6291456000,
      "available_bytes": 10485760000,
      "usage_percent": 37.5
    },
    "disk": {
      "path": "/opt/supervisor-panel/projects",
      "total_bytes": 107374182400,
      "used_bytes": 53687091200,
      "free_bytes": 53687091200,
      "usage_percent": 50.0
    },
    "collected_at": "2026-06-08T00:00:00Z"
  }
}
```

磁盘路径默认使用 `SP_PROJECTS_DIR`，因为这是面板最关心的项目文件所在分区。

### `GET /api/projects/process-statuses`

返回每个项目的 Supervisor 状态和资源状态：

```json
{
  "ok": true,
  "processes": {
    "1": {
      "status": "RUNNING",
      "status_text": "运行中",
      "pid": 1234,
      "cpu_percent": 3.2,
      "memory_bytes": 134217728,
      "memory_percent": 0.8,
      "listen_ports": [8080, 9000],
      "connection_count": 12,
      "available": true,
      "message": ""
    }
  }
}
```

停止状态或采集失败示例：

```json
{
  "status": "STOPPED",
  "status_text": "已停止",
  "pid": 0,
  "available": false,
  "message": "进程未运行"
}
```

## 前端设计

### 系统状态页

新增 `SystemStatusView.vue`，路由为 `/system/status`。顶部导航新增“系统状态”菜单项。

页面布局保持现有 Element Plus 后台风格：

- 页面头部：标题、采集时间、刷新按钮。
- 指标区：CPU、内存、硬盘三张卡片，每张卡片使用 `el-progress` 和数值说明。
- 错误状态：如果采集失败，显示 `el-alert`，并保留刷新按钮。

### 项目列表

在 `ProjectsView.vue` 中增加资源列：

- PID
- CPU
- 内存
- 端口
- 连接数

列表加载时同时请求项目列表和进程状态。现有 5 秒状态轮询改为请求 `GET /api/projects/process-statuses`，同步更新运行状态和资源字段。

### 项目详情

在 `ProjectDetailView.vue` 的页面头部下方增加一行进程资源摘要，展示当前项目的 PID、CPU、内存、端口、连接数。资源信息用独立接口加载，不阻塞文件列表和配置区加载。

## 数据流

1. 前端进入系统状态页，请求 `GET /api/system/status`。
2. 后端 `requireAuthAPI` 校验登录态。
3. `internal/monitor` 读取系统指标，返回快照。
4. 前端每 5 秒刷新一次，页面隐藏时暂停。
5. 前端进入项目列表或详情，请求 `GET /api/projects/process-statuses`。
6. 后端列出项目，逐个调用 Supervisor 状态查询并解析 PID。
7. 对运行中的 PID 读取 `/proc` 指标和 socket 信息。
8. 前端把资源字段合并到对应项目行或详情摘要。

## 错误处理

- 非 Linux 环境：返回 `available=false` 和说明，前端显示不可用。
- `/proc` 文件缺失：按进程已退出处理，不让整个接口失败。
- 权限不足：单个进程返回不可用和错误说明，其他进程继续采集。
- `supervisorctl status` 失败：保留项目记录，状态为 `UNKNOWN`，资源不可用。
- 系统级采集失败：接口返回 `500` 和简短错误消息。

## 测试与验证

后端采用测试优先：

- 为 `/proc/stat` CPU 解析和使用率计算写单元测试。
- 为 `/proc/meminfo` 解析写单元测试。
- 为 `supervisorctl status` PID 解析写单元测试。
- 为 socket inode、监听端口和连接数聚合写单元测试。
- 为 `/api/system/status` 和 `/api/projects/process-statuses` 写 handler 测试。

前端验证：

- 更新 TypeScript API 类型。
- 运行 `npm run typecheck`。
- 运行 `npm run build` 验证静态产物。

整体验证：

- 运行 `go test ./...`。
- 在本地启动后用浏览器检查系统状态页和项目列表列宽，确保移动端不发生文本溢出。

## 风险

- 进程 CPU 百分比需要两次采样才能稳定计算。实现中会在一次请求内做短间隔采样，避免引入后台缓存服务。
- `/proc/<pid>/fd` 读取可能受权限限制。该失败只影响对应进程的网络字段，不影响页面整体可用性。
- Supervisor 输出格式可能因版本略有差异。PID 解析需要覆盖常见 `pid 1234` 格式，解析不到时返回不可用。
- 项目较多时逐个读取 `/proc` 会增加请求耗时。实现会保持采样间隔短，并避免读取无关进程。
