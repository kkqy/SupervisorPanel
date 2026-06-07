# System Process Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build authenticated system resource status and Supervisor-managed process resource status in the existing Go + Vue SupervisorPanel.

**Architecture:** Add a focused Go `internal/monitor` package for Linux `/proc` parsing and runtime snapshots, keep Supervisor control logic in `internal/supervisor`, and expose two JSON APIs from `internal/server`. Extend the Vue app with a system status page plus process-resource fields in project list/detail views.

**Tech Stack:** Go 1.25, standard library `/proc` parsing, existing SQLite store, Vue 3, TypeScript, Element Plus.

---

## File Structure

- Create `internal/monitor/types.go`: public snapshot types returned to the server API.
- Create `internal/monitor/proc.go`: pure parsing helpers for `/proc/stat`, `/proc/meminfo`, `/proc/<pid>/stat`, `/proc/<pid>/status`, socket inode parsing, and `/proc/net/*`.
- Create `internal/monitor/proc_test.go`: unit tests for parsing helpers.
- Create `internal/monitor/collector.go`: `Collector` implementation that samples system and process metrics.
- Create `internal/monitor/collector_test.go`: unit tests for collector behavior using temporary proc-style files where safe.
- Create `internal/monitor/disk_unix.go`: Unix disk usage via `syscall.Statfs`.
- Create `internal/monitor/disk_windows.go`: Windows fallback so local Windows builds compile and return unsupported disk status.
- Modify `internal/supervisor/client.go`: add `StatusWithPID(slug string)` and pure `parseStatusLine`.
- Create `internal/supervisor/client_test.go`: tests for status and PID parsing.
- Modify `internal/server/server.go`: wire monitor collector, add `/api/system/status`, add `/api/projects/process-statuses`.
- Modify `internal/server/server_test.go`: handler tests with a fake monitor collector.
- Modify `web/src/types/api.ts`: add TypeScript response and process metric types.
- Modify `web/src/api/system.ts`: add `getSystemStatus()`.
- Modify `web/src/api/projects.ts`: add `getProjectProcessStatuses()`.
- Modify `web/src/router/index.ts`: add `/system/status` route.
- Create `web/src/views/SystemStatusView.vue`: system resource status page.
- Modify `web/src/layouts/AdminLayout.vue`: add navigation menu item for system status.
- Modify `web/src/views/ProjectsView.vue`: display PID, CPU, memory, ports, connection count, and refresh via new process-status API.
- Modify `web/src/views/ProjectDetailView.vue`: show current project process-resource summary.
- Modify `web/src/styles.css`: add compact metric-grid styles reused by the new page and project detail.

---

### Task 1: Monitor Parsing Tests

**Files:**
- Create: `internal/monitor/proc_test.go`

- [ ] **Step 1: Write failing parser tests**

Create `internal/monitor/proc_test.go`:

```go
package monitor

import (
	"strings"
	"testing"
)

func TestParseCPUStatLine(t *testing.T) {
	sample := "cpu  4705 0 2257 136239 553 0 112 0 0 0"
	got, err := parseCPUStatLine(sample)
	if err != nil {
		t.Fatalf("parseCPUStatLine: %v", err)
	}
	if got.idle != 136792 {
		t.Fatalf("idle = %d, want 136792", got.idle)
	}
	if got.total != 143866 {
		t.Fatalf("total = %d, want 143866", got.total)
	}
}

func TestCPUUsageBetweenSamples(t *testing.T) {
	prev := cpuTimes{idle: 100, total: 200}
	next := cpuTimes{idle: 150, total: 300}
	got := cpuUsagePercent(prev, next)
	if got != 50 {
		t.Fatalf("usage = %.1f, want 50.0", got)
	}
}

func TestParseMeminfo(t *testing.T) {
	meminfo := strings.Join([]string{
		"MemTotal:       16384000 kB",
		"MemFree:         2048000 kB",
		"MemAvailable:   8192000 kB",
		"Buffers:          512000 kB",
		"Cached:          4096000 kB",
	}, "\n")
	got, err := parseMeminfo(meminfo)
	if err != nil {
		t.Fatalf("parseMeminfo: %v", err)
	}
	if got.TotalBytes != 16777216000 {
		t.Fatalf("total = %d, want 16777216000", got.TotalBytes)
	}
	if got.AvailableBytes != 8388608000 {
		t.Fatalf("available = %d, want 8388608000", got.AvailableBytes)
	}
	if got.UsedBytes != 8388608000 {
		t.Fatalf("used = %d, want 8388608000", got.UsedBytes)
	}
	if got.UsagePercent != 50 {
		t.Fatalf("usage = %.1f, want 50.0", got.UsagePercent)
	}
}

func TestParseProcessStatLineHandlesProcessNamesWithSpaces(t *testing.T) {
	line := "1234 (node worker) S 1 2 3 0 -1 4194304 10 0 0 0 25 15 0 0 20 0 7 0 123456 1000000 4096"
	got, err := parseProcessStatLine(line)
	if err != nil {
		t.Fatalf("parseProcessStatLine: %v", err)
	}
	if got.pid != 1234 {
		t.Fatalf("pid = %d, want 1234", got.pid)
	}
	if got.totalTicks != 40 {
		t.Fatalf("totalTicks = %d, want 40", got.totalTicks)
	}
}

func TestParseRSSBytesFromStatus(t *testing.T) {
	status := "Name:\tnode\nVmRSS:\t  20480 kB\n"
	got, err := parseRSSBytesFromStatus(status)
	if err != nil {
		t.Fatalf("parseRSSBytesFromStatus: %v", err)
	}
	if got != 20971520 {
		t.Fatalf("rss = %d, want 20971520", got)
	}
}

func TestParseSocketInode(t *testing.T) {
	got, ok := parseSocketInode("socket:[4026532417]")
	if !ok {
		t.Fatal("socket inode was not parsed")
	}
	if got != "4026532417" {
		t.Fatalf("inode = %q, want 4026532417", got)
	}
}

func TestParseProcNetRows(t *testing.T) {
	content := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 11111",
		"   1: 0100007F:1F90 0100007F:C001 01 00000000:00000000 00:00000000 00000000 1000 0 22222",
	}, "\n")
	rows, err := parseProcNet(content, "tcp")
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if !rows[0].listen || rows[0].port != 8080 || rows[0].inode != "11111" {
		t.Fatalf("first row = %+v, want listen port 8080 inode 11111", rows[0])
	}
	if rows[1].listen || rows[1].port != 8080 || rows[1].inode != "22222" {
		t.Fatalf("second row = %+v, want established port 8080 inode 22222", rows[1])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/monitor
```

Expected: FAIL because package `internal/monitor` and parser functions do not exist.

- [ ] **Step 3: Commit failing tests**

Run:

```bash
git add internal/monitor/proc_test.go
git commit -m "test: add monitor proc parser coverage"
```

---

### Task 2: Monitor Types And Parser Implementation

**Files:**
- Create: `internal/monitor/types.go`
- Create: `internal/monitor/proc.go`
- Test: `internal/monitor/proc_test.go`

- [ ] **Step 1: Add monitor public types**

Create `internal/monitor/types.go`:

```go
package monitor

import "time"

type CPUSnapshot struct {
	UsagePercent float64 `json:"usage_percent"`
}

type MemorySnapshot struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

type DiskSnapshot struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

type SystemSnapshot struct {
	CPU         CPUSnapshot    `json:"cpu"`
	Memory      MemorySnapshot `json:"memory"`
	Disk        DiskSnapshot   `json:"disk"`
	CollectedAt time.Time      `json:"collected_at"`
}

type ProcessSnapshot struct {
	Status          string   `json:"status"`
	StatusText      string   `json:"status_text"`
	PID             int      `json:"pid"`
	CPUPercent      float64  `json:"cpu_percent"`
	MemoryBytes     uint64   `json:"memory_bytes"`
	MemoryPercent   float64  `json:"memory_percent"`
	ListenPorts     []int    `json:"listen_ports"`
	ConnectionCount int      `json:"connection_count"`
	Available       bool     `json:"available"`
	Message         string   `json:"message"`
}
```

- [ ] **Step 2: Add parser implementation**

Create `internal/monitor/proc.go`:

```go
package monitor

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type cpuTimes struct {
	idle  uint64
	total uint64
}

type processTimes struct {
	pid        int
	totalTicks uint64
}

type procNetRow struct {
	proto  string
	inode  string
	port   int
	listen bool
}

func parseCPUStatLine(line string) (cpuTimes, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("invalid cpu stat line")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("parse cpu field %q: %w", field, err)
		}
		values = append(values, value)
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return cpuTimes{idle: idle, total: total}, nil
}

func cpuUsagePercent(prev, next cpuTimes) float64 {
	if next.total <= prev.total {
		return 0
	}
	totalDelta := next.total - prev.total
	idleDelta := uint64(0)
	if next.idle > prev.idle {
		idleDelta = next.idle - prev.idle
	}
	if idleDelta >= totalDelta {
		return 0
	}
	return round1(float64(totalDelta-idleDelta) * 100 / float64(totalDelta))
}

func parseMeminfo(content string) (MemorySnapshot, error) {
	values := map[string]uint64{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return MemorySnapshot{}, fmt.Errorf("parse meminfo %s: %w", key, err)
		}
		values[key] = value * 1024
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total == 0 {
		return MemorySnapshot{}, fmt.Errorf("MemTotal missing")
	}
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	used := uint64(0)
	if total > available {
		used = total - available
	}
	return MemorySnapshot{
		TotalBytes:     total,
		UsedBytes:      used,
		AvailableBytes: available,
		UsagePercent:   round1(float64(used) * 100 / float64(total)),
	}, nil
}

func parseProcessStatLine(line string) (processTimes, error) {
	open := strings.Index(line, "(")
	close := strings.LastIndex(line, ")")
	if open < 1 || close <= open {
		return processTimes{}, fmt.Errorf("invalid process stat line")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line[:open]))
	if err != nil {
		return processTimes{}, fmt.Errorf("parse pid: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(line[close+1:]))
	if len(fields) < 15 {
		return processTimes{}, fmt.Errorf("process stat line too short")
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return processTimes{}, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return processTimes{}, fmt.Errorf("parse stime: %w", err)
	}
	return processTimes{pid: pid, totalTicks: utime + stime}, nil
}

func processCPUPercent(prev, next processTimes, prevCPU, nextCPU cpuTimes, cpuCount int) float64 {
	if next.totalTicks <= prev.totalTicks || nextCPU.total <= prevCPU.total || cpuCount <= 0 {
		return 0
	}
	procDelta := next.totalTicks - prev.totalTicks
	totalDelta := nextCPU.total - prevCPU.total
	return round1(float64(procDelta) * float64(cpuCount) * 100 / float64(totalDelta))
}

func parseRSSBytesFromStatus(content string) (uint64, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == "VmRSS" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse VmRSS: %w", err)
			}
			return value * 1024, nil
		}
	}
	return 0, nil
}

func parseSocketInode(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if inode == "" {
		return "", false
	}
	return inode, true
}

func parseProcNet(content, proto string) ([]procNetRow, error) {
	rows := []procNetRow{}
	for index, line := range strings.Split(content, "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		state := strings.ToUpper(fields[3])
		inode := fields[9]
		port, err := parseHexPort(local)
		if err != nil {
			return nil, err
		}
		listen := state == "0A"
		if strings.HasPrefix(proto, "udp") && state == "07" {
			listen = true
		}
		rows = append(rows, procNetRow{proto: proto, inode: inode, port: port, listen: listen})
	}
	return rows, nil
}

func parseHexPort(localAddress string) (int, error) {
	parts := strings.Split(localAddress, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid local address %q", localAddress)
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", parts[1], err)
	}
	return int(port), nil
}

func summarizeSockets(rows []procNetRow, inodes map[string]struct{}) ([]int, int) {
	portSet := map[int]struct{}{}
	connectionCount := 0
	for _, row := range rows {
		if _, ok := inodes[row.inode]; !ok {
			continue
		}
		connectionCount++
		if row.listen && row.port > 0 {
			portSet[row.port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, connectionCount
}

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}
```

- [ ] **Step 3: Run monitor parser tests**

Run:

```bash
go test ./internal/monitor
```

Expected: PASS for all parser tests.

- [ ] **Step 4: Commit parser implementation**

Run:

```bash
git add internal/monitor/types.go internal/monitor/proc.go internal/monitor/proc_test.go
git commit -m "feat: add monitor proc parsers"
```

---

### Task 3: Supervisor Status PID Parsing

**Files:**
- Modify: `internal/supervisor/client.go`
- Create: `internal/supervisor/client_test.go`

- [ ] **Step 1: Write failing supervisor status parser tests**

Create `internal/supervisor/client_test.go`:

```go
package supervisor

import "testing"

func TestParseStatusLineRunningWithPID(t *testing.T) {
	status, pid := parseStatusLine("sp_p1 RUNNING pid 1234, uptime 0:00:05")
	if status != "RUNNING" {
		t.Fatalf("status = %q, want RUNNING", status)
	}
	if pid != 1234 {
		t.Fatalf("pid = %d, want 1234", pid)
	}
}

func TestParseStatusLineStoppedWithoutPID(t *testing.T) {
	status, pid := parseStatusLine("sp_p1 STOPPED Jun 08 12:00 PM")
	if status != "STOPPED" {
		t.Fatalf("status = %q, want STOPPED", status)
	}
	if pid != 0 {
		t.Fatalf("pid = %d, want 0", pid)
	}
}

func TestParseStatusLineUnknownOnMalformedOutput(t *testing.T) {
	status, pid := parseStatusLine("unexpected")
	if status != "UNKNOWN" {
		t.Fatalf("status = %q, want UNKNOWN", status)
	}
	if pid != 0 {
		t.Fatalf("pid = %d, want 0", pid)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/supervisor
```

Expected: FAIL because `parseStatusLine` does not exist.

- [ ] **Step 3: Implement parser and `StatusWithPID`**

Modify `internal/supervisor/client.go` by replacing `Status` and adding `StatusWithPID` plus `parseStatusLine`:

```go
func (c *Client) Status(slug string) string {
	status, _ := c.StatusWithPID(slug)
	return status
}

func (c *Client) StatusWithPID(slug string) (string, int) {
	out, err := c.run("status", c.ProgramName(slug))
	if out == "" && err != nil {
		return "UNKNOWN", 0
	}
	status, pid := parseStatusLine(out)
	if status == "ERROR" {
		return "UNKNOWN", 0
	}
	return status, pid
}

func parseStatusLine(out string) (string, int) {
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "UNKNOWN", 0
	}
	status := strings.ToUpper(strings.TrimSpace(fields[1]))
	pid := 0
	for index, field := range fields {
		normalized := strings.Trim(strings.ToLower(field), ",")
		if normalized != "pid" || index+1 >= len(fields) {
			continue
		}
		value := strings.Trim(fields[index+1], ",")
		parsed, err := strconv.Atoi(value)
		if err == nil && parsed > 0 {
			pid = parsed
		}
		break
	}
	if status == "" || status == "ERROR" {
		status = "UNKNOWN"
		pid = 0
	}
	return status, pid
}
```

- [ ] **Step 4: Run supervisor tests**

Run:

```bash
go test ./internal/supervisor
```

Expected: PASS.

- [ ] **Step 5: Commit supervisor parser**

Run:

```bash
git add internal/supervisor/client.go internal/supervisor/client_test.go
git commit -m "feat: parse supervisor process pid"
```

---

### Task 4: Monitor Collector

**Files:**
- Create: `internal/monitor/collector.go`
- Create: `internal/monitor/disk_unix.go`
- Create: `internal/monitor/disk_windows.go`
- Create: `internal/monitor/collector_test.go`

- [ ] **Step 1: Write failing collector tests**

Create `internal/monitor/collector_test.go`:

```go
package monitor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type fakeSupervisorStatus struct {
	status string
	pid    int
}

func (f fakeSupervisorStatus) StatusWithPID(slug string) (string, int) {
	return f.status, f.pid
}

func TestSystemSnapshotFromProcRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("proc filesystem is Linux-specific")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "stat"), "cpu  100 0 0 100 0 0 0 0 0 0\n")
	writeFile(t, filepath.Join(root, "meminfo"), "MemTotal: 1000 kB\nMemAvailable: 400 kB\n")

	c := Collector{
		ProcRoot:    root,
		SampleDelay: time.Millisecond,
		ReadFile: func(path string) ([]byte, error) {
			if filepath.Base(path) == "stat" {
				return []byte("cpu  150 0 0 150 0 0 0 0 0 0\n"), nil
			}
			return os.ReadFile(path)
		},
	}
	got, err := c.SystemSnapshot(root)
	if err != nil {
		t.Fatalf("SystemSnapshot: %v", err)
	}
	if got.CPU.UsagePercent != 50 {
		t.Fatalf("cpu usage = %.1f, want 50.0", got.CPU.UsagePercent)
	}
	if got.Memory.UsagePercent != 60 {
		t.Fatalf("memory usage = %.1f, want 60.0", got.Memory.UsagePercent)
	}
	if got.CollectedAt.IsZero() {
		t.Fatal("CollectedAt is zero")
	}
}

func TestProcessSnapshotReturnsUnavailableWhenStopped(t *testing.T) {
	c := Collector{Supervisor: fakeSupervisorStatus{status: "STOPPED", pid: 0}}
	got := c.ProcessSnapshot("p1")
	if got.Available {
		t.Fatal("Available = true, want false")
	}
	if got.Status != "STOPPED" {
		t.Fatalf("Status = %q, want STOPPED", got.Status)
	}
	if got.Message != "进程未运行" {
		t.Fatalf("Message = %q, want 进程未运行", got.Message)
	}
}

func TestSummarizeSocketsForProcessInodes(t *testing.T) {
	rows := []procNetRow{
		{proto: "tcp", inode: "1", port: 8080, listen: true},
		{proto: "tcp", inode: "2", port: 8080, listen: false},
		{proto: "tcp", inode: "3", port: 9000, listen: true},
	}
	ports, count := summarizeSockets(rows, map[string]struct{}{"1": {}, "2": {}})
	if count != 2 {
		t.Fatalf("connection count = %d, want 2", count)
	}
	if len(ports) != 1 || ports[0] != 8080 {
		t.Fatalf("ports = %#v, want [8080]", ports)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/monitor
```

Expected: FAIL because `Collector` does not exist.

- [ ] **Step 3: Implement collector**

Create `internal/monitor/collector.go`:

```go
package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"supervisorpanel/internal/db"
)

type SupervisorStatus interface {
	StatusWithPID(slug string) (string, int)
}

type Collector struct {
	ProcRoot    string
	SampleDelay time.Duration
	ReadFile    func(string) ([]byte, error)
	ReadLink    func(string) (string, error)
	ReadDir     func(string) ([]os.DirEntry, error)
	Supervisor  SupervisorStatus
}

func New(supervisor SupervisorStatus) Collector {
	return Collector{Supervisor: supervisor}
}

func (c Collector) ProcessSnapshots(projects []db.Project) map[string]ProcessSnapshot {
	items := make(map[string]ProcessSnapshot, len(projects))
	for _, project := range projects {
		items[strconv.FormatInt(project.ID, 10)] = c.ProcessSnapshot(project.Slug)
	}
	return items
}

func (c Collector) SystemSnapshot(diskPath string) (SystemSnapshot, error) {
	if runtime.GOOS != "linux" {
		return SystemSnapshot{}, fmt.Errorf("系统状态采集仅支持 Linux")
	}
	prev, err := c.readCPU()
	if err != nil {
		return SystemSnapshot{}, err
	}
	delay := c.SampleDelay
	if delay <= 0 {
		delay = 200 * time.Millisecond
	}
	time.Sleep(delay)
	next, err := c.readCPU()
	if err != nil {
		return SystemSnapshot{}, err
	}
	mem, err := c.readMemory()
	if err != nil {
		return SystemSnapshot{}, err
	}
	disk, err := diskSnapshot(diskPath)
	if err != nil {
		return SystemSnapshot{}, err
	}
	return SystemSnapshot{
		CPU:         CPUSnapshot{UsagePercent: cpuUsagePercent(prev, next)},
		Memory:      mem,
		Disk:        disk,
		CollectedAt: time.Now(),
	}, nil
}

func (c Collector) ProcessSnapshot(slug string) ProcessSnapshot {
	status, pid := "UNKNOWN", 0
	if c.Supervisor != nil {
		status, pid = c.Supervisor.StatusWithPID(slug)
	}
	snapshot := ProcessSnapshot{
		Status:     status,
		StatusText: statusTextCN(status),
		PID:        pid,
	}
	if runtime.GOOS != "linux" {
		snapshot.Message = "进程资源采集仅支持 Linux"
		return snapshot
	}
	if pid <= 0 || status != "RUNNING" {
		snapshot.Message = "进程未运行"
		return snapshot
	}
	prevCPU, prevProc, err := c.readCPUAndProcess(pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	delay := c.SampleDelay
	if delay <= 0 {
		delay = 200 * time.Millisecond
	}
	time.Sleep(delay)
	nextCPU, nextProc, err := c.readCPUAndProcess(pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	mem, err := c.readMemory()
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	rss, err := c.readProcessRSS(pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	ports, connections, networkErr := c.readProcessNetwork(pid)
	snapshot.Available = true
	snapshot.CPUPercent = processCPUPercent(prevProc, nextProc, prevCPU, nextCPU, runtime.NumCPU())
	snapshot.MemoryBytes = rss
	if mem.TotalBytes > 0 {
		snapshot.MemoryPercent = round1(float64(rss) * 100 / float64(mem.TotalBytes))
	}
	snapshot.ListenPorts = ports
	snapshot.ConnectionCount = connections
	if networkErr != nil {
		snapshot.Message = networkErr.Error()
	}
	return snapshot
}

func (c Collector) readCPUAndProcess(pid int) (cpuTimes, processTimes, error) {
	cpu, err := c.readCPU()
	if err != nil {
		return cpuTimes{}, processTimes{}, err
	}
	proc, err := c.readProcessTimes(pid)
	if err != nil {
		return cpuTimes{}, processTimes{}, err
	}
	return cpu, proc, nil
}

func (c Collector) readCPU() (cpuTimes, error) {
	content, err := c.readFile(c.procPath("stat"))
	if err != nil {
		return cpuTimes{}, err
	}
	for _, line := range splitLines(content) {
		if len(line) >= 4 && line[:4] == "cpu " {
			return parseCPUStatLine(line)
		}
	}
	return cpuTimes{}, fmt.Errorf("未找到 CPU 状态")
}

func (c Collector) readMemory() (MemorySnapshot, error) {
	content, err := c.readFile(c.procPath("meminfo"))
	if err != nil {
		return MemorySnapshot{}, err
	}
	return parseMeminfo(string(content))
}

func (c Collector) readProcessTimes(pid int) (processTimes, error) {
	content, err := c.readFile(c.procPath(strconv.Itoa(pid), "stat"))
	if err != nil {
		return processTimes{}, err
	}
	return parseProcessStatLine(string(content))
}

func (c Collector) readProcessRSS(pid int) (uint64, error) {
	content, err := c.readFile(c.procPath(strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	return parseRSSBytesFromStatus(string(content))
}

func (c Collector) readProcessNetwork(pid int) ([]int, int, error) {
	inodes, err := c.readProcessSocketInodes(pid)
	if err != nil {
		return nil, 0, err
	}
	allRows := []procNetRow{}
	for _, item := range []struct {
		path  string
		proto string
	}{
		{"net/tcp", "tcp"},
		{"net/tcp6", "tcp6"},
		{"net/udp", "udp"},
		{"net/udp6", "udp6"},
	} {
		content, readErr := c.readFile(c.procPath(item.path))
		if readErr != nil {
			continue
		}
		rows, parseErr := parseProcNet(string(content), item.proto)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		allRows = append(allRows, rows...)
	}
	return summarizeSockets(allRows, inodes)
}

func (c Collector) readProcessSocketInodes(pid int) (map[string]struct{}, error) {
	fdPath := c.procPath(strconv.Itoa(pid), "fd")
	entries, err := c.readDir(fdPath)
	if err != nil {
		return nil, err
	}
	inodes := map[string]struct{}{}
	for _, entry := range entries {
		target, err := c.readLink(filepath.Join(fdPath, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := parseSocketInode(target); ok {
			inodes[inode] = struct{}{}
		}
	}
	return inodes, nil
}

func (c Collector) procPath(parts ...string) string {
	root := c.ProcRoot
	if root == "" {
		root = "/proc"
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...)
}

func (c Collector) readFile(path string) ([]byte, error) {
	if c.ReadFile != nil {
		return c.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (c Collector) readLink(path string) (string, error) {
	if c.ReadLink != nil {
		return c.ReadLink(path)
	}
	return os.Readlink(path)
}

func (c Collector) readDir(path string) ([]os.DirEntry, error) {
	if c.ReadDir != nil {
		return c.ReadDir(path)
	}
	return os.ReadDir(path)
}

func splitLines(content []byte) []string {
	return strings.Split(string(content), "\n")
}

func statusTextCN(status string) string {
	switch status {
	case "RUNNING":
		return "运行中"
	case "STOPPED":
		return "已停止"
	case "EXITED":
		return "已退出"
	case "STARTING":
		return "启动中"
	case "STOPPING":
		return "停止中"
	case "BACKOFF":
		return "启动失败(重试中)"
	case "FATAL":
		return "启动失败"
	default:
		return "未知"
	}
}
```

- [ ] **Step 4: Add disk helpers**

Create `internal/monitor/disk_unix.go`:

```go
//go:build !windows

package monitor

import "syscall"

func diskSnapshot(path string) (DiskSnapshot, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskSnapshot{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := uint64(0)
	if total > free {
		used = total - free
	}
	usage := float64(0)
	if total > 0 {
		usage = round1(float64(used) * 100 / float64(total))
	}
	return DiskSnapshot{
		Path:         path,
		TotalBytes:   total,
		UsedBytes:    used,
		FreeBytes:    free,
		UsagePercent: usage,
	}, nil
}
```

Create `internal/monitor/disk_windows.go`:

```go
//go:build windows

package monitor

import "fmt"

func diskSnapshot(path string) (DiskSnapshot, error) {
	return DiskSnapshot{Path: path}, fmt.Errorf("磁盘状态采集仅支持 Linux")
}
```

- [ ] **Step 5: Run collector tests**

Run:

```bash
go test ./internal/monitor
```

Expected: PASS. On Windows, Linux-specific system snapshot test is skipped.

- [ ] **Step 6: Commit collector implementation**

Run:

```bash
git add internal/monitor/collector.go internal/monitor/disk_unix.go internal/monitor/disk_windows.go internal/monitor/collector_test.go
git commit -m "feat: collect system and process metrics"
```

---

### Task 5: Backend API Handlers

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

- [ ] **Step 1: Write failing handler tests**

Append to `internal/server/server_test.go`:

```go
type fakeMonitorCollector struct {
	system    monitor.SystemSnapshot
	systemErr error
	processes map[string]monitor.ProcessSnapshot
}

func (f fakeMonitorCollector) SystemSnapshot(path string) (monitor.SystemSnapshot, error) {
	return f.system, f.systemErr
}

func (f fakeMonitorCollector) ProcessSnapshots(projects []db.Project) map[string]monitor.ProcessSnapshot {
	return f.processes
}

func TestHandleAPISystemStatus(t *testing.T) {
	s := &Server{
		cfg: config.Config{ProjectsDir: "/srv/projects"},
		monitor: fakeMonitorCollector{
			system: monitor.SystemSnapshot{
				CPU: monitor.CPUSnapshot{UsagePercent: 12.5},
				Memory: monitor.MemorySnapshot{TotalBytes: 100, UsedBytes: 40, AvailableBytes: 60, UsagePercent: 40},
				Disk: monitor.DiskSnapshot{Path: "/srv/projects", TotalBytes: 200, UsedBytes: 50, FreeBytes: 150, UsagePercent: 25},
				CollectedAt: time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/system/status", nil)
	rr := httptest.NewRecorder()

	s.handleAPISystemStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"usage_percent":12.5`) {
		t.Fatalf("body = %s, want cpu usage", rr.Body.String())
	}
}

func TestHandleAPIProjectProcessStatuses(t *testing.T) {
	store := newTestStore(t)
	projectID, err := store.CreateProject(db.Project{Name: "api", Slug: "p1", Path: t.TempDir(), RunUser: "root"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	s := &Server{
		store: store,
		monitor: fakeMonitorCollector{
			processes: map[string]monitor.ProcessSnapshot{
				strconv.FormatInt(projectID, 10): {
					Status: "RUNNING",
					StatusText: "运行中",
					PID: 1234,
					CPUPercent: 3.2,
					MemoryBytes: 2048,
					ListenPorts: []int{8080},
					ConnectionCount: 2,
					Available: true,
				},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/projects/process-statuses", nil)
	rr := httptest.NewRecorder()

	s.handleAPIProjectProcessStatuses(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"pid":1234`) {
		t.Fatalf("body = %s, want pid", rr.Body.String())
	}
}
```

Also add these imports to `internal/server/server_test.go`:

```go
"strconv"

"supervisorpanel/internal/config"
"supervisorpanel/internal/db"
"supervisorpanel/internal/monitor"
```

Add this test helper to `internal/server/server_test.go`:

```go
func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}
```

- [ ] **Step 2: Run server tests to verify they fail**

Run:

```bash
go test ./internal/server
```

Expected: FAIL because `Server.monitor`, `handleAPISystemStatus`, and `handleAPIProjectProcessStatuses` do not exist.

- [ ] **Step 3: Wire monitor collector in server**

Modify imports in `internal/server/server.go` to include:

```go
"supervisorpanel/internal/monitor"
```

Add near `type Server`:

```go
type monitorCollector interface {
	SystemSnapshot(path string) (monitor.SystemSnapshot, error)
	ProcessSnapshots(projects []db.Project) map[string]monitor.ProcessSnapshot
}
```

Add field to `Server`:

```go
monitor monitorCollector
```

Modify `New` return:

```go
return &Server{
	cfg: cfg,
	store: store,
	sup: sup,
	systemctl: systemctl.Client{Bin: cfg.SystemctlBin},
	monitor: monitor.New(sup),
}, nil
```

- [ ] **Step 4: Add API routes and handlers**

Modify `handleAPIRoute` in `internal/server/server.go`:

```go
if path == "system/status" {
	s.handleAPISystemStatus(w, r)
	return
}
if path == "projects/process-statuses" {
	s.handleAPIProjectProcessStatuses(w, r)
	return
}
```

Add handlers:

```go
func (s *Server) handleAPISystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	collector := s.monitor
	if collector == nil {
		collector = monitor.New(s.sup)
	}
	snapshot, err := collector.SystemSnapshot(s.cfg.ProjectsDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "system": snapshot})
}

func (s *Server) handleAPIProjectProcessStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	projects, err := s.store.ListProjects()
	if err != nil {
		s.serverError(w, err)
		return
	}
	collector := s.monitor
	if collector == nil {
		collector = monitor.New(s.sup)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"processes": collector.ProcessSnapshots(projects),
	})
}
```

- [ ] **Step 5: Run backend tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 6: Commit backend API**

Run:

```bash
git add internal/server/server.go internal/server/server_test.go internal/monitor/collector.go
git commit -m "feat: expose status monitoring APIs"
```

---

### Task 6: Frontend Types And API Clients

**Files:**
- Modify: `web/src/types/api.ts`
- Modify: `web/src/api/system.ts`
- Modify: `web/src/api/projects.ts`

- [ ] **Step 1: Add TypeScript types**

Modify `web/src/types/api.ts`:

```ts
export interface CpuSnapshot {
  usage_percent: number
}

export interface MemorySnapshot {
  total_bytes: number
  used_bytes: number
  available_bytes: number
  usage_percent: number
}

export interface DiskSnapshot {
  path: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  usage_percent: number
}

export interface SystemSnapshot {
  cpu: CpuSnapshot
  memory: MemorySnapshot
  disk: DiskSnapshot
  collected_at: string
}

export interface SystemStatusResponse extends ApiEnvelope {
  system: SystemSnapshot
}

export interface ProcessSnapshot {
  status: string
  status_text: string
  pid: number
  cpu_percent: number
  memory_bytes: number
  memory_percent: number
  listen_ports: number[]
  connection_count: number
  available: boolean
  message: string
}

export interface ProcessStatusesResponse extends ApiEnvelope {
  processes: Record<string, ProcessSnapshot>
}
```

- [ ] **Step 2: Add API client functions**

Modify `web/src/api/system.ts`:

```ts
import { request } from './http'
import type { ActionResponse, SystemStatusResponse } from '@/types/api'

export function getSystemStatus() {
  return request<SystemStatusResponse>('/api/system/status')
}
```

Keep existing `restartSupervisor()` unchanged.

Modify `web/src/api/projects.ts` import list to include `ProcessStatusesResponse`, then add:

```ts
export function getProjectProcessStatuses() {
  return request<ProcessStatusesResponse>('/api/projects/process-statuses')
}
```

- [ ] **Step 3: Run frontend typecheck**

Run:

```bash
cd web
npm run typecheck
```

Expected: PASS.

- [ ] **Step 4: Commit frontend API types**

Run:

```bash
git add web/src/types/api.ts web/src/api/system.ts web/src/api/projects.ts
git commit -m "feat: add frontend status API types"
```

---

### Task 7: System Status Page

**Files:**
- Create: `web/src/views/SystemStatusView.vue`
- Modify: `web/src/router/index.ts`
- Modify: `web/src/layouts/AdminLayout.vue`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Create system status view**

Create `web/src/views/SystemStatusView.vue`:

```vue
<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统状态</h1>
        <p class="page-subtitle">采集时间：{{ collectedAtText }}</p>
      </div>
      <div class="toolbar">
        <el-button :loading="loading" @click="loadStatus">刷新</el-button>
      </div>
    </div>

    <el-alert v-if="errorText" :title="errorText" type="error" show-icon :closable="false" />

    <div class="metric-grid">
      <el-card v-loading="loading" shadow="never">
        <template #header>CPU</template>
        <el-progress type="dashboard" :percentage="percent(system?.cpu.usage_percent)" />
        <p class="metric-value">{{ formatPercent(system?.cpu.usage_percent) }}</p>
      </el-card>

      <el-card v-loading="loading" shadow="never">
        <template #header>内存</template>
        <el-progress type="dashboard" :percentage="percent(system?.memory.usage_percent)" />
        <p class="metric-value">{{ formatPercent(system?.memory.usage_percent) }}</p>
        <p class="muted">{{ formatBytes(system?.memory.used_bytes) }} / {{ formatBytes(system?.memory.total_bytes) }}</p>
      </el-card>

      <el-card v-loading="loading" shadow="never">
        <template #header>硬盘</template>
        <el-progress type="dashboard" :percentage="percent(system?.disk.usage_percent)" />
        <p class="metric-value">{{ formatPercent(system?.disk.usage_percent) }}</p>
        <p class="muted">{{ formatBytes(system?.disk.used_bytes) }} / {{ formatBytes(system?.disk.total_bytes) }}</p>
        <p class="muted mono">{{ system?.disk.path || '-' }}</p>
      </el-card>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import { getSystemStatus } from '@/api/system'
import { errorMessage } from '@/api/http'
import type { SystemSnapshot } from '@/types/api'

const loading = ref(false)
const system = ref<SystemSnapshot>()
const errorText = ref('')
let timer: number | undefined

const collectedAtText = computed(() => {
  if (!system.value?.collected_at) return '-'
  return new Date(system.value.collected_at).toLocaleString()
})

onMounted(() => {
  void loadStatus()
  timer = window.setInterval(() => {
    if (!document.hidden) void loadStatus(false)
  }, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})

async function loadStatus(showLoading = true) {
  if (showLoading) loading.value = true
  try {
    const result = await getSystemStatus()
    system.value = result.system
    errorText.value = ''
  } catch (error) {
    errorText.value = errorMessage(error, '加载系统状态失败')
    ElMessage.error(errorText.value)
  } finally {
    loading.value = false
  }
}

function percent(value?: number) {
  return Math.max(0, Math.min(100, Math.round(value || 0)))
}

function formatPercent(value?: number) {
  return `${(value || 0).toFixed(1)}%`
}

function formatBytes(value?: number) {
  const bytes = value || 0
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}
</script>
```

- [ ] **Step 2: Add route and navigation**

Modify `web/src/router/index.ts`:

```ts
import SystemStatusView from '@/views/SystemStatusView.vue'
```

Add route before account route:

```ts
{ path: '/system/status', name: 'system-status', component: SystemStatusView },
```

Modify `web/src/layouts/AdminLayout.vue`:

```vue
<el-menu-item index="/system/status">系统状态</el-menu-item>
```

Modify `activePath`:

```ts
const activePath = computed(() => {
  if (route.path.startsWith('/account/password')) return '/account/password'
  if (route.path.startsWith('/system/status')) return '/system/status'
  return '/projects'
})
```

- [ ] **Step 3: Add shared metric styles**

Append to `web/src/styles.css`:

```css
.metric-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.metric-value {
  margin: 12px 0 4px;
  font-size: 22px;
  font-weight: 650;
}

.resource-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

@media (max-width: 980px) {
  .metric-grid {
    grid-template-columns: 1fr;
  }
}
```

- [ ] **Step 4: Run frontend typecheck**

Run:

```bash
cd web
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit system status page**

Run:

```bash
git add web/src/views/SystemStatusView.vue web/src/router/index.ts web/src/layouts/AdminLayout.vue web/src/styles.css
git commit -m "feat: add system status page"
```

---

### Task 8: Project Process Status UI

**Files:**
- Modify: `web/src/views/ProjectsView.vue`
- Modify: `web/src/views/ProjectDetailView.vue`

- [ ] **Step 1: Extend project list resource state**

Modify `web/src/views/ProjectsView.vue` imports:

```ts
import { cloneProject, createProject, deleteProject, getProjectProcessStatuses, getProjects, projectAction } from '@/api/projects'
import type { ProcessSnapshot, Project } from '@/types/api'
```

Add state:

```ts
const processStatuses = ref<Record<string, ProcessSnapshot>>({})
```

Add table columns after status:

```vue
<el-table-column label="PID" width="90">
  <template #default="{ row }">{{ processInfo(row.id)?.pid || '-' }}</template>
</el-table-column>
<el-table-column label="CPU" width="90">
  <template #default="{ row }">{{ formatPercent(processInfo(row.id)?.cpu_percent) }}</template>
</el-table-column>
<el-table-column label="内存" width="110">
  <template #default="{ row }">{{ formatBytes(processInfo(row.id)?.memory_bytes) }}</template>
</el-table-column>
<el-table-column label="端口" min-width="140">
  <template #default="{ row }">{{ formatPorts(processInfo(row.id)?.listen_ports) }}</template>
</el-table-column>
<el-table-column label="连接数" width="90">
  <template #default="{ row }">{{ processInfo(row.id)?.connection_count ?? '-' }}</template>
</el-table-column>
```

Replace `refreshStatuses()` with:

```ts
async function refreshStatuses() {
  try {
    const result = await getProjectProcessStatuses()
    processStatuses.value = result.processes
    for (const project of projects.value) {
      const process = result.processes[String(project.id)]
      const status = process?.status || 'UNKNOWN'
      project.status = status
      project.status_text = process?.status_text || statusText(status)
    }
  } catch {
    ElMessage.warning('状态刷新失败，稍后重试')
  }
}
```

In `loadProjects()`, after setting projects:

```ts
await refreshStatuses()
```

Add helpers:

```ts
function processInfo(projectID: number) {
  return processStatuses.value[String(projectID)]
}

function formatPercent(value?: number) {
  if (value === undefined || value === null) return '-'
  return `${value.toFixed(1)}%`
}

function formatBytes(value?: number) {
  if (!value) return '-'
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${value} B`
}

function formatPorts(ports?: number[]) {
  if (!ports?.length) return '-'
  return ports.join(', ')
}
```

- [ ] **Step 2: Extend project detail resource summary**

Modify `web/src/views/ProjectDetailView.vue` imports:

```ts
import { getProjectProcessStatuses } from '@/api/projects'
import type { DirEntry, ProcessSnapshot, ProjectDetailResponse } from '@/types/api'
```

Add state:

```ts
const processStatus = ref<ProcessSnapshot>()
```

Add below page header:

```vue
<el-card shadow="never">
  <div class="resource-summary">
    <el-tag type="info">PID：{{ processStatus?.pid || '-' }}</el-tag>
    <el-tag>CPU：{{ formatPercent(processStatus?.cpu_percent) }}</el-tag>
    <el-tag>内存：{{ formatBytes(processStatus?.memory_bytes) }}</el-tag>
    <el-tag>端口：{{ formatPorts(processStatus?.listen_ports) }}</el-tag>
    <el-tag>连接数：{{ processStatus?.connection_count ?? '-' }}</el-tag>
    <span v-if="processStatus?.message" class="muted">{{ processStatus.message }}</span>
  </div>
</el-card>
```

In `onMounted`, load process status after detail:

```ts
void loadProcessStatus()
```

Add function:

```ts
async function loadProcessStatus() {
  try {
    const result = await getProjectProcessStatuses()
    processStatus.value = result.processes[String(projectID)]
  } catch {
    processStatus.value = undefined
  }
}
```

At the end of `loadDetail()` success path:

```ts
void loadProcessStatus()
```

After successful `runAction`, keep existing `await loadDetail()`; it will refresh the process summary.

Add the same `formatPercent`, `formatBytes`, and `formatPorts` helpers used in `ProjectsView.vue`.

- [ ] **Step 3: Run frontend typecheck**

Run:

```bash
cd web
npm run typecheck
```

Expected: PASS.

- [ ] **Step 4: Commit project process UI**

Run:

```bash
git add web/src/views/ProjectsView.vue web/src/views/ProjectDetailView.vue
git commit -m "feat: show supervisor process resources"
```

---

### Task 9: Final Verification And Build

**Files:**
- Read: all modified files

- [ ] **Step 1: Run Go tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 2: Run frontend typecheck**

Run:

```bash
cd web
npm run typecheck
```

Expected: PASS.

- [ ] **Step 3: Run frontend build**

Run:

```bash
cd web
npm run build
```

Expected: PASS and updates `internal/server/static` build output.

- [ ] **Step 4: Run full git diff review**

Run:

```bash
git diff --stat HEAD
git diff HEAD -- internal/monitor internal/supervisor internal/server web/src
```

Expected: diffs only contain monitoring/API/UI changes described in this plan.

- [ ] **Step 5: Commit built frontend assets if they changed**

Run:

```bash
git status --short
git add internal/server/static web/dist
git commit -m "build: update frontend assets for status pages"
```

Expected: commit succeeds when build artifacts changed. When no build artifacts changed, `git status --short` shows no relevant static asset changes and this commit is skipped.

---

## Self-Review

Spec coverage:

- System CPU, memory, and disk status is covered by Tasks 1, 2, 4, 5, 6, and 7.
- Supervisor-managed process CPU, memory, listening ports, and connection count is covered by Tasks 1 through 6 and Task 8.
- Network scope is listening ports and connection count, matching the confirmed user choice.
- Authenticated APIs are covered by adding routes under existing `/api/` handling and using existing `requireAuthAPI`.
- Frontend navigation, system status page, project list, and project detail views are covered by Tasks 7 and 8.
- Verification commands are covered by Task 9.

Completeness scan:

- The plan does not leave placeholder work or vague edge-case instructions.
- Each implementation task includes concrete file paths, commands, expected results, and code snippets.

Type consistency:

- Go API payload types use JSON fields matching TypeScript interfaces.
- `ProcessSnapshot` field names match the planned backend JSON tags and frontend property reads.
- `SystemSnapshot` field names match `SystemStatusResponse.system`.
