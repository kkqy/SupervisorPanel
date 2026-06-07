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

const defaultProcRoot = "/proc"

// SupervisorStatus 提供项目进程状态和 PID。
type SupervisorStatus interface {
	StatusWithPID(slug string) (string, int)
}

// Collector 汇总系统和进程监控数据。
type Collector struct {
	ProcRoot    string
	SampleDelay time.Duration
	ReadFile    func(string) ([]byte, error)
	ReadLink    func(string) (string, error)
	ReadDir     func(string) ([]os.DirEntry, error)
	Supervisor  SupervisorStatus
}

func New(supervisor SupervisorStatus) Collector {
	return Collector{
		ProcRoot:    defaultProcRoot,
		SampleDelay: 100 * time.Millisecond,
		Supervisor:  supervisor,
	}
}

func (c Collector) SystemSnapshot(diskPath string) (SystemSnapshot, error) {
	if runtime.GOOS != "linux" {
		return SystemSnapshot{}, fmt.Errorf("系统监控仅支持 Linux")
	}

	prevCPU, _, err := readCPU(c)
	if err != nil {
		return SystemSnapshot{}, err
	}
	if c.SampleDelay > 0 {
		time.Sleep(c.SampleDelay)
	}
	nextCPU, _, err := readCPU(c)
	if err != nil {
		return SystemSnapshot{}, err
	}

	memory, err := readMemory(c)
	if err != nil {
		return SystemSnapshot{}, err
	}
	disk, err := diskSnapshot(diskPath)
	if err != nil {
		return SystemSnapshot{}, err
	}

	return SystemSnapshot{
		CPU:         CPUSnapshot{UsagePercent: cpuUsagePercent(prevCPU, nextCPU)},
		Memory:      memory,
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
	if status == "STOPPED" || pid <= 0 {
		snapshot.Message = "进程未运行"
		return snapshot
	}
	if runtime.GOOS != "linux" {
		snapshot.Message = "进程监控仅支持 Linux"
		return snapshot
	}

	prevCPU, cpuCount, err := readCPU(c)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	prevProc, err := readProcessTimes(c, pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	if c.SampleDelay > 0 {
		time.Sleep(c.SampleDelay)
	}
	nextCPU, _, err := readCPU(c)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	nextProc, err := readProcessTimes(c, pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}

	rss, err := readProcessRSS(c, pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	memory, err := readMemory(c)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}
	ports, connections, err := readProcessNetwork(c, pid)
	if err != nil {
		snapshot.Message = err.Error()
		return snapshot
	}

	snapshot.CPUPercent = processCPUPercent(prevProc, nextProc, prevCPU, nextCPU, cpuCount)
	snapshot.MemoryBytes = rss
	if memory.TotalBytes > 0 {
		snapshot.MemoryPercent = round1(float64(rss) * 100 / float64(memory.TotalBytes))
	}
	snapshot.ListenPorts = ports
	snapshot.ConnectionCount = connections
	snapshot.Available = true
	return snapshot
}

func (c Collector) ProcessSnapshots(projects []db.Project) map[string]ProcessSnapshot {
	snapshots := make(map[string]ProcessSnapshot, len(projects))
	for _, project := range projects {
		snapshots[strconv.FormatInt(project.ID, 10)] = c.ProcessSnapshot(project.Slug)
	}
	return snapshots
}

func readCPU(c Collector) (cpuTimes, int, error) {
	content, err := readFile(c, procPath(c, "stat"))
	if err != nil {
		return cpuTimes{}, 0, err
	}

	var total cpuTimes
	cpuCount := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			total, err = parseCPUStatLine(line)
			if err != nil {
				return cpuTimes{}, 0, err
			}
			continue
		}
		if strings.HasPrefix(line, "cpu") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "cpu") {
				if _, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu")); err == nil {
					cpuCount++
				}
			}
		}
	}
	if total.total == 0 {
		return cpuTimes{}, 0, fmt.Errorf("缺少 CPU 统计")
	}
	if cpuCount == 0 {
		cpuCount = runtime.NumCPU()
	}
	return total, cpuCount, nil
}

func readMemory(c Collector) (MemorySnapshot, error) {
	content, err := readFile(c, procPath(c, "meminfo"))
	if err != nil {
		return MemorySnapshot{}, err
	}
	return parseMeminfo(string(content))
}

func readProcessTimes(c Collector, pid int) (processTimes, error) {
	content, err := readFile(c, procPath(c, strconv.Itoa(pid), "stat"))
	if err != nil {
		return processTimes{}, err
	}
	return parseProcessStatLine(string(content))
}

func readProcessRSS(c Collector, pid int) (uint64, error) {
	content, err := readFile(c, procPath(c, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	return parseRSSBytesFromStatus(string(content))
}

func readProcessNetwork(c Collector, pid int) ([]int, int, error) {
	inodes, err := readProcessSocketInodes(c, pid)
	if err != nil {
		return nil, 0, err
	}

	var rows []procNetRow
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		content, err := readFile(c, procPath(c, "net", proto))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, 0, err
		}
		parsed, err := parseProcNet(string(content), proto)
		if err != nil {
			return nil, 0, err
		}
		rows = append(rows, parsed...)
	}

	ports, connections := summarizeSockets(rows, inodes)
	return ports, connections, nil
}

func readProcessSocketInodes(c Collector, pid int) (map[string]struct{}, error) {
	fdPath := procPath(c, strconv.Itoa(pid), "fd")
	entries, err := readDir(c, fdPath)
	if err != nil {
		return nil, err
	}

	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := readLink(c, filepath.Join(fdPath, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := parseSocketInode(target); ok {
			inodes[inode] = struct{}{}
		}
	}
	return inodes, nil
}

func procPath(c Collector, parts ...string) string {
	root := c.ProcRoot
	if root == "" {
		root = defaultProcRoot
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...)
}

func readFile(c Collector, path string) ([]byte, error) {
	if c.ReadFile != nil {
		return c.ReadFile(path)
	}
	return os.ReadFile(path)
}

func readLink(c Collector, path string) (string, error) {
	if c.ReadLink != nil {
		return c.ReadLink(path)
	}
	return os.Readlink(path)
}

func readDir(c Collector, path string) ([]os.DirEntry, error) {
	if c.ReadDir != nil {
		return c.ReadDir(path)
	}
	return os.ReadDir(path)
}

func statusTextCN(status string) string {
	switch status {
	case "RUNNING":
		return "运行中"
	case "STOPPED":
		return "已停止"
	case "STARTING":
		return "启动中"
	case "STOPPING":
		return "停止中"
	case "ERROR":
		return "异常"
	default:
		return status
	}
}
