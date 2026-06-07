package monitor

// CPUSnapshot 是系统 CPU 使用率快照。
type CPUSnapshot struct {
	UsagePercent float64 `json:"usagePercent"`
}

// MemorySnapshot 是系统内存容量与使用率快照，字节为单位。
type MemorySnapshot struct {
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	UsagePercent   float64 `json:"usagePercent"`
}

// DiskSnapshot 是磁盘容量与使用率快照，字节为单位。
type DiskSnapshot struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"totalBytes"`
	FreeBytes    uint64  `json:"freeBytes"`
	UsedBytes    uint64  `json:"usedBytes"`
	UsagePercent float64 `json:"usagePercent"`
}

// SystemSnapshot 汇总系统层面的监控数据。
type SystemSnapshot struct {
	CPU    CPUSnapshot    `json:"cpu"`
	Memory MemorySnapshot `json:"memory"`
	Disks  []DiskSnapshot `json:"disks"`
}

// ProcessSnapshot 是单个进程的监控数据快照。
type ProcessSnapshot struct {
	PID             int      `json:"pid"`
	Name            string   `json:"name"`
	CPUPercent      float64  `json:"cpuPercent"`
	RSSBytes        uint64   `json:"rssBytes"`
	ListeningPorts  []uint16 `json:"listeningPorts"`
	ConnectionCount int      `json:"connectionCount"`
}
