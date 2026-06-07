package monitor

import "time"

// CPUSnapshot 是系统 CPU 使用率快照。
type CPUSnapshot struct {
	UsagePercent float64 `json:"usage_percent"`
}

// MemorySnapshot 是系统内存容量与使用率快照，字节为单位。
type MemorySnapshot struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

// DiskSnapshot 是磁盘容量与使用率快照，字节为单位。
type DiskSnapshot struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

// SystemSnapshot 汇总系统层面的监控数据。
type SystemSnapshot struct {
	CPU         CPUSnapshot    `json:"cpu"`
	Memory      MemorySnapshot `json:"memory"`
	Disk        DiskSnapshot   `json:"disk"`
	CollectedAt time.Time      `json:"collected_at"`
}

// ProcessSnapshot 是单个进程的监控数据快照。
type ProcessSnapshot struct {
	Status          string  `json:"status"`
	StatusText      string  `json:"status_text"`
	PID             int     `json:"pid"`
	CPUPercent      float64 `json:"cpu_percent"`
	MemoryBytes     uint64  `json:"memory_bytes"`
	MemoryPercent   float64 `json:"memory_percent"`
	ListenPorts     []int   `json:"listen_ports"`
	ConnectionCount int     `json:"connection_count"`
	Available       bool    `json:"available"`
	Message         string  `json:"message"`
}
