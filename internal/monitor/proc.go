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
	port   uint16
	inode  string
	listen bool
}

func parseCPUStatLine(line string) (cpuTimes, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("invalid cpu stat line")
	}

	var values []uint64
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("parse cpu field %q: %w", field, err)
		}
		values = append(values, value)
	}

	var total uint64
	for _, value := range values {
		total += value
	}

	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
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
	values := make(map[string]uint64)
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
	if total == 0 {
		return MemorySnapshot{}, fmt.Errorf("MemTotal missing")
	}

	available, ok := values["MemAvailable"]
	if !ok {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if available > total {
		available = total
	}

	used := total - available
	return MemorySnapshot{
		TotalBytes:     total,
		AvailableBytes: available,
		UsedBytes:      used,
		UsagePercent:   round1(float64(used) * 100 / float64(total)),
	}, nil
}

func parseProcessStatLine(line string) (processTimes, error) {
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open <= 0 || close <= open {
		return processTimes{}, fmt.Errorf("invalid process stat line")
	}

	pidText := strings.TrimSpace(line[:open])
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		return processTimes{}, fmt.Errorf("parse pid %q: %w", pidText, err)
	}

	fields := strings.Fields(strings.TrimSpace(line[close+1:]))
	if len(fields) <= 12 {
		return processTimes{}, fmt.Errorf("process stat line missing cpu fields")
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

func processCPUPercent(prev, next processTimes, basis ...uint64) float64 {
	if next.totalTicks <= prev.totalTicks {
		return 0
	}
	delta := next.totalTicks - prev.totalTicks
	if len(basis) == 0 || basis[0] == 0 {
		return round1(float64(delta))
	}
	return round1(float64(delta) * 100 / float64(basis[0]))
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
	return 0, fmt.Errorf("VmRSS missing")
}

func parseSocketInode(target string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]")
	if inode == "" {
		return "", false
	}
	return inode, true
}

func parseProcNet(content, proto string) ([]procNetRow, error) {
	var rows []procNetRow
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return nil, fmt.Errorf("invalid proc net row %q", line)
		}

		port, err := parseHexPort(fields[1])
		if err != nil {
			return nil, err
		}
		state := strings.ToUpper(fields[3])
		rows = append(rows, procNetRow{
			proto:  proto,
			port:   port,
			inode:  fields[9],
			listen: state == "0A" || (strings.HasPrefix(proto, "udp") && state == "07"),
		})
	}
	return rows, nil
}

func parseHexPort(localAddress string) (uint16, error) {
	_, portHex, ok := strings.Cut(localAddress, ":")
	if !ok || portHex == "" {
		return 0, fmt.Errorf("invalid local address %q", localAddress)
	}
	value, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", portHex, err)
	}
	return uint16(value), nil
}

func summarizeSockets(rows []procNetRow, processInodes map[string]struct{}) ([]uint16, int) {
	seenPorts := make(map[uint16]struct{})
	connectionCount := 0
	for _, row := range rows {
		if _, ok := processInodes[row.inode]; !ok {
			continue
		}
		if row.listen {
			seenPorts[row.port] = struct{}{}
			continue
		}
		connectionCount++
	}

	ports := make([]uint16, 0, len(seenPorts))
	for port := range seenPorts {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i] < ports[j]
	})
	return ports, connectionCount
}

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}
