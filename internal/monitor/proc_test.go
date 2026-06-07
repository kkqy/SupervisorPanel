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
