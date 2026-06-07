package monitor

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type stubSupervisor struct {
	status string
	pid    int
}

func (s stubSupervisor) StatusWithPID(string) (string, int) {
	return s.status, s.pid
}

func TestProcessSnapshotStoppedProcessIsUnavailable(t *testing.T) {
	collector := New(stubSupervisor{status: "STOPPED", pid: 0})

	got := collector.ProcessSnapshot("app")

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

func TestSummarizeSocketsCountsMatchingListenAndEstablishedRows(t *testing.T) {
	rows := []procNetRow{
		{proto: "tcp", port: 8080, inode: "listen", listen: true},
		{proto: "tcp", port: 8080, inode: "established", listen: false},
		{proto: "tcp", port: 0, inode: "zero-listen", listen: true},
		{proto: "tcp", port: 9090, inode: "other", listen: true},
	}
	inodes := map[string]struct{}{
		"listen":      {},
		"established": {},
		"zero-listen": {},
	}

	ports, connections := summarizeSockets(rows, inodes)

	if connections != 3 {
		t.Fatalf("connections = %d, want 3", connections)
	}
	if !reflect.DeepEqual(ports, []int{8080}) {
		t.Fatalf("ports = %#v, want []int{8080}", ports)
	}
}

func TestSystemSnapshotReadsLinuxProcSamples(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux proc snapshot test is skipped on Windows")
	}

	procRoot := t.TempDir()
	statPath := filepath.Join(procRoot, "stat")
	meminfoPath := filepath.Join(procRoot, "meminfo")
	statReads := 0
	collector := Collector{
		ProcRoot:    procRoot,
		SampleDelay: 0,
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case statPath:
				statReads++
				if statReads == 1 {
					return []byte("cpu 100 0 0 100\n"), nil
				}
				return []byte("cpu 150 0 0 150\n"), nil
			case meminfoPath:
				return []byte(strings.Join([]string{
					"MemTotal: 1000 kB",
					"MemAvailable: 400 kB",
				}, "\n")), nil
			default:
				return os.ReadFile(path)
			}
		},
	}

	got, err := collector.SystemSnapshot(procRoot)
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
