package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"supervisorpanel/internal/db"
)

type stubSupervisor struct {
	status string
	pid    int
}

func (s stubSupervisor) StatusWithPID(string) (string, int) {
	return s.status, s.pid
}

type mapSupervisor map[string]struct {
	status string
	pid    int
}

func (s mapSupervisor) StatusWithPID(slug string) (string, int) {
	status := s[slug]
	return status.status, status.pid
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

func TestProcessSnapshotStartingProcessDoesNotReadProc(t *testing.T) {
	collector := Collector{
		Supervisor: stubSupervisor{status: "STARTING", pid: 1234},
		ReadFile: func(string) ([]byte, error) {
			t.Fatal("ReadFile should not be called for a STARTING process")
			return nil, nil
		},
	}

	got := collector.ProcessSnapshot("app")

	if got.Available {
		t.Fatal("Available = true, want false")
	}
	if got.Status != "STARTING" {
		t.Fatalf("Status = %q, want STARTING", got.Status)
	}
	if got.PID != 1234 {
		t.Fatalf("PID = %d, want 1234", got.PID)
	}
	if got.Message != "进程未运行" {
		t.Fatalf("Message = %q, want 进程未运行", got.Message)
	}
}

func TestProcessSnapshotKeepsMetricsAvailableWhenNetworkReadFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc snapshot test is skipped on non-Linux")
	}

	networkErr := errors.New("network read failed")
	procRoot := t.TempDir()
	statPath := filepath.Join(procRoot, "stat")
	processStatPath := filepath.Join(procRoot, "1234", "stat")
	processStatusPath := filepath.Join(procRoot, "1234", "status")
	meminfoPath := filepath.Join(procRoot, "meminfo")
	statReads := 0
	processStatReads := 0
	collector := Collector{
		ProcRoot:    procRoot,
		SampleDelay: time.Nanosecond,
		Supervisor:  stubSupervisor{status: "RUNNING", pid: 1234},
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case statPath:
				statReads++
				if statReads == 1 {
					return []byte("cpu 100 0 0 100\n"), nil
				}
				return []byte("cpu 150 0 0 150\n"), nil
			case processStatPath:
				processStatReads++
				if processStatReads == 1 {
					return []byte("1234 (node) S 1 2 3 0 -1 4194304 10 0 0 0 10 10 0 0 20 0 7 0 123456 1000000 4096"), nil
				}
				return []byte("1234 (node) S 1 2 3 0 -1 4194304 10 0 0 0 20 20 0 0 20 0 7 0 123456 1000000 4096"), nil
			case processStatusPath:
				return []byte("Name:\tnode\nVmRSS:\t  100 kB\n"), nil
			case meminfoPath:
				return []byte("MemTotal: 1000 kB\nMemAvailable: 500 kB\n"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
		ReadDir: func(string) ([]os.DirEntry, error) {
			return nil, networkErr
		},
	}

	got := collector.ProcessSnapshot("app")

	if !got.Available {
		t.Fatal("Available = false, want true")
	}
	if got.CPUPercent == 0 {
		t.Fatal("CPUPercent = 0, want sampled CPU value")
	}
	if got.MemoryBytes != 102400 {
		t.Fatalf("MemoryBytes = %d, want 102400", got.MemoryBytes)
	}
	if got.MemoryPercent != 10 {
		t.Fatalf("MemoryPercent = %.1f, want 10.0", got.MemoryPercent)
	}
	if got.Message != networkErr.Error() {
		t.Fatalf("Message = %q, want %q", got.Message, networkErr.Error())
	}
}

func TestNewLeavesSampleDelayZeroForDefaultDelay(t *testing.T) {
	got := New(stubSupervisor{status: "STOPPED"})

	if got.SampleDelay != 0 {
		t.Fatalf("SampleDelay = %s, want zero value", got.SampleDelay)
	}
}

func TestProcessSnapshotsBatchesRunningProcessSamplingWithOneSleep(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc snapshot test is skipped on non-Linux")
	}

	procRoot := t.TempDir()
	statPath := filepath.Join(procRoot, "stat")
	meminfoPath := filepath.Join(procRoot, "meminfo")
	processStatPaths := map[string]int{
		filepath.Join(procRoot, "1234", "stat"): 0,
		filepath.Join(procRoot, "5678", "stat"): 0,
	}
	statusPaths := map[string]string{
		filepath.Join(procRoot, "1234", "status"): "Name:\tone\nVmRSS:\t  100 kB\n",
		filepath.Join(procRoot, "5678", "status"): "Name:\ttwo\nVmRSS:\t  200 kB\n",
	}
	statReads := 0
	sleepCalls := 0
	collector := Collector{
		ProcRoot:    procRoot,
		SampleDelay: time.Nanosecond,
		Supervisor: mapSupervisor{
			"one": {status: "RUNNING", pid: 1234},
			"two": {status: "RUNNING", pid: 5678},
		},
		Sleep: func(time.Duration) {
			sleepCalls++
		},
		ReadFile: func(path string) ([]byte, error) {
			switch {
			case path == statPath:
				statReads++
				if statReads == 1 {
					return []byte("cpu 100 0 0 100\n"), nil
				}
				return []byte("cpu 150 0 0 150\n"), nil
			case path == meminfoPath:
				return []byte("MemTotal: 1000 kB\nMemAvailable: 500 kB\n"), nil
			case statusPaths[path] != "":
				return []byte(statusPaths[path]), nil
			default:
				if reads, ok := processStatPaths[path]; ok {
					processStatPaths[path] = reads + 1
					pid := "1234"
					if strings.Contains(path, "5678") {
						pid = "5678"
					}
					if reads == 0 {
						return []byte(pid + " (node) S 1 2 3 0 -1 4194304 10 0 0 0 10 10 0 0 20 0 7 0 123456 1000000 4096"), nil
					}
					return []byte(pid + " (node) S 1 2 3 0 -1 4194304 10 0 0 0 20 20 0 0 20 0 7 0 123456 1000000 4096"), nil
				}
				return nil, os.ErrNotExist
			}
		},
		ReadDir: func(string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	}

	got := collector.ProcessSnapshots([]db.Project{
		{ID: 1, Slug: "one"},
		{ID: 2, Slug: "two"},
	})

	if sleepCalls != 1 {
		t.Fatalf("sleepCalls = %d, want 1", sleepCalls)
	}
	if !got["1"].Available || !got["2"].Available {
		t.Fatalf("snapshots availability = %v/%v, want both true", got["1"].Available, got["2"].Available)
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
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc snapshot test is skipped on non-Linux")
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
