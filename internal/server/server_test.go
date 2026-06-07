package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"supervisorpanel/internal/config"
	"supervisorpanel/internal/db"
	"supervisorpanel/internal/monitor"
	"supervisorpanel/internal/systemctl"
)

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

func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close test store: %v", err)
		}
	})
	return store
}

func TestHandleAPISystemStatus(t *testing.T) {
	s := &Server{
		cfg: config.Config{ProjectsDir: "/srv/projects"},
		monitor: fakeMonitorCollector{
			system: monitor.SystemSnapshot{
				CPU: monitor.CPUSnapshot{UsagePercent: 12.5},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/system/status", nil)
	rr := httptest.NewRecorder()

	s.handleAPISystemStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), `"usage_percent":12.5`) {
		t.Fatalf("body = %q, want usage_percent 12.5", rr.Body.String())
	}
}

func TestHandleAPIProjectProcessStatuses(t *testing.T) {
	store := newTestStore(t)
	projectID, err := store.CreateProject(db.Project{Name: "demo", Slug: "demo", Path: "/srv/projects/demo", RunUser: "www-data"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	s := &Server{
		store: store,
		monitor: fakeMonitorCollector{
			processes: map[string]monitor.ProcessSnapshot{
				strconv.FormatInt(projectID, 10): {Status: "RUNNING", PID: 1234, Available: true},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/projects/process-statuses", nil)
	rr := httptest.NewRecorder()

	s.handleAPIProjectProcessStatuses(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), `"pid":1234`) {
		t.Fatalf("body = %q, want pid 1234", rr.Body.String())
	}
}

func TestHandleAPIRestartSupervisorReturnsBeforeCommandCompletes(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := &Server{
		systemctl: systemctl.Client{
			Run: func(ctx context.Context, name string, args ...string) (string, error) {
				close(started)
				<-release
				return "done", nil
			},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/system/supervisor/restart", nil)
	rr := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		s.handleAPIRestartSupervisor(rr, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("handler waited for supervisor restart command to complete")
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if !strings.Contains(rr.Body.String(), "已提交重启 Supervisor 命令") {
		t.Fatalf("body = %q, want submitted restart message", rr.Body.String())
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("handler did not start supervisor restart command")
	}
	close(release)
}

func TestListProjectDirEntriesIncludesFileMetadata(t *testing.T) {
	projectRoot := t.TempDir()
	filePath := filepath.Join(projectRoot, "app.log")
	content := []byte("hello metadata")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mtime := time.Date(2026, 6, 8, 9, 30, 0, 123, time.Local)
	if err := os.Chtimes(filePath, mtime, mtime); err != nil {
		t.Fatalf("set file time: %v", err)
	}

	entries, _, _, err := listProjectDirEntries(projectRoot, "", "")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Size != int64(len(content)) {
		t.Fatalf("Size = %d, want %d", entry.Size, len(content))
	}
	if entry.ModifiedAt.IsZero() {
		t.Fatal("ModifiedAt is zero")
	}
	if entry.ModifiedAt.Sub(mtime).Abs() > time.Millisecond {
		t.Fatalf("ModifiedAt = %s, want %s", entry.ModifiedAt, mtime)
	}
	if entry.Owner == "" {
		t.Fatal("Owner is empty")
	}
}
