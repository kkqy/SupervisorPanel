package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"supervisorpanel/internal/systemctl"
)

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
