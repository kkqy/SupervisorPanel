package systemctl

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRestartSupervisorRunsSystemctlRestartSupervisor(t *testing.T) {
	var gotName string
	var gotArgs []string
	client := Client{
		Bin:     "/bin/systemctl",
		Timeout: time.Second,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			gotName = name
			gotArgs = args
			return "done", nil
		},
	}

	out, err := client.RestartSupervisor(context.Background())
	if err != nil {
		t.Fatalf("RestartSupervisor returned error: %v", err)
	}
	if out != "done" {
		t.Fatalf("output = %q, want done", out)
	}
	if gotName != "/bin/systemctl" {
		t.Fatalf("name = %q, want /bin/systemctl", gotName)
	}
	if strings.Join(gotArgs, " ") != "restart supervisor" {
		t.Fatalf("args = %v, want restart supervisor", gotArgs)
	}
}

func TestRestartSupervisorUsesDefaultBin(t *testing.T) {
	var gotName string
	client := Client{
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			gotName = name
			return "", nil
		},
	}

	_, err := client.RestartSupervisor(context.Background())
	if err != nil {
		t.Fatalf("RestartSupervisor returned error: %v", err)
	}
	if gotName != "/usr/bin/systemctl" {
		t.Fatalf("name = %q, want /usr/bin/systemctl", gotName)
	}
}

func TestRestartSupervisorReturnsCommandOutputOnFailure(t *testing.T) {
	client := Client{
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			return "permission denied", errors.New("exit status 1")
		},
	}

	out, err := client.RestartSupervisor(context.Background())
	if err == nil {
		t.Fatal("RestartSupervisor returned nil error")
	}
	if out != "permission denied" {
		t.Fatalf("output = %q, want permission denied", out)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %q, want command output", err.Error())
	}
}

func TestRestartSupervisorTimeoutMessage(t *testing.T) {
	client := Client{
		Timeout: time.Nanosecond,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		},
	}

	_, err := client.RestartSupervisor(context.Background())
	if err == nil {
		t.Fatal("RestartSupervisor returned nil error")
	}
	if !strings.Contains(err.Error(), "重启 Supervisor 超时") {
		t.Fatalf("error = %q, want timeout message", err.Error())
	}
}

func TestRestartSupervisorAsyncDoesNotBlockCaller(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := Client{
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			close(started)
			<-release
			return "done", nil
		},
	}

	resultCh := client.RestartSupervisorAsync(context.Background(), 0)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("async restart did not start runner")
	}
	select {
	case result := <-resultCh:
		t.Fatalf("async restart returned before runner completed: %+v", result)
	default:
	}

	close(release)
	select {
	case result := <-resultCh:
		if result.Err != nil {
			t.Fatalf("async restart returned error: %v", result.Err)
		}
		if result.Output != "done" {
			t.Fatalf("output = %q, want done", result.Output)
		}
	case <-time.After(time.Second):
		t.Fatal("async restart did not return after runner completed")
	}
}
