package systemctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const DefaultBin = "/usr/bin/systemctl"

type Runner func(ctx context.Context, name string, args ...string) (string, error)

type Client struct {
	Bin     string
	Timeout time.Duration
	Run     Runner
}

type Result struct {
	Output string
	Err    error
}

func (c Client) RestartSupervisor(ctx context.Context) (string, error) {
	bin := strings.TrimSpace(c.Bin)
	if bin == "" {
		bin = DefaultBin
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	runner := c.Run
	if runner == nil {
		runner = defaultRun
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := runner(cmdCtx, bin, "restart", "supervisor")
	out = strings.TrimSpace(out)
	if err != nil {
		if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("重启 Supervisor 超时")
		}
		if out != "" {
			return out, fmt.Errorf("重启 Supervisor 失败：%s", out)
		}
		return out, fmt.Errorf("重启 Supervisor 失败：%w", err)
	}
	return out, nil
}

func (c Client) RestartSupervisorAsync(ctx context.Context, delay time.Duration) <-chan Result {
	resultCh := make(chan Result, 1)
	go func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				resultCh <- Result{Err: ctx.Err()}
				return
			case <-timer.C:
			}
		}
		out, err := c.RestartSupervisor(ctx)
		resultCh <- Result{Output: out, Err: err}
	}()
	return resultCh
}

func defaultRun(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
