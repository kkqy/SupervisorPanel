package timesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	c := New("/模拟/systemctl")
	c.TimedatectlBin = "/模拟/timedatectl"
	c.ConfigPath = filepath.Join(t.TempDir(), "timesyncd.conf.d", "90-supervisor-panel.conf")
	// 所有命令均替换为模拟实现，测试不会调用真实系统时间管理工具。
	c.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		switch args[0] {
		case "show":
			if args[1] == "systemd-timesyncd.service" {
				return "LoadState=loaded\nActiveState=active\n", nil
			}
			return "Timezone=Asia/Shanghai\nCanNTP=yes\nNTP=yes\nNTPSynchronized=no\n", nil
		case "show-timesync":
			return "ServerName=ntp.example.com\n", nil
		case "--no-ask-password":
			return "", nil
		default:
			t.Fatalf("非预期命令：%v", args)
			return "", nil
		}
	}
	return c
}

func TestStatus(t *testing.T) {
	c := testClient(t)
	status := c.Status(t.Context())
	if !status.Available || !status.NTPEnabled || status.Synchronized || !status.CustomAvailable || status.Timezone != "Asia/Shanghai" || status.ActiveServer != "ntp.example.com" {
		t.Fatalf("同步状态错误：%+v", status)
	}
	parsed, err := time.Parse(time.RFC3339, status.ServerTime)
	if err != nil || time.Since(parsed) > 2*time.Second || !strings.HasSuffix(status.ServerTime, "+08:00") {
		t.Fatalf("服务器时间或时区错误：%s，%v", status.ServerTime, err)
	}
}

func TestStatusUnavailableStillShowsTime(t *testing.T) {
	for _, output := range []string{"", "Timezone=UTC\nCanNTP=yes", "CanNTP=no\nNTP=no\nNTPSynchronized=no"} {
		t.Run(output, func(t *testing.T) {
			c := testClient(t)
			c.Run = func(context.Context, string, ...string) (string, error) { return output, nil }
			status := c.Status(t.Context())
			if status.Available || status.Message == "" || status.ServerTime == "" {
				t.Fatalf("不可用状态错误：%+v", status)
			}
		})
	}
}

func TestSyncSystemDoesNotWriteConfiguration(t *testing.T) {
	c := testClient(t)
	run := c.Run
	var mutations []string
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if args[0] == "--no-ask-password" {
			mutations = append(mutations, strings.Join(args, " "))
		}
		return run(ctx, name, args...)
	}
	status, err := c.Sync(t.Context(), Request{Mode: "system"})
	if err != nil || status.Synchronized || strings.Join(mutations, ",") != "--no-ask-password set-ntp true" {
		t.Fatalf("系统同步结果错误：%+v，%v，%v", status, err, mutations)
	}
	if _, err := os.Stat(c.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("系统模式不应创建覆盖配置：%v", err)
	}
}

func TestCustomAndRestore(t *testing.T) {
	c := testClient(t)
	status, err := c.Sync(t.Context(), Request{Mode: "custom", Server: "ntp.example.com"})
	if err != nil || status.SourceMode != "custom" || status.CustomServer != "ntp.example.com" {
		t.Fatalf("保存自定义源失败：%+v，%v", status, err)
	}
	content, err := os.ReadFile(c.ConfigPath)
	if err != nil || string(content) != configHeader+"ntp.example.com\nFallbackNTP=\n" {
		t.Fatalf("覆盖配置错误：%s，%v", content, err)
	}
	status, err = c.Sync(t.Context(), Request{Mode: "system"})
	if err != nil || status.SourceMode != "system" {
		t.Fatalf("恢复系统源失败：%+v，%v", status, err)
	}
	if _, err := os.Stat(c.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("切回系统配置应删除面板覆盖文件：%v", err)
	}
}

func TestInvalidServerNeverRunsCommands(t *testing.T) {
	for _, server := range []string{"", "https://ntp.example.com", "ntp.example.com:123", "a\nNTP=evil", "a b", "$(id)", "-bad", "a..b", "a/b", strings.Repeat("a", 64)} {
		t.Run(server, func(t *testing.T) {
			c := testClient(t)
			c.Run = func(context.Context, string, ...string) (string, error) {
				t.Fatal("无效输入不应执行命令")
				return "", nil
			}
			_, err := c.Sync(t.Context(), Request{Mode: "custom", Server: server})
			if err == nil || errorCode(err) != "invalid_request" {
				t.Fatalf("应拒绝无效地址：%v", err)
			}
		})
	}
	for _, server := range []string{"pool.ntp.org", "ntp.example.com.", "192.0.2.1", "2001:db8::1"} {
		if !validServer(server) {
			t.Errorf("应允许域名和 IP：%s", server)
		}
	}
}

func TestCustomFailureRollsBack(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "原无覆盖配置", true: "原有覆盖配置"}[existing], func(t *testing.T) {
			c := testClient(t)
			var previous []byte
			if existing {
				previous = []byte(configHeader + "old.example.com\nFallbackNTP=\n")
				if err := c.writeConfig(previous); err != nil {
					t.Fatal(err)
				}
			}
			run := c.Run
			restarts := 0
			c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
				if args[0] == "--no-ask-password" && args[1] == "restart" {
					restarts++
					if restarts == 1 {
						return "服务启动失败", errors.New("模拟失败")
					}
				}
				return run(ctx, name, args...)
			}
			_, err := c.Sync(t.Context(), Request{Mode: "custom", Server: "new.example.com"})
			if err == nil || !strings.Contains(err.Error(), "已恢复原时间源配置") || restarts != 2 {
				t.Fatalf("应报告失败并重启原配置：%v，重启次数 %d", err, restarts)
			}
			content, readErr := c.readConfig()
			if readErr != nil || string(content) != string(previous) {
				t.Fatalf("未恢复原配置：%s，%v", content, readErr)
			}
		})
	}
}

func TestPermissionAndTimeout(t *testing.T) {
	t.Run("权限不足", func(t *testing.T) {
		c := testClient(t)
		run := c.Run
		c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
			if args[0] == "--no-ask-password" {
				return "Interactive authentication required", errors.New("退出码 1")
			}
			return run(ctx, name, args...)
		}
		_, err := c.Sync(t.Context(), Request{Mode: "system"})
		if err == nil || errorCode(err) != "permission_denied" {
			t.Fatalf("应返回权限不足：%v", err)
		}
	})
	t.Run("命令超时", func(t *testing.T) {
		c := testClient(t)
		c.Run = func(ctx context.Context, _ string, _ ...string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		_, err := c.command(ctx, "模拟命令")
		if err == nil || errorCode(err) != "timeout" {
			t.Fatalf("应返回超时：%v", err)
		}
	})
}

func TestConcurrentSyncRejected(t *testing.T) {
	c := testClient(t)
	run := c.Run
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if args[0] == "--no-ask-password" {
			close(started)
			<-release
		}
		return run(ctx, name, args...)
	}
	go func() {
		_, err := c.Sync(t.Context(), Request{Mode: "system"})
		done <- err
	}()
	<-started
	_, err := c.Sync(t.Context(), Request{Mode: "system"})
	close(release)
	if firstErr := <-done; firstErr != nil {
		t.Fatalf("首次校准不应失败：%v", firstErr)
	}
	if err == nil || errorCode(err) != "busy" {
		t.Fatalf("应拒绝并发校时：%v", err)
	}
}

func TestRollbackFailureIsReported(t *testing.T) {
	c := testClient(t)
	run := c.Run
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if args[0] == "--no-ask-password" && args[1] == "restart" {
			return "", errors.New("模拟服务始终无法启动")
		}
		return run(ctx, name, args...)
	}
	_, err := c.Sync(t.Context(), Request{Mode: "custom", Server: "ntp.example.com"})
	if err == nil || errorCode(err) != "rollback_failed" || !strings.Contains(err.Error(), "恢复原配置或服务失败") {
		t.Fatalf("应明确报告回滚失败：%v", err)
	}
}

func TestCanceledRequestStillRestoresConfiguration(t *testing.T) {
	c := testClient(t)
	run := c.Run
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	restarts := 0
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if args[0] == "--no-ask-password" && args[1] == "restart" {
			restarts++
			if restarts == 1 {
				cancel()
				return "", ctx.Err()
			}
			if ctx.Err() != nil {
				t.Fatal("回滚不应复用已取消的请求上下文")
			}
		}
		return run(ctx, name, args...)
	}
	_, err := c.Sync(ctx, Request{Mode: "custom", Server: "ntp.example.com"})
	if err == nil || errorCode(err) != "timeout" || restarts != 2 {
		t.Fatalf("取消后应完成回滚：%v，重启次数 %d", err, restarts)
	}
	if _, err := os.Stat(c.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("取消后应移除本次创建的覆盖配置：%v", err)
	}
}

func TestCommandSuccessDoesNotImplyNTPEnabled(t *testing.T) {
	c := testClient(t)
	run := c.Run
	c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := run(ctx, name, args...)
		return strings.ReplaceAll(out, "\nNTP=yes", "\nNTP=no"), err
	}
	_, err := c.Sync(t.Context(), Request{Mode: "system"})
	if err == nil || errorCode(err) != "unconfirmed" {
		t.Fatalf("不能把命令成功当作已启用同步：%v", err)
	}
}

func TestOtherServiceAndExternalConfigAreNotModified(t *testing.T) {
	t.Run("其他同步服务", func(t *testing.T) {
		c := testClient(t)
		run := c.Run
		c.Run = func(ctx context.Context, name string, args ...string) (string, error) {
			if args[0] == "show" && args[1] == "systemd-timesyncd.service" {
				return "LoadState=not-found\nActiveState=inactive\n", nil
			}
			if args[0] == "--no-ask-password" {
				t.Fatal("不应修改其他时间同步服务")
			}
			return run(ctx, name, args...)
		}
		_, err := c.Sync(t.Context(), Request{Mode: "custom", Server: "ntp.example.com"})
		if err == nil || errorCode(err) != "unavailable" {
			t.Fatalf("应拒绝不支持的服务：%v", err)
		}
	})
	t.Run("外部配置", func(t *testing.T) {
		c := testClient(t)
		content := []byte("[Time]\nNTP=external.example.com\n")
		if err := c.writeConfig(content); err != nil {
			t.Fatal(err)
		}
		_, err := c.Sync(t.Context(), Request{Mode: "system"})
		after, readErr := os.ReadFile(c.ConfigPath)
		if err == nil || readErr != nil || string(after) != string(content) {
			t.Fatalf("不应覆盖外部配置：%v，%s，%v", err, after, readErr)
		}
	})
}
