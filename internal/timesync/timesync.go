package timesync

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const configHeader = "# 由 SupervisorPanel 管理\n[Time]\nNTP=\nNTP="

type Runner func(context.Context, string, ...string) (string, error)

type Client struct {
	TimedatectlBin string
	SystemctlBin   string
	ConfigPath     string
	Run            Runner
	mu             sync.Mutex
}

type Status struct {
	ServerTime      string `json:"server_time"`
	Timezone        string `json:"timezone"`
	Available       bool   `json:"available"`
	NTPEnabled      bool   `json:"ntp_enabled"`
	Synchronized    bool   `json:"synchronized"`
	SourceMode      string `json:"source_mode"`
	CustomServer    string `json:"custom_server"`
	CustomAvailable bool   `json:"custom_available"`
	ActiveServer    string `json:"active_server"`
	Message         string `json:"message"`
}

type Request struct {
	Mode   string `json:"mode"`
	Server string `json:"server"`
}

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func New(systemctlBin string) *Client {
	if systemctlBin == "" {
		systemctlBin = "/usr/bin/systemctl"
	}
	return &Client{
		TimedatectlBin: "/usr/bin/timedatectl",
		SystemctlBin:   systemctlBin,
		ConfigPath:     "/etc/systemd/timesyncd.conf.d/90-supervisor-panel.conf",
	}
}

func (c *Client) Status(ctx context.Context) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status(ctx)
}

func (c *Client) status(ctx context.Context) Status {
	status := Status{SourceMode: "system"}
	out, err := c.command(ctx, c.TimedatectlBin, "show", "--property=Timezone,CanNTP,NTP,NTPSynchronized")
	props := properties(out)
	status.Timezone = props["Timezone"]
	if err != nil {
		status.Message = err.Error()
	} else if !validBool(props["CanNTP"]) || !validBool(props["NTP"]) || !validBool(props["NTPSynchronized"]) {
		status.Message = "无法识别系统时间同步状态"
	} else {
		status.Available = props["CanNTP"] == "yes"
		status.NTPEnabled = props["NTP"] == "yes"
		status.Synchronized = props["NTPSynchronized"] == "yes"
		if !status.Available {
			status.Message = "未检测到可用的 NTP 同步服务，请先在服务器安装并配置时间同步服务"
		}
	}
	if status.Available {
		out, err := c.command(ctx, c.SystemctlBin, "show", "systemd-timesyncd.service", "--property=LoadState,ActiveState")
		service := properties(out)
		status.CustomAvailable = err == nil && service["LoadState"] == "loaded" && service["ActiveState"] == "active"
		if status.CustomAvailable {
			out, err := c.command(ctx, c.TimedatectlBin, "show-timesync", "--property=ServerName,ServerAddress")
			if err == nil {
				status.ActiveServer = properties(out)["ServerName"]
				if status.ActiveServer == "" {
					status.ActiveServer = properties(out)["ServerAddress"]
				}
			}
		}
	}
	content, err := c.readConfig()
	if err != nil {
		status.Available = false
		status.Message = err.Error()
	} else if len(content) > 0 {
		status.SourceMode = "custom"
		status.CustomServer = strings.TrimSuffix(strings.TrimPrefix(string(content), configHeader), "\nFallbackNTP=\n")
	}
	now := time.Now()
	if zone, err := time.LoadLocation(status.Timezone); status.Timezone != "" && err == nil {
		now = now.In(zone)
	} else {
		status.Timezone = now.Location().String()
	}
	status.ServerTime = now.Format(time.RFC3339)
	return status
}

func (c *Client) Sync(ctx context.Context, request Request) (Status, error) {
	if request.Mode != "system" && request.Mode != "custom" {
		return Status{}, &Error{"invalid_request", "请选择系统配置或自定义 NTP 服务器"}
	}
	request.Server = strings.TrimSpace(request.Server)
	if request.Mode == "custom" && !validServer(request.Server) {
		return Status{}, &Error{"invalid_request", "请输入有效的 NTP 域名或 IP 地址，不支持 URL、端口或多个地址"}
	}
	if !c.mu.TryLock() {
		return Status{}, &Error{"busy", "时间校准正在处理中，请稍后重试"}
	}
	defer c.mu.Unlock()
	before := c.status(ctx)
	if !before.Available {
		return before, &Error{"unavailable", before.Message}
	}
	changeConfig := request.Mode == "custom" || before.SourceMode == "custom"
	if changeConfig && !before.CustomAvailable {
		return before, &Error{"unavailable", "修改时间源需要正在运行的 systemd-timesyncd 服务；其他 NTP 服务请在服务器上配置后选择系统配置"}
	}
	previous, err := c.readConfig()
	if err != nil {
		return before, err
	}
	if changeConfig {
		var content []byte
		if request.Mode == "custom" {
			content = []byte(configHeader + request.Server + "\nFallbackNTP=\n")
		}
		if err := c.writeConfig(content); err != nil {
			return before, classify("保存 NTP 配置失败", "", err)
		}
	}
	_, err = c.command(ctx, c.TimedatectlBin, "--no-ask-password", "set-ntp", "true")
	if err == nil && changeConfig {
		_, err = c.command(ctx, c.SystemctlBin, "--no-ask-password", "restart", "systemd-timesyncd.service")
	}
	if err != nil {
		if changeConfig {
			// 请求取消后仍需独立完成回滚，避免留下未生效的时间源配置。
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
			defer cancel()
			rollbackErr := c.writeConfig(previous)
			if rollbackErr == nil {
				_, rollbackErr = c.command(rollbackCtx, c.SystemctlBin, "--no-ask-password", "restart", "systemd-timesyncd.service")
			}
			if rollbackErr != nil {
				return before, &Error{"rollback_failed", fmt.Sprintf("%v；恢复原配置或服务失败：%v，请检查服务器时间同步服务", err, rollbackErr)}
			}
			return before, &Error{errorCode(err), err.Error() + "；已恢复原时间源配置"}
		}
		return before, err
	}
	after := c.status(ctx)
	if !after.Available {
		return after, &Error{"unconfirmed", "已提交同步命令，但无法确认当前状态：" + after.Message}
	}
	if !after.NTPEnabled {
		return after, &Error{"unconfirmed", "同步命令已执行，但系统未报告自动同步已启用，请检查时间同步服务"}
	}
	return after, nil
}

func (c *Client) command(ctx context.Context, name string, args ...string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", &Error{"unavailable", "此系统不支持通过 systemd 校准时间"}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) (string, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Env = append(os.Environ(), "LC_ALL=C")
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
	}
	out, err := run(ctx, name, args...)
	if ctx.Err() != nil {
		return out, &Error{"timeout", "时间同步操作超时或请求已取消，请刷新状态确认结果"}
	}
	if err != nil {
		return out, classify("时间同步操作失败", out, err)
	}
	return out, nil
}

func classify(action, output string, err error) error {
	text := strings.ToLower(output + " " + err.Error())
	for _, keyword := range []string{"access denied", "permission denied", "not permitted", "authentication", "not authorized"} {
		if errors.Is(err, os.ErrPermission) || strings.Contains(text, keyword) {
			return &Error{"permission_denied", action + "：权限不足，请检查面板服务账户的系统时间管理权限"}
		}
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) || strings.Contains(text, "not been booted with systemd") || strings.Contains(text, "failed to connect to bus") || strings.Contains(text, "ntp not supported") {
		return &Error{"unavailable", action + "：系统时间同步服务不可用，请检查 systemd、timedatectl 和 NTP 服务"}
	}
	return &Error{"command_failed", action + "，请检查服务器时间同步服务与 NTP 配置"}
}

func errorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return "command_failed"
}

func properties(output string) map[string]string {
	result := make(map[string]string)
	for line := range strings.SplitSeq(output, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			result[key] = value
		}
	}
	return result
}

func validBool(value string) bool { return value == "yes" || value == "no" }

func validServer(server string) bool {
	if net.ParseIP(server) != nil {
		return true
	}
	if len(server) == 0 || len(server) > 253 {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(server, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (c *Client) readConfig() ([]byte, error) {
	content, err := os.ReadFile(c.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, classify("读取面板 NTP 配置失败", "", err)
	}
	server := strings.TrimSuffix(strings.TrimPrefix(string(content), configHeader), "\nFallbackNTP=\n")
	if !validServer(server) || string(content) != configHeader+server+"\nFallbackNTP=\n" {
		return nil, &Error{"unavailable", "面板 NTP 配置文件已被外部修改，请先检查 " + c.ConfigPath}
	}
	return content, nil
}

func (c *Client) writeConfig(content []byte) error {
	if len(content) == 0 {
		err := os.Remove(c.ConfigPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.ConfigPath), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.ConfigPath), ".supervisor-panel-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(content)
	modeErr := f.Chmod(0644)
	closeErr := f.Close()
	if err := errors.Join(writeErr, modeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), c.ConfigPath)
}
