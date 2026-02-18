package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"supervisorpanel/internal/db"
)

type Client struct {
	ConfDir          string
	Supervisorctl    string
	SupervisorLogDir string
}

func New(confDir, supervisorctl string) *Client {
	return &Client{
		ConfDir:          confDir,
		Supervisorctl:    supervisorctl,
		SupervisorLogDir: "/var/log/supervisor-panel",
	}
}

func (c *Client) ProgramName(slug string) string {
	return "sp_" + slug
}

func (c *Client) LogFilePath(slug string) string {
	return filepath.Join(c.SupervisorLogDir, c.ProgramName(slug)+".log")
}

func (c *Client) ApplyProject(project db.Project) error {
	if !project.EntryFile.Valid || strings.TrimSpace(project.EntryFile.String) == "" {
		return fmt.Errorf("project main file not configured")
	}
	if err := os.MkdirAll(c.ConfDir, 0o755); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.MkdirAll(c.SupervisorLogDir, 0o755)
	}

	entry := filepath.Join(project.Path, filepath.FromSlash(project.EntryFile.String))
	command := quoteToken(entry)
	if project.Args.Valid && strings.TrimSpace(project.Args.String) != "" {
		command += " " + project.Args.String
	}

	programName := c.ProgramName(project.Slug)
	logFile := filepath.Join(c.SupervisorLogDir, programName+".log")
	conf := strings.Join([]string{
		fmt.Sprintf("[program:%s]", programName),
		fmt.Sprintf("directory=%s", project.Path),
		fmt.Sprintf("command=%s", command),
		fmt.Sprintf("user=%s", project.RunUser),
		"autostart=false",
		"autorestart=true",
		"startsecs=3",
		fmt.Sprintf("stdout_logfile=%s", logFile),
		"stderr_logfile_maxbytes=50MB",
		"stdout_logfile_maxbytes=50MB",
		"redirect_stderr=true",
		"stopasgroup=true",
		"killasgroup=true",
		"",
	}, "\n")

	confPath := filepath.Join(c.ConfDir, programName+".conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		return err
	}

	if _, err := c.run("reread"); err != nil {
		return err
	}
	if _, err := c.run("update"); err != nil {
		return err
	}
	return nil
}

func (c *Client) Control(action, slug string) (string, error) {
	switch action {
	case "start", "stop", "restart":
	default:
		return "", fmt.Errorf("unsupported action: %s", action)
	}
	return c.run(action, c.ProgramName(slug))
}

func (c *Client) Status(slug string) string {
	out, err := c.run("status", c.ProgramName(slug))
	if err != nil {
		return "UNKNOWN"
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "UNKNOWN"
	}
	return fields[1]
}

func (c *Client) RemoveProject(slug string) error {
	program := c.ProgramName(slug)
	_, _ = c.run("stop", program)

	confPath := filepath.Join(c.ConfDir, program+".conf")
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, err := c.run("reread"); err != nil {
		return err
	}
	if _, err := c.run("update"); err != nil {
		return err
	}
	return nil
}

func (c *Client) ReadLog(slug string, limit int) (string, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	logFile := c.LogFilePath(slug)
	content, err := os.ReadFile(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}

func (c *Client) run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Supervisorctl, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	output := strings.TrimSpace(buf.String())
	if err != nil {
		if output == "" {
			output = err.Error()
		}
		return output, fmt.Errorf("supervisorctl %s: %s", strings.Join(args, " "), output)
	}
	return output, nil
}

func quoteToken(v string) string {
	if strings.ContainsAny(v, " \t\n\"'") {
		return strconv.Quote(v)
	}
	return v
}
