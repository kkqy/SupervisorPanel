package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultGitHubAPIBase = "https://api.github.com"
	defaultCheckInterval = 6 * time.Hour
)

type Runner func(ctx context.Context, scriptPath string, env []string) (string, error)

type Config struct {
	Enabled         bool
	CurrentVersion  string
	GitHubRepo      string
	GitHubAPIBase   string
	DownloadBaseURL string
	ScriptPath      string
	CheckInterval   time.Duration
	HTTPClient      *http.Client
	Runner          Runner
}

type Status struct {
	Enabled         bool      `json:"enabled"`
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url"`
	CheckedAt       time.Time `json:"checked_at,omitempty"`
	Error           string    `json:"error"`
	Checking        bool      `json:"checking"`
	Upgrading       bool      `json:"upgrading"`
	UpgradeMessage  string    `json:"upgrade_message"`
	UpgradeStarted  time.Time `json:"upgrade_started_at,omitempty"`
	UpgradeFinished time.Time `json:"upgrade_finished_at,omitempty"`
}

type Service struct {
	cfg    Config
	client *http.Client
	runner Runner

	mu     sync.Mutex
	status Status
}

func New(cfg Config) *Service {
	if cfg.CurrentVersion == "" {
		cfg.CurrentVersion = "dev"
	}
	if cfg.GitHubRepo == "" {
		cfg.GitHubRepo = "kkqy/SupervisorPanel"
	}
	if cfg.GitHubAPIBase == "" {
		cfg.GitHubAPIBase = defaultGitHubAPIBase
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = defaultCheckInterval
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	runner := cfg.Runner
	if runner == nil {
		runner = defaultRunner
	}
	return &Service{
		cfg:    cfg,
		client: client,
		runner: runner,
		status: Status{
			Enabled:        cfg.Enabled,
			CurrentVersion: cfg.CurrentVersion,
		},
	}
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Service) Check(ctx context.Context) Status {
	s.mu.Lock()
	s.status.Enabled = s.cfg.Enabled
	s.status.CurrentVersion = s.cfg.CurrentVersion
	if !s.cfg.Enabled {
		s.status.Error = "更新检测已禁用"
		s.status.Checking = false
		status := s.status
		s.mu.Unlock()
		return status
	}
	s.status.Checking = true
	s.mu.Unlock()

	latest, releaseURL, err := s.fetchLatest(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Checking = false
	s.status.CheckedAt = time.Now()
	if err != nil {
		s.status.Error = err.Error()
		return s.status
	}
	s.status.Error = ""
	s.status.LatestVersion = latest
	s.status.ReleaseURL = releaseURL
	s.status.UpdateAvailable = IsNewerVersion(s.cfg.CurrentVersion, latest)
	return s.status
}

func (s *Service) Start(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	go func() {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.Check(ctx)
		}

		ticker := time.NewTicker(s.cfg.CheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Check(ctx)
			}
		}
	}()
}

func (s *Service) StartUpgrade(ctx context.Context) (Status, error) {
	s.mu.Lock()
	if s.status.Upgrading {
		status := s.status
		s.mu.Unlock()
		return status, errors.New("正在升级，请稍后再试")
	}
	if !s.status.UpdateAvailable || s.status.LatestVersion == "" {
		status := s.status
		s.mu.Unlock()
		return status, errors.New("当前没有可升级的新版本")
	}
	latest := s.status.LatestVersion
	s.status.Upgrading = true
	s.status.UpgradeStarted = time.Now()
	s.status.UpgradeFinished = time.Time{}
	s.status.UpgradeMessage = "已提交升级任务"
	status := s.status
	s.mu.Unlock()

	go s.runUpgrade(ctx, latest)

	return status, nil
}

func (s *Service) runUpgrade(ctx context.Context, latest string) {
	env := []string{
		"RELEASE_VERSION=" + latest,
		"GITHUB_REPO=" + s.cfg.GitHubRepo,
	}
	if strings.TrimSpace(s.cfg.DownloadBaseURL) != "" {
		env = append(env, "DOWNLOAD_BASE_URL="+strings.TrimSpace(s.cfg.DownloadBaseURL))
	}
	output, err := s.runner(ctx, s.resolveScriptPath(), env)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Upgrading = false
	s.status.UpgradeFinished = time.Now()
	if err != nil {
		s.status.UpgradeMessage = strings.TrimSpace(output)
		if s.status.UpgradeMessage == "" {
			s.status.UpgradeMessage = err.Error()
		}
		s.status.Error = err.Error()
		return
	}
	s.status.UpgradeMessage = strings.TrimSpace(output)
	if s.status.UpgradeMessage == "" {
		s.status.UpgradeMessage = "升级命令执行完成，服务可能正在重启"
	}
}

func (s *Service) fetchLatest(ctx context.Context) (string, string, error) {
	repo := strings.Trim(strings.TrimSpace(s.cfg.GitHubRepo), "/")
	if repo == "" || !strings.Contains(repo, "/") {
		return "", "", fmt.Errorf("更新仓库配置不正确")
	}
	base := strings.TrimRight(s.cfg.GitHubAPIBase, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SupervisorPanel update checker")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("检查更新失败：HTTP %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", err
	}
	release.TagName = strings.TrimSpace(release.TagName)
	if release.TagName == "" {
		return "", "", fmt.Errorf("最新版本响应缺少 tag_name")
	}
	return release.TagName, strings.TrimSpace(release.HTMLURL), nil
}

func (s *Service) resolveScriptPath() string {
	if strings.TrimSpace(s.cfg.ScriptPath) != "" {
		return strings.TrimSpace(s.cfg.ScriptPath)
	}
	if path, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(path), "upgrade.sh")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	return filepath.Join("scripts", "upgrade.sh")
}

func defaultRunner(ctx context.Context, scriptPath string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", scriptPath)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func IsNewerVersion(current, latest string) bool {
	currentParts, ok := parseVersion(current)
	if !ok {
		return false
	}
	latestParts, ok := parseVersion(latest)
	if !ok {
		return false
	}
	maxLen := len(currentParts)
	if len(latestParts) > maxLen {
		maxLen = len(latestParts)
	}
	for i := 0; i < maxLen; i++ {
		var currentPart, latestPart int
		if i < len(currentParts) {
			currentPart = currentParts[i]
		}
		if i < len(latestParts) {
			latestPart = latestParts[i]
		}
		if latestPart > currentPart {
			return true
		}
		if latestPart < currentPart {
			return false
		}
	}
	return false
}

func parseVersion(value string) ([]int, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
	if value == "" {
		return nil, false
	}
	if cut := strings.IndexAny(value, "-+"); cut >= 0 {
		value = value[:cut]
	}
	parts := strings.Split(value, ".")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		result = append(result, n)
	}
	return result, true
}

func (s *Service) setStatusForTest(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}
