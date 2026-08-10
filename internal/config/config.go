package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr                     string
	DBPath                   string
	ProjectsDir              string
	SupervisorConfDir        string
	SupervisorctlBin         string
	SystemctlBin             string
	SessionTTLHours          int
	SessionCookieName        string
	SessionSecure            bool
	RuntimeUser              string
	CurrentVersion           string
	UpdateCheckEnabled       bool
	UpdateCheckIntervalHours int
	UpdateGitHubRepo         string
	UpdateGitHubAPIBase      string
	UpdateDownloadBaseURL    string
	UpdateScriptPath         string
	CaddyEnabled             bool
	CaddyDataDir             string
}

func Load() Config {
	return Config{
		Addr:                     getEnv("SP_ADDR", ":8080"),
		DBPath:                   getEnv("SP_DB_PATH", "./data/supervisor-panel.db"),
		ProjectsDir:              getEnv("SP_PROJECTS_DIR", "./projects"),
		SupervisorConfDir:        getEnv("SP_SUPERVISOR_CONF_DIR", "/etc/supervisor/conf.d"),
		SupervisorctlBin:         getEnv("SP_SUPERVISORCTL_BIN", "/usr/bin/supervisorctl"),
		SystemctlBin:             getEnv("SP_SYSTEMCTL_BIN", "/usr/bin/systemctl"),
		SessionTTLHours:          getEnvInt("SP_SESSION_TTL_HOURS", 24),
		SessionCookieName:        getEnv("SP_SESSION_COOKIE_NAME", "sp_session"),
		SessionSecure:            getEnvBool("SP_SESSION_SECURE", false),
		RuntimeUser:              getEnv("SP_RUNTIME_USER", "www-data"),
		UpdateCheckEnabled:       getEnvBool("SP_UPDATE_CHECK_ENABLED", true),
		UpdateCheckIntervalHours: getEnvInt("SP_UPDATE_CHECK_INTERVAL_HOURS", 6),
		UpdateGitHubRepo:         getEnv("SP_UPDATE_GITHUB_REPO", "kkqy/SupervisorPanel"),
		UpdateGitHubAPIBase:      getEnv("SP_UPDATE_GITHUB_API_BASE", "https://api.github.com"),
		UpdateDownloadBaseURL:    getEnv("SP_UPDATE_DOWNLOAD_BASE_URL", ""),
		UpdateScriptPath:         getEnv("SP_UPDATE_SCRIPT_PATH", "/opt/supervisor-panel/upgrade.sh"),
		CaddyEnabled:             getEnvBool("SP_CADDY_ENABLED", true),
		CaddyDataDir:             getEnv("SP_CADDY_DATA_DIR", "./data/caddy"),
	}
}

func getEnv(key, defaultVal string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultVal
	}
	return v
}

func getEnvInt(key string, defaultVal int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func getEnvBool(key string, defaultVal bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return defaultVal
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
