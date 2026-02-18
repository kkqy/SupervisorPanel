package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr              string
	DBPath            string
	ProjectsDir       string
	SupervisorConfDir string
	SupervisorctlBin  string
	SessionTTLHours   int
	SessionCookieName string
	SessionSecure     bool
	RuntimeUser       string
}

func Load() Config {
	return Config{
		Addr:              getEnv("SP_ADDR", ":8080"),
		DBPath:            getEnv("SP_DB_PATH", "./data/supervisor-panel.db"),
		ProjectsDir:       getEnv("SP_PROJECTS_DIR", "./projects"),
		SupervisorConfDir: getEnv("SP_SUPERVISOR_CONF_DIR", "/etc/supervisor/conf.d"),
		SupervisorctlBin:  getEnv("SP_SUPERVISORCTL_BIN", "/usr/bin/supervisorctl"),
		SessionTTLHours:   getEnvInt("SP_SESSION_TTL_HOURS", 24),
		SessionCookieName: getEnv("SP_SESSION_COOKIE_NAME", "sp_session"),
		SessionSecure:     getEnvBool("SP_SESSION_SECURE", false),
		RuntimeUser:       getEnv("SP_RUNTIME_USER", "www-data"),
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
