package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"supervisorpanel/internal/db"
)

func TestBuildConfigCreatesDomainRoutes(t *testing.T) {
	configJSON, err := buildConfig([]db.ProxyBinding{
		{Domain: "b.example.com", Port: 9002},
		{Domain: "a.example.com", Port: 9001},
		{},
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	config := string(configJSON)
	if !strings.Contains(config, `"host":["a.example.com"]`) || !strings.Contains(config, `"dial":"127.0.0.1:9001"`) {
		t.Fatalf("config = %s, want a.example.com upstream", config)
	}
	if strings.Index(config, "a.example.com") > strings.Index(config, "b.example.com") {
		t.Fatalf("routes are not sorted: %s", config)
	}
	var caddyConfig caddy.Config
	if err := json.Unmarshal(configJSON, &caddyConfig); err != nil {
		t.Fatalf("decode Caddy config: %v", err)
	}
	if err := caddy.Validate(&caddyConfig); err != nil {
		t.Fatalf("validate Caddy config: %v", err)
	}
}

func TestBuildConfigWithoutRoutesDoesNotListen(t *testing.T) {
	configJSON, err := buildConfig(nil)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if strings.Contains(string(configJSON), `"listen"`) {
		t.Fatalf("empty config should not listen: %s", configJSON)
	}
}
