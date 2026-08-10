package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/certmagic"

	"supervisorpanel/internal/db"
)

// Caddy 在 SupervisorPanel 进程内运行，并通过重新加载 JSON 配置热更新路由。
type Caddy struct {
	mu      sync.Mutex
	dataDir string
}

func New(dataDir string) *Caddy {
	return &Caddy{dataDir: dataDir}
}

func (c *Caddy) Reload(bindings []db.ProxyBinding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dataDir != "" {
		caddy.DefaultStorage = &certmagic.FileStorage{Path: c.dataDir}
	}

	configJSON, err := buildConfig(bindings)
	if err != nil {
		return err
	}
	if err := caddy.Load(configJSON, false); err != nil {
		return fmt.Errorf("加载 Caddy 配置失败: %w", err)
	}
	return nil
}

func (c *Caddy) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return caddy.Stop()
}

func buildConfig(bindings []db.ProxyBinding) ([]byte, error) {
	type route struct {
		domain string
		port   int
	}
	routes := make([]route, 0, len(bindings))
	for _, binding := range bindings {
		if strings.TrimSpace(binding.Domain) == "" || binding.Port == 0 {
			continue
		}
		routes = append(routes, route{domain: binding.Domain, port: binding.Port})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].domain < routes[j].domain })

	config := map[string]any{
		"admin": map[string]any{
			"disabled": true,
			"config":   map[string]any{"persist": false},
		},
	}
	if len(routes) == 0 {
		return json.Marshal(config)
	}

	httpRoutes := make([]any, 0, len(routes))
	for _, item := range routes {
		httpRoutes = append(httpRoutes, map[string]any{
			"match": []any{map[string]any{"host": []string{item.domain}}},
			"handle": []any{map[string]any{
				"handler":   "reverse_proxy",
				"upstreams": []any{map[string]any{"dial": "127.0.0.1:" + strconv.Itoa(item.port)}},
			}},
		})
	}
	config["apps"] = map[string]any{
		"http": map[string]any{
			"grace_period": "10s",
			"servers": map[string]any{
				"proxy": map[string]any{
					"listen": []string{":443"},
					"routes": httpRoutes,
				},
			},
		},
	}
	return json.Marshal(config)
}
