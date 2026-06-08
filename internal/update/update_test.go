package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "v1.2.3", latest: "v1.2.4", want: true},
		{current: "v1.2.9", latest: "v1.2.10", want: true},
		{current: "1.2.3", latest: "v1.2.3", want: false},
		{current: "v1.3.0", latest: "v1.2.9", want: false},
		{current: "dev", latest: "v1.2.9", want: false},
	}

	for _, tt := range tests {
		if got := IsNewerVersion(tt.current, tt.latest); got != tt.want {
			t.Fatalf("IsNewerVersion(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestCheckFetchesLatestRelease(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/panel/releases/latest" {
			t.Fatalf("path = %s, want latest release path", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.0","html_url":"https://example.test/releases/v1.1.0"}`))
	}))
	defer api.Close()

	service := New(Config{
		Enabled:        true,
		CurrentVersion: "v1.0.0",
		GitHubRepo:     "acme/panel",
		GitHubAPIBase:  api.URL,
		CheckInterval:  time.Hour,
	})

	status := service.Check(context.Background())

	if status.Error != "" {
		t.Fatalf("Error = %q, want empty", status.Error)
	}
	if status.LatestVersion != "v1.1.0" {
		t.Fatalf("LatestVersion = %q, want v1.1.0", status.LatestVersion)
	}
	if !status.UpdateAvailable {
		t.Fatal("UpdateAvailable = false, want true")
	}
	if status.ReleaseURL != "https://example.test/releases/v1.1.0" {
		t.Fatalf("ReleaseURL = %q, want release URL", status.ReleaseURL)
	}
}

func TestCheckDisabledDoesNotCallRemote(t *testing.T) {
	called := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer api.Close()

	service := New(Config{
		Enabled:        false,
		CurrentVersion: "v1.0.0",
		GitHubRepo:     "acme/panel",
		GitHubAPIBase:  api.URL,
		CheckInterval:  time.Hour,
	})

	status := service.Check(context.Background())

	if called {
		t.Fatal("remote API was called while update check is disabled")
	}
	if status.Enabled {
		t.Fatal("Enabled = true, want false")
	}
	if status.Error != "更新检测已禁用" {
		t.Fatalf("Error = %q, want disabled message", status.Error)
	}
}

func TestStartUpgradeRejectsWhenNoUpdateAvailable(t *testing.T) {
	service := New(Config{Enabled: true, CurrentVersion: "v1.0.0", CheckInterval: time.Hour})

	status, err := service.StartUpgrade(context.Background())

	if err == nil {
		t.Fatal("err = nil, want error")
	}
	if status.Upgrading {
		t.Fatal("Upgrading = true, want false")
	}
}

func TestStartUpgradeRunsOneTaskAtATime(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	service := New(Config{
		Enabled:        true,
		CurrentVersion: "v1.0.0",
		CheckInterval:  time.Hour,
		ScriptPath:     "/tmp/upgrade.sh",
		Runner: func(ctx context.Context, scriptPath string, env []string) (string, error) {
			close(started)
			<-release
			return "ok", nil
		},
	})
	service.setStatusForTest(Status{
		Enabled:         true,
		CurrentVersion:  "v1.0.0",
		LatestVersion:   "v1.1.0",
		UpdateAvailable: true,
	})

	status, err := service.StartUpgrade(context.Background())
	if err != nil {
		t.Fatalf("StartUpgrade first err = %v, want nil", err)
	}
	if !status.Upgrading {
		t.Fatal("Upgrading = false, want true")
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("upgrade runner did not start")
	}

	status, err = service.StartUpgrade(context.Background())
	if err == nil {
		close(release)
		t.Fatal("StartUpgrade second err = nil, want duplicate error")
	}
	if !strings.Contains(err.Error(), "正在升级") {
		close(release)
		t.Fatalf("err = %v, want upgrading error", err)
	}
	if !status.Upgrading {
		close(release)
		t.Fatal("Upgrading = false during duplicate request")
	}

	close(release)
}
