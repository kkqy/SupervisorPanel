package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesExistingProjectsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "old.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	_, err = rawDB.Exec(`
CREATE TABLE projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  entry_file TEXT,
  args TEXT,
  run_user TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO projects(name, slug, path, run_user) VALUES('旧项目', 'p1', '/tmp/p1', 'www-data');
`)
	if err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close old database: %v", err)
	}

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateProxyBinding(1, "app.example.com", 9000); err != nil {
		t.Fatalf("create proxy binding: %v", err)
	}
	bindings, err := store.ListProjectProxyBindings(1)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings = %#v, err = %v", bindings, err)
	}
	if bindings[0].Domain != "app.example.com" || bindings[0].Port != 9000 {
		t.Fatalf("binding = %#v", bindings[0])
	}
	if err := store.DeleteProxyBinding(bindings[0].ID, 1); err != nil {
		t.Fatalf("delete proxy binding: %v", err)
	}
}

func TestOpenMigratesLegacyProjectProxyConfig(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = rawDB.Exec(`
CREATE TABLE projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  entry_file TEXT,
  args TEXT,
  run_user TEXT NOT NULL,
  domain TEXT,
  proxy_port INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO projects(name, slug, path, run_user, domain, proxy_port)
VALUES('旧项目', 'p1', '/tmp/p1', 'www-data', 'old.example.com', 8080);
`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	_ = rawDB.Close()

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	bindings, err := store.ListProjectProxyBindings(1)
	if err != nil || len(bindings) != 1 || bindings[0].Domain != "old.example.com" || bindings[0].Port != 8080 {
		t.Fatalf("bindings = %#v, err = %v", bindings, err)
	}
	if err := store.DeleteProxyBinding(bindings[0].ID, 1); err != nil {
		t.Fatalf("delete migrated binding: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close migrated database: %v", err)
	}
	store, err = Open(dbPath)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer store.Close()
	bindings, err = store.ListProjectProxyBindings(1)
	if err != nil || len(bindings) != 0 {
		t.Fatalf("bindings after reopen = %#v, err = %v", bindings, err)
	}
}
