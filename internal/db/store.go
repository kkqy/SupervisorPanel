package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
}

type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
}

type Project struct {
	ID        int64
	Name      string
	Slug      string
	Path      string
	EntryFile sql.NullString
	Args      sql.NullString
	RunUser   string
	CreatedAt string
	UpdatedAt string
}

type ProxyBinding struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"project_id"`
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	CreatedAt string `json:"created_at"`
}

type Session struct {
	Token     string
	AdminID   int64
	ExpiresAt time.Time
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{DB: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.DB.Close()
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  admin_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
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

CREATE TABLE IF NOT EXISTS proxy_bindings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  port INTEGER NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_projects_slug ON projects(slug);
CREATE INDEX IF NOT EXISTS idx_sessions_admin_id ON sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_proxy_bindings_project_id ON proxy_bindings(project_id);
`
	if _, err := s.DB.Exec(schema); err != nil {
		return err
	}
	if err := s.migrateLegacyProxyBindings(); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DROP INDEX IF EXISTS idx_projects_domain`)
	return err
}

func (s *Store) migrateLegacyProxyBindings() error {
	hasDomain, err := s.hasProjectColumn("domain")
	if err != nil || !hasDomain {
		return err
	}
	hasPort, err := s.hasProjectColumn("proxy_port")
	if err != nil || !hasPort {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT OR IGNORE INTO proxy_bindings(project_id, domain, port)
SELECT id, domain, proxy_port FROM projects
WHERE domain IS NOT NULL AND domain <> '' AND proxy_port > 0
`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE projects SET domain = NULL, proxy_port = 0 WHERE domain IS NOT NULL OR proxy_port <> 0`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) hasProjectColumn(name string) (bool, error) {
	rows, err := s.DB.Query(`PRAGMA table_info(projects)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var columnName, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if columnName == name {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) CleanupExpiredSessions() error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	return err
}

func (s *Store) AdminCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(1) FROM admins`).Scan(&n)
	return n, err
}

func (s *Store) GetAdminByUsername(username string) (*Admin, error) {
	row := s.DB.QueryRow(`SELECT id, username, password_hash FROM admins WHERE username = ?`, username)
	var a Admin
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) GetAdminByID(id int64) (*Admin, error) {
	row := s.DB.QueryRow(`SELECT id, username, password_hash FROM admins WHERE id = ?`, id)
	var a Admin
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) CreateAdmin(username, passwordHash string) error {
	_, err := s.DB.Exec(
		`INSERT INTO admins(username, password_hash, updated_at) VALUES(?, ?, CURRENT_TIMESTAMP)`,
		username,
		passwordHash,
	)
	return err
}

func (s *Store) UpdateAdminPassword(adminID int64, passwordHash string) error {
	_, err := s.DB.Exec(
		`UPDATE admins SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash,
		adminID,
	)
	return err
}

func (s *Store) SaveSession(session Session) error {
	_, err := s.DB.Exec(
		`INSERT INTO sessions(token, admin_id, expires_at) VALUES(?, ?, ?)`,
		session.Token,
		session.AdminID,
		session.ExpiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (s *Store) GetSession(token string) (*Session, error) {
	row := s.DB.QueryRow(`SELECT token, admin_id, expires_at FROM sessions WHERE token = ?`, token)
	var sess Session
	var expires string
	if err := row.Scan(&sess.Token, &sess.AdminID, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return nil, fmt.Errorf("parse session expires_at: %w", err)
	}
	sess.ExpiresAt = t
	return &sess, nil
}

func (s *Store) CreateProject(p Project) (int64, error) {
	res, err := s.DB.Exec(
		`INSERT INTO projects(name, slug, path, run_user, updated_at) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		p.Name,
		p.Slug,
		p.Path,
		p.RunUser,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateProjectIdentity(projectID int64, slug, path string) error {
	_, err := s.DB.Exec(
		`UPDATE projects SET slug = ?, path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		slug,
		path,
		projectID,
	)
	return err
}

func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.DB.Query(`
SELECT id, name, slug, path, entry_file, args, run_user,
       datetime(created_at, 'localtime'), datetime(updated_at, 'localtime')
FROM projects ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.Path, &p.EntryFile, &p.Args, &p.RunUser, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *Store) GetProjectByID(id int64) (*Project, error) {
	row := s.DB.QueryRow(`
SELECT id, name, slug, path, entry_file, args, run_user,
       datetime(created_at, 'localtime'), datetime(updated_at, 'localtime')
FROM projects WHERE id = ?`, id)
	var p Project
	if err := row.Scan(&p.ID, &p.Name, &p.Slug, &p.Path, &p.EntryFile, &p.Args, &p.RunUser, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (s *Store) UpdateProjectConfig(projectID int64, entryFile, args, runUser string) error {
	_, err := s.DB.Exec(
		`UPDATE projects SET entry_file = ?, args = ?, run_user = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		entryFile,
		args,
		runUser,
		projectID,
	)
	return err
}

func (s *Store) ListProxyBindings() ([]ProxyBinding, error) {
	return s.listProxyBindings(`
SELECT id, project_id, domain, port, datetime(created_at, 'localtime')
FROM proxy_bindings ORDER BY domain`, nil)
}

func (s *Store) ListProjectProxyBindings(projectID int64) ([]ProxyBinding, error) {
	return s.listProxyBindings(`
SELECT id, project_id, domain, port, datetime(created_at, 'localtime')
FROM proxy_bindings WHERE project_id = ? ORDER BY id DESC`, []any{projectID})
}

func (s *Store) listProxyBindings(query string, args []any) ([]ProxyBinding, error) {
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]ProxyBinding, 0)
	for rows.Next() {
		var binding ProxyBinding
		if err := rows.Scan(&binding.ID, &binding.ProjectID, &binding.Domain, &binding.Port, &binding.CreatedAt); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func (s *Store) GetProxyBindingByID(bindingID int64) (*ProxyBinding, error) {
	row := s.DB.QueryRow(`
SELECT id, project_id, domain, port, datetime(created_at, 'localtime')
FROM proxy_bindings WHERE id = ?`, bindingID)
	var binding ProxyBinding
	if err := row.Scan(&binding.ID, &binding.ProjectID, &binding.Domain, &binding.Port, &binding.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &binding, nil
}

func (s *Store) CreateProxyBinding(projectID int64, domain string, port int) (int64, error) {
	result, err := s.DB.Exec(
		`INSERT INTO proxy_bindings(project_id, domain, port) VALUES(?, ?, ?)`,
		projectID,
		domain,
		port,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) DeleteProxyBinding(bindingID, projectID int64) error {
	_, err := s.DB.Exec(`DELETE FROM proxy_bindings WHERE id = ? AND project_id = ?`, bindingID, projectID)
	return err
}

func (s *Store) DeleteProject(projectID int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM proxy_bindings WHERE project_id = ?`, projectID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM projects WHERE id = ?`, projectID); err != nil {
		return err
	}
	return tx.Commit()
}
