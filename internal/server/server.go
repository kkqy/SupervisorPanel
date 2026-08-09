package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"supervisorpanel/internal/auth"
	"supervisorpanel/internal/config"
	"supervisorpanel/internal/db"
	"supervisorpanel/internal/monitor"
	"supervisorpanel/internal/supervisor"
	"supervisorpanel/internal/systemctl"
	"supervisorpanel/internal/update"
)

//go:embed static/* static/assets/*
var staticFS embed.FS

type Server struct {
	cfg       config.Config
	store     *db.Store
	sup       *supervisor.Client
	monitor   monitorCollector
	systemctl systemctl.Client
	update    updateService
}

type monitorCollector interface {
	SystemSnapshot(path string) (monitor.SystemSnapshot, error)
	ProcessSnapshots(projects []db.Project) map[string]monitor.ProcessSnapshot
}

type updateService interface {
	Status() update.Status
	Check(context.Context) update.Status
	StartUpgrade(context.Context) (update.Status, error)
	Start(context.Context)
}

type ProjectDirEntry struct {
	Name       string
	Path       string
	IsDir      bool
	Executable bool
	Editable   bool
	IsCurrent  bool
	Size       int64
	Owner      string
	ModifiedAt time.Time
}

type BreadcrumbItem struct {
	Name string
	Dir  string
}

type apiProject struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Path       string `json:"path"`
	EntryFile  string `json:"entry_file"`
	Args       string `json:"args"`
	RunUser    string `json:"run_user"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Status     string `json:"status"`
	StatusText string `json:"status_text"`
}

type apiDirEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	IsDir      bool      `json:"is_dir"`
	Executable bool      `json:"executable"`
	Editable   bool      `json:"editable"`
	IsCurrent  bool      `json:"is_current"`
	Size       int64     `json:"size"`
	Owner      string    `json:"owner"`
	ModifiedAt time.Time `json:"modified_at"`
}

type apiBreadcrumbItem struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
}

type ctxKey string

const adminIDKey ctxKey = "adminID"

const maxEditableFileSize = 1 << 20

func New(cfg config.Config, store *db.Store, sup *supervisor.Client) (*Server, error) {
	_ = mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
	updateSvc := update.New(update.Config{
		Enabled:         cfg.UpdateCheckEnabled,
		CurrentVersion:  cfg.CurrentVersion,
		GitHubRepo:      cfg.UpdateGitHubRepo,
		GitHubAPIBase:   cfg.UpdateGitHubAPIBase,
		DownloadBaseURL: cfg.UpdateDownloadBaseURL,
		ScriptPath:      cfg.UpdateScriptPath,
		CheckInterval:   time.Duration(cfg.UpdateCheckIntervalHours) * time.Hour,
	})
	return &Server{
		cfg:       cfg,
		store:     store,
		sup:       sup,
		monitor:   monitor.New(sup),
		systemctl: systemctl.Client{Bin: cfg.SystemctlBin},
		update:    updateSvc,
	}, nil
}

func (s *Server) StartUpdateChecker(ctx context.Context) {
	if s.update == nil {
		return
	}
	s.update.Start(ctx)
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/", s.serveStatic)
	mux.HandleFunc("/api/", s.requireAuthAPI(s.handleAPIRoute))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/projects", s.requireAuth(s.handleProjects))
	mux.HandleFunc("/projects/statuses", s.requireAuth(s.handleProjectStatuses))
	mux.HandleFunc("/projects/", s.requireAuth(s.handleProjectRoute))
	mux.HandleFunc("/account/password", s.requireAuth(s.handlePassword))
	return mux
}

func (s *Server) ensureAdmin(username, password string) error {
	count, err := s.store.AdminCount()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return s.store.CreateAdmin(username, hash)
}

func (s *Server) InitAdmin(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || strings.TrimSpace(password) == "" {
		return fmt.Errorf("username/password cannot be empty")
	}
	admin, err := s.store.GetAdminByUsername(username)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if admin == nil {
		return s.store.CreateAdmin(username, hash)
	}
	return s.store.UpdateAdminPassword(admin.ID, hash)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/projects", http.StatusFound)
		return
	}
	s.serveSPA(w, r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.serveSPA(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求格式错误"})
		return
	}
	username := strings.TrimSpace(req.Username)
	password := req.Password
	admin, err := s.store.GetAdminByUsername(username)
	if err != nil {
		log.Printf("login failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	if admin == nil || auth.VerifyPassword(admin.PasswordHash, password) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "用户名或密码错误"})
		return
	}
	token, err := randomToken(32)
	if err != nil {
		log.Printf("login token failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	expires := time.Now().Add(time.Duration(s.cfg.SessionTTLHours) * time.Hour)
	if err := s.store.SaveSession(db.Session{Token: token, AdminID: admin.ID, ExpiresAt: expires}); err != nil {
		log.Printf("save session failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SessionSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "登录成功",
		"redirect": "/projects",
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cfg.SessionCookieName)
	if err == nil && cookie.Value != "" {
		_ = s.store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleCreateProject(w, r)
		return
	}
	s.serveSPA(w, r)
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if !requireAJAX(w, r) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求格式错误"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "项目名不能为空"})
		return
	}
	runUser := detectRuntimeUser(s.cfg.RuntimeUser)
	seedSlug := fmt.Sprintf("tmp_%d", time.Now().UnixNano())
	projectID, err := s.store.CreateProject(db.Project{Name: name, Slug: seedSlug, Path: "", RunUser: runUser})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "创建失败，可能项目名重复"})
		return
	}
	projectPath := filepath.Join(s.cfg.ProjectsDir, strconv.FormatInt(projectID, 10))
	if err := os.MkdirAll(projectPath, 0o775); err != nil {
		_ = s.store.DeleteProject(projectID)
		log.Printf("create project mkdir failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	if err := syncOwnership(projectPath, runUser, false); err != nil {
		_ = os.RemoveAll(projectPath)
		_ = s.store.DeleteProject(projectID)
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "创建目录成功，但设置目录所有者失败"})
		return
	}
	finalSlug := fmt.Sprintf("p%d", projectID)
	if err := s.store.UpdateProjectIdentity(projectID, finalSlug, projectPath); err != nil {
		_ = os.RemoveAll(projectPath)
		_ = s.store.DeleteProject(projectID)
		log.Printf("update project identity failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"message":    "项目创建成功",
		"project_id": projectID,
	})
}

func (s *Server) handleProjectStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	projects, err := s.store.ListProjects()
	if err != nil {
		s.serverError(w, err)
		return
	}
	statuses := make(map[string]string, len(projects))
	for _, p := range projects {
		statuses[strconv.FormatInt(p.ID, 10)] = s.sup.Status(p.Slug)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"statuses": statuses,
	})
}

func (s *Server) handleAPIRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if path == "me" {
		s.handleAPIMe(w, r)
		return
	}
	if path == "projects" {
		s.handleAPIProjects(w, r)
		return
	}
	if path == "projects/statuses" {
		s.handleAPIProjectStatuses(w, r)
		return
	}
	if path == "system/status" {
		s.handleAPISystemStatus(w, r)
		return
	}
	if path == "system/update" {
		s.handleAPIUpdateStatus(w, r)
		return
	}
	if path == "system/update/check" {
		s.handleAPIUpdateCheck(w, r)
		return
	}
	if path == "system/update/upgrade" {
		s.handleAPIUpdateUpgrade(w, r)
		return
	}
	if path == "projects/process-statuses" {
		s.handleAPIProjectProcessStatuses(w, r)
		return
	}
	if path == "system/supervisor/restart" {
		s.handleAPIRestartSupervisor(w, r)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "projects" {
		http.NotFound(w, r)
		return
	}
	projectID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 {
		s.handleAPIProjectDetail(w, r, projectID)
		return
	}
	if len(parts) == 3 && parts[2] == "logs" {
		s.handleAPIProjectLogs(w, r, projectID)
		return
	}
	if len(parts) == 4 && parts[2] == "files" && parts[3] == "content" {
		s.handleAPIFileContent(w, r, projectID)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleAPIMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	adminID, ok := adminIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
		return
	}
	admin, err := s.store.GetAdminByID(adminID)
	if err != nil || admin == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"admin": map[string]any{
			"id":       admin.ID,
			"username": admin.Username,
		},
	})
}

func (s *Server) handleAPIProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	projects, err := s.store.ListProjects()
	if err != nil {
		s.serverError(w, err)
		return
	}
	items := make([]apiProject, 0, len(projects))
	for _, project := range projects {
		status := s.sup.Status(project.Slug)
		items = append(items, apiProjectPayload(project, status))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"projects":     items,
		"projects_dir": s.cfg.ProjectsDir,
	})
}

func (s *Server) handleAPIProjectStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	s.handleProjectStatuses(w, r)
}

func (s *Server) handleAPISystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	collector := s.monitor
	if collector == nil {
		collector = monitor.New(s.sup)
	}
	snapshot, err := collector.SystemSnapshot(s.cfg.ProjectsDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "system": snapshot})
}

func (s *Server) handleAPIProjectProcessStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	projects, err := s.store.ListProjects()
	if err != nil {
		s.serverError(w, err)
		return
	}
	collector := s.monitor
	if collector == nil {
		collector = monitor.New(s.sup)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "processes": collector.ProcessSnapshots(projects)})
}

func (s *Server) handleAPIUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if s.update == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "update": update.Status{Enabled: false, Error: "更新检测不可用"}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "update": s.update.Status()})
}

func (s *Server) handleAPIUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if s.update == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "更新检测不可用"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "update": s.update.Check(r.Context())})
}

func (s *Server) handleAPIUpdateUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if s.update == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "更新升级不可用"})
		return
	}
	status, err := s.update.StartUpgrade(context.Background())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error(), "update": status})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "已提交升级任务", "update": status})
}

func (s *Server) handleAPIRestartSupervisor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	client := s.systemctl
	if strings.TrimSpace(client.Bin) == "" {
		client.Bin = s.cfg.SystemctlBin
	}
	resultCh := client.RestartSupervisorAsync(context.Background(), 500*time.Millisecond)
	go func() {
		result := <-resultCh
		if result.Err != nil {
			log.Printf("restart supervisor failed: %v", result.Err)
			return
		}
		if strings.TrimSpace(result.Output) != "" {
			log.Printf("restart supervisor completed: %s", result.Output)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "已提交重启 Supervisor 命令"})
}

func (s *Server) handleAPIProjectDetail(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if project == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "项目不存在"})
		return
	}
	rawCurrentDir := strings.TrimSpace(r.URL.Query().Get("dir"))
	currentDir := normalizeUploadRelPath(rawCurrentDir)
	if rawCurrentDir != "" && currentDir == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目录路径不合法"})
		return
	}
	currentEntry := ""
	if project.EntryFile.Valid {
		currentEntry = project.EntryFile.String
	}
	files, err := listProjectFiles(project.Path)
	if err != nil {
		s.serverError(w, err)
		return
	}
	entries, parentDir, breadcrumbs, err := listProjectDirEntries(project.Path, currentDir, currentEntry)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	status := s.sup.Status(project.Slug)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"project":       apiProjectPayload(*project, status),
		"files":         files,
		"entries":       apiEntriesPayload(entries),
		"current_dir":   currentDir,
		"parent_dir":    parentDir,
		"breadcrumbs":   apiBreadcrumbsPayload(breadcrumbs),
		"current_entry": currentEntry,
		"current_args":  nullProjectArgs(*project),
		"status":        status,
		"status_text":   statusTextCN(status),
	})
}

func (s *Server) handleAPIProjectLogs(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if project == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "项目不存在"})
		return
	}
	lines := 200
	if lineVal := strings.TrimSpace(r.URL.Query().Get("lines")); lineVal != "" {
		if parsed, parseErr := strconv.Atoi(lineVal); parseErr == nil && parsed > 0 {
			lines = parsed
		}
	}
	logs, err := s.sup.ReadLog(project.Slug, lines)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	startOffset := int64(0)
	logPath := s.sup.LogFilePath(project.Slug)
	if st, statErr := os.Stat(logPath); statErr == nil {
		startOffset = st.Size()
	}
	status := s.sup.Status(project.Slug)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"project":      apiProjectPayload(*project, status),
		"logs":         logs,
		"lines":        lines,
		"start_offset": startOffset,
		"log_path":     logPath,
	})
}

func (s *Server) handleAPIFileContent(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if project == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "项目不存在"})
		return
	}
	relPath := normalizeUploadRelPath(r.URL.Query().Get("path"))
	if relPath == "" || !isEditableTextFile(relPath) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "该文件类型不支持在线编辑"})
		return
	}
	filePath, err := safeJoin(project.Path, relPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	info, err := os.Stat(filePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件不存在"})
		return
	}
	if info.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "仅支持编辑文本文件"})
		return
	}
	if info.Size() > maxEditableFileSize {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件超过1MB，禁止在线编辑"})
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "读取文件失败"})
		return
	}
	if !isTextContent(content) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "该文件不是可编辑文本"})
		return
	}
	status := s.sup.Status(project.Slug)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"project":    apiProjectPayload(*project, status),
		"path":       relPath,
		"content":    string(content),
		"mtime_nano": strconv.FormatInt(info.ModTime().UnixNano(), 10),
		"max_size":   maxEditableFileSize,
	})
}

func apiProjectPayload(project db.Project, status string) apiProject {
	return apiProject{
		ID:         project.ID,
		Name:       project.Name,
		Slug:       project.Slug,
		Path:       project.Path,
		EntryFile:  nullProjectEntry(project),
		Args:       nullProjectArgs(project),
		RunUser:    project.RunUser,
		CreatedAt:  project.CreatedAt,
		UpdatedAt:  project.UpdatedAt,
		Status:     status,
		StatusText: statusTextCN(status),
	}
}

func nullProjectEntry(project db.Project) string {
	if project.EntryFile.Valid {
		return project.EntryFile.String
	}
	return ""
}

func nullProjectArgs(project db.Project) string {
	if project.Args.Valid {
		return project.Args.String
	}
	return ""
}

func apiEntriesPayload(entries []ProjectDirEntry) []apiDirEntry {
	items := make([]apiDirEntry, 0, len(entries))
	for _, entry := range entries {
		items = append(items, apiDirEntry{
			Name:       entry.Name,
			Path:       entry.Path,
			IsDir:      entry.IsDir,
			Executable: entry.Executable,
			Editable:   entry.Editable,
			IsCurrent:  entry.IsCurrent,
			Size:       entry.Size,
			Owner:      entry.Owner,
			ModifiedAt: entry.ModifiedAt,
		})
	}
	return items
}

func apiBreadcrumbsPayload(breadcrumbs []BreadcrumbItem) []apiBreadcrumbItem {
	items := make([]apiBreadcrumbItem, 0, len(breadcrumbs))
	for _, item := range breadcrumbs {
		items = append(items, apiBreadcrumbItem{Name: item.Name, Dir: item.Dir})
	}
	return items
}

func (s *Server) handleProjectRoute(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/projects/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	projectID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if len(parts) >= 2 && parts[1] == "download" {
			s.handleDownloadFile(w, r, projectID)
			return
		}
		if len(parts) >= 3 && parts[1] == "logs" && parts[2] == "stream" {
			s.handleProjectLogStream(w, r, projectID)
			return
		}
		s.serveSPA(w, r)
		return
	}
	if len(parts) == 1 {
		s.handleProjectDetail(w, r, projectID)
		return
	}
	switch parts[1] {
	case "upload":
		s.handleUpload(w, r, projectID)
	case "config":
		s.handleProjectConfig(w, r, projectID)
	case "action":
		s.handleProjectAction(w, r, projectID)
	case "logs":
		if len(parts) >= 3 && parts[2] == "stream" {
			s.handleProjectLogStream(w, r, projectID)
			return
		}
		s.handleProjectLogs(w, r, projectID)
	case "delete":
		s.handleDeleteProject(w, r, projectID)
	case "clone":
		s.handleCloneProject(w, r, projectID)
	case "mkdir":
		s.handleCreateDir(w, r, projectID)
	case "create-file":
		s.handleCreateFile(w, r, projectID)
	case "rename":
		s.handleRenameEntry(w, r, projectID)
	case "delete-file":
		s.handleDeleteFile(w, r, projectID)
	case "executable":
		s.handleSetExecutable(w, r, projectID)
	case "delete-dir":
		s.handleDeleteDir(w, r, projectID)
	case "download":
		s.handleDownloadFile(w, r, projectID)
	case "files":
		if len(parts) >= 3 && parts[2] == "edit" {
			s.handleEditFile(w, r, projectID)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleProjectDetail(w http.ResponseWriter, r *http.Request, projectID int64) {
	_ = projectID
	if r.Method == http.MethodGet {
		s.serveSPA(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		s.respondUploadResult(w, r, projectID, 0, 0, "上传请求过大或格式错误", true, "")
		return
	}
	if r.MultipartForm == nil {
		s.respondUploadResult(w, r, projectID, 0, 0, "未检测到上传文件", true, "")
		return
	}
	rawCurrentDir := strings.TrimSpace(r.FormValue("current_dir"))
	currentDir := normalizeUploadRelPath(rawCurrentDir)
	if rawCurrentDir != "" && currentDir == "" {
		s.respondUploadResult(w, r, projectID, 0, 0, "当前目录路径不合法", true, "")
		return
	}
	receivedCount := 0
	savedCount := 0
	failReasonCount := map[string]int{}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		for _, fhs := range r.MultipartForm.File {
			files = append(files, fhs...)
		}
	}
	relPaths := r.MultipartForm.Value["rel_paths"]
	for idx, fh := range files {
		receivedCount++
		relPath := ""
		if idx < len(relPaths) {
			relPath = normalizeUploadRelPath(relPaths[idx])
		}
		if relPath == "" {
			relPath = normalizeUploadRelPath(fh.Filename)
		}
		if relPath != "" && currentDir != "" {
			relPath = filepath.ToSlash(filepath.Join(currentDir, relPath))
		}
		if relPath == "" {
			failReasonCount["非法路径"]++
			continue
		}
		dstPath, err := safeJoin(project.Path, relPath)
		if err != nil {
			failReasonCount["路径越界"]++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o775); err != nil {
			failReasonCount["创建目录失败"]++
			continue
		}
		if err := syncOwnership(filepath.Dir(dstPath), project.RunUser, false); err != nil {
			log.Printf("warn: chown dir failed: %v", err)
		}
		src, err := fh.Open()
		if err != nil {
			failReasonCount["读取文件失败"]++
			continue
		}
		dst, err := os.Create(dstPath)
		if err != nil {
			failReasonCount["写入文件失败"]++
			_ = src.Close()
			continue
		}
		_, copyErr := io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		if copyErr != nil {
			failReasonCount["复制内容失败"]++
			continue
		}
		if err := syncOwnership(dstPath, project.RunUser, false); err != nil {
			log.Printf("warn: chown file failed: %v", err)
		}
		savedCount++
	}

	failSummary := summarizeFailReasons(failReasonCount)
	if savedCount == 0 {
		msg := "没有成功上传的文件"
		if failSummary != "" {
			msg += "（" + failSummary + "）"
		}
		s.respondUploadResult(w, r, projectID, receivedCount, savedCount, msg, true, failSummary)
		return
	}
	failedCount := receivedCount - savedCount
	msg := fmt.Sprintf("已上传%d个文件", savedCount)
	if failedCount > 0 {
		msg = fmt.Sprintf("部分上传成功（成功%d/总%d）", savedCount, receivedCount)
		if failSummary != "" {
			msg += "（" + failSummary + "）"
		}
	}
	s.respondUploadResult(w, r, projectID, receivedCount, savedCount, msg, false, failSummary)
}

func (s *Server) handleProjectConfig(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	configFail := func(message string) {
		s.respondProjectConfigResult(w, r, projectID, message, true, "")
	}
	var req struct {
		EntryFile string `json:"entry_file"`
		Args      string `json:"args"`
		RunUser   string `json:"run_user"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		configFail("请求参数错误")
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	entryFile := normalizeUploadRelPath(req.EntryFile)
	args := strings.TrimSpace(req.Args)
	runUser := strings.TrimSpace(req.RunUser)
	if runUser == "" {
		runUser = strings.TrimSpace(project.RunUser)
		if runUser == "" {
			runUser = detectRuntimeUser(s.cfg.RuntimeUser)
		}
	}
	if entryFile == "" {
		if project.EntryFile.Valid && strings.TrimSpace(project.EntryFile.String) != "" {
			entryFile = strings.TrimSpace(project.EntryFile.String)
		} else {
			configFail("请先在文件列表指定主程序（未接收到 entry_file）")
			return
		}
	}
	entryPath, err := safeJoin(project.Path, entryFile)
	if err != nil {
		configFail("主程序路径非法")
		return
	}
	entryInfo, err := os.Stat(entryPath)
	if err != nil {
		configFail("主程序文件不存在")
		return
	}
	if entryInfo.IsDir() {
		configFail("主程序必须是文件")
		return
	}
	if err := ensureExecutable(entryPath, entryInfo.Mode()); err != nil {
		configFail("设置主程序可执行权限失败：" + err.Error())
		return
	}
	if err := s.store.UpdateProjectConfig(project.ID, entryFile, args, runUser); err != nil {
		s.serverError(w, err)
		return
	}
	updatedProject, err := s.store.GetProjectByID(project.ID)
	if err != nil || updatedProject == nil {
		s.serverError(w, fmt.Errorf("reload project failed"))
		return
	}
	if err := syncOwnership(updatedProject.Path, updatedProject.RunUser, true); err != nil {
		configFail("已保存配置，但同步目录所有者失败：" + err.Error())
		return
	}
	if err := s.sup.ApplyProject(*updatedProject); err != nil {
		configFail("已保存配置，但应用Supervisor失败：" + err.Error())
		return
	}
	s.respondProjectConfigResult(w, r, projectID, "配置已保存并应用", false, entryFile)
}

func (s *Server) handleProjectAction(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	action := strings.TrimSpace(req.Action)
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	out, err := s.sup.Control(action, project.Slug)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":      false,
			"message": err.Error(),
			"status":  s.sup.Status(project.Slug),
		})
		return
	}
	currentStatus := s.sup.Status(project.Slug)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": out,
		"status":  currentStatus,
	})
}

func (s *Server) handleProjectLogs(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	_ = projectID
	s.serveSPA(w, r)
}

func (s *Server) handleProjectLogStream(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}

	offset := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil && parsed >= 0 {
			offset = parsed
		}
	}
	logPath := s.sup.LogFilePath(project.Slug)

	writeSSEEvent(w, "ready", map[string]any{"offset": offset})
	flusher.Flush()

	ticker := time.NewTicker(1200 * time.Millisecond)
	heartbeat := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			chunk, nextOffset, readErr := readLogChunk(logPath, offset, 128*1024)
			if readErr != nil {
				writeSSEEvent(w, "error", map[string]any{"message": readErr.Error()})
				flusher.Flush()
				continue
			}
			offset = nextOffset
			if chunk == "" {
				continue
			}
			writeSSEEvent(w, "log", map[string]any{"chunk": chunk, "offset": offset})
			flusher.Flush()
		}
	}
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		ConfirmName string `json:"confirm_name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	confirm := strings.TrimSpace(req.ConfirmName)
	if confirm != project.Name {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请填写正确的项目名以确认删除"})
		return
	}
	if err := s.sup.RemoveProject(project.Slug); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "移除Supervisor配置失败：" + err.Error()})
		return
	}
	if err := os.RemoveAll(project.Path); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "删除项目目录失败：" + err.Error()})
		return
	}
	if err := s.store.DeleteProject(project.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "删除数据库记录失败：" + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "项目已删除"})
}

func (s *Server) handleCloneProject(w http.ResponseWriter, r *http.Request, sourceProjectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	sourceProject, err := s.store.GetProjectByID(sourceProjectID)
	if err != nil || sourceProject == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Name            string `json:"name"`
		IncludeSymlinks bool   `json:"include_symlinks"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	newName := strings.TrimSpace(req.Name)
	if newName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "新项目名称不能为空"})
		return
	}
	includeSymlinks := req.IncludeSymlinks

	seedSlug := fmt.Sprintf("tmp_%d", time.Now().UnixNano())
	newProjectID, err := s.store.CreateProject(db.Project{Name: newName, Slug: seedSlug, Path: "", RunUser: sourceProject.RunUser})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "创建副本失败"})
		return
	}

	newProjectPath := filepath.Join(s.cfg.ProjectsDir, strconv.FormatInt(newProjectID, 10))
	rollback := func() {
		_ = os.RemoveAll(newProjectPath)
		_ = s.store.DeleteProject(newProjectID)
	}

	if err := os.MkdirAll(newProjectPath, 0o775); err != nil {
		rollback()
		log.Printf("clone project mkdir failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	if err := copyProjectTree(sourceProject.Path, newProjectPath, includeSymlinks); err != nil {
		rollback()
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "复制项目文件失败"})
		return
	}
	if err := syncOwnership(newProjectPath, sourceProject.RunUser, true); err != nil {
		rollback()
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "复制成功，但设置目录所有者失败"})
		return
	}
	finalSlug := fmt.Sprintf("p%d", newProjectID)
	if err := s.store.UpdateProjectIdentity(newProjectID, finalSlug, newProjectPath); err != nil {
		rollback()
		log.Printf("clone update identity failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}

	entryFile := ""
	if sourceProject.EntryFile.Valid {
		entryFile = sourceProject.EntryFile.String
	}
	args := ""
	if sourceProject.Args.Valid {
		args = sourceProject.Args.String
	}
	if err := s.store.UpdateProjectConfig(newProjectID, entryFile, args, sourceProject.RunUser); err != nil {
		rollback()
		log.Printf("clone update config failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}

	newProject, err := s.store.GetProjectByID(newProjectID)
	if err != nil || newProject == nil {
		rollback()
		log.Printf("load cloned project failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	if newProject.EntryFile.Valid && strings.TrimSpace(newProject.EntryFile.String) != "" {
		if err := s.sup.ApplyProject(*newProject); err != nil {
			rollback()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "复制完成，但应用Supervisor配置失败：" + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"message":    "项目复制成功（新项目默认未启动）",
		"project_id": newProjectID,
	})
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		RelPath string `json:"rel_path"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	relPath := normalizeUploadRelPath(req.RelPath)
	if relPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	targetPath, err := safeJoin(project.Path, relPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件不存在或无权限访问：" + err.Error()})
		return
	}
	if info.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "仅支持删除文件"})
		return
	}
	if err := os.Remove(targetPath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "删除失败：" + err.Error()})
		return
	}
	cleanupEmptyParents(project.Path, filepath.Dir(targetPath))

	if project.EntryFile.Valid && project.EntryFile.String == relPath {
		args := ""
		if project.Args.Valid {
			args = project.Args.String
		}
		if err := s.store.UpdateProjectConfig(project.ID, "", args, project.RunUser); err == nil {
			_ = s.sup.RemoveProject(project.Slug)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "文件已删除，主程序配置已清空"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "文件已删除"})
}

func (s *Server) handleSetExecutable(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		RelPath    string `json:"rel_path"`
		Executable bool   `json:"executable"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	relPath := normalizeUploadRelPath(req.RelPath)
	if relPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	targetPath, err := safeJoin(project.Path, relPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	info, err := os.Lstat(targetPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件不存在或无权限访问：" + err.Error()})
		return
	}
	if !info.Mode().IsRegular() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "仅支持设置普通文件的执行权限"})
		return
	}
	if err := setExecutable(targetPath, info.Mode(), req.Executable); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "设置执行权限失败：" + err.Error()})
		return
	}
	message := "已设为可执行"
	if !req.Executable {
		message = "已取消可执行"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": message, "executable": req.Executable})
}

func (s *Server) handleCreateDir(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		CurrentDir string `json:"current_dir"`
		Name       string `json:"name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	currentDir := normalizeUploadRelPath(req.CurrentDir)
	name := strings.TrimSpace(req.Name)
	if !isSimplePathName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件夹名称不合法"})
		return
	}
	targetRel := name
	if currentDir != "" {
		targetRel = filepath.ToSlash(filepath.Join(currentDir, name))
	}
	targetPath, err := safeJoin(project.Path, targetRel)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件夹路径不合法"})
		return
	}
	if err := os.MkdirAll(targetPath, 0o775); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "创建文件夹失败"})
		return
	}
	_ = syncOwnership(targetPath, project.RunUser, false)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "文件夹已创建"})
}

func (s *Server) handleCreateFile(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		CurrentDir string `json:"current_dir"`
		Name       string `json:"name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	currentDir := normalizeUploadRelPath(req.CurrentDir)
	name := strings.TrimSpace(req.Name)
	if !isSimplePathName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件名不合法"})
		return
	}
	targetRel := name
	if currentDir != "" {
		targetRel = filepath.ToSlash(filepath.Join(currentDir, name))
	}
	targetPath, err := safeJoin(project.Path, targetRel)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
		return
	}
	if _, err := os.Stat(targetPath); err == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件已存在"})
		return
	}
	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o664)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "创建文件失败"})
		return
	}
	_ = f.Close()
	_ = syncOwnership(targetPath, project.RunUser, false)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "文件已创建"})
}

func (s *Server) handleRenameEntry(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		RelPath string `json:"rel_path"`
		NewName string `json:"new_name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	relPath := normalizeUploadRelPath(req.RelPath)
	if relPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "路径不合法"})
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if !isSimplePathName(newName) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "新名称不合法"})
		return
	}
	sourcePath, err := safeJoin(project.Path, relPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "路径不合法"})
		return
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目标不存在或无权限访问"})
		return
	}
	parentRel := filepath.ToSlash(filepath.Dir(relPath))
	if parentRel == "." {
		parentRel = ""
	}
	targetRel := newName
	if parentRel != "" {
		targetRel = filepath.ToSlash(filepath.Join(parentRel, newName))
	}
	if targetRel == relPath {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"message":       "名称未变化",
			"new_path":      targetRel,
			"current_entry": strings.TrimSpace(project.EntryFile.String),
		})
		return
	}
	targetPath, err := safeJoin(project.Path, targetRel)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目标路径不合法"})
		return
	}
	if _, err := os.Stat(targetPath); err == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目标名称已存在"})
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "无法检查目标路径"})
		return
	}
	if err := os.Rename(sourcePath, targetPath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "重命名失败：" + err.Error()})
		return
	}
	_ = syncOwnership(targetPath, project.RunUser, info.IsDir())

	currentEntry := ""
	if project.EntryFile.Valid {
		currentEntry = strings.TrimSpace(project.EntryFile.String)
	}
	nextEntry, entryChanged := renamedEntryPath(currentEntry, relPath, targetRel, info.IsDir())
	message := "重命名成功"
	if entryChanged {
		args := ""
		if project.Args.Valid {
			args = project.Args.String
		}
		if err := s.store.UpdateProjectConfig(project.ID, nextEntry, args, project.RunUser); err != nil {
			message += "，但主程序配置更新失败，请手动重新设置主程序"
		} else {
			updatedProject, getErr := s.store.GetProjectByID(project.ID)
			if getErr != nil || updatedProject == nil {
				message += "，但主程序配置刷新失败，请稍后检查"
			} else if err := s.sup.ApplyProject(*updatedProject); err != nil {
				message += "，但应用Supervisor失败：" + err.Error()
			}
		}
		currentEntry = nextEntry
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"message":       message,
		"new_path":      targetRel,
		"current_entry": currentEntry,
	})
}

func (s *Server) handleDeleteDir(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		RelPath string `json:"rel_path"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	relPath := normalizeUploadRelPath(req.RelPath)
	if relPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目录路径不合法"})
		return
	}
	targetPath, err := safeJoin(project.Path, relPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目录路径不合法"})
		return
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目录不存在或无权限访问"})
		return
	}
	if !info.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "目标不是目录"})
		return
	}
	if err := os.RemoveAll(targetPath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "删除目录失败"})
		return
	}
	cleanupEmptyParents(project.Path, filepath.Dir(targetPath))

	if project.EntryFile.Valid {
		entry := strings.TrimSpace(project.EntryFile.String)
		if entry == relPath || strings.HasPrefix(entry, relPath+"/") {
			args := ""
			if project.Args.Valid {
				args = project.Args.String
			}
			if err := s.store.UpdateProjectConfig(project.ID, "", args, project.RunUser); err == nil {
				_ = s.sup.RemoveProject(project.Slug)
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "目录已删除，主程序配置已清空"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "目录已删除"})
}

func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request, projectID int64) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}
	currentDir := normalizeUploadRelPath(r.URL.Query().Get("dir"))
	relPath := normalizeUploadRelPath(r.URL.Query().Get("path"))
	if relPath == "" {
		http.Redirect(w, r, projectDirURL(projectID, currentDir, "error", "文件路径不合法"), http.StatusFound)
		return
	}
	targetPath, err := safeJoin(project.Path, relPath)
	if err != nil {
		http.Redirect(w, r, projectDirURL(projectID, currentDir, "error", "文件路径不合法"), http.StatusFound)
		return
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		http.Redirect(w, r, projectDirURL(projectID, currentDir, "error", "文件不存在或无权限访问"), http.StatusFound)
		return
	}
	if info.IsDir() {
		http.Redirect(w, r, projectDirURL(projectID, currentDir, "error", "仅支持下载文件"), http.StatusFound)
		return
	}
	fileName := filepath.Base(relPath)
	attachment := fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", fileName, url.QueryEscape(fileName))
	w.Header().Set("Content-Disposition", attachment)
	http.ServeFile(w, r, targetPath)
}

func (s *Server) handleEditFile(w http.ResponseWriter, r *http.Request, projectID int64) {
	project, err := s.store.GetProjectByID(projectID)
	if err != nil || project == nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.serveSPA(w, r)
		return

	case http.MethodPost:
		if !requireAJAX(w, r) {
			return
		}
		var req struct {
			Path      string `json:"path"`
			Content   string `json:"content"`
			MtimeNano string `json:"mtime_nano"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
			return
		}
		relPath := normalizeUploadRelPath(req.Path)
		content := req.Content
		if relPath == "" || !isEditableTextFile(relPath) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "该文件类型不支持在线编辑"})
			return
		}
		if len(content) > maxEditableFileSize {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件超过1MB，禁止在线编辑"})
			return
		}
		filePath, err := safeJoin(project.Path, relPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件路径不合法"})
			return
		}
		info, err := os.Stat(filePath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "文件不存在"})
			return
		}
		mtimeNano := strings.TrimSpace(req.MtimeNano)
		if mtimeNano != "" && mtimeNano != "0" {
			expectedMtime, err := strconv.ParseInt(mtimeNano, 10, 64)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
				return
			}
			if expectedMtime != info.ModTime().UnixNano() {
				writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "文件已被其他操作修改，请刷新后重试"})
				return
			}
		}
		bytesContent := []byte(content)
		if !isTextContent(bytesContent) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "内容包含非文本数据"})
			return
		}
		if err := writeFileAtomic(filePath, bytesContent, info.Mode()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "保存失败：" + err.Error()})
			return
		}
		if err := syncOwnership(filePath, project.RunUser, false); err != nil {
			log.Printf("warn: sync ownership failed after edit: %v", err)
		}
		st, statErr := os.Stat(filePath)
		nextMtime := int64(0)
		if statErr == nil {
			nextMtime = st.ModTime().UnixNano()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "保存成功", "mtime_nano": strconv.FormatInt(nextMtime, 10)})
		return

	default:
		http.NotFound(w, r)
		return
	}
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.serveSPA(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !requireAJAX(w, r) {
		return
	}
	adminID, ok := adminIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "请求参数错误"})
		return
	}
	current := req.CurrentPassword
	newPass := req.NewPassword
	if len(strings.TrimSpace(newPass)) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "新密码至少8位"})
		return
	}
	admin, err := s.store.GetAdminByID(adminID)
	if err != nil || admin == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "管理员不存在"})
		return
	}
	if auth.VerifyPassword(admin.PasswordHash, current) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "当前密码错误"})
		return
	}
	hash, err := auth.HashPassword(newPass)
	if err != nil {
		log.Printf("hash password failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	if err := s.store.UpdateAdminPassword(adminID, hash); err != nil {
		log.Printf("update password failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": "服务器内部错误"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "密码修改成功"})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie(s.cfg.SessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			if isAJAXRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sess, err := s.store.GetSession(cookie.Value)
		if err != nil || sess == nil {
			if isAJAXRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if time.Now().After(sess.ExpiresAt) {
			_ = s.store.DeleteSession(sess.Token)
			if isAJAXRequest(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), adminIDKey, sess.AdminID)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cfg.SessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
			return
		}
		sess, err := s.store.GetSession(cookie.Value)
		if err != nil || sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
			return
		}
		if time.Now().After(sess.ExpiresAt) {
			_ = s.store.DeleteSession(sess.Token)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "message": "未登录或会话已过期"})
			return
		}
		ctx := context.WithValue(r.Context(), adminIDKey, sess.AdminID)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.Error(w, "static assets unavailable", http.StatusInternalServerError)
		return
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	content, err := fs.ReadFile(staticFS, "static/index.html")
	if err != nil {
		http.Error(w, "frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(content)
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("server error: %v", err)
	http.Error(w, "服务器内部错误", http.StatusInternalServerError)
}

func adminIDFromContext(ctx context.Context) (int64, bool) {
	v := ctx.Value(adminIDKey)
	id, ok := v.(int64)
	return id, ok
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func listProjectFiles(projectPath string) ([]string, error) {
	list := make([]string, 0, 64)
	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(projectPath, path)
		if err != nil {
			return nil
		}
		list = append(list, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(list)
	return list, nil
}

func listProjectDirEntries(projectRoot, currentDir, currentEntry string) ([]ProjectDirEntry, string, []BreadcrumbItem, error) {
	var dirPath string
	var err error
	if strings.TrimSpace(currentDir) == "" {
		dirPath = projectRoot
		currentDir = ""
	} else {
		dirPath, err = safeJoin(projectRoot, currentDir)
		if err != nil {
			return nil, "", nil, fmt.Errorf("目录路径不合法")
		}
	}
	stat, err := os.Stat(dirPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil, fmt.Errorf("目录不存在")
		}
		return nil, "", nil, err
	}
	if !stat.IsDir() {
		return nil, "", nil, fmt.Errorf("目标不是目录")
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, "", nil, err
	}
	items := make([]ProjectDirEntry, 0, len(entries))
	for _, ent := range entries {
		info, err := ent.Info()
		if err != nil {
			return nil, "", nil, err
		}
		name := ent.Name()
		relPath := name
		if currentDir != "" {
			relPath = filepath.ToSlash(filepath.Join(currentDir, name))
		}
		fullPath := filepath.Join(dirPath, name)
		item := ProjectDirEntry{
			Name:       name,
			Path:       relPath,
			IsDir:      ent.IsDir(),
			Executable: !ent.IsDir() && info.Mode().Perm()&0o111 != 0,
			Editable:   !ent.IsDir() && isEditableTextFile(relPath),
			IsCurrent:  !ent.IsDir() && relPath == currentEntry,
			Size:       info.Size(),
			Owner:      fileOwner(fullPath, info),
			ModifiedAt: info.ModTime(),
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	parentDir := ""
	if currentDir != "" {
		parentDir = filepath.ToSlash(filepath.Dir(currentDir))
		if parentDir == "." {
			parentDir = ""
		}
	}

	breadcrumbs := make([]BreadcrumbItem, 0, 8)
	breadcrumbs = append(breadcrumbs, BreadcrumbItem{Name: "根目录", Dir: ""})
	if currentDir != "" {
		parts := strings.Split(currentDir, "/")
		acc := ""
		for _, part := range parts {
			if strings.TrimSpace(part) == "" {
				continue
			}
			if acc == "" {
				acc = part
			} else {
				acc = acc + "/" + part
			}
			breadcrumbs = append(breadcrumbs, BreadcrumbItem{Name: part, Dir: acc})
		}
	}

	return items, parentDir, breadcrumbs, nil
}

func normalizeUploadRelPath(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.ReplaceAll(v, "\\", "/")
	v = filepath.ToSlash(filepath.Clean(v))
	v = strings.TrimPrefix(v, "./")
	v = strings.TrimPrefix(v, "/")
	if v == "." || strings.HasPrefix(v, "../") || strings.Contains(v, ":") {
		return ""
	}
	return v
}

func safeJoin(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	target := filepath.Join(base, filepath.FromSlash(rel))
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if !isPathWithinBase(baseAbs, targetAbs) {
		return "", fmt.Errorf("path escapes project dir")
	}
	return targetAbs, nil
}

func isPathWithinBase(baseAbs, targetAbs string) bool {
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return true
	}
	if strings.HasPrefix(rel, "../") {
		return false
	}
	if runtime.GOOS == "windows" && strings.Contains(rel, ":") {
		return false
	}
	return true
}

func cleanupEmptyParents(projectBase, startDir string) {
	baseAbs, err := filepath.Abs(projectBase)
	if err != nil {
		return
	}
	current, err := filepath.Abs(startDir)
	if err != nil {
		return
	}
	for isPathWithinBase(baseAbs, current) && current != baseAbs {
		entries, readErr := os.ReadDir(current)
		if readErr != nil || len(entries) > 0 {
			return
		}
		if removeErr := os.Remove(current); removeErr != nil {
			return
		}
		current = filepath.Dir(current)
	}
}

func renamedEntryPath(currentEntry, fromRel, toRel string, isDir bool) (string, bool) {
	currentEntry = strings.TrimSpace(currentEntry)
	if currentEntry == "" {
		return "", false
	}
	if !isDir {
		if currentEntry == fromRel {
			return toRel, true
		}
		return currentEntry, false
	}
	if currentEntry == fromRel {
		return toRel, true
	}
	prefix := fromRel + "/"
	if strings.HasPrefix(currentEntry, prefix) {
		return toRel + currentEntry[len(fromRel):], true
	}
	return currentEntry, false
}

func isEditableTextFile(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	if base == ".env" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".txt", ".json", ".yaml", ".yml", ".ini", ".conf", ".toml", ".md", ".log", ".xml", ".csv", ".properties":
		return true
	default:
		return false
	}
}

func isTextContent(content []byte) bool {
	if len(content) > maxEditableFileSize {
		return false
	}
	if strings.ContainsRune(string(content), '\x00') {
		return false
	}
	return utf8.Valid(content)
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sp-edit-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func parseBoolForm(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func copyProjectTree(srcRoot, dstRoot string, includeSymlinks bool) error {
	return filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o775)
		}
		if d.Type()&os.ModeSymlink != 0 {
			if !includeSymlinks {
				return nil
			}
			if runtime.GOOS == "windows" {
				return nil
			}
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, dstPath)
		}
		if err := copyRegularFile(path, dstPath); err != nil {
			return err
		}
		return nil
	})
}

func copyRegularFile(srcPath, dstPath string) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o775); err != nil {
		return err
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return nil
}

func syncOwnership(path, username string, recursive bool) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	usr, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", username, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return fmt.Errorf("parse gid: %w", err)
	}
	chownOne := func(current string) error {
		if err := os.Chown(current, uid, gid); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return err
		}
		return nil
	}
	if !recursive {
		return chownOne(path)
	}
	return filepath.WalkDir(path, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return chownOne(current)
	})
}

func ensureExecutable(path string, mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	targetMode := mode | 0o111
	if targetMode == mode {
		return nil
	}
	return os.Chmod(path, targetMode)
}

func setExecutable(path string, mode os.FileMode, executable bool) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("当前系统不支持设置执行权限")
	}
	targetMode := mode
	if executable {
		targetMode |= 0o111
	} else {
		targetMode &^= 0o111
	}
	if targetMode == mode {
		return nil
	}
	return os.Chmod(path, targetMode)
}

func (s *Server) respondUploadResult(w http.ResponseWriter, r *http.Request, projectID int64, receivedCount, savedCount int, message string, isError bool, failSummary string) {
	_ = r
	status := http.StatusOK
	if isError {
		status = http.StatusBadRequest
	}
	failedCount := receivedCount - savedCount
	if failedCount < 0 {
		failedCount = 0
	}
	writeJSON(w, status, map[string]any{
		"ok":             !isError,
		"count":          savedCount,
		"received_count": receivedCount,
		"saved_count":    savedCount,
		"failed_count":   failedCount,
		"failed_summary": failSummary,
		"message":        message,
		"redirect":       fmt.Sprintf("/projects/%d", projectID),
	})
}

func summarizeFailReasons(reasonCount map[string]int) string {
	if len(reasonCount) == 0 {
		return ""
	}
	parts := make([]string, 0, len(reasonCount))
	for reason, cnt := range reasonCount {
		parts = append(parts, fmt.Sprintf("%s:%d", reason, cnt))
	}
	sort.Strings(parts)
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "，")
}

func (s *Server) respondProjectConfigResult(w http.ResponseWriter, r *http.Request, projectID int64, message string, isError bool, currentEntry string) {
	_ = r
	_ = projectID
	status := http.StatusOK
	if isError {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]any{
		"ok":            !isError,
		"message":       message,
		"current_entry": currentEntry,
	})
}

func decodeJSONBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("invalid json body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func requireAJAX(w http.ResponseWriter, r *http.Request) bool {
	if isAJAXRequest(r) {
		return true
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "仅支持AJAX请求"})
	return false
}

func isAJAXRequest(r *http.Request) bool {
	xrw := strings.TrimSpace(r.Header.Get("X-Requested-With"))
	if strings.EqualFold(xrw, "XMLHttpRequest") {
		return true
	}
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	return strings.Contains(accept, "application/json")
}

func writeSSEEvent(w io.Writer, event string, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
}

func readLogChunk(path string, offset, maxBytes int64) (string, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", offset, err
	}
	size := st.Size()
	if size < offset {
		offset = 0
	}
	if size == offset {
		return "", offset, nil
	}
	readSize := size - offset
	if readSize > maxBytes {
		readSize = maxBytes
	}
	file, err := os.Open(path)
	if err != nil {
		return "", offset, err
	}
	defer file.Close()
	buf := make([]byte, readSize)
	n, err := file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return "", offset, err
	}
	if n <= 0 {
		return "", offset, nil
	}
	chunk := strings.ReplaceAll(string(buf[:n]), "\r\n", "\n")
	return chunk, offset + int64(n), nil
}

func isSimplePathName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, ":") {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	return true
}

func projectDirURL(projectID int64, dir, key, value string) string {
	url := fmt.Sprintf("/projects/%d", projectID)
	params := make([]string, 0, 2)
	if strings.TrimSpace(dir) != "" {
		params = append(params, "dir="+urlEscape(dir))
	}
	if strings.TrimSpace(key) != "" {
		params = append(params, key+"="+urlEscape(value))
	}
	if len(params) == 0 {
		return url
	}
	return url + "?" + strings.Join(params, "&")
}

func detectRuntimeUser(preferred string) string {
	preferred = strings.TrimSpace(preferred)
	if preferred == "" {
		preferred = "www-data"
	}
	if _, err := user.Lookup(preferred); err == nil {
		return preferred
	}
	if _, err := user.Lookup("root"); err == nil {
		return "root"
	}
	return preferred
}

func urlEscape(v string) string {
	replacer := strings.NewReplacer("%", "%25", " ", "%20", "&", "%26", "?", "%3F", "#", "%23", "+", "%2B")
	return replacer.Replace(v)
}

func statusTextCN(status string) string {
	v := strings.ToUpper(strings.TrimSpace(status))
	switch v {
	case "RUNNING":
		return "运行中"
	case "STOPPED":
		return "已停止"
	case "EXITED":
		return "已退出"
	case "STARTING":
		return "启动中"
	case "STOPPING":
		return "停止中"
	case "BACKOFF":
		return "启动失败(重试中)"
	case "FATAL":
		return "启动失败"
	case "UNKNOWN", "":
		return "未知"
	default:
		return v
	}
}
