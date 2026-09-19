package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"supervisorpanel/internal/timesync"
)

type timeSyncService interface {
	Status(context.Context) timesync.Status
	Sync(context.Context, timesync.Request) (timesync.Status, error)
}

func (s *Server) handleAPISystemTime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": s.timeSync.Status(ctx)})
}

func (s *Server) handleAPISyncTime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// 限制为同源脚本请求，防止登录状态下被跨站表单触发校时。
	origin, originErr := url.Parse(r.Header.Get("Origin"))
	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" || r.Header.Get("Sec-Fetch-Site") == "cross-site" ||
		(r.Header.Get("Origin") != "" && (originErr != nil || !strings.EqualFold(origin.Host, r.Host) || (origin.Scheme != "https" && origin.Scheme != "http"))) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "message": "请从面板页面提交时间校准请求"})
		return
	}
	var request timesync.Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "时间校准参数无效"})
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "时间校准参数无效"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	status, err := s.timeSync.Sync(ctx, request)
	if err != nil {
		code := http.StatusInternalServerError
		var syncErr *timesync.Error
		if errors.As(err, &syncErr) {
			switch syncErr.Code {
			case "invalid_request":
				code = http.StatusBadRequest
			case "permission_denied":
				code = http.StatusForbidden
			case "unavailable":
				code = http.StatusServiceUnavailable
			case "busy":
				code = http.StatusConflict
			case "timeout":
				code = http.StatusGatewayTimeout
			}
		}
		writeJSON(w, code, map[string]any{"ok": false, "message": err.Error(), "time": status})
		return
	}
	// 配置生效与时钟完成同步是两个阶段；服务重启后内核可能保留旧的同步标记。
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "time": status,
		"message": "已启用 NTP 自动同步，请查看系统同步状态；时间调整由系统同步服务完成",
	})
}
