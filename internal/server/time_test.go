package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"supervisorpanel/internal/config"
	"supervisorpanel/internal/db"
	"supervisorpanel/internal/timesync"
)

type fakeTimeSync struct {
	err     error
	calls   int
	request timesync.Request
}

func (f *fakeTimeSync) Status(context.Context) timesync.Status {
	return timesync.Status{ServerTime: "2026-09-20T12:00:00+08:00", Available: true}
}

func (f *fakeTimeSync) Sync(_ context.Context, request timesync.Request) (timesync.Status, error) {
	f.calls++
	f.request = request
	return timesync.Status{ServerTime: "2026-09-20T12:00:00+08:00", NTPEnabled: true}, f.err
}

func TestTimeRoutesAuthenticationAndRequestProtection(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateAdmin("测试管理员", "测试密码摘要"); err != nil {
		t.Fatal(err)
	}
	admin, err := store.GetAdminByUsername("测试管理员")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSession(db.Session{Token: "test-session", AdminID: admin.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, body, origin string
		login, ajax                      bool
		want, calls                      int
	}{
		{name: "未登录读取", method: "GET", path: "/api/system/time", want: 401},
		{name: "未登录校时", method: "POST", path: "/api/system/time/sync", want: 401},
		{name: "读取时间", method: "GET", path: "/api/system/time", login: true, want: 200},
		{name: "表单请求", method: "POST", path: "/api/system/time/sync", login: true, body: `{"mode":"system"}`, want: 403},
		{name: "跨站请求", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, origin: "https://other.example", body: `{"mode":"system"}`, want: 403},
		{name: "无效参数", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{`, want: 400},
		{name: "额外参数", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{"mode":"system","command":"date"}`, want: 400},
		{name: "多个对象", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{"mode":"system"}{}`, want: 400},
		{name: "超大请求", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{"server":"` + strings.Repeat("a", 1100) + `"}`, want: 400},
		{name: "系统校准", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{"mode":"system"}`, want: 202, calls: 1},
		{name: "自定义校准", method: "POST", path: "/api/system/time/sync", login: true, ajax: true, body: `{"mode":"custom","server":"ntp.example.com"}`, want: 202, calls: 1},
		{name: "禁止读取触发校时", method: "GET", path: "/api/system/time/sync", login: true, ajax: true, want: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeTimeSync{}
			s := &Server{cfg: config.Config{SessionCookieName: "sp_session"}, store: store, timeSync: service}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.login {
				r.AddCookie(&http.Cookie{Name: "sp_session", Value: "test-session"})
			}
			if tc.ajax {
				r.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			s.Routes().ServeHTTP(w, r)
			if w.Code != tc.want || service.calls != tc.calls {
				t.Fatalf("状态码 %d（期望 %d），命令调用 %d（期望 %d），响应 %s", w.Code, tc.want, service.calls, tc.calls, w.Body.String())
			}
			if tc.want == 200 && (!strings.Contains(w.Body.String(), "+08:00") || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatalf("时间响应应保留服务器时区且不可缓存：%s", w.Body.String())
			}
			if tc.name == "自定义校准" && service.request.Server != "ntp.example.com" {
				t.Fatalf("未传递自定义时间源：%+v", service.request)
			}
		})
	}
}

func TestTimeSyncErrors(t *testing.T) {
	for code, want := range map[string]int{
		"invalid_request": 400, "permission_denied": 403, "unavailable": 503,
		"busy": 409, "timeout": 504, "rollback_failed": 500,
	} {
		t.Run(code, func(t *testing.T) {
			s := &Server{timeSync: &fakeTimeSync{err: &timesync.Error{Code: code, Message: "校准失败"}}}
			r := httptest.NewRequest(http.MethodPost, "/api/system/time/sync", strings.NewReader(`{"mode":"system"}`))
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			w := httptest.NewRecorder()
			s.handleAPISyncTime(w, r)
			if w.Code != want || !strings.Contains(w.Body.String(), "校准失败") {
				t.Fatalf("错误响应不符：%d，%s", w.Code, w.Body.String())
			}
		})
	}
}
