package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/konghanghang/openlist-strm/internal/config"
	"github.com/konghanghang/openlist-strm/internal/logger"
)

func newAuthTestServer(t *testing.T, password, apiToken string) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	if err := logger.Init(&config.LogConfig{Level: "error"}); err != nil {
		t.Fatalf("logger init: %v", err)
	}

	cfg := &config.Config{
		API:      config.APIConfig{Token: apiToken},
		Web:      config.WebConfig{Username: "admin", Password: password},
		Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "test.db")},
	}
	s := &Server{cfg: cfg, router: gin.New(), auth: newAuthManager(cfg)}
	s.auth.limiter = newLoginLimiter()

	s.router.POST("/api/auth/login", s.handleLogin)
	s.router.GET("/api/auth/status", s.handleAuthStatus)
	protected := s.router.Group("/api", s.adminAuthMiddleware())
	protected.GET("/status", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return s
}

func doRequest(s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w
}

func sessionCookieFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	return ""
}

func TestAdminAuth_RejectsWithoutSession(t *testing.T) {
	s := newAuthTestServer(t, "secret", "")
	if w := doRequest(s, "GET", "/api/status", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAdminAuth_LoginThenAccess(t *testing.T) {
	s := newAuthTestServer(t, "secret", "")

	w := doRequest(s, "POST", "/api/auth/login", `{"username":"admin","password":"secret"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", w.Code, w.Body.String())
	}
	token := sessionCookieFrom(w)
	if token == "" {
		t.Fatal("expected session cookie")
	}

	cookie := map[string]string{"Cookie": sessionCookieName + "=" + token}
	if w := doRequest(s, "GET", "/api/status", "", cookie); w.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want 200", w.Code)
	}
	if w := doRequest(s, "GET", "/api/auth/status", "", cookie); !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("auth status body = %s", w.Body.String())
	}
}

func TestAdminAuth_WrongPassword(t *testing.T) {
	s := newAuthTestServer(t, "secret", "")
	w := doRequest(s, "POST", "/api/auth/login", `{"username":"admin","password":"nope"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if sessionCookieFrom(w) != "" {
		t.Fatal("must not issue cookie on failure")
	}
}

func TestAdminAuth_APITokenStillWorks(t *testing.T) {
	s := newAuthTestServer(t, "secret", "api-token")
	w := doRequest(s, "GET", "/api/status", "", map[string]string{"X-API-Token": "api-token"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestAdminAuth_DisabledKeepsLegacyBehavior(t *testing.T) {
	s := newAuthTestServer(t, "", "")
	if w := doRequest(s, "GET", "/api/status", "", nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestAuthManager_TamperedAndExpiredToken(t *testing.T) {
	s := newAuthTestServer(t, "secret", "")
	token, _ := s.auth.issueToken()

	if _, err := s.auth.verifyToken(token + "x"); err == nil {
		t.Fatal("tampered token must be rejected")
	}

	s.auth.now = func() time.Time { return time.Now().Add(sessionTTL + time.Minute) }
	if _, err := s.auth.verifyToken(token); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestLoginLimiter_LocksAfterMaxFailures(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	for i := 0; i < loginMaxFailures; i++ {
		l.recordFailure("1.2.3.4", now)
	}
	if l.retryAfter("1.2.3.4", now) <= 0 {
		t.Fatal("expected lock")
	}
	if l.retryAfter("1.2.3.4", now.Add(loginLockDuration+time.Second)) != 0 {
		t.Fatal("lock should expire")
	}
}
