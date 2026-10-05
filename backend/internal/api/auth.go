package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/konghanghang/openlist-strm/internal/config"
	"github.com/konghanghang/openlist-strm/internal/logger"
)

const (
	sessionCookieName = "olstrm_session"
	sessionTTL        = 7 * 24 * time.Hour
	sessionKeyFile    = "session.key"

	loginMaxFailures  = 5
	loginLockDuration = 15 * time.Minute
	loginFailureDelay = 500 * time.Millisecond

	defaultWebUsername = "admin"
	defaultWebPassword = "admin123"
)

var errInvalidSession = errors.New("invalid session")

// authManager 负责 Web UI 登录会话：签发 / 校验 HMAC 签名的无状态 Cookie。
// 签名密钥 = HMAC(持久化随机密钥, 用户名+密码)，修改密码后旧会话自动失效。
type authManager struct {
	enabled  bool
	username string
	password string
	key      []byte
	limiter  *loginLimiter
	now      func() time.Time
}

func newAuthManager(cfg *config.Config) *authManager {
	username := cfg.Web.Username
	if username == "" {
		username = defaultWebUsername
	}

	m := &authManager{
		enabled:  cfg.Web.Password != "",
		username: username,
		password: cfg.Web.Password,
		limiter:  newLoginLimiter(),
		now:      time.Now,
	}

	if !m.enabled {
		logger.Warn.Println("Web 登录未启用（web.password 为空），管理面板与 API 处于无保护状态，请勿直接暴露到公网")
		return m
	}

	secret := loadOrCreateSessionSecret(cfg.Database.Path)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(m.username + "\x00" + m.password))
	m.key = mac.Sum(nil)

	if m.password == defaultWebPassword {
		logger.Warn.Println("Web 登录仍在使用默认密码，请尽快修改配置文件中的 web.password")
	}
	logger.Info.Printf("Web 登录已启用，用户名: %s，会话有效期: %s", m.username, sessionTTL)
	return m
}

// loadOrCreateSessionSecret 读取与数据库同目录的会话密钥，不存在则生成。
// 持久化失败时退化为进程内随机密钥，仅影响“重启后需重新登录”。
func loadOrCreateSessionSecret(dbPath string) []byte {
	keyPath := filepath.Join(filepath.Dir(dbPath), sessionKeyFile)

	if data, err := os.ReadFile(keyPath); err == nil && len(data) >= 32 {
		return data
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("failed to generate session secret: %v", err))
	}

	if err := os.WriteFile(keyPath, secret, 0o600); err != nil {
		logger.Warn.Printf("无法持久化会话密钥到 %s: %v（重启后需要重新登录）", keyPath, err)
	} else {
		logger.Info.Printf("已生成新的会话密钥: %s", keyPath)
	}
	return secret
}

func (m *authManager) checkCredentials(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(m.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(m.password)) == 1
	return userOK && passOK
}

func (m *authManager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *authManager) issueToken() (string, time.Time) {
	expires := m.now().Add(sessionTTL)
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(m.username + "|" + strconv.FormatInt(expires.Unix(), 10)),
	)
	return payload + "." + m.sign(payload), expires
}

func (m *authManager) verifyToken(token string) (string, error) {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || payload == "" || sig == "" {
		return "", errInvalidSession
	}
	if !hmac.Equal([]byte(sig), []byte(m.sign(payload))) {
		return "", errInvalidSession
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", errInvalidSession
	}
	username, expStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return "", errInvalidSession
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || m.now().Unix() >= exp {
		return "", errInvalidSession
	}
	return username, nil
}

// sessionUser 返回当前请求的已登录用户名；未登录返回空串。
func (m *authManager) sessionUser(c *gin.Context) string {
	token, err := c.Cookie(sessionCookieName)
	if err != nil || token == "" {
		return ""
	}
	username, err := m.verifyToken(token)
	if err != nil {
		return ""
	}
	return username
}

func isSecureRequest(c *gin.Context) bool {
	return c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

func setSessionCookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
}

// loginLimiter 按客户端 IP 统计连续失败次数，超过阈值后临时锁定。
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

type loginAttempt struct {
	failures    int
	lockedUntil time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginAttempt)}
}

// retryAfter 返回剩余锁定时长；0 表示允许尝试。
func (l *loginLimiter) retryAfter(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok || entry.lockedUntil.IsZero() {
		return 0
	}
	if now.Before(entry.lockedUntil) {
		return entry.lockedUntil.Sub(now)
	}
	delete(l.entries, ip)
	return 0
}

// recordFailure 记录一次失败，返回是否因此触发锁定。
func (l *loginLimiter) recordFailure(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok {
		entry = &loginAttempt{}
		l.entries[ip] = entry
	}
	entry.failures++
	if entry.failures >= loginMaxFailures {
		entry.lockedUntil = now.Add(loginLockDuration)
		return true
	}
	return false
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin POST /api/auth/login
func (s *Server) handleLogin(c *gin.Context) {
	if !s.auth.enabled {
		c.JSON(http.StatusOK, gin.H{"authenticated": true, "auth_enabled": false})
		return
	}

	ip := c.ClientIP()
	if wait := s.auth.limiter.retryAfter(ip, s.auth.now()); wait > 0 {
		minutes := int(wait.Minutes()) + 1
		c.Header("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试", minutes),
		})
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入用户名和密码"})
		return
	}

	if !s.auth.checkCredentials(req.Username, req.Password) {
		locked := s.auth.limiter.recordFailure(ip, s.auth.now())
		logger.Warn.Printf("Web 登录失败: ip=%s username=%q locked=%v", ip, req.Username, locked)
		time.Sleep(loginFailureDelay)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	s.auth.limiter.reset(ip)
	token, expires := s.auth.issueToken()
	setSessionCookie(c, token, int(time.Until(expires).Seconds()))
	logger.Info.Printf("Web 登录成功: ip=%s username=%s", ip, s.auth.username)

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"auth_enabled":  true,
		"username":      s.auth.username,
	})
}

// handleLogout POST /api/auth/logout
func (s *Server) handleLogout(c *gin.Context) {
	setSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"authenticated": false})
}

// handleAuthStatus GET /api/auth/status
func (s *Server) handleAuthStatus(c *gin.Context) {
	if !s.auth.enabled {
		c.JSON(http.StatusOK, gin.H{"auth_enabled": false, "authenticated": true})
		return
	}
	username := s.auth.sessionUser(c)
	c.JSON(http.StatusOK, gin.H{
		"auth_enabled":  true,
		"authenticated": username != "",
		"username":      username,
	})
}

// validAPIToken 判断请求是否携带了正确的 API Token（仅在配置了 api.token 时有效）。
func (s *Server) validAPIToken(c *gin.Context) bool {
	expected := s.cfg.API.Token
	if expected == "" {
		return false
	}
	token := c.GetHeader("X-API-Token")
	if token == "" {
		token = c.GetHeader("Authorization")
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// adminAuthMiddleware 保护管理类 API：
//   - 启用 Web 登录时：有效会话 Cookie 或有效 API Token 二者满足其一即可
//   - 未启用 Web 登录时：沿用原有行为（配置了 api.token 才校验）
func (s *Server) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.auth.enabled {
			if s.cfg.API.Token != "" && !s.validAPIToken(c) {
				abortUnauthorized(c, "invalid or missing API token")
				return
			}
			c.Next()
			return
		}

		if s.auth.sessionUser(c) != "" || s.validAPIToken(c) {
			c.Next()
			return
		}
		abortUnauthorized(c, "未登录或登录已过期")
	}
}

func abortUnauthorized(c *gin.Context, msg string) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": msg})
	c.Abort()
}
