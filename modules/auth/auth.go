package auth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Esimorp/Goimbal/apps/core"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&Module{})
	httpcaddyfile.RegisterHandlerDirective("goimbal_auth", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Module
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Module 是 Goimbal 鉴权模块
// SecretKey 是 JWT 的密钥
// Strategy 是鉴权策略分为 sample 和 single
// Strategy:Sample  只验证jwt是否合法,jti是否在黑名单
// Strategy:Standard  验证iat是否大于logout_at
// Strategy:Single  在 iat 基础上校验 jti（确保同类设备只有一台在线）。
type Module struct {
	// 鉴权配置
	SecretKey string `json:"secret_key,omitempty"`
	Strategy  string `json:"strategy,omitempty"` // sample, single

	// RoleClaimKey 指定了获取用户角色的Claim Key
	RoleClaimKey string `json:"role_claim_key,omitempty"`
	// UidClaimKey 指定了获取用户ID的Claim Key
	UidClaimKey        string `json:"uid_claim_key,omitempty"`
	ClientTypeClaimKey string `json:"client_type_claim_key,omitempty"`

	// RoleGoimbalKey 指定了设置用户角色的Header Key
	RoleGoimbalKey string `json:"role_goimbal_key,omitempty"`
	// UidGoimbalKey 指定了设置用户ID的Header Key
	UidGoimbalKey string `json:"uid_goimbal_key,omitempty"`

	AnonymousRole    string   `json:"anonymous_role,omitempty"`
	ExpectedAudience string   `json:"audience,omitempty"`
	PublicPaths      []string `json:"public_paths,omitempty"`

	// 内部使用的快速匹配器
	repl     *caddy.Replacer
	matchers caddyhttp.MatcherSet
	engine   *core.GoimbalApp

	Output string `json:"output,omitempty"`
}

func (m *Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.goimbal_auth",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision 建立与大脑的连接
func (m *Module) Provision(ctx caddy.Context) error {
	app, err := ctx.App("goimbal")
	if err != nil {
		return err
	}
	m.engine = app.(*core.GoimbalApp)

	// 2. 设置 Claim 查找默认值
	if m.UidClaimKey == "" {
		m.UidClaimKey = "uid"
	}
	if m.RoleClaimKey == "" {
		m.RoleClaimKey = "role"
	}

	// 3. 设置 Header 注入默认值 (遵循 Goimbal 规范)
	if m.UidGoimbalKey == "" {
		m.UidGoimbalKey = "X-Goimbal-UID"
	}
	if m.RoleGoimbalKey == "" {
		m.RoleGoimbalKey = "X-Goimbal-Role"
	}

	if len(m.PublicPaths) > 0 {
		// 使用 MatchPath 创建匹配器，并赋值给 MatcherSet
		m.matchers = caddyhttp.MatcherSet{
			caddyhttp.MatchPath(m.PublicPaths),
		}
	}

	return nil
}

func (m *Module) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// 定义字段与指针的映射
	stringFields := map[string]*string{
		"secret_key":            &m.SecretKey,
		"strategy":              &m.Strategy,
		"role_claim_key":        &m.RoleClaimKey,
		"uid_claim_key":         &m.UidClaimKey,
		"role_goimbal_key":      &m.RoleGoimbalKey,
		"uid_goimbal_key":       &m.UidGoimbalKey,
		"client_type_claim_key": &m.ClientTypeClaimKey,
		"anonymous_role":        &m.AnonymousRole,
		"audience":              &m.ExpectedAudience,
	}

	for d.Next() {
		for d.NextBlock(0) {
			sub := d.Val()

			// 1. 处理普通字符串字段
			if ptr, ok := stringFields[sub]; ok {
				if !d.Args(ptr) {
					return d.ArgErr()
				}
				continue
			}

			// 2. 处理特殊字段（如切片或逻辑分支）
			switch sub {
			case "public_paths":
				m.PublicPaths = d.RemainingArgs()
				if len(m.PublicPaths) == 0 {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown subdirective '%s'", sub)
			}
		}
	}
	return nil
}

func (m *Module) setUid(r *http.Request, uid string) {
	if uid != "" {
		caddyhttp.SetVar(r.Context(), "goimbal_uid", uid)
		r.Header.Set(m.UidGoimbalKey, uid)
	}
}

func (m *Module) setRole(r *http.Request, role string) {
	if role != "" {
		caddyhttp.SetVar(r.Context(), "goimbal_role", role)
		r.Header.Set(m.RoleGoimbalKey, role)
	}
}
func (m *Module) setIdentity(r *http.Request, uid, role string) {
	r.Header.Set(m.UidGoimbalKey, uid)
	r.Header.Set(m.RoleGoimbalKey, role)

	// 注入 Context (留给 Caddy 内部后续插件)
	m.engine.SetIdentity(r, uid, role)
}

func (m *Module) BanUser(uid string) error {
	return m.engine.GetDB().Str().Set("banned:uid:"+uid, "1")
}

// IsUserBanned 检查用户是否在黑名单
func (m *Module) IsUserBanned(uid string) bool {
	exists, _ := m.engine.GetDB().Str().Get("banned:uid:" + uid)
	return exists != nil
}

func (m *Module) RevokeToken(jti string) error {
	return m.engine.GetDB().Str().Set("banned:jti:"+jti, "1")
}

func (m *Module) IsTokenRevoked(jti string) bool {
	exists, _ := m.engine.GetDB().Str().Get("banned:jti:" + jti)
	return exists != nil
}

func (m *Module) isIatExpired(uid string, iat int64) bool {
	// 从大脑获取 logoff:{uid} 的时间戳
	val, err := m.engine.GetDB().Str().Get("logoff:uid:" + uid)
	if err != nil || val == nil {
		return false // 没有设置过登出时间，视为有效
	}

	// 将存储的字符串时间戳转为 int64
	cutoff, err := strconv.ParseInt(val.String(), 10, 64)
	if err != nil {
		return false // 如果格式不对，不拦截（安全起见，防止 DB 脏数据导致无法登录）
	}

	// 如果签发时间 (iat) 小于 截止时间 (cutoff)，说明是旧 Token
	return iat < cutoff
}

func (m *Module) isLatestSession(uid, clientType, jti string) bool {
	if jti == "" {
		return false
	}

	// 从大脑获取 active:{uid}:{clientType} 存储的最新 JTI
	val, err := m.engine.GetDB().Str().Get("active:" + uid + ":" + clientType)
	if err != nil || val == nil {
		// 如果 DB 里没记录（可能被手动删了），出于安全考虑应判定为无效
		return false
	}

	// 只有当传入的 JTI 与 DB 中保存的最新的 JTI 完全一致时才放行
	return val.String() == jti
}

func (m *Module) authenticate(r *http.Request) error {
	tokenStr := m.extractToken(r)
	m.engine.GetLogger().Info("auth_request authenticate", zap.String("token", tokenStr))

	if tokenStr == "" {
		if m.AnonymousRole != "" {
			m.engine.GetLogger().Info("auth_request m.AnonymousRole", zap.String("AnonymousRole", m.AnonymousRole))

			m.setIdentity(r, "anonymous", m.AnonymousRole)
			return nil
		}
		return fmt.Errorf("missing_token")
	}

	// JWT 解析
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return []byte(m.SecretKey), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("invalid_token")
	}

	if m.ExpectedAudience != "" {
		auds, _ := claims.GetAudience() // jwt-go v5 推荐写法

		found := false
		for _, a := range auds {
			if a == m.ExpectedAudience {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("invalid_audience: expected %s", m.ExpectedAudience)
		}
	}

	// 提取核心 Claim
	uid := core.ToString(claims[m.UidClaimKey])
	jti, _ := claims["jti"].(string)
	ctyp := core.ToString(claims[m.ClientTypeClaimKey])
	if ctyp == "" {
		ctyp = "default"
	}

	// --- 大脑联动：三级防御 ---

	// 第一级：全局 UID 黑名单 (由 ga.IsUserBanned 处理)
	if m.IsUserBanned(uid) {
		return fmt.Errorf("account_locked")
	}

	// 第二级：JTI 级黑名单 (手动注销的 Token)
	if m.IsTokenRevoked(jti) {
		return fmt.Errorf("token_revoked")
	}

	// 第三级：策略判定 (IAT/Single-Point)
	if m.Strategy == "standard" || m.Strategy == "single" {
		// 校验 IAT 是否过期（全局登出逻辑）
		iat, _ := claims["iat"].(float64)
		if m.isIatExpired(uid, int64(iat)) {
			return fmt.Errorf("session_expired_by_logout")
		}
	}

	if m.Strategy == "single" {
		// 校验是否为该平台最新 Session
		if !m.isLatestSession(uid, ctyp, jti) {
			return fmt.Errorf("session_preempted")
		}
	}

	// 全部通过，注入身份
	role := core.ToString(claims[m.RoleClaimKey])
	m.setIdentity(r, uid, role)

	// 清理 Authorization Header，保护后端不被干扰
	r.Header.Del("Authorization")
	return nil
}

func (m *Module) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logger := m.engine.GetLogger() // 从大脑获取统一日志句柄
	logger.Info("auth_request")
	// 1. 公共路径检查 (最快放行)
	if m.matchers != nil && m.matchers.Match(r) {
		// 如果是公共路径，尝试提取身份但即使失败也放行
		logger.Info("auth_request authenticate")
		_ = m.authenticate(r)
		return next.ServeHTTP(w, r)
	}
	logger.Info("auth_request not public")

	// 2. 执行核心鉴权
	err := m.authenticate(r)
	if err != nil {
		logger.Info("auth_request not err != nil")

		logger.Debug("auth_failed",
			zap.String("remote_ip", r.RemoteAddr),
			zap.String("path", r.URL.Path),
			zap.Error(err))

		// 根据错误类型细化状态码
		if err.Error() == "account_locked" {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return next.ServeHTTP(w, r)
}

// extractToken 辅助函数：从多种渠道寻找凭证
func (m *Module) extractToken(r *http.Request) string {
	// 优先从 Header 寻找: Authorization: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 其次从 Cookie 寻找 (HttpOnly 安全模式)
	if cookie, err := r.Cookie("goimbal_token"); err == nil {
		return cookie.Value
	}

	if queryToken := r.URL.Query().Get("goimbal_token"); queryToken != "" {
		return queryToken
	}
	return ""
}
