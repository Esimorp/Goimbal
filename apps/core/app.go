package core

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/nalgeon/redka"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&GoimbalApp{})
}

// GoimbalApp 是 Goimbal 的核心大脑
type GoimbalApp struct {
	// DBPath 是 SQLite/Redka 文件的存储路径
	DBPath string `json:"db_path,omitempty"`

	db     *redka.DB
	logger *zap.Logger
}

// CaddyModule 返回模块元数据
func (ga *GoimbalApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "goimbal",
		New: func() caddy.Module { return new(GoimbalApp) },
	}
}

// Provision 初始化 Redka 存储
func (ga *GoimbalApp) Provision(ctx caddy.Context) error {
	ga.logger = ctx.Logger(ga)

	if ga.DBPath == "" {
		ga.DBPath = "goimbal.db" // 默认文件名
	}

	// 开启 Redka 引擎
	db, err := redka.Open(ga.DBPath, nil)
	if err != nil {
		return fmt.Errorf("goimbal: failed to open storage: %v", err)
	}
	ga.db = db

	ga.logger.Info("Goimbal engine initialized",
		zap.String("db_path", ga.DBPath),
		zap.String("status", "stabilized"))

	return nil
}

// Start 启动 App 运行态
func (ga *GoimbalApp) Start() error {
	return nil
}
func (ga *GoimbalApp) Stop() error {
	if ga.db != nil {
		return ga.db.Close()
	}
	return nil
}

// Cleanup 优雅关闭，确保数据落盘
func (ga *GoimbalApp) Cleanup() error {
	return nil
}

// GetDB 导出给其他模块调用的接口
func (ga *GoimbalApp) GetDB() *redka.DB {
	return ga.db
}

func (ga *GoimbalApp) GetLogger() *zap.Logger {
	return ga.logger
}

// SetUserActiveSession 标记用户在特定端的活跃 JTI (单点登录核心)
func (ga *GoimbalApp) SetUserActiveSession(uid, clientType, jti string) error {
	key := fmt.Sprintf("active:%s:%s", uid, clientType)
	return ga.db.Str().Set(key, jti)
}

// CheckUserSessionValid 校验 Token 是否依然有效（未被踢，未过期）
func (ga *GoimbalApp) CheckUserSessionValid(uid, clientType, jti string) (bool, error) {
	key := fmt.Sprintf("active:%s:%s", uid, clientType)
	val, err := ga.db.Str().Get(key)
	if err != nil || val == nil {
		return true, nil // 如果没有记录，默认视为有效（或根据策略决定）
	}
	return val.String() == jti, nil
}

func (ga *GoimbalApp) SetIdentity(r *http.Request, uid string, role string) {
	caddyhttp.SetVar(r.Context(), "goimbal.uid", uid)
	caddyhttp.SetVar(r.Context(), "goimbal.role", role)
}

// BanUser 全局封禁用户

// 接口静态检查（防呆设计）
var (
	_ caddy.App          = (*GoimbalApp)(nil)
	_ caddy.Provisioner  = (*GoimbalApp)(nil)
	_ caddy.CleanerUpper = (*GoimbalApp)(nil)
)
