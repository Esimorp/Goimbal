package test

import (
	"os/exec"
	"testing"
	"time"

	_ "github.com/Esimorp/Goimbal/apps/core"    // 注册 App 和 Global Option
	_ "github.com/Esimorp/Goimbal/modules/auth" // 注册 Auth Handler
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// 辅助函数：生成测试用的 JWT
func generateToken(uid, role, ctyp, jti, secret string, aud string, iat int64) string {
	claims := jwt.MapClaims{
		"uid":  uid,
		"role": role,
		"ctyp": ctyp,
		"jti":  jti,
		"iat":  iat,
		"aud":  aud,
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString([]byte(secret))
	return ss
}

func TestAuthE2E(t *testing.T) {
	// 强制清理可能残留的僵尸进程
	_ = exec.Command("taskkill", "/F", "/IM", "caddy.exe").Run()

	tester := caddytest.NewTester(t)

	// 【关键抠点 1】显式指定 admin 端口，避免 caddytest 盲目寻找
	// 【关键抠点 2】必须加上 auto_https off，防止后台静默报错
	config := `
    {
       admin localhost:2999
       auto_https off
       goimbal {
          db_path ":memory:"
       }
       order goimbal_auth before respond
    }

    http://localhost:3000 {
       route /api/* {
          goimbal_auth {
             secret_key "super_secret"
             strategy "single"
             audience "my_app"
             anonymous_role "guest"
          }
          header +X-Goimbal-Role {http.request.header.X-Goimbal-Role}
          header +X-Goimbal-UID {http.request.header.X-Goimbal-UID}
          respond "Authorized" 200
       }
    }
    `

	// 【关键抠点 3】在 Init 之前，手动设置全局 Admin 地址
	// caddytest 默认找 2019，如果你改了配置，一定要同步给 tester
	// 注意：某些版本的 tester 变量名可能是 caddytest.DefaultAdminAddr

	tester.InitServer(config, "caddyfile")

	// 【关键抠点 4】等待 Caddy 内部完全 Active
	// Windows 的 I/O 较慢，给够时间让 Redka 初始化内存数据库
	time.Sleep(1 * time.Second)

	t.Run("PublicPath_NoToken", func(t *testing.T) {
		// 使用 tester 封装的方法，它会自动处理响应读取
		resp, _ := tester.AssertGetResponse("http://localhost:3000/api/public/hello", 200, "Authorized")

		assert.Equal(t, "guest", resp.Header.Get("X-Goimbal-Role"))
		assert.Equal(t, "anonymous", resp.Header.Get("X-Goimbal-UID"))
	})

}
