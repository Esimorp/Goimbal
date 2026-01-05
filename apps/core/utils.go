package core

import (
	"fmt"
	"strconv"
)

// ToString 将任意类型安全转换为字符串，特别针对 JWT 中的数字和 nil 进行处理
func ToString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case float64:
		// 解决 JWT 数字被解析为浮点数的问题 (123 -> "123")
		return strconv.FormatFloat(s, 'f', 0, 64)
	case int, int64:
		return fmt.Sprintf("%d", s)
	default:
		return fmt.Sprintf("%v", v)
	}
}
