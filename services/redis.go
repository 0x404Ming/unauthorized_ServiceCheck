package services

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"strings"
	"unauthorized_ServiceCheck/config"
)

// RedisChecker 实现 ServiceChecker 接口
type RedisChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (r *RedisChecker) Check(ip string) (bool, string) {
	var result strings.Builder
	var found bool

	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", ip, config.RedisPort),
	})

	_, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		result.WriteString(fmt.Sprintf("%s Redis %d: 未授权访问漏洞检测失败: %s\n", ip, config.RedisPort, err))
		return false, result.String()
	}

	found = true
	result.WriteString(fmt.Sprintf("%s Redis %d: 存在未授权漏洞\n", ip, config.RedisPort))
	return found, result.String()
}
