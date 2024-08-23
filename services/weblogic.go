package services

import (
	"fmt"
	"strings"
	"unauthorized_ServiceCheck/config"
	"unauthorized_ServiceCheck/utils"
)

// WeblogicChecker 实现 ServiceChecker 接口
type WeblogicChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (s *WeblogicChecker) Check(ip string) (bool, string) {
	var result strings.Builder
	var found bool

	for _, urlPath := range config.WeblogicPaths {
		isVulnerable, err := utils.CheckHTTP(ip, config.WebLogicPort, urlPath)
		if err != nil {
			result.WriteString(fmt.Sprintf("Path %s: 检测失败: %s\n", urlPath, err))
			continue
		}
		if isVulnerable {
			found = true
			result.WriteString(fmt.Sprintf(" %s%s: 存在未授权访问漏洞\n", ip, urlPath))
		} else {
			result.WriteString(fmt.Sprintf("Path %s: 不存在未授权访问漏洞\n", urlPath))
		}
	}

	if !found {
		result.WriteString("未检测到未授权访问漏洞\n")
	}

	return found, result.String()
}
