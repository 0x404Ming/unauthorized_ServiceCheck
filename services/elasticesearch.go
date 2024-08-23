package services

import (
	"fmt"
	"strings"
	"unauthorized_ServiceCheck/config"
	"unauthorized_ServiceCheck/utils"
)

// ElasticsearchChecker 实现 ServiceChecker 接口
type ElasticsearchChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (e *ElasticsearchChecker) Check(ip string) (bool, string) {
	var results strings.Builder
	var found bool

	for _, urlPath := range config.ElasticsearchPaths {
		isVulnerable, err := utils.CheckHTTP(ip, config.ElasticsearchPort, urlPath)
		if err != nil {
			results.WriteString(fmt.Sprintf("Path %s: 检测失败: %s\n", urlPath, err))
			continue
		}
		if isVulnerable {
			found = true
			results.WriteString(fmt.Sprintf("Path %s: 存在未授权访问漏洞\n", urlPath))
		} else {
			results.WriteString(fmt.Sprintf("Path %s: 不存在未授权访问漏洞\n", urlPath))
		}
	}

	if !found {
		results.WriteString("未检测到未授权访问漏洞\n")
	}

	return found, results.String()
}
