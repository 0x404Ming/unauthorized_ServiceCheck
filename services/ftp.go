package services

import (
	"fmt"
	"strings"
	"unauthorized_ServiceCheck/config"
	"unauthorized_ServiceCheck/utils"
)

// FTPChecker 实现 ServiceChecker 接口
type FTPChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (f *FTPChecker) Check(ip string) (bool, string) {
	var result strings.Builder
	var found bool

	isVulnerable, err := utils.CheckTCP(ip, config.FTPDefaultPort)
	if err != nil {
		result.WriteString(fmt.Sprintf("FTP %d: 检测失败: %s\n", config.FTPDefaultPort, err))
		return false, result.String()
	}

	if isVulnerable {
		found = true
		result.WriteString(fmt.Sprintf("FTP %d: 存在未授权访问漏洞\n", ip))
	} else {
		result.WriteString(fmt.Sprintf("FTP %d: 不存在未授权访问漏洞\n", config.FTPDefaultPort))
	}

	return found, result.String()
}
