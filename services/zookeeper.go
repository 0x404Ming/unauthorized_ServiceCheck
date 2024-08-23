package services

import (
	"fmt"
	"unauthorized_ServiceCheck/config"
	"unauthorized_ServiceCheck/utils"
)

// ZookeeperChecker 实现 ServiceChecker 接口
type ZookeeperChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (z *ZookeeperChecker) Check(ip string) (bool, string) {
	// 执行 TCP 连接检查
	isVulnerable, err := utils.CheckTCP(ip, config.ZookeeperPort)
	if err != nil {
		// 如果出现错误，返回 false 并附带错误信息
		return false, fmt.Sprintf("Zookeeper %d: 未授权访问漏洞检测失败: %s", config.ZookeeperPort, err)
	}

	if isVulnerable {
		// 如果检测到漏洞，返回 true 并提供详细信息
		return true, fmt.Sprintf("Zookeeper %s: 存在未授权访问漏洞", ip)
	}

	// 如果未检测到漏洞，返回 false 并提供信息
	return false, fmt.Sprintf("Zookeeper %d: 不存在未授权访问漏洞", config.ZookeeperPort)
}
