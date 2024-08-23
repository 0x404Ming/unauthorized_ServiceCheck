package services

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"strings"
	"unauthorized_ServiceCheck/config"
)

// MongoDBChecker 实现 ServiceChecker 接口
type MongoDBChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (m *MongoDBChecker) Check(ip string) (bool, string) {
	var result strings.Builder
	var found bool

	// MongoDB 不需要用户名和密码进行未授权访问检测
	dsn := fmt.Sprintf("mongodb://%s:%d/?authSource=admin", ip, config.MongoDBPort)
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(dsn))
	if err != nil {
		return false, fmt.Sprintf("MongoDB %d: 未授权访问检测失败: %s", config.MongoDBPort, err)
	}
	defer func() {
		_ = client.Disconnect(context.Background())
	}()

	err = client.Ping(context.Background(), nil)
	if err != nil {
		return false, fmt.Sprintf("MongoDB %d: 未授权访问检测失败: %s", config.MongoDBPort, err)
	}

	// 如果 Ping 成功，说明可以未授权访问 MongoDB
	found = true
	result.WriteString(fmt.Sprintf("MongoDB %d: 存在未授权访问漏洞", config.MongoDBPort))

	return found, result.String()
}
