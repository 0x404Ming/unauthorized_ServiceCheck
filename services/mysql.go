package services

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"strings"
	"sync"
	"unauthorized_ServiceCheck/config"
)

// 常见的弱口令列表
var weakPasswords = []string{
	"password", "123456", "123456789", "qwerty", "abc123", "password1", "12345678", "qwerty123",
	"1q2w3e4r", "admin", "letmein", "welcome", "monkey", "1234567", "football", "password123",
}

// 常见的用户名列表
var usernames = []string{
	"admin", "root", "user", "guest",
}

// MySQLChecker 实现 ServiceChecker 接口
type MySQLChecker struct{}

// Check 实现了 ServiceChecker 接口的 Check 方法
func (m *MySQLChecker) Check(ip string) (bool, string) {
	var result strings.Builder
	var found bool
	var wg sync.WaitGroup
	passwordChan := make(chan string)

	// 启动 goroutines 进行并发检查
	for _, user := range usernames {
		for _, password := range weakPasswords {
			wg.Add(1)
			go func(u, pw string) {
				defer wg.Done()
				dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", u, pw, ip, config.MySQLDefaultPort)
				db, err := sql.Open("mysql", dsn)
				if err != nil {
					return
				}
				defer db.Close()

				if err := db.Ping(); err == nil {
					passwordChan <- fmt.Sprintf("用户名: %s, 密码: %s", u, pw)
				}
			}(user, password)
		}
	}

	// 启动一个 goroutine 来关闭通道
	go func() {
		wg.Wait()
		close(passwordChan)
	}()

	// 收集结果
	for pw := range passwordChan {
		found = true
		result.WriteString(fmt.Sprintf("MySQL %d: 存在弱口令: %s\n", config.MySQLDefaultPort, pw))
	}

	if !found {
		result.WriteString(fmt.Sprintf("MySQL %d: 未检测到弱口令\n", config.MySQLDefaultPort))
	}

	return found, result.String()
}
