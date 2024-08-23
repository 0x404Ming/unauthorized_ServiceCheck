package utils

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// User-Agent 字符串列表
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Edge/91.0.864.64",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36",
	"Opera/9.80 (Windows NT 6.0; U; en) Presto/2.12.388 Version/12.18",
}

func getRandomUserAgent() string {
	//rand.Seed(time.Now().UnixNano())

	return userAgents[rand.Intn(len(userAgents))]
}

// CheckHTTP 检查指定的 IP 和路径是否存在漏洞，支持 HTTP 和 HTTPS
func CheckHTTP(ip string, port int, path string) (bool, error) {
	// 构造 URL
	protocol := "http"
	if port == 443 {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/%s", protocol, ip, port, path)

	// 根据协议选择 Transport
	tr := &http.Transport{}
	if protocol == "https" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // 允许不安全的 HTTPS 证书
	}

	client := &http.Client{
		Timeout:   5 * time.Second, // 设置请求超时
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil // 返回 true 表示存在漏洞
	}
	return false, nil // 返回 false 表示不存在漏洞
}

// CheckTCP 检查指定的 IP 和端口是否可以建立 TCP 连接
func CheckTCP(ip string, port int) (bool, error) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		// 连接失败，可能是端口关闭或网络问题
		return false, err
	}
	defer conn.Close()

	// 连接成功，返回存在漏洞
	return true, nil
}
