package services

// ServiceChecker 定义了通用的服务检查接口
type ServiceChecker interface {
	Check(ip string) (bool, string)
}
