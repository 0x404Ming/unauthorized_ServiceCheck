package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"unauthorized_ServiceCheck/services"
)

// 检查服务
func checkServices(ip string) []string {
	var results []string

	checkers := map[string]services.ServiceChecker{
		"Redis":         &services.RedisChecker{},
		"FTP":           &services.FTPChecker{},
		"Elasticsearch": &services.ElasticsearchChecker{},
		"MySQL":         &services.MySQLChecker{},
		"Zookeeper":     &services.ZookeeperChecker{},
		"Weblogic":      &services.WeblogicChecker{},
	}

	for serviceName, checker := range checkers {
		found, result := checker.Check(ip)
		if found {
			results = append(results, fmt.Sprintf("%s:\n%s", serviceName, result))
		}
	}
	return results
}

func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func writeResultsToFile(results []string, filename string) error {
	if len(results) == 0 {
		fmt.Println("No vulnerabilities detected. No results saved.")
		return nil
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range results {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	// Define command-line flags
	ipFile := flag.String("f", "", "Path to the file containing IP addresses")
	ipList := flag.String("i", "", "Comma-separated list of IP addresses")
	outputFile := flag.String("o", "result.txt", "Path to the file where results will be saved")

	flag.Parse()

	var ips []string
	var err error

	if *ipFile != "" {
		ips, err = readIPsFromFile(*ipFile)
		if err != nil {
			fmt.Printf("Error reading IPs from file: %s\n", err)
			os.Exit(1)
		}
	} else if *ipList != "" {
		ips = strings.Split(*ipList, ",")
		for i := range ips {
			ips[i] = strings.TrimSpace(ips[i])
		}
	} else {
		fmt.Println("Usage: unauthorized_ServiceCheck -f <file> or -i <ip1,ip2,...>")
		os.Exit(1)
	}

	var results []string

	// 打印总数
	totalIPs := len(ips)
	fmt.Printf("Total IPs to scan: %d\n", totalIPs)

	for i, ip := range ips {
		ipResults := checkServices(ip)
		if len(ipResults) > 0 {
			results = append(results, ipResults...)
		}

		// 打印进度
		progress := float64(i+1) / float64(totalIPs) * 100
		fmt.Printf("Progress: %.2f%% (%d/%d) - Current IP: %s\r", progress, i+1, totalIPs, ip)
	}

	fmt.Println() // 打印换行符，结束进度条

	if err := writeResultsToFile(results, *outputFile); err != nil {
		fmt.Printf("Error writing results to file: %s\n", err)
		os.Exit(1)
	}

}
