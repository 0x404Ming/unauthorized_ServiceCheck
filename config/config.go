package config

const (
	// 服务端口
	RedisPort         = 6379
	ZookeeperPort     = 2181
	FTPDefaultPort    = 21
	ElasticsearchPort = 9200
	WebLogicPort      = 7001
	MongoDBPort       = 27017
	MySQLDefaultPort  = 3306
)

var ElasticsearchPaths = []string{
	"_plugin/head/",
	"/_cat/indices",
	"/_river/_search",
	"_nodes",
}

var WeblogicPaths = []string{
	"console/css/%252e%252e%252fconsole.portal",
}
