package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cast"
)

const (
	// DebugMode indicates service mode is debug.
	DebugMode = "debug"
	// TestMode indicates service mode is test.
	TestMode = "test"
	// ReleaseMode indicates service mode is release.
	ReleaseMode = "release"
)

type Config struct {
	Environment string // debug, test, release
	Version     string

	PostgresHost     string
	PostgresPort     int
	PostgresPassword string
	PostgresUser     string
	PostgresDatabase string

	ServiceName string

	RedisHost       string
	RedisPort       string
	RedisPassword   string
	ContentGRPCPort string
	UserServicePort string
	UserServiceHost string
}

func Load() Config {

	if err := godotenv.Load(); err != nil {
		fmt.Println("error!!!", err)
	}
	cfg := Config{}

	cfg.PostgresHost = cast.ToString(getOrReturnDefault("POSTGRES_HOST", "localhost"))
	cfg.PostgresPort = cast.ToInt(getOrReturnDefault("POSTGRES_PORT", 5432))
	cfg.PostgresDatabase = cast.ToString(getOrReturnDefault("POSTGRES_DATABASE", "auth_service"))
	cfg.PostgresUser = cast.ToString(getOrReturnDefault("POSTGRES_USER", "mirodil"))
	cfg.PostgresPassword = cast.ToString(getOrReturnDefault("POSTGRES_PASSWORD", "1212"))
	cfg.ServiceName = "auth_service"
	cfg.ContentGRPCPort = cast.ToString(getOrReturnDefault("CONTENT_GRPC_PORT", ":8084"))

	cfg.RedisHost = "localhost" //cast.ToString(getOrReturnDefault("REDIS_HOST", "localhost"))
	cfg.RedisPort = "6379"      //cast.ToString(getOrReturnDefault("REDIS_PORT", "6379"))
	cfg.RedisPassword = cast.ToString(getOrReturnDefault("REDIS_PASSWORD", "password"))
	cfg.UserServicePort = cast.ToString(getOrReturnDefault("USER_SERVICE_PORT", ":8083"))
	cfg.UserServiceHost = cast.ToString(getOrReturnDefault("USER_SERVICE_HOST", "localhost"))

	return cfg
}

func getOrReturnDefault(key string, defaultValue interface{}) interface{} {

	if os.Getenv(key) == "" {
		return defaultValue
	}

	return os.Getenv(key)
}
