package main

import (
	"authserver/config"
	"authserver/grpc"
	grpc_client "authserver/grpc/client"
	"authserver/storage/postgres"
	"authserver/storage/redis"
	"context"
	"net"

	"github.com/saidamir98/udevs_pkg/logger"
)

func main() {
	cfg := config.Load()

	loggerLevel := logger.LevelDebug

	switch cfg.Environment {
	case config.DebugMode:
		loggerLevel = logger.LevelDebug
	case config.TestMode:
		loggerLevel = logger.LevelDebug
	default:
		loggerLevel = logger.LevelInfo
	}

	log := logger.NewLogger(cfg.ServiceName, loggerLevel)
	defer logger.Cleanup(log)

	newRedis := redis.New(cfg)

	pgStore, err := postgres.NewPostgres(context.Background(), cfg, newRedis)
	if err != nil {
		log.Panic("postgres.NewPostgres", logger.Error(err))
	}
	defer pgStore.CloseDB()

	svcs, err := grpc_client.New(cfg)
	if err != nil {
		log.Panic("client.NewGrpcClients", logger.Error(err))
	}

	grpcServer := grpc.SetUpServer(cfg, log, pgStore, svcs)

	lis, err := net.Listen("tcp", cfg.ContentGRPCPort)
	if err != nil {
		log.Panic("net.Listen", logger.Error(err))
	}

	log.Info("GRPC: Server being started...", logger.String("port", cfg.ContentGRPCPort))

	if err := grpcServer.Serve(lis); err != nil {
		log.Panic("grpcServer.Serve", logger.Error(err))
	}
}
