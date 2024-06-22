package grpc

import (
	"authserver/config"
	"authserver/genproto/auth_service"
	grpc_client "authserver/grpc/client"
	"authserver/grpc/service"
	"authserver/storage"

	"github.com/saidamir98/udevs_pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func SetUpServer(cfg config.Config, log logger.LoggerI, strg storage.IStorage, srvc grpc_client.GrpcClientI) (grpcServer *grpc.Server) {

	grpcServer = grpc.NewServer()

	auth_service.RegisterCustomerAuthServer(grpcServer, service.NewCustomerAuthService(cfg, log, strg, srvc))

	auth_service.RegisterSellerAuthServer(grpcServer, service.NewSellerAuthService(cfg, log, strg, srvc))

	auth_service.RegisterSystemUserAuthServer(grpcServer, service.NewSystemUserAuthService(cfg, log, strg, srvc))

	reflection.Register(grpcServer)

	return
}
