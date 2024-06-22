package grpc_client

import (
	"authserver/config"

	"log"

	us "authserver/genproto/user_service"

	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcClientI interface {
	UserService() us.CustomerServiceClient
	SystemUserService() us.UsServiceClient
	SellerService() us.SellerServiceClient
}

type GrpcClient struct {
	cfg         config.Config
	connections map[string]interface{}
}

func New(cfg config.Config) (*GrpcClient, error) {

	connUser, err := grpc.NewClient(
		fmt.Sprintf("%s:%s", cfg.UserServiceHost, cfg.UserServicePort),
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		return nil, fmt.Errorf("user service dial host: %v port :%v err:%v",
			cfg.UserServiceHost, cfg.UserServicePort, err)
	}

	return &GrpcClient{
		cfg: cfg,
		connections: map[string]interface{}{
			"user_service": us.NewCustomerServiceClient(connUser),
			"system_user":  us.NewUsServiceClient(connUser),
			"seller":       us.NewSellerServiceClient(connUser),
		},
	}, nil
}

func (g *GrpcClient) UserService() us.CustomerServiceClient {
	client, ok := g.connections["user_service"].(us.CustomerServiceClient)
	if !ok {
		log.Println("failed to assert type for user_service")
		return nil
	}
	return client
}

func (g *GrpcClient) SystemUserService() us.UsServiceClient {
	client, ok := g.connections["system_user"].(us.UsServiceClient)
	if !ok {
		log.Println("failed to assert type for system_user")
		return nil
	}
	return client
}

func (g *GrpcClient) SellerService() us.SellerServiceClient {
	client, ok := g.connections["seller"].(us.SellerServiceClient)
	if !ok {
		log.Println("failed to assert type for seller")
		return nil
	}
	return client
}
