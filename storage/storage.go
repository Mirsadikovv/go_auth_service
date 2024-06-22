package storage

import (
	auth "authserver/genproto/auth_service"
	"context"
	"time"
)

type IStorage interface {
	CloseDB()
	Customer() CustomerStorage
	Seller() SellerStorage
	SystemUser() SystemUserStorage
	Redis() IRedisStorage
}

type CustomerStorage interface {
	GmailCheck(context.Context, *auth.GmailCheckRequest) (*auth.GmailCheckResponse, error)
	Create(context.Context, *auth.CreateRequest) (*auth.Empty, error)
	UpdatePassword(context.Context, *auth.CreateRequest) (*auth.Empty, error)
}

type IRedisStorage interface {
	SetX(context.Context, string, interface{}, time.Duration) error
	Get(context.Context, string) interface{}
	Del(context.Context, string) error
}

type SellerStorage interface {
	SellerGmailCheck(context.Context, *auth.SellerGmailCheckRequest) (*auth.SellerGmailCheckResponse, error)
	SellerCreate(context.Context, *auth.SellerCreateRequest) (*auth.SellerEmpty, error)
	SellerUpdatePassword(context.Context, *auth.SellerCreateRequest) (*auth.SellerEmpty, error)
}

type SystemUserStorage interface {
	SystemUserGmailCheck(context.Context, *auth.SystemUserGmailCheckRequest) (*auth.SystemUserGmailCheckResponse, error)
	SystemUserCreate(context.Context, *auth.SystemUserCreateRequest) (*auth.SystemUserEmpty, error)
	SystemUserUpdatePassword(context.Context, *auth.SystemUserCreateRequest) (*auth.SystemUserEmpty, error)
}
