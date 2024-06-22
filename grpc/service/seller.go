package service

import (
	"authserver/config"
	"authserver/genproto/auth_service"
	"authserver/genproto/user_service"
	grpc_client "authserver/grpc/client"
	"authserver/pkg/hash"
	smtp "authserver/pkg/helper"
	"log"

	"authserver/pkg/jwt"
	"authserver/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/saidamir98/udevs_pkg/logger"
)

type SellerService struct {
	cfg      config.Config
	log      logger.LoggerI
	strg     storage.IStorage
	services grpc_client.GrpcClientI
}

func NewSellerAuthService(cfg config.Config, log logger.LoggerI, strg storage.IStorage, srvs grpc_client.GrpcClientI) *SellerService {
	return &SellerService{
		cfg:      cfg,
		log:      log,
		strg:     strg,
		services: srvs,
	}
}

func (c *SellerService) SellerGmailCheck(ctx context.Context, req *auth_service.SellerGmailCheckRequest) (*auth_service.SellerGmailCheckResponse, error) {
	data, err := c.strg.Seller().SellerGmailCheck(ctx, &auth_service.SellerGmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerLogin-Create-->>>", logger.Error(err))
		log.Println("data", data)
		return nil, errors.New("you are already registered")
	}
	return data, err
}

func (c *SellerService) SellerCreate(ctx context.Context, req *auth_service.SellerCreateRequest) (*auth_service.SellerEmpty, error) {
	c.log.Info("---SellerCreateLoginCreate-->>>", logger.Any("req", req))

	data, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerLogin-Create-->>>", logger.Error(err))
		log.Println("data", data)
		return nil, errors.New("you are already registered")
	}

	_, err = c.strg.Customer().Create(ctx, (*auth_service.CreateRequest)(req))
	if err != nil {
		c.log.Error("CustomerLogin-Create", logger.Error(err))
	}

	return nil, err
}

func (c SellerService) SellerLoginByPassword(ctx context.Context, req *auth_service.SellerLoginRequest) (*auth_service.SellerLoginResponse, error) {

	c.log.Info("---SellerLoginByPassword-->>>", logger.Any("req", req))

	resp := &auth_service.SellerLoginResponse{}

	data, err := c.strg.Seller().SellerGmailCheck(ctx, &auth_service.SellerGmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---SellerLoginCheck--->>>", logger.Error(err))
		return nil, err
	}

	if err = hash.CompareHashAndPassword(data.Password, req.Password); err != nil {
		c.log.Error("---CheckPassword--->>>", logger.Error(err))
		return nil, errors.New("wrong password")
	}
	id, err := c.services.SellerService().GetByGmail(ctx, &user_service.SellerGmail{Gmail: req.Gmail})
	if err != nil {
		return nil, err
	}

	m := make(map[interface{}]interface{})
	m["user_id"] = id
	m["user_role"] = config.SELLER_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---SellerLogin--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c SellerService) SellerRegisterByMail(ctx context.Context, req *auth_service.SellerGmailCheckRequest) (*auth_service.SellerEmpty, error) {
	c.log.Info("---SellerRegisterByMail--->>>", logger.Any("req", req))
	resp := &auth_service.SellerEmpty{}

	password, _ := c.strg.Seller().SellerGmailCheck(ctx, &auth_service.SellerGmailCheckRequest{Gmail: req.Gmail})
	if password == nil {
		otp := smtp.GenerateOTP()
		msg := fmt.Sprintf("Your OTP: %v. DON'T give anyone", otp)
		err := c.strg.Redis().SetX(ctx, req.Gmail, otp, time.Minute*2)
		if err != nil {
			return resp, err
		}

		err = smtp.Sendmail(req.Gmail, msg)
		if err != nil {
			return resp, err
		}
	} else {
		return resp, errors.New("you are already registered")
	}

	return resp, nil
}

func (c SellerService) SellerRegisterByMailConfirm(ctx context.Context, req *auth_service.SellerRConfirm) (*auth_service.SellerEmpty, error) {
	resp := &auth_service.SellerEmpty{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		c.log.Error("---SellerConfirmByMail--->>>", logger.Error(errors.New("wrong otp")))
		return resp, errors.New("wrong otp")
	}
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return resp, err
	}

	_, err = c.strg.Seller().SellerCreate(ctx, &auth_service.SellerCreateRequest{Password: hashedPassword, Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---SellerConfirmByMail--->>>", logger.Error(err))
		return resp, err
	}

	return resp, nil
}

func (c SellerService) SellerLoginByGmail(ctx context.Context, req *auth_service.SellerGmailCheckRequest) (*auth_service.SellerEmpty, error) {
	resp := &auth_service.SellerEmpty{}
	_, err := c.strg.Seller().SellerGmailCheck(ctx, &auth_service.SellerGmailCheckRequest{Gmail: req.Gmail})
	if err != sql.ErrNoRows {
		otp := smtp.GenerateOTP()
		err := c.strg.Redis().SetX(ctx, req.Gmail, otp, time.Minute*2)
		if err != nil {
			return resp, err
		}
		msg := fmt.Sprintf("Your OTP: %v. DON'T give anyone", otp)
		err = smtp.Sendmail(req.Gmail, msg)
		if err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func (c SellerService) SellerLoginByGmailComfirm(ctx context.Context, req *auth_service.SellerLoginByGmailRequest) (*auth_service.SellerLoginResponse, error) {

	resp := &auth_service.SellerLoginResponse{}
	c.log.Info("---LoginByGmailComfirm-->>>", logger.Any("req", req))
	_, err := c.strg.Seller().SellerGmailCheck(ctx, &auth_service.SellerGmailCheckRequest{Gmail: req.Gmail})
	if err != sql.ErrNoRows {
		return nil, errors.New("you are not registered")
	}

	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return nil, errors.New("wrong otp")
	}
	id, err := c.services.SellerService().GetByGmail(ctx, &user_service.SellerGmail{Gmail: req.Gmail})
	if err != nil {
		return nil, err
	}

	m := make(map[interface{}]interface{})
	m["user_id"] = id
	m["user_role"] = config.SELLER_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---SellerLoginByMailConfirm--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c SellerService) SellerResetPassword(ctx context.Context, req *auth_service.SellerGmailCheckRequest) (*auth_service.SellerEmpty, error) {
	resp := &auth_service.SellerEmpty{}
	c.log.Info("---SellerResetPassword--->>>", logger.Any("req", req))

	otp := smtp.GenerateOTP()
	msg := fmt.Sprintf("Your OTP: %v. DON'T give anyone", otp)
	err := c.strg.Redis().SetX(ctx, req.Gmail, otp, time.Minute*2)
	if err != nil {
		return resp, err
	}

	err = smtp.Sendmail(req.Gmail, msg)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (c SellerService) SellerResetPasswordConfirm(ctx context.Context, req *auth_service.SellerPasswordConfirm) (*auth_service.SellerEmpty, error) {
	resp := &auth_service.SellerEmpty{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return resp, errors.New("invalid otp")
	}

	resp, err := c.strg.Seller().SellerUpdatePassword(ctx, &auth_service.SellerCreateRequest{Gmail: req.Gmail, Password: req.Password})
	if err != nil {
		return resp, nil
	}

	return resp, nil
}
