package service

import (
	"authserver/config"
	"authserver/genproto/auth_service"
	"authserver/genproto/user_service"
	grpc_client "authserver/grpc/client"
	"authserver/pkg/hash"
	smtp "authserver/pkg/helper"
	"authserver/pkg/jwt"
	"log"

	"authserver/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/saidamir98/udevs_pkg/logger"
)

type CustomerService struct {
	cfg      config.Config
	log      logger.LoggerI
	strg     storage.IStorage
	services grpc_client.GrpcClientI
}

func (c *CustomerService) GmailCheck(ctx context.Context, req *auth_service.GmailCheckRequest) (resp *auth_service.GmailCheckResponse, err error) {
	data, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerLogin-Create-->>>", logger.Error(err))
		log.Println("data", data)
		return nil, errors.New("you are already registered")
	}
	return data, err
}

func NewCustomerAuthService(cfg config.Config, log logger.LoggerI, strg storage.IStorage, srvs grpc_client.GrpcClientI) *CustomerService {
	return &CustomerService{
		cfg:      cfg,
		log:      log,
		strg:     strg,
		services: srvs,
	}
}

func (c *CustomerService) Create(ctx context.Context, req *auth_service.CreateRequest) (*auth_service.Empty, error) {
	c.log.Info("---CustomerLoginCreate-->>>", logger.Any("req", req))

	data, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err == nil {
		c.log.Error("---CustomerLogin-Create-->>>", logger.Error(err))
		log.Println("data", data)
		log.Println("you are already registered", err)

		return nil, errors.New("you are already registered")
	}
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	_, err = c.strg.Customer().Create(ctx, &auth_service.CreateRequest{Password: hashedPassword, Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerConfirmByMail--->>>", logger.Error(err))
		return nil, err
	}

	return nil, err
}

func (c CustomerService) LoginByPassword(ctx context.Context, req *auth_service.LoginRequest) (*auth_service.LoginResponse, error) {

	c.log.Info("---CustomerLoginByPassword-->>>", logger.Any("req", req))

	resp := &auth_service.LoginResponse{}

	id, err := c.services.UserService().GetByGmail(ctx, &user_service.CustomerGmail{Gmail: req.Gmail})
	if err != nil {
		fmt.Println("error checking while gmail")

	}

	/*this check user_service of customer if gmail is not avaible there that saying err or if not connect to user_service
	/*id, err := c.services.CustomerService().GetByGmail(ctx, &user_service.CustomerGmail{Gmail: req.Gmail})
	/*if err != nil {
	/*	return nil, err
	/*}*/

	fmt.Println()

	data, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerLogin--->>>", logger.Error(err))
		fmt.Println(data)
		return nil, err
	}

	if err = hash.CompareHashAndPassword(data.Password, req.Password); err != nil {
		c.log.Error("---CustomerLogin--->>>", logger.Error(err))
		return nil, err
	}

	m := make(map[interface{}]interface{})
	m["user_id"] = id
	m["user_role"] = config.CUSTOMER_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---CustomerLogin--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c CustomerService) RegisterByMail(ctx context.Context, req *auth_service.GmailCheckRequest) (*auth_service.Empty, error) {
	c.log.Info("---CustomerRegisterByMail--->>>", logger.Any("req", req))
	resp := &auth_service.Empty{}

	password, _ := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if password == nil {
		fmt.Println("AT IF ")
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

func (c CustomerService) RegisterByMailConfirm(ctx context.Context, req *auth_service.RConfirm) (*auth_service.RegGmailResp, error) {
	resp := &auth_service.RegGmailResp{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		c.log.Error("---CustomerConfirmByMail--->>>", logger.Error(errors.New("wrong otp")))
		return nil, errors.New("wrong otp")
	}
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	primaryKey, err := c.services.UserService().Create(ctx, &user_service.CreateCustomer{
		Email:       req.Gmail,
		Languange:   req.Language,
		Gender:      req.Gender,
		DateOfBirth: req.DateOfBirth,
	})

	if err != nil {
		return nil, err
	}

	_, err = c.strg.Customer().Create(ctx, &auth_service.CreateRequest{Password: hashedPassword, Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---CustomerConfirmByMail--->>>", logger.Error(err))
		return nil, err
	}

	resp = &auth_service.RegGmailResp{Id: primaryKey.Id}

	return resp, nil
}

func (c CustomerService) LoginByGmail(ctx context.Context, req *auth_service.GmailCheckRequest) (*auth_service.Empty, error) {
	resp := &auth_service.Empty{}
	_, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err != sql.ErrNoRows {
		otp := smtp.GenerateOTP()
		err := c.strg.Redis().SetX(ctx, req.Gmail, otp, time.Minute*2)
		if err != nil {
			return resp, err
		}
		msg := fmt.Sprintf("Your OTP: %v. DON'T give anyone", otp)
		err = smtp.Sendmail(req.Gmail, msg)
		fmt.Printf("Your OTP: %v. DON'T give anyone", otp)
		if err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func (c CustomerService) LoginByGmailComfirm(ctx context.Context, req *auth_service.LoginByGmailRequest) (*auth_service.LoginResponse, error) {
	resp := &auth_service.LoginResponse{}
	c.log.Info("---LoginByGmailComfirm-->>>", logger.Any("req", req))

	_, err := c.strg.Customer().GmailCheck(ctx, &auth_service.GmailCheckRequest{Gmail: req.Gmail})
	if err == sql.ErrNoRows {
		return nil, errors.New("you are not registered")
	}

	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return nil, errors.New("wrong otp")
	}

	id, err := c.services.UserService().GetByGmail(ctx, &user_service.CustomerGmail{Gmail: req.Gmail})
	if err != nil {
		return nil, err
	}

	m := make(map[interface{}]interface{})
	m["user_id"] = id
	m["user_role"] = config.CUSTOMER_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---CustomerLoginByMailConfirm--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c CustomerService) ResetPassword(ctx context.Context, req *auth_service.GmailCheckRequest) (*auth_service.Empty, error) {
	resp := &auth_service.Empty{}
	c.log.Info("---CustomerResetPassword--->>>", logger.Any("req", req))

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

func (c CustomerService) ResetPasswordConfirm(ctx context.Context, req *auth_service.CustomerPasswordConfirm) (*auth_service.Empty, error) {
	resp := &auth_service.Empty{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return resp, errors.New("invalid otp")
	}

	resp, err := c.strg.Customer().UpdatePassword(ctx, &auth_service.CreateRequest{Gmail: req.Gmail, Password: req.Password})
	if err != nil {
		return resp, nil
	}

	return resp, nil
}
