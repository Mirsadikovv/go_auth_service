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

type SystemUserService struct {
	cfg      config.Config
	log      logger.LoggerI
	strg     storage.IStorage
	services grpc_client.GrpcClientI
}

// SystemUserGmailCheck implements auth_service.SystemUserAuthServer.
func (c *SystemUserService) SystemUserGmailCheck(context.Context, *auth_service.SystemUserGmailCheckRequest) (*auth_service.SystemUserGmailCheckResponse, error) {
	panic("unimplemented")
}

func NewSystemUserAuthService(cfg config.Config, log logger.LoggerI, strg storage.IStorage, srvs grpc_client.GrpcClientI) *SystemUserService {
	return &SystemUserService{
		cfg:      cfg,
		log:      log,
		strg:     strg,
		services: srvs,
	}
}

func (c *SystemUserService) SystemUserCreate(ctx context.Context, req *auth_service.SystemUserCreateRequest) (*auth_service.SystemUserEmpty, error) {
	c.log.Info("---SellerCreateLoginCreate-->>>", logger.Any("req", req))

	data, err := c.strg.SystemUser().SystemUserGmailCheck(ctx, &auth_service.SystemUserGmailCheckRequest{Gmail: req.Gmail})
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

func (c SystemUserService) SystemUserLoginByPassword(ctx context.Context, req *auth_service.SystemUserLoginRequest) (*auth_service.SystemUserLoginResponse, error) {

	c.log.Info("---SystemUserLoginByPassword-->>>", logger.Any("req", req))

	resp := &auth_service.SystemUserLoginResponse{}

	data, err := c.strg.SystemUser().SystemUserGmailCheck(ctx, &auth_service.SystemUserGmailCheckRequest{Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---SystemUserLogin--->>>", logger.Error(err))
		return nil, err
	}

	if err = hash.CompareHashAndPassword(data.Password, req.Password); err != nil {
		c.log.Error("---SystemUserLogin--->>>", logger.Error(err))
		return nil, err
	}

	m := make(map[interface{}]interface{})
	id, err := c.services.SystemUserService().GetByGmail(ctx, &user_service.SystemUserGmail{Gmail: req.Gmail})
	if err != nil {
		return nil, err
	}
	m["user_id"] = id
	m["user_role"] = config.SYSTEM_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---SystemUserLogin--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c SystemUserService) SystemUserRegisterByMail(ctx context.Context, req *auth_service.SystemUserGmailCheckRequest) (*auth_service.SystemUserEmpty, error) {
	c.log.Info("---SystemUserRegisterByMail--->>>", logger.Any("req", req))
	resp := &auth_service.SystemUserEmpty{}

	password, _ := c.strg.SystemUser().SystemUserGmailCheck(ctx, &auth_service.SystemUserGmailCheckRequest{Gmail: req.Gmail})
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

func (c SystemUserService) SystemUserRegisterByMailConfirm(ctx context.Context, req *auth_service.SystemUserRConfirm) (*auth_service.RespRegSeller, error) {
	resp := &auth_service.RespRegSeller{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		c.log.Error("---SystemUserConfirmByMail--->>>", logger.Error(errors.New("wrong otp")))
		return nil, errors.New("wrong otp")
	}
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	_, err = c.strg.SystemUser().SystemUserCreate(ctx, &auth_service.SystemUserCreateRequest{Password: hashedPassword, Gmail: req.Gmail})
	if err != nil {
		c.log.Error("---SystemUserConfirmByMail--->>>", logger.Error(err))
		return nil, err
	}

	primaryKey, err := c.services.SystemUserService().Create(ctx, &user_service.CreateUs{
		Gmail: req.Gmail,
		Role:  req.Role,
	})
	if err != nil {
		c.log.Error("---SystemUserCreating--->>>", logger.Error(err))
		return nil, err
	}

	resp = &auth_service.RespRegSeller{Id: primaryKey.Id}

	return resp, nil
}

func (c SystemUserService) SystemUserLoginByGmail(ctx context.Context, req *auth_service.SystemUserGmailCheckRequest) (*auth_service.SystemUserEmpty, error) {
	_, err := c.strg.SystemUser().SystemUserGmailCheck(ctx, &auth_service.SystemUserGmailCheckRequest{Gmail: req.Gmail})
	resp := &auth_service.SystemUserEmpty{}
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

func (c SystemUserService) SystemUserLoginByGmailComfirm(ctx context.Context, req *auth_service.SystemUserLoginByGmailRequest) (*auth_service.SystemUserLoginResponse, error) {
	resp := &auth_service.SystemUserLoginResponse{}
	//_, err := c.strg.SystemUser().SystemUserGmailCheck(ctx, &auth_service.SystemUserGmailCheckRequest{Gmail: req.Gmail})
	//if err == sql.ErrNoRows {
	//	return nil, errors.New("you are not registered")
	//}

	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return nil, errors.New("wrong otp")
	}
	//id, err := c.services.SystemUserService().GetByGmail(ctx, &user_service.SystemUserGmail{Gmail: req.Gmail})
	//if err != nil {
	//	return nil, err
	//}

	m := make(map[interface{}]interface{})
	m["user_id"] = 3948
	m["user_role"] = config.SYSTEM_TYPE
	accesstoken, refreshtoken, err := jwt.GenJWT(m)
	if err != nil {
		c.log.Error("---SystemUserLoginByMailConfirm--->>>", logger.Error(err))
		return nil, err
	}

	resp.Accesstoken = accesstoken
	resp.Refreshtoken = refreshtoken

	return resp, nil
}

func (c SystemUserService) SystemUserResetPassword(ctx context.Context, req *auth_service.SystemUserGmailCheckRequest) (*auth_service.SystemUserEmpty, error) {
	c.log.Info("---SystemUserResetPassword--->>>", logger.Any("req", req))
	resp := &auth_service.SystemUserEmpty{}

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

func (c SystemUserService) SystemUserResetPasswordConfirm(ctx context.Context, req *auth_service.SystemUserPasswordConfirm) (*auth_service.SystemUserEmpty, error) {
	resp := &auth_service.SystemUserEmpty{}
	validOtp := c.strg.Redis().Get(ctx, req.Gmail)
	if validOtp != req.Otp {
		return resp, errors.New("invalid otp")
	}

	resp, err := c.strg.SystemUser().SystemUserUpdatePassword(ctx, &auth_service.SystemUserCreateRequest{Gmail: req.Gmail, Password: req.Password})
	if err != nil {
		return resp, nil
	}

	return resp, nil
}
