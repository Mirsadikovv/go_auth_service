package postgres

import (
	auth "authserver/genproto/auth_service"
	"authserver/pkg/hash"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type sellerRepo struct {
	db *pgxpool.Pool
}

func NewSeller(db *pgxpool.Pool) sellerRepo {
	return sellerRepo{
		db: db,
	}
}

func (c *sellerRepo) SellerGmailCheck(ctx context.Context, req *auth.SellerGmailCheckRequest) (*auth.SellerGmailCheckResponse, error) {
	resp := &auth.SellerGmailCheckResponse{}
	query := `SELECT 
			 pasword
			 	FROM seller
				WHERE gmail=$1`

	err := c.db.QueryRow(ctx, query, req.Gmail).Scan(&resp.Password)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *sellerRepo) SellerCreate(ctx context.Context, req *auth.SellerCreateRequest) (*auth.SellerEmpty, error) {
	resp := &auth.SellerEmpty{}
	query := `INSERT INTO seller (pasword, gmail, created_at)
						VALUES ($1, $2, NOW())
	`
	_, err := c.db.Exec(ctx, query, req.Password, req.Gmail)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *sellerRepo) SellerUpdatePassword(ctx context.Context, req *auth.SellerCreateRequest) (*auth.SellerEmpty, error) {
	resp := &auth.SellerEmpty{}
	hashedPassword, err := hash.HashPassword(req.Password)
	if err != nil {
		return resp, err
	}
	query := `UPDATE seller SET
			pasword=$1,updated_at=NOW()
			WHERE gmail=$2`
	_, err = c.db.Exec(ctx, query, hashedPassword, req.Gmail)
	if err != nil {
		return resp, err
	}

	return resp, err
}
