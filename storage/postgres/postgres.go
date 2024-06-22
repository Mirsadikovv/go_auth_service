package postgres

import (
	"authserver/config"
	"authserver/storage"
	"authserver/storage/redis"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/lib/pq"
)

type Store struct {
	Pool  *pgxpool.Pool
	cfg   config.Config
	redis storage.IRedisStorage
}

func NewPostgres(ctx context.Context, cfg config.Config, redis storage.IRedisStorage) (storage.IStorage, error) {
	url := fmt.Sprintf(`host=%s port=%v user=%s password=%s database=%s sslmode=disable`,
		cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDatabase)

	pgxPoolConfig, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	pgxPoolConfig.MaxConns = 50
	pgxPoolConfig.MaxConnLifetime = time.Hour

	newPool, err := pgxpool.NewWithConfig(ctx, pgxPoolConfig)
	if err != nil {
		return nil, err
	}

	return Store{
		Pool:  newPool,
		redis: redis,
		cfg:   cfg,
	}, nil
}
func (s Store) CloseDB() {
	s.Pool.Close()
}

func (s Store) Customer() storage.CustomerStorage {
	newCustomer := NewCustomer(s.Pool)

	return &newCustomer
}

func (s Store) Seller() storage.SellerStorage {
	newSeller := NewSeller(s.Pool)

	return &newSeller
}

func (s Store) SystemUser() storage.SystemUserStorage {
	newSystemUser := NewSystemUser(s.Pool)

	return &newSystemUser
}

func (s Store) Redis() storage.IRedisStorage {
	return redis.New(s.cfg)
}
