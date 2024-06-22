CREATE TABLE IF NOT EXISTS customer(
    gmail varchar UNIQUE,
    pasword varchar,
    created_at timestamp default NOW(),
    updated_at timestamp,
    deleted_at int default 0
);

CREATE TABLE IF NOT EXISTS seller(
    gmail varchar UNIQUE,
    pasword varchar,
    created_at timestamp default NOW(),
    updated_at timestamp,
    deleted_at int default 0
);

CREATE TABLE IF NOT EXISTS systemuser(
    gmail varchar UNIQUE,
    pasword varchar,
    created_at timestamp default NOW(),
    updated_at timestamp,
    deleted_at int default 0
);
