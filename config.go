package main

import (
    "fmt"
    "encoding/json"
    "os"
)

type PostgresConfig struct {
    Host string "json:\"host\""
    Port int "json:\"port\""
    User string "json:\"user\""
    Password string "json:\"password\""
    Name string "json:\"name\""
}

type Config struct {
    Port int "json:\"port\""
    Env string "json:\"env\""
    Pepper string "json:\"pepper\""
    HMACKey string "json:\"hmac_key\""

    Database PostgresConfig "json:\"database\""
}

func (c PostgresConfig) Dialect() string {
    return "postgres"
}

func (c PostgresConfig) ConnectionInfo() string {
    if c.Password == "" {
        return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable", c.Host, c.Port, c.User, c.Name)
    }

    return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", c.Host, c.Port, c.User, c.Password, c.Name)
}

func DefaultPostgresConfig() PostgresConfig {
    return PostgresConfig{
        Host: "localhost",
        Port: 5432,
        User: "postgres",
        Password: "root",
        Name: "lenslocked_dev",
    }
}

func (c Config) IsProd() bool {
    return c.Env == "prod"
}

func DefaultConfig() Config {
    return Config{
        Port: 9090,
        Env: "dev",
        Pepper: "secret-random-string",
        HMACKey: "secret-hmac-key",
        Database: DefaultPostgresConfig(),
    }
}

func LoadConfig(configReq bool) Config {
    f, err := os.Open(".config")
    if err != nil {
        if configReq {
            panic(err)
        }
        fmt.Println("using the default config")
        return DefaultConfig()
    }

    var c Config
    dec := json.NewDecoder(f)
    err = dec.Decode(&c)
    if err != nil {
        panic(err)
    }

    fmt.Println("successfully loaded .config")
    return c
}
