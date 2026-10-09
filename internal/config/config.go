package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port        string
	DatabasePath string
	SessionSecret string
	Environment string
}

func Load() (Config, error) {
	cfg := Config{
		Port:          getEnv("PORT", "8080"),
		DatabasePath:  getEnv("DATABASE_PATH", "./data/secrust.db"),
		SessionSecret: strings.TrimSpace(os.Getenv("SESSION_SECRET")),
		Environment:   getEnv("ENVIRONMENT", "development"),
	}

	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("PORT must be between 1 and 65535")
	}

	if cfg.DatabasePath == "" {
		return Config{}, errors.New("DATABASE_PATH cannot be empty")
	}

	if cfg.Environment != "development" &&
		cfg.Environment != "production" &&
		cfg.Environment != "test" {
		return Config{}, errors.New(
			"ENVIRONMENT must be development, production, or test",
		)
	}

	if cfg.Environment == "production" && len(cfg.SessionSecret) < 32 {
		return Config{}, errors.New(
			"SESSION_SECRET must contain at least 32 characters in production",
		)
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}