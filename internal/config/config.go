package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                      string
	DatabasePath              string
	SessionSecret             string
	Environment               string
	DetectionInterval         time.Duration
	DetectionWindow           time.Duration
	DetectionMinErrors        int
	DetectionSuppressFor      time.Duration
	DetectionMinAuthFailures  int
	DetectionMinNotFound      int
	DetectionMinRequestsPerIP int
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

	interval, err := time.ParseDuration(getEnv("DETECTION_INTERVAL", "1m"))
	if err != nil || interval <= 0 {
		return Config{}, errors.New("DETECTION_INTERVAL must be a positive duration")
	}

	window, err := time.ParseDuration(getEnv("DETECTION_WINDOW", "5m"))
	if err != nil || window <= 0 {
		return Config{}, errors.New("DETECTION_WINDOW must be a positive duration")
	}

	suppressFor, err := time.ParseDuration(getEnv("DETECTION_SUPPRESS_FOR", "30m"))
	if err != nil || suppressFor <= 0 {
		return Config{}, errors.New("DETECTION_SUPPRESS_FOR must be a positive duration")
	}

	minErrors, err := strconv.Atoi(getEnv("DETECTION_MIN_ERRORS", "10"))
	if err != nil || minErrors < 1 {
		return Config{}, errors.New("DETECTION_MIN_ERRORS must be a positive integer")
	}
	minAuthFailures, err := strconv.Atoi(
		getEnv("DETECTION_MIN_AUTH_FAILURES", "10"),
	)

	if err != nil || minAuthFailures < 1 {
		return Config{}, errors.New(
			"DETECTION_MIN_AUTH_FAILURES must be a positive integer",
		)
	}
	minNotFound, err := strconv.Atoi(
		getEnv("DETECTION_MIN_NOT_FOUND", "10"),
	)
	if err != nil || minNotFound < 1 {
		return Config{}, errors.New(
			"DETECTION_MIN_NOT_FOUND must be a positive integer",
		)
	}
	minRequestsPerIP, err := strconv.Atoi(
		getEnv("DETECTION_MIN_REQUESTS_PER_IP", "100"),
	)
	if err != nil || minRequestsPerIP < 1 {
		return Config{}, errors.New(
			"DETECTION_MIN_REQUESTS_PER_IP must be a positive integer",
		)
	}
	cfg.DetectionInterval = interval
	cfg.DetectionWindow = window
	cfg.DetectionMinErrors = minErrors
	cfg.DetectionMinAuthFailures = minAuthFailures
	cfg.DetectionMinNotFound = minNotFound
	cfg.DetectionSuppressFor = suppressFor
	cfg.DetectionMinRequestsPerIP = minRequestsPerIP

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
