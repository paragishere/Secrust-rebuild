package config

import (
	"testing"
	"time"
)

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PORT",
		"DATABASE_PATH",
		"SESSION_SECRET",
		"ENVIRONMENT",
		"DETECTION_INTERVAL",
		"DETECTION_WINDOW",
		"DETECTION_MIN_ERRORS",
		"DETECTION_MIN_AUTH_FAILURES",
		"DETECTION_SUPPRESS_FOR",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadDetectionDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.DetectionInterval != time.Minute {
		t.Errorf("expected 1m interval, got %s", cfg.DetectionInterval)
	}
	if cfg.DetectionWindow != 5*time.Minute {
		t.Errorf("expected 5m window, got %s", cfg.DetectionWindow)
	}
	if cfg.DetectionMinErrors != 10 {
		t.Errorf("expected 10 minimum errors, got %d", cfg.DetectionMinErrors)
	}
	if cfg.DetectionMinAuthFailures != 10 {
		t.Errorf("expected 10 minimum auth failures, got %d",
			cfg.DetectionMinAuthFailures)
	}
	if cfg.DetectionSuppressFor != 30*time.Minute {
		t.Errorf("expected 30m suppression, got %s", cfg.DetectionSuppressFor)
	}
	if cfg.DetectionMinRequestsPerIP != 100 {
		t.Errorf("expected 100 minimum requests per IP, got %d",
			cfg.DetectionMinRequestsPerIP)
	}
}

func TestLoadRejectsInvalidDetectionConfig(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"invalid interval", "DETECTION_INTERVAL", "not-a-duration"},
		{"zero interval", "DETECTION_INTERVAL", "0s"},
		{"invalid window", "DETECTION_WINDOW", "abc"},
		{"negative window", "DETECTION_WINDOW", "-1m"},
		{"invalid minimum", "DETECTION_MIN_ERRORS", "zero"},
		{"zero minimum", "DETECTION_MIN_ERRORS", "0"},
		{"invalid auth failure minimum", "DETECTION_MIN_AUTH_FAILURES", "abc"},
		{"zero auth failure minimum", "DETECTION_MIN_AUTH_FAILURES", "0"},
		{"negative auth failure minimum", "DETECTION_MIN_AUTH_FAILURES", "-1"},
		{"invalid 404 minimum", "DETECTION_MIN_NOT_FOUND", "abc"},
		{"zero 404 minimum", "DETECTION_MIN_NOT_FOUND", "0"},
		{"negative 404 minimum", "DETECTION_MIN_NOT_FOUND", "-1"},
		{"invalid suppression", "DETECTION_SUPPRESS_FOR", "abc"},
		{"zero suppression", "DETECTION_SUPPRESS_FOR", "0s"},
		{"invalid requests-per-IP minimum", "DETECTION_MIN_REQUESTS_PER_IP", "abc"},
		{"zero requests-per-IP minimum", "DETECTION_MIN_REQUESTS_PER_IP", "0"},
		{"negative requests-per-IP minimum", "DETECTION_MIN_REQUESTS_PER_IP", "-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConfigEnv(t)
			t.Setenv(tt.key, tt.value)

			if _, err := Load(); err == nil {
				t.Fatalf("expected Load() to reject %s=%q", tt.key, tt.value)
			}
		})
	}
}

func TestLoadAcceptsCustomDetectionConfig(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DETECTION_INTERVAL", "30s")
	t.Setenv("DETECTION_WINDOW", "10m")
	t.Setenv("DETECTION_MIN_ERRORS", "20")
	t.Setenv("DETECTION_MIN_AUTH_FAILURES", "5")
	t.Setenv("DETECTION_SUPPRESS_FOR", "45m")
	t.Setenv("DETECTION_MIN_NOT_FOUND", "5")
	t.Setenv("DETECTION_MIN_REQUESTS_PER_IP", "50")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.DetectionInterval != 30*time.Second ||
		cfg.DetectionWindow != 10*time.Minute ||
		cfg.DetectionMinErrors != 20 ||
		cfg.DetectionMinAuthFailures != 5 ||
		cfg.DetectionSuppressFor != 45*time.Minute {
		t.Fatalf("unexpected detection configuration: %+v", cfg)
	}
}
