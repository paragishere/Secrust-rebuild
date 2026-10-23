package alerts

import (
	"context"
	"log/slog"
	"time"
)

type Scheduler struct {
	detector *Detector
	interval time.Duration
	logger   *slog.Logger
}

func NewScheduler(
	detector *Detector,
	interval time.Duration,
	logger *slog.Logger,
) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}

	return &Scheduler{
		detector: detector,
		interval: interval,
		logger:   logger,
	}
}

// Run performs an initial detection pass, then repeats at the configured interval.
// It returns when the supplied context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	if s == nil || s.detector == nil || s.interval <= 0 {
		s.logger.Error("alert scheduler is not configured correctly")
		return
	}

	s.runDetection(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("alert scheduler stopped")
			return
		case <-ticker.C:
			s.runDetection(ctx)
		}
	}
}

func (s *Scheduler) runDetection(ctx context.Context) {
	result, err := s.detector.RunHTTP5xxSpikeDetection(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.logger.Error("HTTP 5xx detection failed", "error", err)
		return
	}

	s.logger.Info(
		"HTTP 5xx detection completed",
		"candidates", result.CandidatesFound,
		"created", result.AlertsCreated,
		"suppressed", result.AlertsSuppressed,
	)
}
