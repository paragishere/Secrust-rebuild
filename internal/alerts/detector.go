package alerts

import (
	"context"
	"fmt"
	"time"
)

const HTTP5xxSpikeRuleKey = "http.5xx_spike"

type DetectorConfig struct {
	Window                 time.Duration
	MinimumCount           int
	BruteForceMinimumCount int
	SuppressFor            time.Duration
	NotFoundMinimumCount   int
}

type Detector struct {
	repo   *Repository
	config DetectorConfig
}

type DetectionResult struct {
	CandidatesFound  int `json:"candidates_found"`
	AlertsCreated    int `json:"alerts_created"`
	AlertsSuppressed int `json:"alerts_suppressed"`
}

func NewDetector(repo *Repository, config DetectorConfig) (*Detector, error) {
	if repo == nil {
		return nil, fmt.Errorf("alert repository is required")
	}
	if config.Window <= 0 {
		return nil, fmt.Errorf("detection window must be positive")
	}
	if config.MinimumCount < 1 {
		return nil, fmt.Errorf("minimum count must be positive")
	}
	if config.BruteForceMinimumCount < 1 {
		return nil, fmt.Errorf("brute-force minimum count must be positive")
	}
	if config.SuppressFor <= 0 {
		return nil, fmt.Errorf("suppression duration must be positive")
	}
	if config.NotFoundMinimumCount < 1 {
		return nil, fmt.Errorf("404 minimum count must be positive")
	}

	return &Detector{
		repo:   repo,
		config: config,
	}, nil
}

// RunHTTP5xxSpikeDetection checks recent HTTP server errors and creates alerts.
func (d *Detector) RunHTTP5xxSpikeDetection(
	ctx context.Context,
) (DetectionResult, error) {
	if d == nil || d.repo == nil {
		return DetectionResult{}, fmt.Errorf("detector is not initialized")
	}

	now := time.Now().UTC()
	candidates, err := d.repo.FindHTTPErrorSpikes(
		ctx,
		now.Add(-d.config.Window),
		d.config.MinimumCount,
	)
	if err != nil {
		return DetectionResult{}, fmt.Errorf("query HTTP error spikes: %w", err)
	}

	result := DetectionResult{
		CandidatesFound: len(candidates),
	}

	for _, candidate := range candidates {
		since := now.Add(-d.config.SuppressFor)

		exists, err := d.repo.HasRecentOpenAlert(
			ctx,
			candidate.WebsiteID,
			HTTP5xxSpikeRuleKey,
			since,
		)
		if err != nil {
			return result, fmt.Errorf("check duplicate alert for website %s: %w",
				candidate.WebsiteID, err)
		}

		if exists {
			result.AlertsSuppressed++
			continue
		}

		_, err = d.repo.Create(ctx, CreateInput{
			WebsiteID: candidate.WebsiteID,
			Severity:  "high",
			Type:      "http_error_spike",
			Message: fmt.Sprintf(
				"Detected %d HTTP 5xx responses within the configured detection window",
				candidate.ErrorCount,
			),
			RuleKey: HTTP5xxSpikeRuleKey,
			Details: map[string]any{
				"error_count": candidate.ErrorCount,
				"window":      d.config.Window.String(),
				"first_seen":  candidate.FirstSeen,
				"last_seen":   candidate.LastSeen,
			},
		})
		if err != nil {
			return result, fmt.Errorf("create HTTP error spike alert for website %s: %w",
				candidate.WebsiteID, err)
		}

		result.AlertsCreated++
	}

	return result, nil
}

const BruteForceRuleKey = "auth.brute_force"

// RunBruteForceDetection detects repeated authentication failures from the same IP.
func (d *Detector) RunBruteForceDetection(
	ctx context.Context,
) (DetectionResult, error) {
	if d == nil || d.repo == nil {
		return DetectionResult{}, fmt.Errorf("detector is not initialized")
	}

	now := time.Now().UTC()
	candidates, err := d.repo.FindBruteForceCandidates(
		ctx,
		now.Add(-d.config.Window),
		d.config.BruteForceMinimumCount,
	)
	if err != nil {
		return DetectionResult{}, fmt.Errorf("query brute-force candidates: %w", err)
	}

	result := DetectionResult{
		CandidatesFound: len(candidates),
	}

	for _, candidate := range candidates {
		since := now.Add(-d.config.SuppressFor)

		exists, err := d.repo.HasRecentOpenAlertForIP(
			ctx,
			candidate.WebsiteID,
			BruteForceRuleKey,
			candidate.IP,
			since,
		)
		if err != nil {
			return result, fmt.Errorf(
				"check duplicate brute-force alert for website %s and IP %s: %w",
				candidate.WebsiteID,
				candidate.IP,
				err,
			)
		}

		if exists {
			result.AlertsSuppressed++
			continue
		}

		_, err = d.repo.Create(ctx, CreateInput{
			WebsiteID: candidate.WebsiteID,
			Severity:  "high",
			Type:      "brute_force",
			Message: fmt.Sprintf(
				"Detected %d authentication failures from IP %s within the configured detection window",
				candidate.FailureCount,
				candidate.IP,
			),
			IP:      candidate.IP,
			RuleKey: BruteForceRuleKey,
			Details: map[string]any{
				"failure_count": candidate.FailureCount,
				"source_ip":     candidate.IP,
				"window":        d.config.Window.String(),
				"first_seen":    candidate.FirstSeen,
				"last_seen":     candidate.LastSeen,
			},
		})
		if err != nil {
			return result, fmt.Errorf(
				"create brute-force alert for website %s and IP %s: %w",
				candidate.WebsiteID,
				candidate.IP,
				err,
			)
		}

		result.AlertsCreated++
	}

	return result, nil
}

const NotFoundRuleKey = "http.404_spike"

// RunNotFoundDetection detects repeated HTTP 404 responses.
func (d *Detector) RunNotFoundDetection(
	ctx context.Context,
) (DetectionResult, error) {
	if d == nil || d.repo == nil {
		return DetectionResult{}, fmt.Errorf("detector is not initialized")
	}

	now := time.Now().UTC()
	candidates, err := d.repo.FindNotFoundCandidates(
		ctx,
		now.Add(-d.config.Window),
		d.config.NotFoundMinimumCount,
	)
	if err != nil {
		return DetectionResult{}, fmt.Errorf("query HTTP 404 candidates: %w", err)
	}

	result := DetectionResult{CandidatesFound: len(candidates)}

	for _, candidate := range candidates {
		since := now.Add(-d.config.SuppressFor)

		exists, err := d.repo.HasRecentOpenAlert(
			ctx,
			candidate.WebsiteID,
			NotFoundRuleKey,
			since,
		)
		if err != nil {
			return result, fmt.Errorf(
				"check duplicate HTTP 404 alert for website %s: %w",
				candidate.WebsiteID, err,
			)
		}

		if exists {
			result.AlertsSuppressed++
			continue
		}

		_, err = d.repo.Create(ctx, CreateInput{
			WebsiteID: candidate.WebsiteID,
			Severity:  "medium",
			Type:      "http_404_spike",
			Message: fmt.Sprintf(
				"Detected %d HTTP 404 responses within the configured detection window",
				candidate.ErrorCount,
			),
			RuleKey: NotFoundRuleKey,
			Details: map[string]any{
				"error_count": candidate.ErrorCount,
				"window":      d.config.Window.String(),
				"first_seen":  candidate.FirstSeen,
				"last_seen":   candidate.LastSeen,
			},
		})
		if err != nil {
			return result, fmt.Errorf(
				"create HTTP 404 alert for website %s: %w",
				candidate.WebsiteID, err,
			)
		}

		result.AlertsCreated++
	}

	return result, nil
}
