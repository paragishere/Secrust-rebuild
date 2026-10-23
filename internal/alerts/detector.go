package alerts

import (
	"context"
	"fmt"
	"time"
)

const HTTP5xxSpikeRuleKey = "http.5xx_spike"

type DetectorConfig struct {
	Window       time.Duration
	MinimumCount int
	SuppressFor  time.Duration
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
	if config.SuppressFor <= 0 {
		return nil, fmt.Errorf("suppression duration must be positive")
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
