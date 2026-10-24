package alerts

import (
	"context"
	"fmt"
	"time"
)

type ErrorSpikeCandidate struct {
	OrganizationID string
	WebsiteID      string
	ErrorCount     int
	FirstSeen      string
	LastSeen       string
}

func (r *Repository) FindHTTPErrorSpikes(
	ctx context.Context,
	since time.Time,
	minimumCount int,
) ([]ErrorSpikeCandidate, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("alert repository is not initialized")
	}
	if minimumCount < 1 {
		return nil, fmt.Errorf("minimum count must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			w.organization_id,
			l.website_id,
			COUNT(*),
			MIN(l.created_at),
			MAX(l.created_at)
		FROM logs l
		JOIN websites w ON w.id = l.website_id
		WHERE w.status = 'active'
		  AND l.status BETWEEN 500 AND 599
		  AND l.created_at >= ?
		GROUP BY w.organization_id, l.website_id
		HAVING COUNT(*) >= ?
		ORDER BY COUNT(*) DESC, l.website_id ASC
	`, since.UTC().Format(time.RFC3339Nano), minimumCount)
	if err != nil {
		return nil, fmt.Errorf("find HTTP error spikes: %w", err)
	}
	defer rows.Close()

	candidates := make([]ErrorSpikeCandidate, 0)

	for rows.Next() {
		var candidate ErrorSpikeCandidate
		if err := rows.Scan(
			&candidate.OrganizationID,
			&candidate.WebsiteID,
			&candidate.ErrorCount,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan HTTP error spike: %w", err)
		}
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate HTTP error spikes: %w", err)
	}

	return candidates, nil
}

type BruteForceCandidate struct {
	OrganizationID string
	WebsiteID      string
	IP             string
	FailureCount   int
	FirstSeen      string
	LastSeen       string
}

// FindBruteForceCandidates finds source IPs with repeated authentication failures.
func (r *Repository) FindBruteForceCandidates(
	ctx context.Context,
	since time.Time,
	minimumCount int,
) ([]BruteForceCandidate, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("alert repository is not initialized")
	}
	if minimumCount < 1 {
		return nil, fmt.Errorf("minimum count must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			w.organization_id,
			l.website_id,
			l.ip,
			COUNT(*),
			MIN(l.created_at),
			MAX(l.created_at)
		FROM logs l
		JOIN websites w ON w.id = l.website_id
		WHERE w.status = 'active'
		  AND l.event_type = 'auth_failure'
		  AND l.ip IS NOT NULL
		  AND trim(l.ip) <> ''
		  AND l.created_at >= ?
		GROUP BY w.organization_id, l.website_id, l.ip
		HAVING COUNT(*) >= ?
		ORDER BY COUNT(*) DESC, l.website_id ASC, l.ip ASC
	`, since.UTC().Format(time.RFC3339Nano), minimumCount)
	if err != nil {
		return nil, fmt.Errorf("find brute-force candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]BruteForceCandidate, 0)
	for rows.Next() {
		var candidate BruteForceCandidate
		if err := rows.Scan(
			&candidate.OrganizationID,
			&candidate.WebsiteID,
			&candidate.IP,
			&candidate.FailureCount,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan brute-force candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate brute-force candidates: %w", err)
	}

	return candidates, nil
}

type NotFoundCandidate struct {
	OrganizationID string
	WebsiteID      string
	ErrorCount     int
	FirstSeen      string
	LastSeen       string
}

// FindNotFoundCandidates finds active websites with repeated HTTP 404 responses.
func (r *Repository) FindNotFoundCandidates(
	ctx context.Context,
	since time.Time,
	minimumCount int,
) ([]NotFoundCandidate, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("alert repository is not initialized")
	}
	if minimumCount < 1 {
		return nil, fmt.Errorf("minimum count must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			w.organization_id,
			l.website_id,
			COUNT(*),
			MIN(l.created_at),
			MAX(l.created_at)
		FROM logs l
		JOIN websites w ON w.id = l.website_id
		WHERE w.status = 'active'
		  AND l.status = 404
		  AND l.created_at >= ?
		GROUP BY w.organization_id, l.website_id
		HAVING COUNT(*) >= ?
		ORDER BY COUNT(*) DESC, l.website_id ASC
	`, since.UTC().Format(time.RFC3339Nano), minimumCount)
	if err != nil {
		return nil, fmt.Errorf("find HTTP 404 candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]NotFoundCandidate, 0)

	for rows.Next() {
		var candidate NotFoundCandidate
		if err := rows.Scan(
			&candidate.OrganizationID,
			&candidate.WebsiteID,
			&candidate.ErrorCount,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan HTTP 404 candidate: %w", err)
		}

		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate HTTP 404 candidates: %w", err)
	}

	return candidates, nil
}

type RequestRateCandidate struct {
	OrganizationID string
	WebsiteID      string
	IP             string
	RequestCount   int
	FirstSeen      string
	LastSeen       string
}

// FindRequestRateCandidates finds IPs exceeding the request threshold
// for active websites within the supplied time window.
func (r *Repository) FindRequestRateCandidates(
	ctx context.Context,
	since time.Time,
	minimumCount int,
) ([]RequestRateCandidate, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("alert repository is not initialized")
	}
	if minimumCount < 1 {
		return nil, fmt.Errorf("minimum count must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			w.organization_id,
			l.website_id,
			trim(l.ip),
			COUNT(*),
			MIN(l.created_at),
			MAX(l.created_at)
		FROM logs l
		JOIN websites w ON w.id = l.website_id
		WHERE w.status = 'active'
		  AND l.ip IS NOT NULL
		  AND trim(l.ip) <> ''
		  AND l.created_at >= ?
		GROUP BY w.organization_id, l.website_id, trim(l.ip)
		HAVING COUNT(*) >= ?
		ORDER BY COUNT(*) DESC, l.website_id ASC, trim(l.ip) ASC
	`, since.UTC().Format(time.RFC3339Nano), minimumCount)
	if err != nil {
		return nil, fmt.Errorf("find request-rate candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]RequestRateCandidate, 0)

	for rows.Next() {
		var candidate RequestRateCandidate
		if err := rows.Scan(
			&candidate.OrganizationID,
			&candidate.WebsiteID,
			&candidate.IP,
			&candidate.RequestCount,
			&candidate.FirstSeen,
			&candidate.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan request-rate candidate: %w", err)
		}

		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate request-rate candidates: %w", err)
	}

	return candidates, nil
}
