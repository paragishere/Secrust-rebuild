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
