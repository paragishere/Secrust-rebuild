package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	SuspiciousUserAgentRuleKey = "http.suspicious_user_agent"
	InjectionPatternRuleKey    = "http.injection_pattern"
	SensitivePathRuleKey       = "http.sensitive_path_probe"
	DistributedBruteForceKey   = "auth.distributed_brute_force"
	TrafficAnomalyRuleKey      = "http.traffic_anomaly"
	AuthDeniedSpikeRuleKey     = "auth.denied_spike"
)

type advancedLog struct {
	WebsiteID string
	IP        string
	Path      string
	Status    int
	UserAgent string
	EventType string
	CreatedAt string
}

type advancedFinding struct {
	websiteID string
	ip        string
	ruleKey   string
	alertType string
	severity  string
	message   string
	details   map[string]any
}

func (d *Detector) RunAdvancedDetection(ctx context.Context) (DetectionResult, error) {
	if d == nil || d.repo == nil || d.repo.db == nil {
		return DetectionResult{}, fmt.Errorf("detector is not initialized")
	}

	now := time.Now().UTC()
	since := now.Add(-d.config.Window)

	rows, err := d.repo.db.QueryContext(ctx, `
SELECT l.website_id, COALESCE(trim(l.ip), ''), l.path,
       l.status, COALESCE(l.user_agent, ''), l.event_type,
       l.created_at
FROM logs l
JOIN websites w ON w.id = l.website_id
WHERE w.status = 'active'
  AND l.created_at >= ?
ORDER BY l.created_at ASC
`, since.Format(time.RFC3339Nano))
	if err != nil {
		return DetectionResult{}, fmt.Errorf("query logs for advanced detection: %w", err)
	}

	logs := make([]advancedLog, 0)
	for rows.Next() {
		var item advancedLog
		if err := rows.Scan(
			&item.WebsiteID, &item.IP, &item.Path, &item.Status,
			&item.UserAgent, &item.EventType, &item.CreatedAt,
		); err != nil {
			rows.Close()
			return DetectionResult{}, fmt.Errorf("scan advanced detection log: %w", err)
		}
		logs = append(logs, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return DetectionResult{}, fmt.Errorf("iterate advanced detection logs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return DetectionResult{}, fmt.Errorf("close advanced detection rows: %w", err)
	}

	findings := make([]advancedFinding, 0)
	type ipKey struct {
		website string
		ip      string
	}
	type websiteKey struct {
		website string
	}
	type grouped struct {
		count int
		ips   map[string]bool
		first string
		last  string
	}

	suspiciousAgents := []string{
		"sqlmap", "nikto", "masscan", "zgrab", "nuclei",
		"gobuster", "dirbuster", "wpscan", "acunetix",
		"nessus", "ffuf", "hydra", "metasploit",
	}
	injectionPatterns := []string{
		"union select", "' or 1=1", "\" or 1=1", "<script",
		"%3cscript", "javascript:", "onerror=", "onload=",
		"../", "%2e%2e%2f", "information_schema",
	}
	sensitivePaths := []string{
		"/.env", "/.git", "/wp-admin", "/wp-login.php",
		"/phpmyadmin", "/server-status", "/actuator",
		"/swagger", "/config.php", "/backup", "/etc/passwd",
		"/.aws", "/debug",
	}

	agentGroups := make(map[ipKey]*grouped)
	injectionGroups := make(map[ipKey]*grouped)
	sensitiveGroups := make(map[ipKey]*grouped)
	deniedGroups := make(map[ipKey]*grouped)
	distributedGroups := make(map[websiteKey]*grouped)

	add := func(groups map[ipKey]*grouped, key ipKey, item advancedLog) {
		g := groups[key]
		if g == nil {
			g = &grouped{first: item.CreatedAt}
			groups[key] = g
		}
		g.count++
		g.last = item.CreatedAt
	}
	addDistributed := func(key websiteKey, item advancedLog) {
		g := distributedGroups[key]
		if g == nil {
			g = &grouped{first: item.CreatedAt, ips: make(map[string]bool)}
			distributedGroups[key] = g
		}
		g.count++
		g.last = item.CreatedAt
		if item.IP != "" {
			g.ips[item.IP] = true
		}
	}

	for _, item := range logs {
		if err := ctx.Err(); err != nil {
			return DetectionResult{}, err
		}
		key := ipKey{website: item.WebsiteID, ip: item.IP}
		lowerUA := strings.ToLower(item.UserAgent)
		lowerPath := strings.ToLower(item.Path)

		for _, pattern := range suspiciousAgents {
			if strings.Contains(lowerUA, pattern) {
				add(agentGroups, key, item)
				break
			}
		}
		for _, pattern := range injectionPatterns {
			if strings.Contains(lowerPath, pattern) {
				add(injectionGroups, key, item)
				break
			}
		}
		for _, pattern := range sensitivePaths {
			if strings.Contains(lowerPath, pattern) {
				add(sensitiveGroups, key, item)
				break
			}
		}
		if item.Status == 401 || item.Status == 403 {
			add(deniedGroups, key, item)
		}
		if item.EventType == "auth_failure" {
			addDistributed(websiteKey{website: item.WebsiteID}, item)
		}
	}

	for key, g := range agentGroups {
		findings = append(findings, advancedFinding{
			websiteID: key.website, ip: key.ip,
			ruleKey: SuspiciousUserAgentRuleKey, alertType: "suspicious_user_agent",
			severity: "high",
			message:  "Request used a known security-scanner or attack-tool User-Agent",
			details: map[string]any{
				"source_ip": key.ip, "matching_requests": g.count,
				"window":     d.config.Window.String(),
				"first_seen": g.first, "last_seen": g.last,
			},
		})
	}
	for key, g := range injectionGroups {
		findings = append(findings, advancedFinding{
			websiteID: key.website, ip: key.ip,
			ruleKey: InjectionPatternRuleKey, alertType: "injection_pattern",
			severity: "high",
			message:  "Request path contains a suspicious SQL injection, XSS, or traversal pattern",
			details: map[string]any{
				"source_ip": key.ip, "matching_requests": g.count,
				"window":     d.config.Window.String(),
				"first_seen": g.first, "last_seen": g.last,
			},
		})
	}
	for key, g := range sensitiveGroups {
		findings = append(findings, advancedFinding{
			websiteID: key.website, ip: key.ip,
			ruleKey: SensitivePathRuleKey, alertType: "sensitive_path_probe",
			severity: "medium",
			message:  "Request targeted a commonly exposed or sensitive path",
			details: map[string]any{
				"source_ip": key.ip, "matching_requests": g.count,
				"window":     d.config.Window.String(),
				"first_seen": g.first, "last_seen": g.last,
			},
		})
	}
	for key, g := range deniedGroups {
		if g.count < d.config.BruteForceMinimumCount {
			continue
		}
		findings = append(findings, advancedFinding{
			websiteID: key.website, ip: key.ip,
			ruleKey: AuthDeniedSpikeRuleKey, alertType: "auth_denied_spike",
			severity: "medium",
			message:  fmt.Sprintf("Detected %d HTTP 401/403 responses from one IP", g.count),
			details: map[string]any{
				"source_ip": key.ip, "denied_count": g.count,
				"window":     d.config.Window.String(),
				"first_seen": g.first, "last_seen": g.last,
			},
		})
	}
	for key, g := range distributedGroups {
		if g.count < d.config.BruteForceMinimumCount || len(g.ips) < 3 {
			continue
		}
		findings = append(findings, advancedFinding{
			websiteID: key.website,
			ruleKey:   DistributedBruteForceKey, alertType: "distributed_brute_force",
			severity: "high",
			message:  fmt.Sprintf("Detected %d authentication failures from %d distinct IPs", g.count, len(g.ips)),
			details: map[string]any{
				"failure_count": g.count, "distinct_source_ips": len(g.ips),
				"window":     d.config.Window.String(),
				"first_seen": g.first, "last_seen": g.last,
			},
		})
	}

	// Compare current traffic with the immediately preceding window.
	currentCounts := make(map[string]int)
	previousCounts := make(map[string]int)
	previousSince := since.Add(-d.config.Window).Format(time.RFC3339Nano)
	currentSince := since.Format(time.RFC3339Nano)
	baselineRows, err := d.repo.db.QueryContext(ctx, `
SELECT l.website_id,
       SUM(CASE WHEN l.created_at >= ? THEN 1 ELSE 0 END),
       SUM(CASE WHEN l.created_at < ? THEN 1 ELSE 0 END)
FROM logs l
JOIN websites w ON w.id = l.website_id
WHERE w.status = 'active'
  AND l.created_at >= ?
GROUP BY l.website_id
`, currentSince, currentSince, previousSince)
	if err != nil {
		return DetectionResult{}, fmt.Errorf("query traffic baseline: %w", err)
	}
	for baselineRows.Next() {
		var websiteID string
		var current, previous int
		if err := baselineRows.Scan(&websiteID, &current, &previous); err != nil {
			baselineRows.Close()
			return DetectionResult{}, fmt.Errorf("scan traffic baseline: %w", err)
		}
		currentCounts[websiteID] = current
		previousCounts[websiteID] = previous
	}
	if err := baselineRows.Err(); err != nil {
		baselineRows.Close()
		return DetectionResult{}, fmt.Errorf("iterate traffic baseline: %w", err)
	}
	if err := baselineRows.Close(); err != nil {
		return DetectionResult{}, fmt.Errorf("close traffic baseline rows: %w", err)
	}
	for websiteID, current := range currentCounts {
		previous := previousCounts[websiteID]
		if current < d.config.RequestRateMinimumCount || previous < 1 || current < previous*3 {
			continue
		}
		findings = append(findings, advancedFinding{
			websiteID: websiteID,
			ruleKey:   TrafficAnomalyRuleKey, alertType: "traffic_anomaly",
			severity: "medium",
			message:  fmt.Sprintf("Request volume increased from %d to %d compared with the previous window", previous, current),
			details: map[string]any{
				"current_requests": current, "previous_requests": previous,
				"window": d.config.Window.String(),
			},
		})
	}

	result := DetectionResult{CandidatesFound: len(findings)}
	for _, finding := range findings {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var (
			exists bool
			err    error
		)
		if finding.ip != "" {
			exists, err = d.repo.HasRecentOpenAlertForIP(
				ctx, finding.websiteID, finding.ruleKey, finding.ip,
				now.Add(-d.config.SuppressFor),
			)
		} else {
			exists, err = d.repo.HasRecentOpenAlert(
				ctx, finding.websiteID, finding.ruleKey,
				now.Add(-d.config.SuppressFor),
			)
		}
		if err != nil {
			return result, fmt.Errorf("check duplicate %s alert: %w", finding.ruleKey, err)
		}
		if exists {
			result.AlertsSuppressed++
			continue
		}
		_, err = d.repo.Create(ctx, CreateInput{
			WebsiteID: finding.websiteID,
			Severity:  finding.severity,
			Type:      finding.alertType,
			Message:   finding.message,
			IP:        finding.ip,
			RuleKey:   finding.ruleKey,
			Details:   finding.details,
		})
		if err != nil {
			return result, fmt.Errorf("create %s alert: %w", finding.ruleKey, err)
		}
		result.AlertsCreated++
	}
	return result, nil
}
