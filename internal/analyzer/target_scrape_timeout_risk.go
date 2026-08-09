package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const TargetScrapeTimeoutRiskAnalyzerID = "builtin.target_scrape_timeout_risk"

const defaultTargetScrapeTimeoutRatioThreshold = 0.8

type TargetScrapeTimeoutRiskAnalyzer struct{}

func NewTargetScrapeTimeoutRiskAnalyzer() *TargetScrapeTimeoutRiskAnalyzer {
	return &TargetScrapeTimeoutRiskAnalyzer{}
}

func (a *TargetScrapeTimeoutRiskAnalyzer) ID() string {
	return TargetScrapeTimeoutRiskAnalyzerID
}

func (a *TargetScrapeTimeoutRiskAnalyzer) Name() string {
	return "Target Scrape Timeout Risk"
}

func (a *TargetScrapeTimeoutRiskAnalyzer) Version() string {
	return "0.1.0"
}

func (a *TargetScrapeTimeoutRiskAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *TargetScrapeTimeoutRiskAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	threshold := floatConfig(analysis.Config, "target_scrape_timeout_ratio_threshold", defaultTargetScrapeTimeoutRatioThreshold)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_target_scrape_timeout_risks", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, target := range targets {
		if !isActivePrometheusTarget(target) {
			continue
		}
		duration, ok := parseTargetDuration(target.Metadata[model.MetadataScrapeDuration])
		if !ok {
			continue
		}
		timeout, ok := parseTargetDuration(target.Metadata[model.MetadataScrapeTimeout])
		if !ok {
			continue
		}
		ratio := float64(duration) / float64(timeout)
		if ratio < threshold {
			continue
		}
		if allowedResource(target, allowed, model.MetadataScrapeURL, model.MetadataScrapePool) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "TargetScrapeTimeoutRisk",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("prometheus target %q scrape duration is %s of %s timeout (ratio %.2f, threshold %.2f)", target.Name, duration, timeout, ratio, threshold),
			},
			Recommendation: "优化 exporter 响应时间、减少高成本采集或调整 scrape timeout；scrape 耗时接近 timeout 时容易出现间歇性采集失败。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"scrape_duration": duration.String(),
				"scrape_timeout":  timeout.String(),
				"ratio":           fmt.Sprintf("%.4f", ratio),
				"threshold":       fmt.Sprintf("%.4f", threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseTargetDuration(raw string) (time.Duration, bool) {
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}
