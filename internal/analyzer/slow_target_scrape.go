package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SlowTargetScrapeAnalyzerID = "builtin.slow_target_scrape"

const defaultSlowTargetScrapeThreshold = 5 * time.Second

type SlowTargetScrapeAnalyzer struct{}

func NewSlowTargetScrapeAnalyzer() *SlowTargetScrapeAnalyzer {
	return &SlowTargetScrapeAnalyzer{}
}

func (a *SlowTargetScrapeAnalyzer) ID() string {
	return SlowTargetScrapeAnalyzerID
}

func (a *SlowTargetScrapeAnalyzer) Name() string {
	return "Slow Target Scrape"
}

func (a *SlowTargetScrapeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SlowTargetScrapeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *SlowTargetScrapeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "slow_target_scrape_threshold", defaultSlowTargetScrapeThreshold)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_slow_target_scrapes", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, target := range targets {
		if !isActivePrometheusTarget(target) {
			continue
		}
		duration, err := time.ParseDuration(strings.TrimSpace(target.Metadata[model.MetadataScrapeDuration]))
		if err != nil || duration <= threshold {
			continue
		}
		if allowedResource(target, allowed, model.MetadataScrapeURL, model.MetadataScrapePool) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "SlowTargetScrape",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("prometheus target %q scrape duration is %s, threshold is %s", target.Name, duration, threshold),
			},
			Recommendation: "检查 exporter 响应耗时、采集标签规模和网络链路；慢 scrape 容易逼近 scrape_timeout，导致样本缺失或采集抖动。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"scrape_duration": duration.String(),
				"threshold":       threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func isActivePrometheusTarget(target model.Resource) bool {
	return target.Type == model.ResourceTypeTarget &&
		isPrometheusCompatibleSource(target.Source.System) &&
		target.Status == model.ResourceStatusActive
}
