package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const StaleTargetScrapeAnalyzerID = "builtin.stale_target_scrape"

const defaultStaleTargetScrapeThreshold = 10 * time.Minute

type StaleTargetScrapeAnalyzer struct{}

func NewStaleTargetScrapeAnalyzer() *StaleTargetScrapeAnalyzer {
	return &StaleTargetScrapeAnalyzer{}
}

func (a *StaleTargetScrapeAnalyzer) ID() string {
	return StaleTargetScrapeAnalyzerID
}

func (a *StaleTargetScrapeAnalyzer) Name() string {
	return "Stale Target Scrape"
}

func (a *StaleTargetScrapeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *StaleTargetScrapeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *StaleTargetScrapeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "stale_target_scrape_threshold", defaultStaleTargetScrapeThreshold)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_stale_target_scrapes", nil))
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isActivePrometheusTarget(target) {
			continue
		}
		lastScrape, ok := parseTargetLastScrape(target)
		if !ok {
			continue
		}
		age := now.Sub(lastScrape)
		if age <= threshold {
			continue
		}
		if allowedResource(target, allowed, model.MetadataScrapeURL, model.MetadataScrapePool) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "StaleTargetScrape",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("prometheus target %q was last scraped at %s, threshold is %s", target.Name, lastScrape.Format(time.RFC3339), threshold),
			},
			Recommendation: "检查 Prometheus target discovery、scrape 配置、网络连通性和 exporter 存活状态；target 长时间未 scrape 会导致指标断流和告警失真。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"last_scrape": lastScrape.Format(time.RFC3339),
				"age":         age.Round(time.Second).String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseTargetLastScrape(target model.Resource) (time.Time, bool) {
	raw := strings.TrimSpace(target.Metadata[model.MetadataLastScrape])
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
