package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
)

const WideLogQueryAnalyzerID = "builtin.wide_log_query"

type WideLogQueryAnalyzer struct{}

func NewWideLogQueryAnalyzer() *WideLogQueryAnalyzer {
	return &WideLogQueryAnalyzer{}
}

func (a *WideLogQueryAnalyzer) ID() string {
	return WideLogQueryAnalyzerID
}

func (a *WideLogQueryAnalyzer) Name() string {
	return "Wide Log Query"
}

func (a *WideLogQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *WideLogQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel}
}

func (a *WideLogQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "wide_log_query_threshold", defaultWideRangeQueryThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !strings.Contains(strings.ToLower(resource.Metadata[model.MetadataQueryLanguage]), "logql") {
			continue
		}
		query := strings.TrimSpace(resource.Metadata[model.MetadataQuery])
		if query == "" {
			continue
		}
		duration, ok := maxPromQLRangeDuration(query)
		if !ok || duration <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "WideLogQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("LogQL max range selector is %s, threshold is %s", duration, threshold),
			},
			Recommendation: "缩短 LogQL range selector，或将高频日志查询改为指标化、预聚合或更精确的标签过滤，降低 Loki 查询和存储扫描成本。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"max_range":   duration.String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
