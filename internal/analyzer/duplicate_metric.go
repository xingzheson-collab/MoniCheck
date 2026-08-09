package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DuplicateMetricAnalyzerID = "builtin.duplicate_metric"

type DuplicateMetricAnalyzer struct{}

func NewDuplicateMetricAnalyzer() *DuplicateMetricAnalyzer {
	return &DuplicateMetricAnalyzer{}
}

func (a *DuplicateMetricAnalyzer) ID() string {
	return DuplicateMetricAnalyzerID
}

func (a *DuplicateMetricAnalyzer) Name() string {
	return "Duplicate Metric"
}

func (a *DuplicateMetricAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateMetricAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *DuplicateMetricAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		name := normalizeMetricName(metric.Name)
		if name == "" {
			continue
		}
		groups[name] = append(groups[name], metric)
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for name, duplicates := range groups {
		if len(duplicates) < 2 {
			continue
		}
		sort.Slice(duplicates, func(i, j int) bool {
			return duplicates[i].ID < duplicates[j].ID
		})

		original := duplicates[0]
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), name, duplicate.ID),
				Type:     "DuplicateMetric",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("metric %q has the same normalized name as %q", duplicate.Name, original.Name),
				},
				Recommendation: "确认重复指标是否来自不同采集链路或重复暴露；如果语义相同，建议合并采集或统一命名与来源。",
				Metadata: map[string]string{
					"analyzer_id":       a.ID(),
					"duplicate_of_id":   original.ID,
					"duplicate_of_name": original.Name,
					"normalized_metric": name,
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func normalizeMetricName(name string) string {
	return strings.TrimSpace(name)
}
