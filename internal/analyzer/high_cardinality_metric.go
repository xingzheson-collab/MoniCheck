package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighCardinalityMetricAnalyzerID = "builtin.high_cardinality_metric"
	defaultSeriesCountThreshold     = 1000
)

type HighCardinalityMetricAnalyzer struct{}

func NewHighCardinalityMetricAnalyzer() *HighCardinalityMetricAnalyzer {
	return &HighCardinalityMetricAnalyzer{}
}

func (a *HighCardinalityMetricAnalyzer) ID() string {
	return HighCardinalityMetricAnalyzerID
}

func (a *HighCardinalityMetricAnalyzer) Name() string {
	return "High Cardinality Metric"
}

func (a *HighCardinalityMetricAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighCardinalityMetricAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *HighCardinalityMetricAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	threshold := seriesCountThreshold(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		count, ok := metricSeriesCount(metric)
		if !ok || count <= threshold {
			continue
		}
		countSource := metricSeriesCountSource(metric)
		metadata := map[string]string{
			"analyzer_id":         a.ID(),
			"series_count":        strconv.Itoa(count),
			"series_count_source": countSource,
			"threshold":           strconv.Itoa(threshold),
		}
		if value := strings.TrimSpace(metric.Metadata[model.MetadataTSDBHeadSeriesCount]); value != "" {
			metadata[model.MetadataTSDBHeadSeriesCount] = value
		}
		if value := strings.TrimSpace(metric.Metadata[model.MetadataRecentSeriesCount]); value != "" {
			metadata[model.MetadataRecentSeriesCount] = value
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), metric.ID),
			Type:     "HighCardinalityMetric",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   metric.ID,
				Type: metric.Type,
				Name: metric.Name,
			},
			Evidence: []string{
				fmt.Sprintf("metric %q has %d series from %s, threshold is %d", metric.Name, count, countSource, threshold),
			},
			Recommendation: "Review the metric's label design, especially unbounded values such as user_id, request_id, raw path, or pod. Remove or aggregate labels that are not needed for queries or alerts.",
			Metadata:       metadata,
			Status:         model.FindingStatusOpen,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	return findings, nil
}

func metricSeriesCountSource(metric model.Resource) string {
	source := strings.TrimSpace(metric.Metadata[model.MetadataSeriesCountSource])
	if source == "" {
		return "unknown"
	}
	return source
}

func metricSeriesCount(metric model.Resource) (int, bool) {
	value := strings.TrimSpace(metric.Metadata[model.MetadataSeriesCount])
	if value == "" {
		return 0, false
	}
	count, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return count, true
}

func seriesCountThreshold(config map[string]any) int {
	return intConfig(config, "series_count_threshold", defaultSeriesCountThreshold)
}

func isActiveMetric(metric model.Resource) bool {
	return metric.Type == model.ResourceTypeMetric && metric.Status == model.ResourceStatusActive
}
