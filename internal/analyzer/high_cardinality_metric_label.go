package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighCardinalityMetricLabelAnalyzerID  = "builtin.high_cardinality_metric_label"
	defaultMetricLabelValueCountThreshold = 1000
)

type HighCardinalityMetricLabelAnalyzer struct{}

func NewHighCardinalityMetricLabelAnalyzer() *HighCardinalityMetricLabelAnalyzer {
	return &HighCardinalityMetricLabelAnalyzer{}
}

func (a *HighCardinalityMetricLabelAnalyzer) ID() string      { return HighCardinalityMetricLabelAnalyzerID }
func (a *HighCardinalityMetricLabelAnalyzer) Name() string    { return "High Cardinality Metric Label" }
func (a *HighCardinalityMetricLabelAnalyzer) Version() string { return "0.1.0" }
func (a *HighCardinalityMetricLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetricLabel}
}

func (a *HighCardinalityMetricLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetricLabel})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "metric_label_value_threshold", defaultMetricLabelValueCountThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, label := range labels {
		if label.Status != model.ResourceStatusActive {
			continue
		}
		count, ok := positiveMetadataInt(label, model.MetadataMetricLabelValueCount)
		if !ok || count <= threshold {
			continue
		}
		metadata := map[string]string{
			"analyzer_id": a.ID(),
			"label":       label.Name,
			"value_count": strconv.Itoa(count),
			"threshold":   strconv.Itoa(threshold),
		}
		evidence := fmt.Sprintf("Prometheus metric label %q has %d values in the TSDB Head, threshold is %d", label.Name, count, threshold)
		if value := strings.TrimSpace(label.Metadata[model.MetadataMetricLabelTopValue]); value != "" {
			metadata[model.MetadataMetricLabelTopValue] = value
			metadata[model.MetadataMetricLabelTopSeries] = label.Metadata[model.MetadataMetricLabelTopSeries]
			evidence += fmt.Sprintf("; top value %q appears in %s series", value, label.Metadata[model.MetadataMetricLabelTopSeries])
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), label.ID),
			Type:           "HighCardinalityMetricLabel",
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: label.ID, Type: label.Type, Name: label.Name},
			Evidence:       []string{evidence},
			Recommendation: "检查该 Prometheus label 的值域和来源；删除无界 user/request/trace 标识，规范 path 等动态值，并优先保留稳定、可枚举的聚合维度。",
			Metadata:       metadata,
			Status:         model.FindingStatusOpen,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.Name < findings[j].Resource.Name })
	return findings, nil
}

func positiveMetadataInt(resource model.Resource, key string) (int, bool) {
	value := strings.TrimSpace(resource.Metadata[key])
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed > 0
}
