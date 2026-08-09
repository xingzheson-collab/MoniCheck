package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighMemoryMetricLabelAnalyzerID        = "builtin.high_memory_metric_label"
	defaultMetricLabelMemoryBytesThreshold = 1024 * 1024
)

type HighMemoryMetricLabelAnalyzer struct{}

func NewHighMemoryMetricLabelAnalyzer() *HighMemoryMetricLabelAnalyzer {
	return &HighMemoryMetricLabelAnalyzer{}
}

func (a *HighMemoryMetricLabelAnalyzer) ID() string      { return HighMemoryMetricLabelAnalyzerID }
func (a *HighMemoryMetricLabelAnalyzer) Name() string    { return "High Memory Metric Label" }
func (a *HighMemoryMetricLabelAnalyzer) Version() string { return "0.1.0" }
func (a *HighMemoryMetricLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetricLabel}
}

func (a *HighMemoryMetricLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetricLabel})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "metric_label_memory_bytes_threshold", defaultMetricLabelMemoryBytesThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, label := range labels {
		if label.Status != model.ResourceStatusActive {
			continue
		}
		memoryBytes, ok := positiveMetadataInt(label, model.MetadataMetricLabelMemoryBytes)
		if !ok || memoryBytes <= threshold {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), label.ID),
			Type:     "HighMemoryMetricLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: label.ID, Type: label.Type, Name: label.Name},
			Evidence: []string{
				fmt.Sprintf("Prometheus metric label %q uses %d bytes of value text in the TSDB Head, threshold is %d bytes", label.Name, memoryBytes, threshold),
			},
			Recommendation: "缩短该 label 的值并减少不同值数量；避免完整 URL、UUID、请求标识或其他长字符串进入 Prometheus labels。",
			Metadata: map[string]string{
				"analyzer_id":  a.ID(),
				"label":        label.Name,
				"memory_bytes": strconv.Itoa(memoryBytes),
				"threshold":    strconv.Itoa(threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.Name < findings[j].Resource.Name })
	return findings, nil
}
