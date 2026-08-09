package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/costattribution"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	UnallocatedMetricCostAnalyzerID         = "builtin.unallocated_metric_cost"
	AmbiguousMetricCostAllocationAnalyzerID = "builtin.ambiguous_metric_cost_allocation"
)

var defaultCostAllocationRequiredDimensions = []string{"team"}

type UnallocatedMetricCostAnalyzer struct{}

func NewUnallocatedMetricCostAnalyzer() *UnallocatedMetricCostAnalyzer {
	return &UnallocatedMetricCostAnalyzer{}
}

func (a *UnallocatedMetricCostAnalyzer) ID() string {
	return UnallocatedMetricCostAnalyzerID
}

func (a *UnallocatedMetricCostAnalyzer) Name() string {
	return "Unallocated Metric Cost"
}

func (a *UnallocatedMetricCostAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnallocatedMetricCostAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *UnallocatedMetricCostAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return executeMetricCostAttribution(ctx, analysis, a.ID(), costattribution.StateUnallocated)
}

type AmbiguousMetricCostAllocationAnalyzer struct{}

func NewAmbiguousMetricCostAllocationAnalyzer() *AmbiguousMetricCostAllocationAnalyzer {
	return &AmbiguousMetricCostAllocationAnalyzer{}
}

func (a *AmbiguousMetricCostAllocationAnalyzer) ID() string {
	return AmbiguousMetricCostAllocationAnalyzerID
}

func (a *AmbiguousMetricCostAllocationAnalyzer) Name() string {
	return "Ambiguous Metric Cost Allocation"
}

func (a *AmbiguousMetricCostAllocationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *AmbiguousMetricCostAllocationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *AmbiguousMetricCostAllocationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return executeMetricCostAttribution(ctx, analysis, a.ID(), costattribution.StateAmbiguous)
}

func executeMetricCostAttribution(ctx context.Context, analysis Context, analyzerID string, targetState string) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}
	dimensions := costAllocationRequiredDimensions(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		series, measured := metricSeriesCount(metric)
		if !measured || series <= 0 {
			continue
		}
		for _, dimension := range dimensions {
			state, _, valueCount := costattribution.Resolve(metric, dimension)
			if state != targetState {
				continue
			}
			findingType := "UnallocatedMetricCost"
			evidence := fmt.Sprintf("metric %q has %d measured series but no %s attribution", metric.Name, series, dimension)
			recommendation := fmt.Sprintf("Add one stable %s label or metadata value so the measured active series can be assigned to a single owner or cost center.", dimension)
			if targetState == costattribution.StateAmbiguous {
				findingType = "AmbiguousMetricCostAllocation"
				evidence = fmt.Sprintf("metric %q has %d measured series and %d conflicting %s attribution values", metric.Name, series, valueCount, dimension)
				recommendation = fmt.Sprintf("Normalize the metric's %s label and metadata to one stable value; MoniCheck will not choose between conflicting owners automatically.", dimension)
			}
			findings = append(findings, model.Finding{
				ID:             model.StableID(analyzerID, metric.ID, dimension),
				Type:           findingType,
				Severity:       model.SeverityWarning,
				Resource:       model.ResourceRef{ID: metric.ID, Type: metric.Type, Name: metric.Name},
				Evidence:       []string{evidence},
				Recommendation: recommendation,
				Metadata: map[string]string{
					"analyzer_id":            analyzerID,
					"allocation_dimension":   dimension,
					"allocation_value_count": strconv.Itoa(valueCount),
					"series_count":           strconv.Itoa(series),
					"series_count_source":    metricSeriesCountSource(metric),
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func costAllocationRequiredDimensions(config map[string]any) []string {
	configured := stringSliceConfig(config, "cost_allocation_required_dimensions", defaultCostAllocationRequiredDimensions)
	normalized, _ := costattribution.NormalizeDimensions(configured)
	if len(normalized) == 0 {
		return append([]string(nil), defaultCostAllocationRequiredDimensions...)
	}
	return normalized
}
