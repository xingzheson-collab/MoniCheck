package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

const MetricCostDriftAnalyzerID = "builtin.metric_cost_drift"

type MetricCostDriftAnalyzer struct{}

func NewMetricCostDriftAnalyzer() *MetricCostDriftAnalyzer {
	return &MetricCostDriftAnalyzer{}
}

func (a *MetricCostDriftAnalyzer) ID() string {
	return MetricCostDriftAnalyzerID
}

func (a *MetricCostDriftAnalyzer) Name() string {
	return "Metric Cost Drift"
}

func (a *MetricCostDriftAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MetricCostDriftAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *MetricCostDriftAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.ReportExports == nil {
		return []model.Finding{}, nil
	}
	lookback := durationConfig(analysis.Config, "cost_metric_drift_lookback", report.DefaultCostMetricDriftLookback)
	ratioThreshold := floatConfig(analysis.Config, "cost_metric_growth_ratio_threshold", report.DefaultCostMetricGrowthRatioThreshold)
	minimum := int64(intConfig(analysis.Config, "cost_metric_growth_minimum", int(report.DefaultCostMetricGrowthMinimum)))
	baseline, _, err := report.LatestCostMetricSeriesBaselines(ctx, analysis.ReportExports, time.Now().UTC().Add(-lookback))
	if err != nil || len(baseline) == 0 {
		return nil, err
	}
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		previous, found := baseline[metric.ID]
		current, measured := metricSeriesCount(metric)
		if !found || !measured || int64(current) <= previous.Series ||
			strings.TrimSpace(metric.Metadata[model.MetadataConnectorID]) != strings.TrimSpace(previous.ConnectorID) ||
			strings.TrimSpace(metricSeriesCountSource(metric)) != strings.TrimSpace(previous.MeasurementSource) ||
			!metric.UpdatedAt.After(previous.SnapshotAt) {
			continue
		}
		increase := int64(current) - previous.Series
		ratio := float64(increase) / float64(previous.Series)
		if increase < minimum || ratio < ratioThreshold {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), metric.ID),
			Type:           "RapidMetricCostGrowth",
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: metric.ID, Type: metric.Type, Name: metric.Name},
			Evidence:       []string{fmt.Sprintf("metric %q grew from %d to %d measured series (+%d, %.1f%%) since the Cost snapshot at %s", metric.Name, previous.Series, current, increase, ratio*100, previous.SnapshotAt.Format(time.RFC3339))},
			Recommendation: "对比快照后的部署、目标发现和标签变更，确认新增 series 是否符合容量计划；否则限制高基数标签、减少采集范围或回滚异常配置。",
			Metadata: map[string]string{
				"analyzer_id":         a.ID(),
				"baseline_at":         previous.SnapshotAt.Format(time.RFC3339),
				"baseline_series":     strconv.FormatInt(previous.Series, 10),
				"current_series":      strconv.Itoa(current),
				"series_growth_delta": strconv.FormatInt(increase, 10),
				"series_growth_ratio": strconv.FormatFloat(ratio, 'f', 6, 64),
				"series_count_source": metricSeriesCountSource(metric),
				"connector_id":        metric.Metadata[model.MetadataConnectorID],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
