package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const LongDashboardTimeRangeAnalyzerID = "builtin.long_dashboard_time_range"

const defaultLongDashboardTimeRangeThreshold = 7 * 24 * time.Hour

type LongDashboardTimeRangeAnalyzer struct{}

func NewLongDashboardTimeRangeAnalyzer() *LongDashboardTimeRangeAnalyzer {
	return &LongDashboardTimeRangeAnalyzer{}
}

func (a *LongDashboardTimeRangeAnalyzer) ID() string {
	return LongDashboardTimeRangeAnalyzerID
}

func (a *LongDashboardTimeRangeAnalyzer) Name() string {
	return "Long Dashboard Time Range"
}

func (a *LongDashboardTimeRangeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *LongDashboardTimeRangeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *LongDashboardTimeRangeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "long_dashboard_time_range_threshold", defaultLongDashboardTimeRangeThreshold)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_long_dashboard_time_ranges", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if dashboard.Source.System != "grafana" || !isActiveDashboard(dashboard) {
			continue
		}
		timeRange, err := time.ParseDuration(strings.TrimSpace(dashboard.Metadata[model.MetadataDashboardTimeRange]))
		if err != nil || timeRange <= threshold {
			continue
		}
		if allowedResource(dashboard, allowed, model.MetadataDashboardUID) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "LongDashboardTimeRange",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q default time range is %s, threshold is %s", dashboard.Name, timeRange, threshold),
			},
			Recommendation: "缩短 Dashboard 默认时间范围，或为长周期分析拆分专用看板；过长默认范围会增加数据源扫描量并拖慢打开速度。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"time_range":  timeRange.String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
