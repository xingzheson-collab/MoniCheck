package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const FastDashboardRefreshAnalyzerID = "builtin.fast_dashboard_refresh"

const defaultFastDashboardRefreshThreshold = 30 * time.Second

type FastDashboardRefreshAnalyzer struct{}

func NewFastDashboardRefreshAnalyzer() *FastDashboardRefreshAnalyzer {
	return &FastDashboardRefreshAnalyzer{}
}

func (a *FastDashboardRefreshAnalyzer) ID() string {
	return FastDashboardRefreshAnalyzerID
}

func (a *FastDashboardRefreshAnalyzer) Name() string {
	return "Fast Dashboard Refresh"
}

func (a *FastDashboardRefreshAnalyzer) Version() string {
	return "0.1.0"
}

func (a *FastDashboardRefreshAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *FastDashboardRefreshAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "fast_dashboard_refresh_threshold", defaultFastDashboardRefreshThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if dashboard.Source.System != "grafana" || !isActiveDashboard(dashboard) {
			continue
		}
		refresh, ok := parseDashboardRefresh(dashboard.Metadata[model.MetadataDashboardRefresh])
		if !ok || refresh >= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "FastDashboardRefresh",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q refreshes every %s, threshold is %s", dashboard.Name, refresh, threshold),
			},
			Recommendation: "延长 Dashboard 自动刷新间隔，或仅在排障页面保留短刷新；过短刷新会放大数据源查询压力和浏览器渲染成本。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"refresh":     refresh.String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseDashboardRefresh(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "off" || raw == "false" || raw == "0" {
		return 0, false
	}
	return parsePromQLDuration(raw)
}
