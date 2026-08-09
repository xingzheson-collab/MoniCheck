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
	DashboardQueryFanoutAnalyzerID       = "builtin.dashboard_query_fanout"
	defaultDashboardQueryFanoutThreshold = 15
)

type DashboardQueryFanoutAnalyzer struct{}

func NewDashboardQueryFanoutAnalyzer() *DashboardQueryFanoutAnalyzer {
	return &DashboardQueryFanoutAnalyzer{}
}

func (a *DashboardQueryFanoutAnalyzer) ID() string {
	return DashboardQueryFanoutAnalyzerID
}

func (a *DashboardQueryFanoutAnalyzer) Name() string {
	return "Dashboard Query Fanout"
}

func (a *DashboardQueryFanoutAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DashboardQueryFanoutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *DashboardQueryFanoutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, "dashboard_query_fanout_threshold", defaultDashboardQueryFanoutThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if dashboard.Source.System != "grafana" || dashboard.Status != model.ResourceStatusActive {
			continue
		}
		panels := dashboardQueryPanels(dashboard.ID, analysis)
		if len(panels) <= threshold {
			continue
		}

		panelNames := sampledConsumerNames(panels, defaultHighImpactMetricConsumerNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "DashboardQueryFanout",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q has %d query panels, threshold is %d", dashboard.Name, len(panels), threshold),
				fmt.Sprintf("sample query panels: %s", strings.Join(panelNames, ", ")),
			},
			Recommendation: "拆分高 fanout Dashboard，减少默认首屏查询数量；对重复或重型 PromQL 使用 Recording Rule 预聚合，降低打开页面时的数据源并发压力。",
			Metadata: map[string]string{
				"analyzer_id":       a.ID(),
				"query_panel_count": strconv.Itoa(len(panels)),
				"threshold":         strconv.Itoa(threshold),
				"panels":            strings.Join(panelNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func dashboardQueryPanels(dashboardID string, analysis Context) []model.Resource {
	panels := make([]model.Resource, 0)
	seen := map[string]bool{}
	for _, relationship := range analysis.Graph.Incoming(dashboardID) {
		if relationship.Type != model.RelationshipBelongsTo || seen[relationship.FromID] {
			continue
		}
		panel, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || panel.Type != model.ResourceTypePanel || panel.Status != model.ResourceStatusActive {
			continue
		}
		if strings.TrimSpace(panel.Metadata[model.MetadataPromQL]) == "" {
			continue
		}
		seen[panel.ID] = true
		panels = append(panels, panel)
	}
	sortResourcesByTypeAndName(panels)
	return panels
}
