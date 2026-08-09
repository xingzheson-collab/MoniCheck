package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const LargeDashboardAnalyzerID = "builtin.large_dashboard"

const defaultLargeDashboardPanelThreshold = 20

type LargeDashboardAnalyzer struct{}

func NewLargeDashboardAnalyzer() *LargeDashboardAnalyzer {
	return &LargeDashboardAnalyzer{}
}

func (a *LargeDashboardAnalyzer) ID() string {
	return LargeDashboardAnalyzerID
}

func (a *LargeDashboardAnalyzer) Name() string {
	return "Large Dashboard"
}

func (a *LargeDashboardAnalyzer) Version() string {
	return "0.1.0"
}

func (a *LargeDashboardAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *LargeDashboardAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := intConfig(analysis.Config, "large_dashboard_panel_threshold", defaultLargeDashboardPanelThreshold)
	for _, dashboard := range dashboards {
		if dashboard.Status != model.ResourceStatusActive {
			continue
		}
		panelCount := dashboardPanelCount(dashboard.ID, analysis.Graph)
		if panelCount <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "LargeDashboard",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("dashboard %q has %d panels, threshold is %d", dashboard.Name, panelCount, threshold),
			},
			Recommendation: "考虑拆分大型 Dashboard，减少单页查询压力并提升维护性。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"panel_count": fmt.Sprintf("%d", panelCount),
				"threshold":   fmt.Sprintf("%d", threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func dashboardPanelCount(dashboardID string, resourceGraph interface {
	Incoming(resourceID string) []model.Relationship
	Resource(id string) (model.Resource, bool)
}) int {
	var count int
	for _, relationship := range resourceGraph.Incoming(dashboardID) {
		if relationship.Type != model.RelationshipBelongsTo {
			continue
		}
		resource, ok := resourceGraph.Resource(relationship.FromID)
		if ok && resource.Type == model.ResourceTypePanel && resource.Status == model.ResourceStatusActive {
			count++
		}
	}
	return count
}
