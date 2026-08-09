package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const EmptyDashboardAnalyzerID = "builtin.empty_dashboard"

type EmptyDashboardAnalyzer struct{}

func NewEmptyDashboardAnalyzer() *EmptyDashboardAnalyzer {
	return &EmptyDashboardAnalyzer{}
}

func (a *EmptyDashboardAnalyzer) ID() string {
	return EmptyDashboardAnalyzerID
}

func (a *EmptyDashboardAnalyzer) Name() string {
	return "Empty Dashboard"
}

func (a *EmptyDashboardAnalyzer) Version() string {
	return "0.1.0"
}

func (a *EmptyDashboardAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *EmptyDashboardAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if dashboard.Status != model.ResourceStatusActive {
			continue
		}
		if hasPanel(analysis.Graph.Incoming(dashboard.ID), analysis.Graph) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "EmptyDashboard",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("dashboard %q has no panel relationship", dashboard.Name),
			},
			Recommendation: "确认该 Dashboard 是否仍有价值；如果没有任何 Panel，建议归档或删除。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func hasPanel(relationships []model.Relationship, resourceGraph interface {
	Resource(id string) (model.Resource, bool)
}) bool {
	for _, relationship := range relationships {
		if relationship.Type != model.RelationshipBelongsTo {
			continue
		}
		resource, ok := resourceGraph.Resource(relationship.FromID)
		if ok && resource.Type == model.ResourceTypePanel && resource.Status == model.ResourceStatusActive {
			return true
		}
	}
	return false
}
