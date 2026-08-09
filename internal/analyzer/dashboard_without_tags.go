package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DashboardWithoutTagsAnalyzerID = "builtin.dashboard_without_tags"

type DashboardWithoutTagsAnalyzer struct{}

func NewDashboardWithoutTagsAnalyzer() *DashboardWithoutTagsAnalyzer {
	return &DashboardWithoutTagsAnalyzer{}
}

func (a *DashboardWithoutTagsAnalyzer) ID() string {
	return DashboardWithoutTagsAnalyzerID
}

func (a *DashboardWithoutTagsAnalyzer) Name() string {
	return "Dashboard Without Tags"
}

func (a *DashboardWithoutTagsAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DashboardWithoutTagsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *DashboardWithoutTagsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if !isActiveDashboard(dashboard) || dashboard.Source.System != "grafana" {
			continue
		}
		if strings.TrimSpace(dashboard.Metadata[model.MetadataDashboardTags]) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "DashboardWithoutTags",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q has no tags", dashboard.Name),
			},
			Recommendation: "为 Dashboard 补充服务、团队、环境或用途标签，便于搜索、归类、权限治理和报表聚合。",
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
