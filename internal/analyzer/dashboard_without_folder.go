package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DashboardWithoutFolderAnalyzerID = "builtin.dashboard_without_folder"

type DashboardWithoutFolderAnalyzer struct{}

func NewDashboardWithoutFolderAnalyzer() *DashboardWithoutFolderAnalyzer {
	return &DashboardWithoutFolderAnalyzer{}
}

func (a *DashboardWithoutFolderAnalyzer) ID() string {
	return DashboardWithoutFolderAnalyzerID
}

func (a *DashboardWithoutFolderAnalyzer) Name() string {
	return "Dashboard Without Folder"
}

func (a *DashboardWithoutFolderAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DashboardWithoutFolderAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *DashboardWithoutFolderAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if !isActiveDashboard(dashboard) || dashboard.Source.System != "grafana" || hasDashboardFolder(dashboard.Metadata) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "DashboardWithoutFolder",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q has no folder metadata", dashboard.Name),
			},
			Recommendation: "将 Dashboard 归入业务、团队或环境对应的 Grafana folder，便于权限管理、责任归属和治理报表聚合。",
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

func hasDashboardFolder(metadata map[string]string) bool {
	return strings.TrimSpace(metadata[model.MetadataFolderUID]) != "" ||
		strings.TrimSpace(metadata[model.MetadataFolderTitle]) != ""
}
