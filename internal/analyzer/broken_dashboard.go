package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BrokenDashboardAnalyzerID = "builtin.broken_dashboard"

type BrokenDashboardAnalyzer struct{}

func NewBrokenDashboardAnalyzer() *BrokenDashboardAnalyzer {
	return &BrokenDashboardAnalyzer{}
}

func (a *BrokenDashboardAnalyzer) ID() string {
	return BrokenDashboardAnalyzerID
}

func (a *BrokenDashboardAnalyzer) Name() string {
	return "Broken Dashboard"
}

func (a *BrokenDashboardAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BrokenDashboardAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *BrokenDashboardAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if !isDashboardEligibleForHealthDetection(dashboard) {
			continue
		}
		evidence := dashboardEvidence(dashboard)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "BrokenDashboard",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence:       evidence,
			Recommendation: "检查 Dashboard 是否仍存在、Grafana 导入状态是否正常，以及关联 Datasource 和 Panel 配置是否有效。",
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

func dashboardEvidence(dashboard model.Resource) []string {
	health := strings.TrimSpace(dashboard.Metadata[model.MetadataHealth])

	evidence := make([]string, 0, 2)
	if health != "" && !strings.EqualFold(health, "ok") && !strings.EqualFold(health, "up") {
		evidence = append(evidence, fmt.Sprintf("dashboard health is %q", health))
	}
	if dashboard.Status == model.ResourceStatusBroken && len(evidence) == 0 {
		evidence = append(evidence, "dashboard status is BROKEN")
	}
	return evidence
}

func isDashboardEligibleForHealthDetection(dashboard model.Resource) bool {
	return dashboard.Type == model.ResourceTypeDashboard &&
		dashboard.Status != model.ResourceStatusDeprecated &&
		dashboard.Status != model.ResourceStatusDeleted
}
