package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const GrafanaDatabaseUnhealthyAnalyzerID = "builtin.grafana_database_unhealthy"

type GrafanaDatabaseUnhealthyAnalyzer struct{}

func NewGrafanaDatabaseUnhealthyAnalyzer() *GrafanaDatabaseUnhealthyAnalyzer {
	return &GrafanaDatabaseUnhealthyAnalyzer{}
}

func (a *GrafanaDatabaseUnhealthyAnalyzer) ID() string {
	return GrafanaDatabaseUnhealthyAnalyzerID
}

func (a *GrafanaDatabaseUnhealthyAnalyzer) Name() string {
	return "Grafana Database Unhealthy"
}

func (a *GrafanaDatabaseUnhealthyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *GrafanaDatabaseUnhealthyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *GrafanaDatabaseUnhealthyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "grafana" ||
			resource.Metadata[model.MetadataGrafanaRuntime] != "true" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(resource.Metadata[model.MetadataGrafanaDatabaseStatus]))
		if status == "" || status == "ok" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "GrafanaDatabaseUnhealthy",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Grafana health API reports database status %q", status)},
			Recommendation: "检查 Grafana 数据库连通性、连接池、迁移状态和后端存储健康；恢复 `/api/health` 的 database=ok 后重新同步。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"database_status": status,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
