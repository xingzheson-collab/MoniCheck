package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const LokiNotReadyAnalyzerID = "builtin.loki_not_ready"

type LokiNotReadyAnalyzer struct{}

func NewLokiNotReadyAnalyzer() *LokiNotReadyAnalyzer {
	return &LokiNotReadyAnalyzer{}
}

func (a *LokiNotReadyAnalyzer) ID() string {
	return LokiNotReadyAnalyzerID
}

func (a *LokiNotReadyAnalyzer) Name() string {
	return "Loki Runtime Not Ready"
}

func (a *LokiNotReadyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *LokiNotReadyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *LokiNotReadyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "loki" ||
			resource.Metadata[model.MetadataLokiRuntime] != "true" ||
			resource.Metadata[model.MetadataLokiReadinessAvailable] != "true" ||
			resource.Metadata[model.MetadataLokiReady] != "false" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "LokiNotReady",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"Loki /ready returned HTTP 503 and explicitly reported the configured component as not ready"},
			Recommendation: "检查 Loki 组件服务状态、ring 成员、KV store、ingester readiness 以及 query-frontend/querier 连接；恢复 `/ready` 为 HTTP 200 后重新同步。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"ready":       "false",
				"scope":       "configured_component",
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
